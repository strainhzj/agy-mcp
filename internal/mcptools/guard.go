// HTTP transport guards: the rate, in-flight and session-count limits the
// plan's protected deployment requires ("limit HTTP request size and rate").
// Request size is bounded by the SDK's own default body cap (4 MiB); this
// layer adds the three dimensions the SDK leaves open:
//
//   - RatePerSec: a token bucket (burst equal to the rate) over authenticated
//     requests, so a confused-deputy client that acquired its token cannot
//     spend unbounded server CPU on request parsing and dispatch.
//   - MaxInflight: a semaphore over requests being processed, so one caller
//     cannot hold unbounded concurrent work in memory.
//   - SessionTimeout + MaxSessions: the SDK closes idle sessions after the
//     timeout; the count is enforced here by tracking the session ids the
//     server itself issued (read off the response headers) and refusing new
//     sessions past the cap.
//
// The zero HTTPGuard disables everything and the middleware is not installed,
// so an unrestricted upstream server behaves exactly as before. Rejections
// are plain HTTP status codes (429 or 503): an MCP client treats the call as
// failed and retries, and the job-store semantics make that retry safe.
package mcptools

import (
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/tphakala/agy-mcp/v2/internal/config"
)

// mcpSessionHeader is the header the Streamable HTTP transport uses to carry
// the session id, in both directions.
const mcpSessionHeader = "Mcp-Session-Id"

// httpGuard carries the resolved limits plus the mutable state the
// middleware needs. Construct with newHTTPGuard; the zero value guards
// nothing, so callers install it only when the guard is Limited.
type httpGuard struct {
	limits config.HTTPGuard

	mu         sync.Mutex
	tokens     float64   // token bucket level
	lastRefill time.Time // last token refill

	inflight chan struct{}

	sessionsMu sync.Mutex
	sessions   map[string]time.Time // server-issued session ids, last seen
}

// newHTTPGuard builds the guard for the given limits. maxSessions is only
// meaningful with a session timeout (config.Resolve enforces the pairing);
// the constructor keeps the same assumption.
func newHTTPGuard(limits config.HTTPGuard) *httpGuard {
	g := &httpGuard{
		limits:     limits,
		tokens:     limits.RatePerSec,
		lastRefill: time.Now(),
		sessions:   map[string]time.Time{},
	}
	if limits.MaxInflight > 0 {
		g.inflight = make(chan struct{}, limits.MaxInflight)
	}
	return g
}

// middleware wraps h with the active limits in the order that bounds damage
// earliest: in-flight first (memory), then rate (CPU), then sessions (per
// session bookkeeping in the SDK).
func (g *httpGuard) middleware(h http.Handler) http.Handler {
	if g == nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.inflight != nil {
			select {
			case g.inflight <- struct{}{}:
				defer func() { <-g.inflight }()
			default:
				http.Error(w, "server is at its in-flight request limit; retry shortly", http.StatusServiceUnavailable)
				return
			}
		}
		if !g.allowRate() {
			http.Error(w, "request rate limit exceeded; retry shortly", http.StatusTooManyRequests)
			return
		}
		if g.limits.MaxSessions > 0 {
			rec, admit := g.admitSession(w, r)
			if !admit {
				return // the refusal is already written
			}
			if rec != nil {
				defer g.registerSession(rec)
				w = rec
			}
		}
		h.ServeHTTP(w, r)
	})
}

// allowRate spends one token from the bucket, refilling lazily by elapsed
// time. Burst equals the rate, so a caller may spend one second's worth at
// once and then is held to the sustained rate.
func (g *httpGuard) allowRate() bool {
	if g.limits.RatePerSec <= 0 {
		return true
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	elapsed := now.Sub(g.lastRefill).Seconds()
	g.lastRefill = now
	g.tokens = math.Min(g.limits.RatePerSec, g.tokens+elapsed*g.limits.RatePerSec)
	if g.tokens < 1 {
		return false
	}
	g.tokens--
	return true
}

// sessionRecorder captures the session id the wrapped handler assigns on its
// response, so the guard tracks exactly the sessions this server issued and
// never the ids a client invents (those get the SDK's 404 and cost nothing).
type sessionRecorder struct {
	http.ResponseWriter
	sessionID string
}

func (s *sessionRecorder) WriteHeader(code int) {
	if id := s.Header().Get(mcpSessionHeader); id != "" {
		s.sessionID = id
	}
	s.ResponseWriter.WriteHeader(code)
}

// admitSession gates new sessions on the cap and reports what the handler
// must do next. The two returns are deliberately separate, because a nil
// recorder means two very different things:
//
//   - (nil, false): the request was refused and the error is already written
//     (a new session arrived while the cap holds);
//   - (nil, true): pass the request through untouched. Either it carries a
//     session id (known: refresh it; unknown: let the handler answer it, a
//     404 that costs one SDK lookup and registers nothing);
//   - (rec, true): a new session under the cap; the handler must write
//     through the recorder so the id it assigns can be registered.
//
// Collapsing the first two into one nil return is the bug this shape exists
// to prevent: the middleware would then end the request without calling the
// handler, and Go would answer an empty 200 for every call that carried a
// session id.
func (g *httpGuard) admitSession(w http.ResponseWriter, r *http.Request) (*sessionRecorder, bool) {
	id := r.Header.Get(mcpSessionHeader)
	g.sessionsMu.Lock()
	defer g.sessionsMu.Unlock()
	g.evictIdleLocked()
	if id != "" {
		if _, known := g.sessions[id]; known {
			g.sessions[id] = time.Now()
		}
		// Known or not, the handler answers: a bogus id gets its 404 from the
		// SDK, which is also the only place that can tell.
		return nil, true
	}
	// No session id: a new-session request (initialize). Refuse at the cap.
	if len(g.sessions) >= g.limits.MaxSessions {
		http.Error(w, "server is at its session limit; existing sessions age out after their idle timeout", http.StatusTooManyRequests)
		return nil, false
	}
	return &sessionRecorder{ResponseWriter: w}, true
}

// registerSession records the id the handler assigned on its response. A
// concurrent burst could momentarily overshoot the cap between the gate and
// this registration; the next admitSession call evicts the idle entries and
// re-reads the count, so the overshoot self-corrects within one request.
func (g *httpGuard) registerSession(rec *sessionRecorder) {
	if rec == nil || rec.sessionID == "" {
		return
	}
	g.sessionsMu.Lock()
	defer g.sessionsMu.Unlock()
	g.sessions[rec.sessionID] = time.Now()
}

// evictIdleLocked drops sessions idle past the configured timeout, so retired
// sessions free cap room. Callers hold sessionsMu.
func (g *httpGuard) evictIdleLocked() {
	cutoff := time.Now().Add(-g.limits.SessionTimeout)
	for id, seen := range g.sessions {
		if seen.Before(cutoff) {
			delete(g.sessions, id)
		}
	}
}

// installGuard wraps h with the guard middleware when the limits are active,
// and returns h untouched otherwise (the upstream zero-config behavior).
func installGuard(g config.HTTPGuard, h http.Handler) http.Handler {
	if !g.Limited() {
		return h
	}
	return newHTTPGuard(g).middleware(h)
}
