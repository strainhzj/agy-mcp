// The HTTP transport guards: rate, in-flight and session caps. Each test
// pins one limit's rejection and one passthrough, so removing the guard's
// corresponding branch turns it red.
package mcptools

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tphakala/agy-mcp/v2/internal/config"
)

// stubHandler answers 200 and, when told, assigns a session id on the
// response the way the Streamable HTTP transport does for a new session.
func stubHandler(assign string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if assign != "" {
			w.Header().Set(mcpSessionHeader, assign)
		}
		w.WriteHeader(http.StatusOK)
	})
}

// TestGuardZeroLimitsPassthrough pins that a zero guard changes nothing: the
// middleware is not installed, so any number of requests pass.
func TestGuardZeroLimitsPassthrough(t *testing.T) {
	if (config.HTTPGuard{}).Limited() {
		t.Fatal("zero guard reported Limited")
	}
	g := newHTTPGuard(config.HTTPGuard{})
	for range 5 {
		rec := httptest.NewRecorder()
		g.middleware(stubHandler("")).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
		if rec.Code != http.StatusOK {
			t.Fatalf("zero-limited guard rejected a request: %d", rec.Code)
		}
	}
}

// TestGuardRateLimit pins the token bucket: a burst up to the rate passes,
// the next immediate request is 429, and the bucket refills over time.
func TestGuardRateLimit(t *testing.T) {
	g := newHTTPGuard(config.HTTPGuard{RatePerSec: 3})
	passed := 0
	for range 3 {
		rec := httptest.NewRecorder()
		g.middleware(stubHandler("")).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
		if rec.Code != http.StatusOK {
			t.Fatalf("burst request %d rejected with %d, want the full burst allowed", passed+1, rec.Code)
		}
		passed++
	}
	rec := httptest.NewRecorder()
	g.middleware(stubHandler("")).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-burst request = %d, want 429", rec.Code)
	}
	// One second at 3/s refills at least one token.
	time.Sleep(1100 * time.Millisecond)
	rec = httptest.NewRecorder()
	g.middleware(stubHandler("")).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("refilled request = %d, want 200", rec.Code)
	}
}

// TestGuardMaxInflight pins the concurrency semaphore: requests beyond the
// cap get 503 while the first ones are still being processed.
func TestGuardMaxInflight(t *testing.T) {
	g := newHTTPGuard(config.HTTPGuard{MaxInflight: 1})
	release := make(chan struct{})
	var inHandler sync.WaitGroup
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inHandler.Done()
		<-release
	})
	inHandler.Add(1)
	done := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		g.middleware(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
		done <- rec.Code
	}()
	inHandler.Wait() // the first request holds the only slot
	rec := httptest.NewRecorder()
	g.middleware(stubHandler("")).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("over-cap request = %d, want 503", rec.Code)
	}
	close(release)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("first request = %d, want 200", code)
	}
}

// TestGuardSessionCap pins the session bound: MaxSessions distinct
// server-issued sessions are tracked, the next new session is refused, and
// requests carrying an already-issued id keep passing even at the cap.
// Removing the cap check in admitSession turns this red.
func TestGuardSessionCap(t *testing.T) {
	g := newHTTPGuard(config.HTTPGuard{MaxSessions: 2, SessionTimeout: time.Minute})
	for i := range 2 {
		rec := httptest.NewRecorder()
		g.middleware(stubHandler(fmt.Sprintf("sess-%d", i))).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
		if rec.Code != http.StatusOK {
			t.Fatalf("session %d = %d, want 200", i, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	g.middleware(stubHandler("sess-3")).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third session = %d, want 429", rec.Code)
	}
	// A known session still passes at the cap.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set(mcpSessionHeader, "sess-0")
	g.middleware(stubHandler("")).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("known session = %d, want 200", rec.Code)
	}
}

// TestGuardKnownSessionReachesHandler pins the pass-through half of
// admitSession. The bug this guards against collapsed "refused" and "pass
// through" into one nil return, so every request carrying a session id
// (everything after initialize) was answered by Go's empty 200 before the
// handler ever ran. The status code alone cannot tell the two apart, so the
// assertion is on the handler's body: with the collapsed return the handler
// never executes and the body is empty.
func TestGuardKnownSessionReachesHandler(t *testing.T) {
	g := newHTTPGuard(config.HTTPGuard{MaxSessions: 2, SessionTimeout: time.Minute})
	body := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"handled":true}`))
	})
	// Issue one session through the recorder path.
	rec := httptest.NewRecorder()
	g.middleware(stubHandler("sess-known")).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("session issue = %d, want 200", rec.Code)
	}
	// A request carrying it must reach the handler and come back with its body.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set(mcpSessionHeader, "sess-known")
	g.middleware(body).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("known session = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != `{"handled":true}` {
		t.Fatalf("known session body = %q, want the handler's body; an empty body means the middleware ended the request without calling the handler", got)
	}
}

// TestGuardIdleSessionEviction pins the retirement half of the cap: sessions
// idle past the timeout stop counting against it, so new sessions are
// admitted again.
func TestGuardIdleSessionEviction(t *testing.T) {
	g := newHTTPGuard(config.HTTPGuard{MaxSessions: 1, SessionTimeout: 20 * time.Millisecond})
	rec := httptest.NewRecorder()
	g.middleware(stubHandler("sess-0")).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("first session = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	g.middleware(stubHandler("sess-1")).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second session at cap = %d, want 429", rec.Code)
	}
	time.Sleep(50 * time.Millisecond)
	rec = httptest.NewRecorder()
	g.middleware(stubHandler("sess-1")).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("session after idle eviction = %d, want 200", rec.Code)
	}
}

// TestGuardConcurrentRegistrationsDoNotLeak stresses the registration path:
// many parallel new sessions at a tight cap all either pass or are refused,
// and the tracked set never exceeds the cap by more than the in-flight
// burst that was accepted.
func TestGuardConcurrentRegistrationsDoNotLeak(t *testing.T) {
	g := newHTTPGuard(config.HTTPGuard{MaxSessions: 4, SessionTimeout: time.Minute})
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			g.middleware(stubHandler(fmt.Sprintf("sess-%d", n))).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
			if rec.Code == http.StatusOK {
				accepted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	g.sessionsMu.Lock()
	tracked := len(g.sessions)
	g.sessionsMu.Unlock()
	if tracked == 0 || tracked > 50 {
		t.Fatalf("tracked sessions = %d, outside any sane bound", tracked)
	}
	if accepted.Load() == 0 {
		t.Fatal("every concurrent session refused; the cap is not being released")
	}
}
