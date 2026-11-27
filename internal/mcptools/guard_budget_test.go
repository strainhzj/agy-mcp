// The session-cap contracts the hardening acceptance found broken, pinned
// deterministically.
//
// An initialize request is admitted before its handler assigns the session id,
// so counting only issued sessions let a burst of concurrent initializes all
// pass the cap and register afterwards: with MaxSessions=1 two sessions were
// admitted and tracked. The reservation (admitSession's pending counter,
// released by registerSession) is what closes that window. Removing either
// half turns the corresponding test red.

package mcptools

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tphakala/agy-mcp/v2/internal/config"
)

// TestGuardConcurrentInitializationsRespectMaxSessions pins the reservation:
// while the first handler is admitted but has not yet written its session id,
// a second initialize must be refused rather than admitted on the strength of
// a count that has not caught up yet.
func TestGuardConcurrentInitializationsRespectMaxSessions(t *testing.T) {
	g := newHTTPGuard(config.HTTPGuard{MaxSessions: 1, SessionTimeout: time.Minute})

	// The first handler blocks before writing its id, which is exactly the
	// window the reservation covers.
	inHandler := make(chan struct{})
	release := make(chan struct{})
	var entered atomic.Int32
	blocking := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered.Add(1)
		close(inHandler)
		<-release
		w.Header().Set(mcpSessionHeader, "sess-first")
		w.WriteHeader(http.StatusOK)
	})

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		first  int
		second int
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		rec := httptest.NewRecorder()
		g.middleware(blocking).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
		mu.Lock()
		first = rec.Code
		mu.Unlock()
	}()
	<-inHandler // the first request holds the only slot, still unregistered

	go func() {
		defer wg.Done()
		rec := httptest.NewRecorder()
		g.middleware(stubHandler("sess-second")).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
		mu.Lock()
		second = rec.Code
		mu.Unlock()
	}()
	// Wait for the second request to be answered rather than guessing at a
	// sleep, but bound it so a broken reservation cannot hang the suite.
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		answered := second != 0
		mu.Unlock()
		if answered || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if got := entered.Load(); got != 1 {
		t.Errorf("handlers entered = %d, want exactly 1; the cap let a second initialize in", got)
	}
	if first != http.StatusOK {
		t.Errorf("first request = %d, want 200", first)
	}
	if second != http.StatusTooManyRequests {
		t.Errorf("second concurrent initialize = %d, want 429", second)
	}
	g.sessionsMu.Lock()
	tracked, pending := len(g.sessions), g.pending
	g.sessionsMu.Unlock()
	if tracked != 1 {
		t.Errorf("tracked sessions = %d, want 1", tracked)
	}
	if pending != 0 {
		t.Errorf("pending reservations = %d after both requests settled, want 0; a leaked slot permanently shrinks the cap", pending)
	}
}

// TestGuardSessionSlotReleasedWhenNoIDAssigned pins the other half of the
// reservation: a handler that assigns no session id (an error response) must
// still release the slot it reserved, or every refused initialize would
// permanently consume one.
func TestGuardSessionSlotReleasedWhenNoIDAssigned(t *testing.T) {
	g := newHTTPGuard(config.HTTPGuard{MaxSessions: 1, SessionTimeout: time.Minute})
	noID := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	rec := httptest.NewRecorder()
	g.middleware(noID).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("first request = %d, want 500", rec.Code)
	}
	rec = httptest.NewRecorder()
	g.middleware(stubHandler("sess-next")).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("second request = %d, want 200; the reservation was not released", rec.Code)
	}
	g.sessionsMu.Lock()
	defer g.sessionsMu.Unlock()
	if len(g.sessions) != 1 || g.pending != 0 {
		t.Fatalf("sessions=%d pending=%d, want 1 tracked and 0 pending", len(g.sessions), g.pending)
	}
}

// TestGuardSessionCapSequentialStillHolds keeps the original cap semantics
// from regressing: issued sessions count, a known id passes at the cap, and
// the sequential path is unchanged.
func TestGuardSessionCapSequentialStillHolds(t *testing.T) {
	g := newHTTPGuard(config.HTTPGuard{MaxSessions: 1, SessionTimeout: time.Minute})
	rec := httptest.NewRecorder()
	g.middleware(stubHandler("sess-0")).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("first session = %d, want 200", rec.Code)
	}
	rec = httptest.NewRecorder()
	g.middleware(stubHandler("sess-1")).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second session at cap = %d, want 429", rec.Code)
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set(mcpSessionHeader, "sess-0")
	g.middleware(stubHandler("")).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("known session at cap = %d, want 200", rec.Code)
	}
}

// TestGuardConcurrentBurstNeverExceedsCap stresses the reservation with a real
// burst: at MaxSessions=4, no more than four sessions may ever be tracked at
// once, whatever the interleaving.
func TestGuardConcurrentBurstNeverExceedsCap(t *testing.T) {
	const maxSessions = 4
	g := newHTTPGuard(config.HTTPGuard{MaxSessions: maxSessions, SessionTimeout: time.Minute})
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			g.middleware(stubHandler("sess-"+string(rune('a'+n%26))+"-"+time.Now().String())).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
		}(i)
	}
	wg.Wait()
	g.sessionsMu.Lock()
	defer g.sessionsMu.Unlock()
	tracked := len(g.sessions)
	if tracked > maxSessions {
		t.Fatalf("tracked sessions = %d, want at most the cap %d", tracked, maxSessions)
	}
	if g.pending != 0 {
		t.Fatalf("pending reservations = %d after the burst settled, want 0", g.pending)
	}
}
