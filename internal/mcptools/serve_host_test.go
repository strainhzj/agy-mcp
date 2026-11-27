package mcptools

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tphakala/agy-mcp/v2/internal/config"
	"github.com/tphakala/agy-mcp/v2/internal/manager"
)

// initializeBody is the smallest well-formed initialize request: enough for the
// streamable transport to answer, and enough to prove a Host refusal happened
// before the JSON-RPC layer rather than inside it.
const initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`

// sendInitialize posts an initialize request to the handler with the given Host
// header and bearer token, and reports the status code and body.
func sendInitialize(t *testing.T, h http.Handler, host, token string) (code int, body string) {
	t.Helper()
	ts := httptest.NewServer(h)
	defer ts.Close()
	req := postJSON(t, ts.URL+"/mcp", initializeBody)
	req.Host = host
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(b)
}

// TestProtectedHTTPRejectsUnlistedHost pins the Host allowlist that replaces the
// SDK's localhost check on a protected instance. The profile disables that
// check so a bridge-published Host header can reach the JSON-RPC layer; without
// an allowlist in its place, any Host would do, and the DNS-rebinding defense
// the check provided would be gone. A request carrying the right token but a
// Host outside the configured set must be refused with 403.
func TestProtectedHTTPRejectsUnlistedHost(t *testing.T) {
	root := canonicalTempDir(t)
	m := protectedManager(t, root)
	h := HTTPHandler(m, "synthetic-token")

	code, body := sendInitialize(t, h, "not-in-the-allowlist.invalid", "synthetic-token")
	if code != http.StatusForbidden {
		t.Fatalf("unlisted Host = %d, want 403; body=%q", code, body)
	}

	// The configured hosts still pass: the allowlist must not refuse the
	// deployment it was written for.
	for _, host := range []string{"127.0.0.8:8765"} {
		code, body := sendInitialize(t, h, host, "synthetic-token")
		if code != http.StatusOK {
			t.Fatalf("allowed Host %s = %d, want 200; body=%q", host, code, body)
		}
	}
}

// TestProtectedHTTPHostRefusalNeedsTheToken pins the ordering: the Host check
// sits inside the bearer check, so an unauthenticated caller cannot use the
// 403-vs-401 difference to learn which Hosts the server accepts. A wrong token
// gets 401 whatever Host it names.
func TestProtectedHTTPHostRefusalNeedsTheToken(t *testing.T) {
	root := canonicalTempDir(t)
	h := HTTPHandler(protectedManager(t, root), "synthetic-token")
	for _, host := range []string{"not-in-the-allowlist.invalid", "127.0.0.8:8765"} {
		code, _ := sendInitialize(t, h, host, "wrong-token")
		if code != http.StatusUnauthorized {
			t.Fatalf("wrong token with Host %s = %d, want 401 (the Host check must not run first)", host, code)
		}
	}
}

// TestUnprotectedHTTPKeepsUpstreamHostBehavior pins the other half: with no
// allowlist configured the middleware is not installed, so an unrestricted
// server's Host handling is exactly what the SDK does.
//
// Note the direction: an empty allowlist ACCEPTS every Host, which is what
// makes the middleware a no-op for upstream servers. The 403 an unrestricted
// server gives a non-local Host is the SDK's own localhost check, unchanged:
// this test pins that the profile is the only thing that alters Host handling,
// in either direction.
func TestUnprotectedHTTPKeepsUpstreamHostBehavior(t *testing.T) {
	m := manager.New(config.Config{StateDir: t.TempDir()})
	if !m.Policy().HostAllowed("anything.invalid:1234") {
		t.Fatal("an empty policy refused a Host; an empty allowlist must accept every Host so the middleware stays off")
	}
	h := HTTPHandler(m, "")
	// The SDK's localhost check still applies to an unprotected server, so a
	// non-local Host is refused there too: that is upstream behavior, and it is
	// what the protected profile's allowlist replaces.
	if code, _ := sendInitialize(t, h, "anything.invalid:1234", ""); code == http.StatusOK {
		t.Fatal("unprotected server accepted a non-local Host; the SDK's localhost check must stay in force there")
	}
	// A localhost Host passes, as it always has.
	if code, _ := sendInitialize(t, h, "127.0.0.1", ""); code != http.StatusOK {
		t.Fatalf("unprotected server refused a localhost Host = %d, want 200", code)
	}
}

// TestSyncWaitCapUsesResolvedValue pins the client-timeout budget wiring: the
// inline wait must be bounded by the value config.Resolve produced, not by a
// second read of the environment that could disagree with it. Under the
// profile that value is mandatory and strictly parsed, so a manager carrying
// one must have it honored.
func TestSyncWaitCapUsesResolvedValue(t *testing.T) {
	root := canonicalTempDir(t)
	m := protectedManager(t, root)
	// Hand-build a manager carrying a resolved cap the way config.Resolve would
	// under the profile, and check the tool layer reads it.
	resolved := manager.New(config.Config{
		StateDir:     t.TempDir(),
		SyncWaitCap:  30 * time.Second,
		Policy:       m.Policy(),
		DefaultModel: "",
	})
	if got := maxSyncWait(resolved); got != 30*time.Second {
		t.Fatalf("maxSyncWait with a resolved cap = %v, want 30s", got)
	}
	// A zero resolved value (a hand-built Config, or the nil-manager shape)
	// falls back rather than expiring every inline wait before it starts.
	if got := maxSyncWait(m); got != config.ResolveSyncWaitCap(func(string) string { return "" }) {
		t.Fatalf("maxSyncWait with no resolved cap = %v, want the default ceiling", got)
	}
	if got := maxSyncWait(nil); got != config.ResolveSyncWaitCap(func(string) string { return "" }) {
		t.Fatalf("maxSyncWait with a nil manager = %v, want the default ceiling", got)
	}
}

// TestParseWaitClampsToResolvedCap pins the clamp itself: a caller asking for
// longer than the resolved ceiling is clamped to it, and an omitted wait
// defaults to it.
func TestParseWaitClampsToResolvedCap(t *testing.T) {
	m := manager.New(config.Config{StateDir: t.TempDir(), SyncWaitCap: 20 * time.Second})
	got, err := parseWait(m, "5m")
	if err != nil {
		t.Fatalf("parseWait: %v", err)
	}
	if got != 20*time.Second {
		t.Fatalf("over-cap wait = %v, want it clamped to the resolved 20s", got)
	}
	got, err = parseWait(m, "")
	if err != nil {
		t.Fatalf("parseWait: %v", err)
	}
	if got != 20*time.Second {
		t.Fatalf("default wait = %v, want the resolved 20s", got)
	}
	got, err = parseWait(m, "3s")
	if err != nil {
		t.Fatalf("parseWait: %v", err)
	}
	if got != 3*time.Second {
		t.Fatalf("under-cap wait = %v, want 3s unchanged", got)
	}
}

// TestProtectedInstructionsNameModeRefusal keeps the schema pruning and the
// prose in step: if the instructions still invite a mode, the schema that
// removed it is contradicted by the text a model actually reads.
func TestProtectedInstructionsNameModeRefusal(t *testing.T) {
	root := canonicalTempDir(t)
	cs := connect(t, protectedManager(t, root), nil)
	instr := cs.InitializeResult().Instructions
	if !strings.Contains(instr, "json_schema") {
		t.Fatalf("instructions lack the json_schema note:\n%s", instr)
	}
}
