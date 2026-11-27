package mcptools

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tphakala/agy-mcp/v2/internal/config"
	"github.com/tphakala/agy-mcp/v2/internal/manager"
	"github.com/tphakala/agy-mcp/v2/internal/policy"
	"github.com/tphakala/agy-mcp/v2/internal/proc"
)

// protectedManager builds a manager with the protected single-project policy
// and a fresh state dir. Nothing here execs agy.
//
// The policy is the worker-view shape internal/config resolves: the only
// allowed root is the worker mount, and the manifest's snapshot root is what
// that mount maps onto on the host. So a caller passes /workspace/... and the
// value that comes back out is the same spelling, never a host path.
func protectedManager(t *testing.T, root string) *manager.Manager {
	t.Helper()
	return manager.New(config.Config{
		StateDir: t.TempDir(),
		Policy: policy.Policy{
			Profile:             policy.ProfilePi,
			AllowedRoots:        []string{"/workspace"},
			DefaultCwd:          "/workspace",
			WorkerMount:         "/workspace",
			SnapshotRoot:        root,
			SessionPolicy:       policy.SessionPolicyDisabled,
			ForceSandbox:        true,
			DisableJSONSchema:   true,
			Mode:                policy.ModePolicy{DisableClientMode: true},
			AllowedHosts:        []string{"127.0.0.8:8765"},
			RequireHTTPToken:    true,
			SnapshotFingerprint: "sha256:" + strings.Repeat("a", 64),
			ProjectID:           "proj-1",
			InstanceID:          "inst-1",
		},
		ProjectID:  "proj-1",
		InstanceID: "inst-1",
	})
}

// protectedManagerPolicy returns the protected policy shape on its own, for
// tests that build a Manager with their own state dir (so "no job was
// created" can be asserted against a store the test owns).
func protectedManagerPolicy(t *testing.T, root string) policy.Policy {
	t.Helper()
	return protectedManager(t, root).Policy()
}

// canonicalTempDir is an existing directory with its symlink-resolved path,
// matching what the policy stores.
func canonicalTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve tempdir: %v", err)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("abs tempdir: %v", err)
	}
	return abs
}

// TestProtectedServerDescribesItself pins the §4.5 contract: under a protected
// profile the instructions and tool descriptions must state what the profile
// enforces (single read-only project, single-turn, schema refused), not
// restate the unrestricted defaults. The nil-manager path keeps the upstream
// text, which is what the other tool tests already pin.
func TestProtectedServerDescribesItself(t *testing.T) {
	root := canonicalTempDir(t)
	cs := connect(t, protectedManager(t, root), nil)
	instr := cs.InitializeResult().Instructions
	for _, want := range []string{
		"single-project",
		"read-only",
		"single-turn",
		"json_schema is refused",
		"conversation_id, continue_latest and list_sessions are unavailable",
	} {
		if !strings.Contains(instr, want) {
			t.Errorf("protected instructions lack %q; got:\n%s", want, instr)
		}
	}
	if strings.Contains(instr, "continue the latest thread for a directory") {
		t.Error("protected instructions still advertise continue_latest")
	}

	res, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	descs := map[string]string{}
	for _, tool := range res.Tools {
		descs[tool.Name] = tool.Description
	}
	for name, want := range map[string][]string{
		toolAgyRun:       {"read-only project workspace", "single-turn", "json_schema are refused"},
		toolAgyRunSync:   {"read-only project snapshot", "conversation continuation and json_schema refused"},
		toolListSessions: {"session policy forbids conversation continuation", "always fails with a policy error"},
	} {
		desc, ok := descs[name]
		if !ok {
			t.Fatalf("tool %s not registered", name)
		}
		for _, w := range want {
			if !strings.Contains(desc, w) {
				t.Errorf("%s description lacks %q; got:\n%s", name, w, desc)
			}
		}
	}
	if strings.Contains(descs[toolAgyRun], "permission checks disabled") {
		t.Error("protected agy_run description still carries the unrestricted permission-checks text")
	}
}

// TestProtectedServerRefusesSessionsAndSchema exercises the tool layer over
// the in-memory transport: list_sessions fails with a policy error (never
// reads the cache), and a run carrying json_schema is refused before any job
// exists. The refusal logic itself is pinned in the manager tests; this pins
// that the tools are wired to it.
func TestProtectedServerRefusesSessionsAndSchema(t *testing.T) {
	if !proc.Supported {
		t.Skip("job supervision unsupported on this platform")
	}
	root := canonicalTempDir(t)
	cs := connect(t, protectedManager(t, root), nil)

	// The SDK surfaces a handler error as an IsError result (the JSON-RPC
	// error text rides in the content), so both surfaces are checked.
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: toolListSessions,
	})
	if err == nil && !res.IsError {
		t.Fatal("list_sessions succeeded under a protected profile")
	}
	if msg := toolErrorText(err, res); !strings.Contains(msg, "session policy") {
		t.Fatalf("list_sessions error = %q; want a policy error", msg)
	}

	res, err = cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: toolAgyRunSync,
		Arguments: map[string]any{
			"prompt":      "p",
			"json_schema": `{"type":"object"}`,
			"cwd":         root,
		},
	})
	if err == nil && !res.IsError {
		t.Fatal("agy_run_sync accepted json_schema under a protected profile")
	}
	if msg := toolErrorText(err, res); !strings.Contains(msg, "json_schema") {
		t.Fatalf("schema refusal = %q; want it to name json_schema", msg)
	}
}

// toolErrorText extracts the error message whichever surface the SDK chose.
func toolErrorText(err error, res *mcp.CallToolResult) string {
	if err != nil {
		return err.Error()
	}
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}
