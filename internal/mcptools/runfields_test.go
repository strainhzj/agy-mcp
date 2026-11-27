package mcptools

import (
	"maps"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tphakala/agy-mcp/v2/internal/config"
	"github.com/tphakala/agy-mcp/v2/internal/jobstore"
	"github.com/tphakala/agy-mcp/v2/internal/manager"
	"github.com/tphakala/agy-mcp/v2/internal/policy"
	"github.com/tphakala/agy-mcp/v2/internal/proc"
)

// TestProtectedToolsListHidesForbiddenFields pins the schema half of the
// parameter contract: under a protected profile the run tools must not
// advertise a parameter the server refuses. A field that always fails is not a
// constraint, it is a trap: the model reads the schema, sends the field, and
// burns a tool call learning it was refused. Removing the protected input
// types (or registering runInput for a protected server) turns this red.
func TestProtectedToolsListHidesForbiddenFields(t *testing.T) {
	root := canonicalTempDir(t)
	cs := connect(t, protectedManager(t, root), nil)
	tools, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	for _, name := range []string{toolAgyRun, toolAgyRunSync} {
		var tool *mcp.Tool
		for _, candidate := range tools.Tools {
			if candidate.Name == name {
				tool = candidate
				break
			}
		}
		if tool == nil {
			t.Fatalf("tool %s missing from tools/list", name)
		}
		schema, ok := tool.InputSchema.(map[string]any)
		if !ok {
			t.Fatalf("tool %s input schema has type %T, want object", name, tool.InputSchema)
		}
		props, ok := schema["properties"].(map[string]any)
		if !ok {
			t.Fatalf("tool %s schema properties have type %T", name, schema["properties"])
		}
		for _, forbidden := range []string{"mode", "json_schema", "continue_latest", "conversation_id"} {
			if _, present := props[forbidden]; present {
				t.Errorf("protected %s schema still advertises %q", name, forbidden)
			}
		}
		// The fields a protected run does accept must still be there, or the
		// pruning went too far and the tool became unusable.
		for _, want := range []string{"prompt", "cwd", "timeout", "priority", "idempotency_key"} {
			if _, present := props[want]; !present {
				t.Errorf("protected %s schema lost the accepted field %q", name, want)
			}
		}
	}
}

// TestProtectedToolsListAdvertisesHandleUnderManagedOnly pins the managed-only
// shape: the continuation field comes back, but described as this server's
// opaque handle rather than a native conversation id.
func TestProtectedToolsListAdvertisesHandleUnderManagedOnly(t *testing.T) {
	root := canonicalTempDir(t)
	pol := protectedManagerPolicy(t, root)
	pol.SessionPolicy = policy.SessionPolicyManagedOnly
	m := manager.New(config.Config{
		StateDir: t.TempDir(),
		Policy:   pol,
	})
	cs := connect(t, m, nil)
	tools, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	for _, name := range []string{toolAgyRun, toolAgyRunSync} {
		var tool *mcp.Tool
		for _, candidate := range tools.Tools {
			if candidate.Name == name {
				tool = candidate
				break
			}
		}
		if tool == nil {
			t.Fatalf("tool %s missing from tools/list", name)
		}
		schema := tool.InputSchema.(map[string]any)
		props := schema["properties"].(map[string]any)
		field, present := props["conversation_id"]
		if !present {
			t.Fatalf("managed-only %s schema lost conversation_id; handles must be passable", name)
		}
		desc, _ := field.(map[string]any)["description"].(string)
		if !strings.Contains(desc, "handle") {
			t.Errorf("managed-only %s conversation_id description = %q; want it to name the handle", name, desc)
		}
		for _, forbidden := range []string{"mode", "json_schema", "continue_latest"} {
			if _, present := props[forbidden]; present {
				t.Errorf("managed-only %s schema still advertises %q", name, forbidden)
			}
		}
	}
}

// TestProtectedRunRefusesModeKeyPresence is the presence half of the contract:
// the policy refuses the mode key whatever its value, including the empty
// string and null, which a typed decode cannot distinguish from absence. The
// refusal must happen before a job directory exists, so the store stays empty.
func TestProtectedRunRefusesModeKeyPresence(t *testing.T) {
	if !proc.Supported {
		t.Skip("job supervision unsupported on this platform")
	}
	root := canonicalTempDir(t)
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"value", map[string]any{"mode": "accept-edits"}},
		{"empty string", map[string]any{"mode": ""}},
		{"null", map[string]any{"mode": nil}},
		{"wrong type", map[string]any{"mode": 7}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Each subtest owns its manager and state dir, so "no job was created"
			// is a statement about this refusal alone.
			state := t.TempDir()
			m := manager.New(config.Config{
				StateDir: state,
				Policy:   protectedManagerPolicy(t, root),
			})
			cs := connect(t, m, nil)
			args := map[string]any{"prompt": "contract evidence only"}
			maps.Copy(args, tc.args)
			res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: toolAgyRun, Arguments: args})
			if err == nil && (res == nil || !res.IsError) {
				t.Fatalf("mode=%v accepted under a protected profile", tc.args["mode"])
			}
			if msg := toolErrorText(err, res); !strings.Contains(msg, "mode") {
				t.Fatalf("mode refusal = %q, want it to name mode", msg)
			}
			// The refusal must precede job creation: no dir, no worker.
			ids, lerr := jobstore.New(state).List()
			if lerr != nil {
				t.Fatalf("list jobs: %v", lerr)
			}
			if len(ids) != 0 {
				t.Fatalf("refused mode request created job dirs %q", ids)
			}
		})
	}
}

// TestProtectedRunSyncRefusesDisabledKeys covers the same gate on
// agy_run_sync, so the two run tools cannot drift on it: each disabled key is
// refused by name and leaves no job behind.
func TestProtectedRunSyncRefusesDisabledKeys(t *testing.T) {
	if !proc.Supported {
		t.Skip("job supervision unsupported on this platform")
	}
	root := canonicalTempDir(t)
	for _, tc := range []struct {
		key  string
		args map[string]any
	}{
		{"mode", map[string]any{"mode": "accept-edits"}},
		{"json_schema", map[string]any{"json_schema": `{"type":"object"}`}},
		{"continue_latest", map[string]any{"continue_latest": true}},
		{"conversation_id", map[string]any{"conversation_id": "native-looking-id"}},
	} {
		t.Run(tc.key, func(t *testing.T) {
			state := t.TempDir()
			m := manager.New(config.Config{
				StateDir: state,
				Policy:   protectedManagerPolicy(t, root),
			})
			cs := connect(t, m, nil)
			args := map[string]any{"prompt": "p"}
			maps.Copy(args, tc.args)
			res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: toolAgyRunSync, Arguments: args})
			if err == nil && (res == nil || !res.IsError) {
				t.Fatalf("%s accepted under a protected profile", tc.key)
			}
			if msg := toolErrorText(err, res); !strings.Contains(msg, tc.key) {
				t.Fatalf("%s refusal = %q, want it to name %s", tc.key, msg, tc.key)
			}
			ids, lerr := jobstore.New(state).List()
			if lerr != nil {
				t.Fatalf("list jobs: %v", lerr)
			}
			if len(ids) != 0 {
				t.Fatalf("refused %s request created job dirs %q", tc.key, ids)
			}
		})
	}
}

// TestUnrestrictedRunKeepsModeField pins the upstream-compat half: with no
// policy the run schema still advertises mode, and the raw-key gate is a
// no-op. Without this, the protected pruning could not be told apart from a
// blanket removal.
func TestUnrestrictedRunKeepsModeField(t *testing.T) {
	cs := connect(t, nil, nil)
	tools, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	for _, name := range []string{toolAgyRun, toolAgyRunSync} {
		var tool *mcp.Tool
		for _, candidate := range tools.Tools {
			if candidate.Name == name {
				tool = candidate
				break
			}
		}
		if tool == nil {
			t.Fatalf("tool %s missing from tools/list", name)
		}
		props := tool.InputSchema.(map[string]any)["properties"].(map[string]any)
		for _, want := range []string{"mode", "json_schema", "continue_latest", "conversation_id"} {
			if _, present := props[want]; !present {
				t.Errorf("unrestricted %s schema lost %q; upstream behavior must be unchanged", name, want)
			}
		}
	}
}
