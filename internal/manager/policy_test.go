package manager

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tphakala/agy-mcp/v2/internal/jobstore"
	"github.com/tphakala/agy-mcp/v2/internal/policy"
	"github.com/tphakala/agy-mcp/v2/internal/proc"
)

// policyRoot returns an existing canonical directory for use as the single
// allowed root, plus a second directory outside it.
func policyRoot(t *testing.T) (root, outside string) {
	t.Helper()
	root = canonicalDir(t, t.TempDir())
	outside = canonicalDir(t, t.TempDir())
	return root, outside
}

func canonicalDir(t *testing.T, p string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("resolve %s: %v", p, err)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		t.Fatalf("abs %s: %v", resolved, err)
	}
	return abs
}

// restrictedPol is the protected single-root policy the manager tests use.
// SessionPolicy is disabled explicitly because that is what the pi profile
// resolves to: a hand-built Policy with an empty SessionPolicy means allow,
// and these tests exercise the protected behavior, not the zero value.
func restrictedPol(root string) policy.Policy {
	return policy.Policy{
		Profile:       policy.ProfilePi,
		AllowedRoots:  []string{root},
		DefaultCwd:    root,
		SessionPolicy: policy.SessionPolicyDisabled,
		ForceSandbox:  true,
	}
}

func TestNormalizeRequestRestrictedPaths(t *testing.T) {
	root, outside := policyRoot(t)
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(filepath.Dir(root), filepath.Base(root)+"-evil")
	if err := os.MkdirAll(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sibling) })

	m := newManager(t, managerOpts{pol: restrictedPol(root)})
	base := StartRequest{Prompt: "p", Timeout: time.Minute}

	t.Run("inside canonicalized", func(t *testing.T) {
		req, err := m.normalizeRequest(StartRequest{Prompt: "p", Cwd: sub, Timeout: time.Minute})
		if err != nil {
			t.Fatalf("inside cwd refused: %v", err)
		}
		if req.Cwd != sub {
			t.Fatalf("cwd %q, want canonical %q", req.Cwd, sub)
		}
	})
	t.Run("empty resolves to default cwd", func(t *testing.T) {
		req, err := m.normalizeRequest(base)
		if err != nil {
			t.Fatalf("empty cwd refused: %v", err)
		}
		if req.Cwd != root {
			t.Fatalf("cwd %q, want default %q", req.Cwd, root)
		}
	})
	t.Run("empty without default refused", func(t *testing.T) {
		m := newManager(t, managerOpts{pol: policy.Policy{AllowedRoots: []string{root}}})
		if _, err := m.normalizeRequest(base); err == nil {
			t.Fatal("empty cwd accepted with no default")
		}
	})
	t.Run("relative refused", func(t *testing.T) {
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", Cwd: "sub", Timeout: time.Minute}); err == nil {
			t.Fatal("relative cwd accepted")
		}
	})
	t.Run("outside refused", func(t *testing.T) {
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", Cwd: outside, Timeout: time.Minute}); err == nil {
			t.Fatal("outside cwd accepted")
		}
	})
	t.Run("sibling prefix refused", func(t *testing.T) {
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", Cwd: sibling, Timeout: time.Minute}); err == nil {
			t.Fatal("sibling-prefix cwd accepted")
		}
	})
	t.Run("traversal refused", func(t *testing.T) {
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", Cwd: root + "/..", Timeout: time.Minute}); err == nil {
			t.Fatal("parent traversal cwd accepted")
		}
	})
	t.Run("escaping dirs refused whole", func(t *testing.T) {
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", Cwd: sub, Dirs: []string{sub, "../outside"}, Timeout: time.Minute}); err == nil {
			t.Fatal("dirs with an escaping entry accepted")
		}
	})
	t.Run("valid dirs normalized", func(t *testing.T) {
		// ".." from sub resolves to the root itself: inside, and canonical.
		req, err := m.normalizeRequest(StartRequest{Prompt: "p", Cwd: sub, Dirs: []string{".."}, Timeout: time.Minute})
		if err != nil {
			t.Fatalf("valid dirs refused: %v", err)
		}
		if !slices.Equal(req.Dirs, []string{root}) {
			t.Fatalf("dirs %q, want [%q]", req.Dirs, root)
		}
	})
}

func TestNormalizeRequestForceSandbox(t *testing.T) {
	root, _ := policyRoot(t)
	m := newManager(t, managerOpts{pol: policy.Policy{AllowedRoots: []string{root}, DefaultCwd: root, ForceSandbox: true}})
	req, err := m.normalizeRequest(StartRequest{Prompt: "p", Timeout: time.Minute})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !req.Sandbox {
		t.Fatal("ForceSandbox did not turn sandbox on")
	}
	// The flag must reach the argv too: args are built from the normalized
	// request, so this pins the whole chain, not just the struct field.
	if !slices.Contains(buildAgyArgsWithSkipPermissions(req, true), sandboxFlag) {
		t.Fatalf("args lack %s: %q", sandboxFlag, buildAgyArgsWithSkipPermissions(req, true))
	}
}

func TestNormalizeRequestSchema(t *testing.T) {
	root, _ := policyRoot(t)
	valid := `{"type":"object"}`
	t.Run("protected refuses every schema", func(t *testing.T) {
		m := newManager(t, managerOpts{pol: restrictedPol(root)})
		// A protected profile refuses json_schema wholesale, valid inline
		// objects included: only the wholesale refusal closes the
		// file-path-reading hole MEASURED on agy 1.5.17, because agy treats a
		// non-JSON value as a path.
		for _, schema := range []string{valid, "/etc/hosts", "[]"} {
			if _, err := m.normalizeRequest(StartRequest{Prompt: "p", JSONSchema: schema, Timeout: time.Minute}); err == nil {
				t.Fatalf("schema %q accepted under the protected profile", schema)
			}
		}
	})
	t.Run("inline-only accepts objects and trims", func(t *testing.T) {
		m := newManager(t, managerOpts{pol: policy.Policy{AllowedRoots: []string{root}, DefaultCwd: root, InlineJSONSchemaOnly: true}})
		req, err := m.normalizeRequest(StartRequest{Prompt: "p", JSONSchema: "  " + valid + "  ", Timeout: time.Minute})
		if err != nil {
			t.Fatalf("valid inline schema refused: %v", err)
		}
		if req.JSONSchema != valid {
			t.Fatalf("schema %q not trimmed to %q", req.JSONSchema, valid)
		}
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", JSONSchema: "/etc/hosts", Timeout: time.Minute}); err == nil {
			t.Fatal("path-like schema accepted under inline-only")
		}
	})
	t.Run("unrestricted passthrough", func(t *testing.T) {
		m := newManager(t, managerOpts{})
		req, err := m.normalizeRequest(StartRequest{Prompt: "p", JSONSchema: "/etc/hosts", Timeout: time.Minute})
		if err != nil {
			t.Fatalf("schema refused with no policy: %v", err)
		}
		if req.JSONSchema != "/etc/hosts" {
			t.Fatalf("unrestricted schema mangled: %q", req.JSONSchema)
		}
	})
}

func TestNormalizeRequestSessionPolicy(t *testing.T) {
	root, _ := policyRoot(t)
	t.Run("disabled refuses continuation", func(t *testing.T) {
		m := newManager(t, managerOpts{pol: restrictedPol(root)})
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", ContinueLatest: true, Timeout: time.Minute}); err == nil {
			t.Fatal("continue_latest accepted under disabled")
		}
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", ConversationID: "cid", Timeout: time.Minute}); err == nil {
			t.Fatal("conversation_id accepted under disabled")
		}
	})
	t.Run("disable-continue-latest alone", func(t *testing.T) {
		// DisableContinueLatest can stand alone under SessionPolicyAllow: the
		// knob refuses continue_latest without touching explicit ids.
		m := newManager(t, managerOpts{pol: policy.Policy{AllowedRoots: []string{root}, DefaultCwd: root, DisableContinueLatest: true}})
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", ContinueLatest: true, Timeout: time.Minute}); err == nil {
			t.Fatal("continue_latest accepted under DisableContinueLatest")
		}
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", ConversationID: "cid", Timeout: time.Minute}); err != nil {
			t.Fatalf("conversation_id refused under DisableContinueLatest alone: %v", err)
		}
	})
	t.Run("unrestricted keeps upstream behavior", func(t *testing.T) {
		m := newManager(t, managerOpts{withCacheFile: true})
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", ConversationID: "cid", Timeout: time.Minute}); err != nil {
			t.Fatalf("conversation_id refused with no policy: %v", err)
		}
	})
}

func TestNormalizeRequestRunOptions(t *testing.T) {
	root, _ := policyRoot(t)
	pol := policy.Policy{
		AllowedRoots:  []string{root},
		DefaultCwd:    root,
		AllowedModels: []string{"m1"},
		MaxTimeout:    20 * time.Minute,
	}
	m := newManager(t, managerOpts{pol: pol, defaultModel: "m1", defaultTimeout: 20 * time.Minute})
	t.Run("whitelisted model and default timeout pass", func(t *testing.T) {
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p"}); err != nil {
			t.Fatalf("default run refused: %v", err)
		}
	})
	t.Run("unlisted model refused", func(t *testing.T) {
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", Model: "m2", Timeout: time.Minute}); err == nil {
			t.Fatal("unlisted model accepted")
		}
	})
	t.Run("timeout over cap refused", func(t *testing.T) {
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", Timeout: 21 * time.Minute}); err == nil {
			t.Fatal("timeout over the cap accepted")
		}
	})
	t.Run("agent selection disabled", func(t *testing.T) {
		m := newManager(t, managerOpts{pol: policy.Policy{AllowedRoots: []string{root}, DefaultCwd: root, DisableAgentSelection: true}})
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", Agent: "reviewer", Timeout: time.Minute}); err == nil {
			t.Fatal("agent accepted while selection is disabled")
		}
	})
	t.Run("agent whitelist", func(t *testing.T) {
		m := newManager(t, managerOpts{pol: policy.Policy{AllowedRoots: []string{root}, DefaultCwd: root, AllowedAgents: []string{"reviewer"}}})
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", Agent: "reviewer", Timeout: time.Minute}); err != nil {
			t.Fatalf("whitelisted agent refused: %v", err)
		}
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", Agent: "other", Timeout: time.Minute}); err == nil {
			t.Fatal("unlisted agent accepted")
		}
	})
}

// TestStartJobPolicyRefusalCreatesNothing pins the admission-order contract:
// a request the policy refuses is refused before any job dir is created and
// before any concurrency slot is taken, so refusals leave no state behind.
// The store staying empty is the observable: StartJob creates the dir only
// after normalizeRequest passes, so a refusal with a non-empty store means
// the checks moved downstream.
func TestStartJobPolicyRefusalCreatesNothing(t *testing.T) {
	if !proc.Supported {
		t.Skip("job supervision unsupported on this platform")
	}
	root, outside := policyRoot(t)
	m := newManager(t, managerOpts{pol: restrictedPol(root), defaultTimeout: time.Minute})
	for _, req := range []StartRequest{
		{Prompt: "p", Cwd: outside},
		{Prompt: "p", Cwd: "relative"},
		{Prompt: "p", JSONSchema: "/etc/hosts"},
		{Prompt: "p", ContinueLatest: true},
		{Prompt: "p", ConversationID: "cid"},
		{Prompt: "p", Timeout: 30 * time.Minute},
	} {
		if _, err := m.StartJob(req); err == nil {
			t.Fatalf("request %+v accepted", req)
		}
		ids, lerr := m.store.List()
		if lerr != nil {
			t.Fatalf("list store: %v", lerr)
		}
		if len(ids) != 0 {
			t.Fatalf("refused request %+v created job dirs %q", req, ids)
		}
	}
}

// buildForeignRecord is the ownership record another instance would have
// written; every ownership refusal test uses it for the foreign case.
func buildForeignRecord(t *testing.T, dir string) {
	t.Helper()
	writeOwnershipRecord(t, dir, "other-project", "other-instance")
}

func writeOwnershipRecord(t *testing.T, dir, project, instance string) {
	t.Helper()
	rec, err := json.Marshal(jobOwnership{Profile: policy.ProfilePi, ProjectID: project, InstanceID: instance})
	if err != nil {
		t.Fatal(err)
	}
	if err := jobstore.WriteOwnershipFile(dir, rec); err != nil {
		t.Fatalf("write ownership: %v", err)
	}
}

// protectedManagerWithJob builds a protected manager and stages one job whose
// ownership record matches it, returning the manager and the job id.
func protectedManagerWithJob(t *testing.T) (m *Manager, jobID string) {
	t.Helper()
	root, _ := policyRoot(t)
	m = newManager(t, managerOpts{
		pol:        restrictedPol(root),
		projectID:  "proj-1",
		instanceID: "inst-1",
	})
	dir, err := m.store.Create(jobstore.Meta{ID: "j", StartedAt: time.Now(), BootID: readBootID()})
	if err != nil {
		t.Fatalf("create job: %v", err)
	}
	writeOwnershipRecord(t, dir, "proj-1", "inst-1")
	return m, "j"
}

// TestProtectedScopeRefusesForeignHandles pins the acceptance criterion:
// Status, State, Cancel, MarkCollected and MarkDismissed all refuse a job
// whose ownership record is missing or names another instance or project,
// with the same error a missing job produces, and without changing its
// state. Removing the ownershipRefused call at any of these entries turns
// this test red at that entry.
func TestProtectedScopeRefusesForeignHandles(t *testing.T) {
	if !proc.Supported {
		t.Skip("job supervision unsupported on this platform")
	}
	m, _ := protectedManagerWithJob(t)
	// Stage a foreign job in the same store: same cwd, live-looking meta.
	dir, err := m.store.Create(jobstore.Meta{ID: "foreign", StartedAt: time.Now(), BootID: readBootID()})
	if err != nil {
		t.Fatal(err)
	}
	buildForeignRecord(t, dir)
	// And an unattributed one (no ownership record at all): an old job from
	// before the profile, or a dir from a shared store.
	if _, err := m.store.Create(jobstore.Meta{ID: "unattributed", StartedAt: time.Now(), BootID: readBootID()}); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"foreign", "unattributed"} {
		if _, err := m.Status(id); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Status(%s) = %v; want an fs.ErrNotExist-class error", id, err)
		}
		if _, err := m.State(id); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("State(%s) = %v; want an fs.ErrNotExist-class error", id, err)
		}
		if err := m.Cancel(id); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Cancel(%s) = %v; want an fs.ErrNotExist-class error", id, err)
		}
		if err := m.MarkCollected(id); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("MarkCollected(%s) = %v", id, err)
		}
		if err := m.MarkDismissed(id); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("MarkDismissed(%s) = %v", id, err)
		}
		// A refusal must not modify the foreign job: no cancel sentinel, no
		// collected marker.
		if _, done := m.store.ExitCode(id); done {
			t.Errorf("job %s gained an exit-code sentinel during refusals", id)
		}
		if m.store.Collected(id) {
			t.Errorf("job %s gained a collected marker during refusals", id)
		}
	}
	// The instance's own job stays fully usable through the same entries.
	if _, err := m.Status("j"); err != nil {
		t.Fatalf("Status on the instance's own job failed: %v", err)
	}
}

// TestProtectedScopeReplayRefusesForeignJob covers idempotent replay: a key
// bound to a foreign job must refuse the replay, not return the foreign job
// id, even when the request matches. findIdempotentJob is the entry StartJob
// uses, so this pins the path a retry actually takes.
func TestProtectedScopeReplayRefusesForeignJob(t *testing.T) {
	if !proc.Supported {
		t.Skip("job supervision unsupported on this platform")
	}
	m, _ := protectedManagerWithJob(t)
	req := StartRequest{Prompt: "p", Cwd: "/w", IdempotencyKey: "k", Timeout: time.Minute}
	meta := jobstore.Meta{
		ID: "foreign", IdempotencyKey: "k", RequestKey: requestKey(req),
		Cwd: "/w", Prompt: "p", Timeout: time.Minute, StartedAt: time.Now(), BootID: readBootID(), PID: 999999,
	}
	fdir, err := m.store.Create(meta)
	if err != nil {
		t.Fatal(err)
	}
	buildForeignRecord(t, fdir)
	_, _, err = m.findIdempotentJob(req, buildAgyArgs(req), true)
	if err == nil {
		t.Fatal("replay of a foreign job returned a job")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("replay refusal = %v; want an fs.ErrNotExist-class error", err)
	}
}

// TestProtectedScopeOwnReplayStillWorks guards against the refusal overreach:
// a protected instance replays its own jobs, so the refusal must key on the
// ownership record, not on the profile alone.
func TestProtectedScopeOwnReplayStillWorks(t *testing.T) {
	if !proc.Supported {
		t.Skip("job supervision unsupported on this platform")
	}
	m, _ := protectedManagerWithJob(t)
	req := StartRequest{Prompt: "p", Cwd: "/w", IdempotencyKey: "k", Timeout: time.Minute}
	// Re-stage "j" as this instance's keyed job for the same request.
	meta, err := m.store.Load("j")
	if err != nil {
		t.Fatal(err)
	}
	meta.IdempotencyKey = "k"
	meta.RequestKey = requestKey(req)
	meta.Cwd = "/w"
	meta.Prompt = "p"
	meta.Timeout = time.Minute
	meta.PID = 999999
	if err := m.store.UpdateMeta(meta); err != nil {
		t.Fatal(err)
	}
	job, found, err := m.findIdempotentJob(req, buildAgyArgs(req), true)
	if err != nil || !found || job.ID != "j" {
		t.Fatalf("own replay = %+v, %v, %v; want job j", job, found, err)
	}
}

// TestRestoreAndCollectRefusesUnownedStore pins the startup refusal: a
// protected instance must not adopt a store holding jobs without a matching
// ownership record, whatever their state.
func TestRestoreAndCollectRefusesUnownedStore(t *testing.T) {
	if !proc.Supported {
		t.Skip("job supervision unsupported on this platform")
	}
	m, _ := protectedManagerWithJob(t)
	dir, err := m.store.Create(jobstore.Meta{ID: "stray", StartedAt: time.Now().Add(-time.Hour), BootID: readBootID()})
	if err != nil {
		t.Fatal(err)
	}
	buildForeignRecord(t, dir)
	if _, err := m.RestoreAndCollect(); err == nil {
		t.Fatal("startup adopted a store holding a foreign job")
	}
	// The stray job must still be there: the refusal is the operator's signal,
	// not a silent adoption or a silent deletion.
	if _, err := m.store.Load("stray"); err != nil {
		t.Fatalf("the refused job was removed during the scan: %v", err)
	}
}

// TestStatusBlankConversationUnderSessionPolicy pins the no-session-handles
// contract: under a non-allow session policy, Status and AwaitConversationID
// never hand back an agy conversation id, even though the job has one.
func TestStatusBlankConversationUnderSessionPolicy(t *testing.T) {
	if !proc.Supported {
		t.Skip("job supervision unsupported on this platform")
	}
	root, _ := policyRoot(t)
	m := newManager(t, managerOpts{pol: restrictedPol(root), projectID: "p", instanceID: "i"})
	const conv = "11111111-2222-3333-4444-555555555555"
	dir, err := m.store.Create(jobstore.Meta{ID: "j", ConversationID: conv, StartedAt: time.Now(), BootID: readBootID()})
	if err != nil {
		t.Fatal(err)
	}
	writeOwnershipRecord(t, dir, "p", "i")
	st, err := m.Status("j")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.ConversationID != "" {
		t.Fatalf("Status leaked conversation id %q under the session policy", st.ConversationID)
	}
	if got := m.AwaitConversationID(t.Context(), Job{ID: "j", ConversationID: conv}); got != "" {
		t.Fatalf("AwaitConversationID returned %q under the session policy", got)
	}
	// The unrestricted manager keeps returning the id: the blanking is the
	// policy's, not a regression of the plumbing.
	m2 := newManager(t, managerOpts{projectID: "p", instanceID: "i"})
	d2, err := m2.store.Create(jobstore.Meta{ID: "j", ConversationID: conv, StartedAt: time.Now(), BootID: readBootID()})
	if err != nil {
		t.Fatal(err)
	}
	_ = d2
	st2, err := m2.Status("j")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st2.ConversationID != conv {
		t.Fatalf("unrestricted Status lost the conversation id: %q", st2.ConversationID)
	}
}

// TestListSessionsDisabled pins the list_sessions gate: a non-allow session
// policy refuses the listing with an explicit policy error instead of reading
// agy's host-wide conversation cache.
func TestListSessionsDisabled(t *testing.T) {
	root, _ := policyRoot(t)
	for _, sp := range []policy.SessionPolicy{policy.SessionPolicyDisabled, policy.SessionPolicyManagedOnly} {
		m := newManager(t, managerOpts{pol: policy.Policy{AllowedRoots: []string{root}, DefaultCwd: root, SessionPolicy: sp}, withCacheFile: true})
		_, err := m.ListSessions("")
		if err == nil || !strings.Contains(err.Error(), "session policy") {
			t.Fatalf("ListSessions under %s = %v; want a policy error", sp, err)
		}
	}
}
