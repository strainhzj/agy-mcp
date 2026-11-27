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

// policyRoot returns an existing canonical directory to serve as the
// protected instance's host-side snapshot root, plus a second directory
// outside it. Callers spell caller-visible paths with wpath: under the pi
// profile the only allowed root is the worker mount, and the snapshot root is
// what that mount maps onto on the host.
func policyRoot(t *testing.T) (root, outside string) {
	t.Helper()
	root = canonicalDir(t, t.TempDir())
	outside = canonicalDir(t, t.TempDir())
	return root, outside
}

// wpath spells a host path under root in the worker view the pi profile
// exposes, which is what a caller passes and what the policy writes back.
// The worker view is a fixed POSIX mount: caller-visible paths always use
// "/" separators regardless of the host OS, so a Windows CI host sees the
// same shape a real deployment produces.
func wpath(t *testing.T, root, host string) string {
	t.Helper()
	rel, err := filepath.Rel(root, host)
	if err != nil {
		t.Fatalf("rel %s under %s: %v", host, root, err)
	}
	return policy.WorkerMountPath + "/" + filepath.ToSlash(rel)
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

// restrictedPol is the protected single-project policy the manager tests
// use. It is the shape internal/config resolves for the pi profile: the worker
// mount is the only allowed root, and the manifest's snapshot root is what
// that mount maps onto on the host.
//
// SessionPolicy is disabled explicitly because that is what the pi profile
// resolves to: a hand-built Policy with an empty SessionPolicy means allow,
// and these tests exercise the protected behavior, not the zero value.
func restrictedPol(root string) policy.Policy {
	return policy.Policy{
		Profile:             policy.ProfilePi,
		AllowedRoots:        []string{"/workspace"},
		DefaultCwd:          "/workspace",
		WorkerMount:         "/workspace",
		SnapshotRoot:        root,
		SnapshotFingerprint: "sha256:" + strings.Repeat("a", 64),
		SessionPolicy:       policy.SessionPolicyDisabled,
		ForceSandbox:        true,
		DisableJSONSchema:   true,
		Mode:                policy.ModePolicy{DisableClientMode: true},
		// Agent selection is off by default under the profile (config's
		// applyProfileRequirements sets it when the variable is unset), so the
		// hand-built fixture must say so explicitly: a Policy built here bypasses
		// config, and a fixture that left it false would exercise a shape no real
		// deployment resolves to.
		DisableAgentSelection: true,
		AllowedHosts:          []string{"127.0.0.8:8765"},
		MaxTimeout:            24 * time.Hour,
		RequireHTTPToken:      true,
		ProjectID:             "proj-1",
		InstanceID:            "inst-1",
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
		req, err := m.normalizeRequest(StartRequest{Prompt: "p", Cwd: wpath(t, root, sub), Timeout: time.Minute})
		if err != nil {
			t.Fatalf("inside cwd refused: %v", err)
		}
		if req.Cwd != wpath(t, root, sub) {
			t.Fatalf("cwd %q, want worker-view %q", req.Cwd, wpath(t, root, sub))
		}
	})
	t.Run("empty resolves to default cwd", func(t *testing.T) {
		req, err := m.normalizeRequest(base)
		if err != nil {
			t.Fatalf("empty cwd refused: %v", err)
		}
		if req.Cwd != "/workspace" {
			t.Fatalf("cwd %q, want the worker mount /workspace", req.Cwd)
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
		// outside is a host directory outside the snapshot; in the worker view
		// there is no path that names it.
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", Cwd: outside, Timeout: time.Minute}); err == nil {
			t.Fatal("outside cwd accepted")
		}
	})
	t.Run("sibling prefix refused", func(t *testing.T) {
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", Cwd: "/workspace-evil", Timeout: time.Minute}); err == nil {
			t.Fatal("sibling-prefix cwd accepted")
		}
	})
	t.Run("traversal refused", func(t *testing.T) {
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", Cwd: "/workspace/..", Timeout: time.Minute}); err == nil {
			t.Fatal("parent traversal cwd accepted")
		}
	})
	t.Run("escaping dirs refused whole", func(t *testing.T) {
		if _, err := m.normalizeRequest(StartRequest{Prompt: "p", Cwd: wpath(t, root, sub), Dirs: []string{wpath(t, root, sub), "../outside"}, Timeout: time.Minute}); err == nil {
			t.Fatal("dirs with an escaping entry accepted")
		}
	})
	t.Run("valid dirs normalized", func(t *testing.T) {
		// ".." from sub resolves to the snapshot root: inside, and the worker
		// view of it.
		req, err := m.normalizeRequest(StartRequest{Prompt: "p", Cwd: wpath(t, root, sub), Dirs: []string{".."}, Timeout: time.Minute})
		if err != nil {
			t.Fatalf("valid dirs refused: %v", err)
		}
		if !slices.Equal(req.Dirs, []string{"/workspace"}) {
			t.Fatalf("dirs %q, want [/workspace]", req.Dirs)
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
	writeOwnershipFingerprint(t, dir, project, instance, "")
}

// writeOwnershipFingerprint stages an ownership record with an explicit
// snapshot fingerprint ("" means a record from before fingerprints existed,
// which only matches an instance that itself has no fingerprint).
func writeOwnershipFingerprint(t *testing.T, dir, project, instance, fingerprint string) {
	t.Helper()
	rec, err := json.Marshal(jobOwnership{Profile: policy.ProfilePi, ProjectID: project, InstanceID: instance, SnapshotFingerprint: fingerprint})
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

// TestProtectedScopeReplaySkipsForeignJob covers idempotent replay scoping:
// a key bound to a foreign job is never this instance's binding, so the scan
// skips the record without naming it (the caller retries and creates this
// instance's own binding for the key), while the same key with a different
// request on this instance's OWN job still refuses, naming only its own id.
// Naming a scanned foreign id in either message would hand a caller another
// deployment's identifier just by reusing its key.
func TestProtectedScopeReplaySkipsForeignJob(t *testing.T) {
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
	job, found, err := m.findIdempotentJob(req, buildAgyArgs(req), true)
	if err != nil || found {
		t.Fatalf("foreign-keyed scan = %+v, %v, %v; want no binding and no error", job, found, err)
	}

	// The refusal keeps its teeth on this instance's own jobs: the same key
	// with a different request names the job id, and that id is our own "j".
	own, err := m.store.Load("j")
	if err != nil {
		t.Fatal(err)
	}
	own.IdempotencyKey = "k"
	own.RequestKey = requestKey(req)
	own.Cwd = "/w"
	own.Prompt = "p"
	own.Timeout = time.Minute
	own.PID = 999999
	if err := m.store.UpdateMeta(own); err != nil {
		t.Fatal(err)
	}
	other := req
	other.Prompt = "a different request"
	_, _, err = m.findIdempotentJob(other, buildAgyArgs(other), true)
	if err == nil || !strings.Contains(err.Error(), "j") {
		t.Fatalf("own mismatch = %v, want a refusal naming our own job j", err)
	}
}

// TestProtectedScopeOwnershipFourFieldsMatch pins the acceptance criterion
// that a tampered ownership record is refused on ANY of its four fields, not
// just the ones an earlier build compared. Each subtest changes exactly one
// field and asserts the same indistinguishable unknown-job error from both the
// caller-facing gate (ownershipRefused) and Status, and that the foreign job's
// state is left untouched. Removing the profile comparison from
// ownershipMatches turns its subtest red; removing any other field turns that
// field's subtest red.
func TestProtectedScopeOwnershipFourFieldsMatch(t *testing.T) {
	if !proc.Supported {
		t.Skip("job supervision unsupported on this platform")
	}
	const (
		project  = "proj-1"
		instance = "inst-1"
	)
	// A fingerprint is a runtime value, not a constant: it is built the same way
	// the policy fixtures build theirs.
	goodFP := "sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		name   string
		mutate func(own *jobOwnership)
	}{
		{"profile", func(o *jobOwnership) { o.Profile = "default" }},
		{"profile emptied", func(o *jobOwnership) { o.Profile = "" }},
		{"project", func(o *jobOwnership) { o.ProjectID = "other-project" }},
		{"instance", func(o *jobOwnership) { o.InstanceID = "other-instance" }},
		{"snapshot fingerprint", func(o *jobOwnership) { o.SnapshotFingerprint = "sha256:" + strings.Repeat("b", 64) }},
		{"snapshot fingerprint emptied", func(o *jobOwnership) { o.SnapshotFingerprint = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, _ := policyRoot(t)
			m := newManager(t, managerOpts{
				pol: restrictedPol(root), projectID: project, instanceID: instance,
				snapshotFingerprint: goodFP,
			})
			dir, err := m.store.Create(jobstore.Meta{ID: "j", StartedAt: time.Now(), BootID: readBootID()})
			if err != nil {
				t.Fatal(err)
			}
			writeOwnershipFingerprint(t, dir, project, instance, goodFP)
			b, err := os.ReadFile(jobstore.OwnershipPath(dir))
			if err != nil {
				t.Fatal(err)
			}
			var own jobOwnership
			if err := json.Unmarshal(b, &own); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&own)
			b, err = json.Marshal(own)
			if err != nil {
				t.Fatal(err)
			}
			if err := jobstore.WriteOwnershipFile(dir, b); err != nil {
				t.Fatal(err)
			}

			if err := m.ownershipRefused("j"); err == nil {
				t.Errorf("ownershipRefused accepted a record with only %s changed", tc.name)
			} else if !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("ownershipRefused error = %v, want the indistinguishable unknown-job error", err)
			}
			if _, err := m.Status("j"); err == nil {
				t.Errorf("Status accepted a job whose ownership %s was tampered", tc.name)
			} else if !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("Status error = %v, want the indistinguishable unknown-job error", err)
			}
			// The refusal must not touch the foreign job's state.
			if _, done := m.store.ExitCode("j"); done {
				t.Error("refused job gained an exit-code sentinel")
			}
		})
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

// TestProtectedScopeSnapshotFingerprintBindsReplay pins the snapshot-version
// half of ownership: the fingerprint comes from the deployment record, so a
// job created against one snapshot version is out of scope for the same
// instance after the workspace is redeployed with new content. Replay skips
// it (the retry creates a fresh binding) and Status refuses it like any other
// foreign handle. Removing the fingerprint comparison in ownershipRefused
// turns this red.
func TestProtectedScopeSnapshotFingerprintBindsReplay(t *testing.T) {
	if !proc.Supported {
		t.Skip("job supervision unsupported on this platform")
	}
	root, _ := policyRoot(t)
	m := newManager(t, managerOpts{
		pol:                 restrictedPol(root),
		projectID:           "p",
		instanceID:          "i",
		snapshotFingerprint: "fp-2",
	})
	req := StartRequest{Prompt: "p", Cwd: "/w", IdempotencyKey: "k", Timeout: time.Minute}
	dir, err := m.store.Create(jobstore.Meta{
		ID: "old-snapshot", IdempotencyKey: "k", RequestKey: requestKey(req),
		Cwd: "/w", Prompt: "p", Timeout: time.Minute, StartedAt: time.Now(), BootID: readBootID(), PID: 999999,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The job belongs to this project and instance, but to the previous
	// snapshot version.
	writeOwnershipFingerprint(t, dir, "p", "i", "fp-1")

	job, found, err := m.findIdempotentJob(req, buildAgyArgs(req), true)
	if err != nil || found {
		t.Fatalf("cross-snapshot replay = %+v, %v, %v; want no binding", job, found, err)
	}
	if _, err := m.Status("old-snapshot"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Status across snapshots = %v, want an fs.ErrNotExist-class error", err)
	}
	// The same fingerprint matches, so a redeployment that keeps the snapshot
	// version (a plain restart) still replays its own jobs.
	dir2, err := m.store.Create(jobstore.Meta{
		ID: "same-snapshot", IdempotencyKey: "k2", RequestKey: requestKey(req),
		Cwd: "/w", Prompt: "p", Timeout: time.Minute, StartedAt: time.Now(), BootID: readBootID(), PID: 999999,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeOwnershipFingerprint(t, dir2, "p", "i", "fp-2")
	req2 := req
	req2.IdempotencyKey = "k2"
	if _, found, err := m.findIdempotentJob(req2, buildAgyArgs(req2), true); err != nil || !found {
		t.Fatalf("same-snapshot replay = %v, %v; want the job replayed", found, err)
	}
}

// TestGarbageCollectKeepsForeignJobs pins the deletion-side ownership gate:
// a protected instance whose state directory holds another deployment's jobs
// (a misdirected or shared dir) keeps them untouched in its GC sweeps, while
// the owning instance collects them normally. Removing the ownershipRefused
// call in gcEvaluate turns the first half red.
func TestGarbageCollectKeepsForeignJobs(t *testing.T) {
	if !proc.Supported {
		t.Skip("job supervision unsupported on this platform")
	}
	root, _ := policyRoot(t)
	state := t.TempDir()
	a := newManager(t, managerOpts{stateDir: state, jobTTL: time.Hour, pol: restrictedPol(root), projectID: "pa", instanceID: "ia"})
	b := newManager(t, managerOpts{stateDir: state, jobTTL: time.Hour, pol: restrictedPol(root), projectID: "pb", instanceID: "ib"})

	dir, err := b.store.Create(jobstore.Meta{
		ID: "b-expired", StartedAt: time.Now().Add(-2 * time.Hour), BootID: readBootID(), Cwd: root,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeOwnershipFingerprint(t, dir, "pb", "ib", "")
	if err := b.store.WriteExitCode("b-expired", 0); err != nil {
		t.Fatal(err)
	}

	removed, err := a.GarbageCollect()
	if err != nil {
		t.Fatalf("foreign instance GC: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("foreign instance removed %v; it must keep jobs it cannot attribute", removed)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("foreign job dir vanished: %v", err)
	}

	removed, err = b.GarbageCollect()
	if err != nil {
		t.Fatalf("owning instance GC: %v", err)
	}
	if len(removed) != 1 || removed[0] != "b-expired" {
		t.Fatalf("owning instance removed %v, want [b-expired]", removed)
	}
}

// TestProtectedInterruptedPartialIsReportedFailed pins the Phase 1 restart
// rule: a protected job whose supervisor died without a sentinel, with
// streamed text but no result payload, is failed/interrupted with the partial
// text kept, never a done. The upstream relabel (done+partial) is pinned
// right behind it so the protected branch cannot leak into upstream behavior.
func TestProtectedInterruptedPartialIsReportedFailed(t *testing.T) {
	root, _ := policyRoot(t)
	m := newManager(t, managerOpts{pol: restrictedPol(root), projectID: "p", instanceID: "i"})
	dir, err := m.store.Create(jobstore.Meta{ID: "dead-partial", StartedAt: time.Now().Add(-time.Minute), BootID: "old-boot", Cwd: root})
	if err != nil {
		t.Fatal(err)
	}
	writeOwnershipFingerprint(t, dir, "p", "i", "")
	if err := os.WriteFile(jobstore.OutPath(dir), []byte("partial streamed answer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := m.Status("dead-partial")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != StateFailed || st.FailureReason != ReasonInterrupted {
		t.Fatalf("protected interrupted = %s/%s, want failed/interrupted", st.State, st.FailureReason)
	}
	if !st.Partial || st.Result != "partial streamed answer" || st.Error == "" {
		t.Fatalf("protected interrupted lost the partial text or the explanation: %+v", st)
	}

	up := newManager(t, managerOpts{})
	udir, err := up.store.Create(jobstore.Meta{ID: "up-partial", StartedAt: time.Now().Add(-time.Minute), BootID: "old-boot"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jobstore.OutPath(udir), []byte("partial streamed answer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ust, err := up.Status("up-partial")
	if err != nil {
		t.Fatalf("upstream Status: %v", err)
	}
	if ust.State != StateDone || !ust.Partial {
		t.Fatalf("upstream interrupted = %s/%v, want the upstream done+partial", ust.State, ust.Partial)
	}
}

// TestProtectedProbeGateBoundsConcurrency pins the listing-probe bound: a
// protected instance hands out at most protectedProbeConcurrency probe slots,
// and a held slot blocks the next acquisition until released.
func TestProtectedProbeGateBoundsConcurrency(t *testing.T) {
	root, _ := policyRoot(t)
	m := newManager(t, managerOpts{pol: restrictedPol(root)})
	m.probeGate = make(chan struct{}, protectedProbeConcurrency)
	// Hold every slot the cap allows, then try for one more.
	held := make([]func(), 0, protectedProbeConcurrency)
	for range protectedProbeConcurrency {
		held = append(held, m.probeSlot())
	}
	acquired := make(chan func(), 1)
	go func() { acquired <- m.probeSlot() }()
	select {
	case r := <-acquired:
		r()
		t.Fatal("acquired a probe slot beyond the cap")
	case <-time.After(150 * time.Millisecond):
	}
	for _, r := range held {
		r()
	}
	select {
	case r := <-acquired:
		r()
	case <-time.After(2 * time.Second):
		t.Fatal("probe slot not granted after release")
	}
}
