package manager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tphakala/agy-mcp/v2/internal/config"
	"github.com/tphakala/agy-mcp/v2/internal/jobstore"
	"github.com/tphakala/agy-mcp/v2/internal/policy"
)

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve tempdir: %v", err)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		t.Fatalf("abs tempdir: %v", resolved)
	}
	return abs
}

// TestCheckPolicyUnrestrictedPinsDefault pins the upstream-compat branch: a
// zero policy reports PASS with the unrestricted default, so an upstream
// install's doctor output and exit code are unchanged by this check.
func TestCheckPolicyUnrestrictedPinsDefault(t *testing.T) {
	m := New(config.Config{StateDir: t.TempDir()})
	got := m.checkPolicy()
	if got.Status != CheckPass {
		t.Fatalf("status = %v (%s), want PASS", got.Status, got.Detail)
	}
	if !strings.Contains(got.Detail, "unrestricted (default)") {
		t.Fatalf("detail = %q, want the unrestricted default note", got.Detail)
	}
}

// TestCheckPolicyRestrictedListsRootsAndReminder covers the configured case:
// the roots are named, the session policy is stated, and the verdict carries
// the standing reminder that parameter checks are not a filesystem boundary.
// Removing the reminder line from checkPolicy turns this red.
func TestCheckPolicyRestrictedListsRootsAndReminder(t *testing.T) {
	root := canonicalTempDir(t)
	m := New(config.Config{
		StateDir: t.TempDir(),
		Policy: policy.Policy{
			AllowedRoots:  []string{root},
			SessionPolicy: policy.SessionPolicyDisabled,
		},
	})
	got := m.checkPolicy()
	if got.Status != CheckPass {
		t.Fatalf("status = %v (%s), want PASS", got.Status, got.Detail)
	}
	for _, want := range []string{root, "session policy disabled", "not a filesystem boundary"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("detail lacks %q:\n%s", want, got.Detail)
		}
	}
}

// TestCheckPolicyFailsOnVanishedRoot is the defensive re-validation: a root
// that existed when the policy was built but was deleted afterwards must fail
// the check, because ValidateAndNormalize would refuse it at the next boot.
func TestCheckPolicyFailsOnVanishedRoot(t *testing.T) {
	root := canonicalTempDir(t)
	gone := filepath.Join(root, "vanished")
	m := New(config.Config{
		StateDir: t.TempDir(),
		Policy: policy.Policy{
			AllowedRoots: []string{gone},
		},
	})
	got := m.checkPolicy()
	if got.Status != CheckFail {
		t.Fatalf("status = %v (%s), want FAIL for a missing root", got.Status, got.Detail)
	}
}

// TestCheckPolicyProtectedRequiresIdentity covers the profile branch: profile
// pi with no deployment identity fails the check.
func TestCheckPolicyProtectedRequiresIdentity(t *testing.T) {
	root := canonicalTempDir(t)
	m := New(config.Config{
		StateDir: t.TempDir(),
		Policy: policy.Policy{
			Profile:       policy.ProfilePi,
			AllowedRoots:  []string{"/workspace"},
			WorkerMount:   "/workspace",
			SnapshotRoot:  root,
			SessionPolicy: policy.SessionPolicyDisabled,
			AllowedHosts:  []string{"127.0.0.8:8765"},
			Mode:          policy.ModePolicy{DisableClientMode: true},
		},
	})
	got := m.checkPolicy()
	if got.Status != CheckFail {
		t.Fatalf("status = %v (%s), want FAIL without identity", got.Status, got.Detail)
	}
	if !strings.Contains(got.Detail, config.EnvInstanceID) {
		t.Fatalf("detail = %q, want it to name %s", got.Detail, config.EnvInstanceID)
	}
}

// TestCheckPolicyProtectedFailsOnForeignJob covers the state-dir ownership
// scan: a job in the store without a matching ownership record fails the
// check and names the job id, which is what an operator needs to clean a
// reused state dir. Doctor is host-side, so the id is the point; the caller
// facing path (ownershipRefused) says nothing, which its own test pins.
func TestCheckPolicyProtectedFailsOnForeignJob(t *testing.T) {
	root := canonicalTempDir(t)
	state := canonicalTempDir(t)
	if err := jobstore.WriteInstanceRecord(state, jobstore.InstanceRecord{
		Contract:            jobstore.InstanceContract,
		ProjectID:           "proj-1",
		InstanceID:          "inst-1",
		SnapshotFingerprint: "fp-1",
	}); err != nil {
		t.Fatal(err)
	}
	m := New(config.Config{
		StateDir: state,
		Policy: policy.Policy{
			Profile:       policy.ProfilePi,
			AllowedRoots:  []string{"/workspace"},
			WorkerMount:   "/workspace",
			SnapshotRoot:  root,
			SessionPolicy: policy.SessionPolicyDisabled,
			AllowedHosts:  []string{"127.0.0.8:8765"},
			Mode:          policy.ModePolicy{DisableClientMode: true},
		},
		ProjectID:           "proj-1",
		InstanceID:          "inst-1",
		SnapshotFingerprint: "fp-1",
	})
	dir, err := m.store.Create(jobstore.Meta{ID: "stray", StartedAt: time.Now(), BootID: readBootID()})
	if err != nil {
		t.Fatal(err)
	}
	if err := jobstore.WriteOwnershipFile(dir, []byte(`{"profile":"pi","project_id":"other","instance_id":"other-inst"}`)); err != nil {
		t.Fatal(err)
	}
	got := m.checkPolicy()
	if got.Status != CheckFail {
		t.Fatalf("status = %v (%s), want FAIL with a foreign job present", got.Status, got.Detail)
	}
	if !strings.Contains(got.Detail, "stray") {
		t.Fatalf("detail = %q, want it to name the foreign job", got.Detail)
	}
}

// TestCheckPolicyProtectedCleanStorePasses: the happy path, so the foreign
// failure cannot be satisfied by any nonzero scan outcome. It needs a matching
// deployment record too, since the record check is part of the protected
// verdict.
func TestCheckPolicyProtectedCleanStorePasses(t *testing.T) {
	root := canonicalTempDir(t)
	state := canonicalTempDir(t)
	if err := jobstore.WriteInstanceRecord(state, jobstore.InstanceRecord{
		Contract:            jobstore.InstanceContract,
		ProjectID:           "proj-1",
		InstanceID:          "inst-1",
		SnapshotFingerprint: "fp-1",
	}); err != nil {
		t.Fatal(err)
	}
	m := New(config.Config{
		StateDir: state,
		Policy: policy.Policy{
			Profile:       policy.ProfilePi,
			AllowedRoots:  []string{"/workspace"},
			WorkerMount:   "/workspace",
			SnapshotRoot:  root,
			SessionPolicy: policy.SessionPolicyDisabled,
			AllowedHosts:  []string{"127.0.0.8:8765"},
			Mode:          policy.ModePolicy{DisableClientMode: true},
		},
		ProjectID:           "proj-1",
		InstanceID:          "inst-1",
		SnapshotFingerprint: "fp-1",
	})
	got := m.checkPolicy()
	if got.Status != CheckPass {
		t.Fatalf("status = %v (%s), want PASS", got.Status, got.Detail)
	}
	if !strings.Contains(got.Detail, "deployment record") || !strings.Contains(got.Detail, "fp-1") {
		t.Fatalf("detail = %q, want it to report the deployment record and fingerprint", got.Detail)
	}
}

// TestCheckPolicyProtectedFailsWithoutDeploymentRecord covers the record half
// of the protected verdict: a state dir without the launcher-written record
// fails the check even with a clean ownership scan, because the start itself
// would be refused.
func TestCheckPolicyProtectedFailsWithoutDeploymentRecord(t *testing.T) {
	root := canonicalTempDir(t)
	m := New(config.Config{
		StateDir: canonicalTempDir(t),
		Policy: policy.Policy{
			Profile:       policy.ProfilePi,
			AllowedRoots:  []string{"/workspace"},
			WorkerMount:   "/workspace",
			SnapshotRoot:  root,
			SessionPolicy: policy.SessionPolicyDisabled,
			AllowedHosts:  []string{"127.0.0.8:8765"},
			Mode:          policy.ModePolicy{DisableClientMode: true},
		},
		ProjectID:           "proj-1",
		InstanceID:          "inst-1",
		SnapshotFingerprint: "fp-1",
	})
	got := m.checkPolicy()
	if got.Status != CheckFail {
		t.Fatalf("status = %v (%s), want FAIL without a deployment record", got.Status, got.Detail)
	}
	if !strings.Contains(got.Detail, "deployment record") {
		t.Fatalf("detail = %q, want it to name the missing deployment record", got.Detail)
	}
}

// TestCheckPolicyProtectedReportsNewGates pins the profile-only lines
// doctor now reports: the project manifest, the snapshot root and fingerprint,
// the Host allowlist, the mode decision and the agent-selection state. These
// are the settings whose absence is a startup refusal, so naming them in the
// report is what makes a refusal explainable after the fact. Removing
// protectedPolicyLines (or any of its branches) turns the corresponding
// assertion red.
func TestCheckPolicyProtectedReportsNewGates(t *testing.T) {
	root := canonicalTempDir(t)
	state := canonicalTempDir(t)
	fingerprint := "sha256:" + strings.Repeat("a", 64)
	if err := jobstore.WriteInstanceRecord(state, jobstore.InstanceRecord{
		Contract:            jobstore.InstanceContract,
		ProjectID:           "proj-1",
		InstanceID:          "inst-1",
		SnapshotFingerprint: fingerprint,
	}); err != nil {
		t.Fatal(err)
	}
	m := New(config.Config{
		StateDir: state,
		Policy: policy.Policy{
			Profile:               policy.ProfilePi,
			AllowedRoots:          []string{"/workspace"},
			DefaultCwd:            "/workspace",
			WorkerMount:           "/workspace",
			SnapshotRoot:          root,
			SnapshotFingerprint:   fingerprint,
			SessionPolicy:         policy.SessionPolicyDisabled,
			AllowedHosts:          []string{"192.168.5.45:8865", "127.0.0.8:8765"},
			Mode:                  policy.ModePolicy{DisableClientMode: true},
			DisableAgentSelection: true,
			ProjectManifestPath:   "/etc/agy-mcp/pi-instance/project-manifest.json",
		},
		ProjectID:           "proj-1",
		InstanceID:          "inst-1",
		SnapshotFingerprint: fingerprint,
	})
	got := m.checkPolicy()
	if got.Status != CheckPass {
		t.Fatalf("status = %v (%s), want PASS", got.Status, got.Detail)
	}
	for _, want := range []string{
		"project manifest /etc/agy-mcp/pi-instance/project-manifest.json",
		"snapshot root " + root,
		"http allowed hosts 192.168.5.45:8865, 127.0.0.8:8765",
		"client mode refused",
		"agent selection disabled",
	} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("detail lacks %q:\n%s", want, got.Detail)
		}
	}
	// The snapshot-root line abbreviates the fingerprint: a report line is not
	// the place for 64 hex characters. (The deployment-record line below prints
	// it in full by design, because that is the value an operator compares
	// against the manifest when a start is refused.)
	var snapshotLine string
	for l := range strings.Lines(got.Detail) {
		line := strings.TrimSuffix(l, "\n")
		if strings.Contains(line, "snapshot root "+root) {
			snapshotLine = line
		}
	}
	if snapshotLine == "" {
		t.Fatalf("detail lacks the snapshot root line:\n%s", got.Detail)
	}
	if strings.Contains(snapshotLine, fingerprint) {
		t.Errorf("snapshot root line printed the full fingerprint %q; want the abbreviated form", fingerprint)
	}
	if !strings.Contains(snapshotLine, "sha256:aaaaaaaaaaaa") {
		t.Errorf("snapshot root line %q lacks the abbreviated fingerprint", snapshotLine)
	}
}

// TestCheckPolicyProtectedFailsWithoutManifest pins the manifest half of the
// fail-closed verdict: a protected policy that lost its manifest fails the
// check and names the variable, rather than passing on the other settings.
func TestCheckPolicyProtectedFailsWithoutManifest(t *testing.T) {
	root := canonicalTempDir(t)
	m := New(config.Config{
		StateDir: canonicalTempDir(t),
		Policy: policy.Policy{
			Profile:       policy.ProfilePi,
			AllowedRoots:  []string{"/workspace"},
			WorkerMount:   "/workspace",
			SnapshotRoot:  root,
			SessionPolicy: policy.SessionPolicyDisabled,
			AllowedHosts:  []string{"127.0.0.8:8765"},
			Mode:          policy.ModePolicy{DisableClientMode: true},
		},
		ProjectID:  "proj-1",
		InstanceID: "inst-1",
	})
	got := m.checkPolicy()
	if got.Status != CheckFail {
		t.Fatalf("status = %v (%s), want FAIL without a manifest", got.Status, got.Detail)
	}
	if !strings.Contains(got.Detail, config.EnvProjectManifest) {
		t.Fatalf("detail = %q, want it to name %s", got.Detail, config.EnvProjectManifest)
	}
}

// TestDoctorConfigSourcesPolicyLines extends the config-sources acceptance:
// the effective policy settings (max timeout, sync wait cap, session policy,
// default timeout) appear with their resolution, and the token still never
// leaks.
func TestDoctorConfigSourcesPolicyLines(t *testing.T) {
	t.Setenv(config.EnvMaxTimeout, "20m")
	t.Setenv(config.EnvSyncWaitCap, "50s")
	const secret = "policy-test-secret"
	root := canonicalTempDir(t)
	m := New(config.Config{
		AgyPath:        "/env/agy",
		StateDir:       "/env/state",
		HTTPToken:      secret,
		DefaultTimeout: 20 * time.Minute,
		Policy: policy.Policy{
			MaxTimeout:   20 * time.Minute,
			AllowedRoots: []string{root},
		},
	})
	got := m.checkConfigSources()
	if got.Status != CheckPass {
		t.Fatalf("status = %v (%s), want PASS", got.Status, got.Detail)
	}
	for _, want := range []string{
		config.EnvMaxTimeout,
		config.EnvSyncWaitCap + "=50s",
		"20m0s",
		"session policy",
		"lowered to MaxTimeout",
	} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("detail lacks %q:\n%s", want, got.Detail)
		}
	}
	if strings.Contains(got.Detail, secret) {
		t.Errorf("detail leaked the token value:\n%s", got.Detail)
	}
	if _, err := os.Stat(root); err != nil {
		t.Errorf("root vanished mid-test: %v", err)
	}
}
