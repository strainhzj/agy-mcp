//go:build linux || darwin

package manager

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tphakala/agy-mcp/v2/internal/config"
	"github.com/tphakala/agy-mcp/v2/internal/jobstore"
	"github.com/tphakala/agy-mcp/v2/internal/policy"
	"github.com/tphakala/agy-mcp/v2/internal/testutil"
)

// envDumpSupervisor writes a fake supervisor that dumps its environment into
// the job dir before finishing, so a test can assert what the supervisor (and
// through it agy) actually received.
func envDumpSupervisor(t *testing.T) string {
	t.Helper()
	script := "#!/bin/sh\n" +
		"dir=\"$2\"\n" +
		"env > \"$dir/env-dump\"\n" +
		"printf 'done' > \"$dir/out\"\n" +
		"echo 0 > \"$dir/exit_code\"\n"
	path := filepath.Join(t.TempDir(), "fake-supervisor-env")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestStartJobProtectedWritesOwnership runs the real spawn path under the
// protected policy and asserts the ownership record exists and matches the
// deployment identity. writeOwnership runs between store.Create and the
// supervisor spawn, so removing that call (or gating it on anything other
// than Protected) turns this red.
func TestStartJobProtectedWritesOwnership(t *testing.T) {
	root, _ := policyRoot(t)
	m := newManager(t, managerOpts{
		pol:            restrictedPol(root),
		projectID:      "proj-1",
		instanceID:     "inst-1",
		agyPath:        "/usr/bin/agy",
		supervisorExe:  testutil.WriteFakeSupervisor(t, testutil.FakeSupervisor{Out: "done"}),
		defaultTimeout: time.Minute,
	})
	job, err := m.StartJob(StartRequest{Prompt: "analyze", Cwd: root})
	if err != nil {
		t.Fatalf("StartJob: %v", err)
	}
	deferJobDone(t, m, job.ID)
	dir, err := m.store.Dir(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := readOwnershipRecord(dir)
	if err != nil {
		t.Fatalf("ownership record missing after a protected spawn: %v", err)
	}
	if rec.ProjectID != "proj-1" || rec.InstanceID != "inst-1" || rec.Profile != policy.ProfilePi {
		t.Fatalf("ownership record %+v, want proj-1/inst-1 under pi", rec)
	}
	// ForceSandbox rides through: the persisted argv must carry --sandbox.
	meta, err := m.store.Load(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(meta.Args, sandboxFlag) {
		t.Fatalf("persisted args lack %s: %q", sandboxFlag, meta.Args)
	}
	if !slices.Contains(meta.Args, "--dangerously-skip-permissions") {
		t.Fatalf("persisted args lost the default skip-permissions flag: %q", meta.Args)
	}
}

// TestStartJobDisableSkipPermissions pins the DisableSkipPermissions wiring:
// the persisted argv must not carry the flag, and a keyless retry must still
// replay (sameRequest compares under the same skipPermissions value).
func TestStartJobDisableSkipPermissions(t *testing.T) {
	root, _ := policyRoot(t)
	pol := restrictedPol(root)
	pol.DisableSkipPermissions = true
	m := newManager(t, managerOpts{
		pol:            pol,
		projectID:      "p",
		instanceID:     "i",
		agyPath:        "/usr/bin/agy",
		supervisorExe:  testutil.WriteFakeSupervisor(t, testutil.FakeSupervisor{Out: "done"}),
		defaultTimeout: time.Minute,
	})
	job, err := m.StartJob(StartRequest{Prompt: "analyze", Cwd: root})
	if err != nil {
		t.Fatalf("StartJob: %v", err)
	}
	deferJobDone(t, m, job.ID)
	meta, err := m.store.Load(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(meta.Args, "--dangerously-skip-permissions") {
		t.Fatalf("DisableSkipPermissions left the flag in the argv: %q", meta.Args)
	}
	// sameRequest must agree in both directions: the skipPermissions value the
	// args were built with decides the comparison, so a flipped policy cannot
	// silently replay a job built under the other one. Sandbox mirrors what
	// the policy forced during normalization, since meta.Args carry it.
	req := StartRequest{Prompt: "analyze", Cwd: meta.Cwd, Timeout: meta.Timeout, Sandbox: true}
	off := buildAgyArgsWithSkipPermissions(req, false)
	if !sameRequest(meta, req, off, false) {
		t.Fatal("sameRequest refused its own keyless job built under skipPermissions=false")
	}
	if sameRequest(meta, req, buildAgyArgsWithSkipPermissions(req, true), true) {
		t.Fatal("sameRequest matched a job built under skipPermissions=false against skipPermissions=true args")
	}
}

// TestSpawnEnvStrippedOfControlPlaneVariables pins the token-isolation
// contract at both spawn boundaries the test can reach: the supervisor sees
// no AGY_MCP_* variable at all, and neither does the version probe. Setting
// a synthetic token here is the acceptance test's shape: the secret must not
// survive into any child process environment.
func TestSpawnEnvStrippedOfControlPlaneVariables(t *testing.T) {
	t.Setenv(config.EnvHTTPToken, "synthetic-secret-token")
	t.Setenv("AGY_MCP_STATE_DIR", "/synthetic-state")

	// Supervisor boundary: the manager sanitizes what it hands the supervisor,
	// and the supervisor sanitizes again before agy runs, so one dump covers
	// both filters' output as the worker would see it.
	root, _ := policyRoot(t)
	m := newManager(t, managerOpts{
		pol:            restrictedPol(root),
		agyPath:        "/usr/bin/agy",
		supervisorExe:  envDumpSupervisor(t),
		defaultTimeout: time.Minute,
	})
	job, err := m.StartJob(StartRequest{Prompt: "p", Cwd: root})
	if err != nil {
		t.Fatalf("StartJob: %v", err)
	}
	deferJobDone(t, m, job.ID)
	// The dump is written by the supervisor before its sentinel, so waiting
	// for the sentinel here proves the dir is final before the read. The
	// deferred wait above only covers teardown ordering.
	testutil.WaitFor(t, 15*time.Second, func() bool {
		_, ok := m.store.ExitCode(job.ID)
		return ok
	}, "supervisor did not write its exit-code sentinel")
	dir, err := m.store.Dir(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	dump, err := os.ReadFile(filepath.Join(dir, "env-dump"))
	if err != nil {
		t.Fatalf("supervisor env dump missing: %v", err)
	}
	for line := range strings.SplitSeq(string(dump), "\n") {
		if strings.HasPrefix(line, "AGY_MCP_") {
			t.Errorf("supervisor environment carried control-plane variable: %s", line)
		}
	}

	// Probe boundary: a fake agy that echoes the variable into its version
	// output. The real readAgyVersion is wired back in over newManager's stub.
	fake := filepath.Join(t.TempDir(), "fake-agy-env")
	script := "#!/bin/sh\nprintf 'TOKEN=[%s]\\n' \"$AGY_MCP_HTTP_TOKEN\"\necho 1.5.17\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	m2 := newManager(t, managerOpts{agyPath: fake})
	m2.readAgyVersion = readAgyVersion
	out, err := m2.readAgyVersion(t.Context(), fake)
	if err != nil {
		t.Fatalf("version probe: %v", err)
	}
	if strings.Contains(out, "synthetic-secret-token") {
		t.Fatalf("version probe saw the control-plane token: %q", out)
	}
	if !strings.Contains(out, "TOKEN=[]") {
		t.Fatalf("probe output %q does not show the variable as unset; the dump harness is broken", out)
	}
}

// TestOwnershipRecordRoundTrip covers the jobstore helper the manager uses:
// atomic write, then read back through the same path constant.
func TestOwnershipRecordRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := jobstore.WriteOwnershipFile(dir, []byte(`{"profile":"pi","project_id":"p","instance_id":"i"}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	rec, err := readOwnershipRecord(dir)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if rec.Profile != policy.ProfilePi || rec.ProjectID != "p" || rec.InstanceID != "i" {
		t.Fatalf("record %+v", rec)
	}
}
