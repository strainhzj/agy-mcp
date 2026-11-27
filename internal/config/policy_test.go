package config

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tphakala/agy-mcp/v2/internal/jobstore"
	"github.com/tphakala/agy-mcp/v2/internal/policy"
)

// writeRecord writes the deployment record the controlled launcher would
// write, so a pi-profile resolve sees the state-dir contract it requires
// (project, instance and a snapshot fingerprint).
func writeRecord(t *testing.T, stateDir, project, instance string) {
	t.Helper()
	if err := jobstore.WriteInstanceRecord(stateDir, jobstore.InstanceRecord{
		Contract:            jobstore.InstanceContract,
		ProjectID:           project,
		InstanceID:          instance,
		SnapshotFingerprint: "fp-" + instance,
	}); err != nil {
		t.Fatalf("write instance record: %v", err)
	}
}

// writeRecordFingerprint writes a deployment record naming an explicit
// snapshot fingerprint, for the cases where the record and the manifest must
// agree (or deliberately disagree).
func writeRecordFingerprint(t *testing.T, stateDir, project, instance, fingerprint string) {
	t.Helper()
	if err := jobstore.WriteInstanceRecord(stateDir, jobstore.InstanceRecord{
		Contract:            jobstore.InstanceContract,
		ProjectID:           project,
		InstanceID:          instance,
		SnapshotFingerprint: fingerprint,
	}); err != nil {
		t.Fatalf("write instance record: %v", err)
	}
}

// writeManifest writes the project manifest the controlled launcher writes
// for a pi instance: the snapshot root, the fixed worker mount, a content
// fingerprint and read_only. It returns the manifest path. On POSIX the file
// mode is 0440 because LoadProjectManifest refuses a group- or world-writable
// one. Windows cannot express those bits (Go derives FileMode from the
// read-only attribute alone), and a read-only file would also break TempDir
// cleanup, so Windows writes the ordinary 0666 and relies on the loader
// skipping the POSIX-only check.
func writeManifest(t *testing.T, snapshot, project, fingerprint string) string {
	t.Helper()
	path := filepath.Join(dir(t), "project-manifest.json")
	// The snapshot root is an OS path: on Windows it carries backslashes that
	// are invalid JSON escapes, so it goes through json.Marshal rather than
	// being spliced into the template raw.
	root, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot root: %v", err)
	}
	body := `{"schema_version":1,"project_id":"` + project +
		`","snapshot_root":` + string(root) +
		`,"snapshot_fingerprint":"` + fingerprint +
		`","worker_mount":"/workspace","read_only":true}`
	perm := os.FileMode(0o440)
	if runtime.GOOS == "windows" {
		perm = 0o666
	}
	if err := os.WriteFile(path, []byte(body), perm); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}

// piEnv is the environment a controlled launcher exports for a pi instance.
// The snapshot root lives outside the state dir, the manifest names it, and
// the deployment record carries the same snapshot fingerprint, so the two
// records of the one snapshot version agree.
func piEnv(t *testing.T) map[string]string {
	t.Helper()
	snapshot := dir(t)
	state := dir(t)
	fingerprint := "sha256:" + strings.Repeat("a", 64)
	writeRecordFingerprint(t, state, "proj-1", "inst-1", fingerprint)
	manifest := writeManifest(t, snapshot, "proj-1", fingerprint)
	return map[string]string{
		EnvProfile:          policy.ProfilePi,
		EnvAllowedRoots:     "/workspace",
		EnvDefaultCwd:       "/workspace",
		EnvStateDir:         state,
		EnvInstanceID:       "inst-1",
		EnvProjectID:        "proj-1",
		EnvMaxTimeout:       "20m",
		EnvMaxConcurrency:   "2",
		EnvSyncWaitCap:      "50s",
		EnvHTTPAllowedHosts: "192.168.5.45:8865,127.0.0.8:8765",
		EnvProjectManifest:  manifest,
	}
}

// dir returns an existing canonical temporary directory (roots and cwd values
// are validated by EvalSymlinks, and on macOS the TempDir path itself is a
// symlink, so tests must compare against the resolved form).
func dir(t *testing.T) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve tempdir: %v", err)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		t.Fatalf("abs tempdir: %v", err)
	}
	return abs
}

// clearPolicyEnv unsets every policy variable Resolve reads, so a test only
// sets what it names. t.Setenv cannot unset, so this uses os.Unsetenv with a
// cleanup that restores the prior state (including set-but-empty).
//
// The list is the full env surface Resolve consults, including the project
// manifest, the Host allowlist, the mode switches and the sync-wait cap: a
// variable left over from an earlier test would leak into the
// upstream-default gate and make a lie of it.
func clearPolicyEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		EnvProfile, EnvAllowedRoots, EnvDefaultCwd, EnvForceSandbox,
		EnvDisableSkipPermissions, EnvInlineJSONSchemaOnly, EnvSessionPolicy,
		EnvDisableContinueLatest, EnvDisableAgentSelection, EnvAllowedAgents,
		EnvAllowedModels, EnvMaxTimeout, EnvMaxConcurrency, EnvRequireHTTPToken,
		EnvInstanceID, EnvProjectID, EnvStateDir,
		EnvHTTPSessionTimeout, EnvHTTPMaxSessions, EnvHTTPMaxInflight,
		EnvHTTPRatePerSec, EnvStateBudget, EnvSessionTTL,
		EnvProjectManifest, EnvHTTPAllowedHosts, EnvDisableMode, EnvFixedMode,
		EnvSyncWaitCap, "AGY_MCP_SNAPSHOT_FINGERPRINT",
	} {
		old, had := os.LookupEnv(name)
		// Best-effort env surgery in a test: a failure here is a broken test
		// environment, which the assertion below would surface as a wrong
		// resolution anyway.
		_ = os.Unsetenv(name)
		t.Cleanup(func() {
			if had {
				t.Setenv(name, old)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
}

// resolveFor unsets the policy environment, applies set, and runs Resolve.
// Values in set are applied with t.Setenv, so an explicit empty value means
// set-but-empty, distinct from unset (which resolveFor leaves unset).
func resolveFor(t *testing.T, set map[string]string) (Config, error) {
	t.Helper()
	clearPolicyEnv(t)
	for k, v := range set {
		t.Setenv(k, v)
	}
	return Resolve()
}

func TestResolveUnsetPolicyKeepsUpstreamDefaults(t *testing.T) {
	// This is the upstream-compat gate: with no policy variable set at all,
	// Resolve must produce the exact defaults upstream shipped (30m default
	// timeout, 4-way concurrency, allow session policy, no path checks).
	c, err := resolveFor(t, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if c.Policy.Restricted() || c.Policy.Protected() || c.Policy.ForceSandbox ||
		c.Policy.DisableSkipPermissions || c.Policy.InlineJSONSchemaOnly ||
		c.Policy.DisableContinueLatest || c.Policy.DisableAgentSelection ||
		c.Policy.RequireHTTPToken || c.Policy.MaxTimeout != 0 {
		t.Fatalf("unset environment produced a non-zero policy: %+v", c.Policy)
	}
	if c.Policy.SessionPolicy != policy.SessionPolicyAllow {
		t.Fatalf("session policy %q, want allow", c.Policy.SessionPolicy)
	}
	if c.DefaultTimeout != 30*time.Minute || c.MaxConcurrency != 4 {
		t.Fatalf("defaults drifted: timeout %s concurrency %d", c.DefaultTimeout, c.MaxConcurrency)
	}
}

func TestResolvePolicyVariables(t *testing.T) {
	root := dir(t)
	c, err := resolveFor(t, map[string]string{
		EnvAllowedRoots:           root,
		EnvDefaultCwd:             root,
		EnvForceSandbox:           "true",
		EnvDisableSkipPermissions: "1",
		EnvSessionPolicy:          "disabled",
		EnvDisableContinueLatest:  "yes",
		EnvAllowedAgents:          "reviewer, planner",
		EnvAllowedModels:          "m1,m2",
		EnvMaxTimeout:             "20m",
		EnvMaxConcurrency:         "2",
		EnvRequireHTTPToken:       "on",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	p := c.Policy
	if !p.Restricted() || p.AllowedRoots[0] != root {
		t.Fatalf("roots %+v", p.AllowedRoots)
	}
	if p.DefaultCwd != root || !p.ForceSandbox || !p.DisableSkipPermissions ||
		!p.DisableContinueLatest || !p.RequireHTTPToken {
		t.Fatalf("switches wrong: %+v", p)
	}
	if p.SessionPolicy != policy.SessionPolicyDisabled {
		t.Fatalf("session policy %q", p.SessionPolicy)
	}
	if !equalList(p.AllowedAgents, []string{"reviewer", "planner"}) {
		t.Fatalf("agents %q", p.AllowedAgents)
	}
	if !equalList(p.AllowedModels, []string{"m1", "m2"}) {
		t.Fatalf("models %q", p.AllowedModels)
	}
	if p.MaxTimeout != 20*time.Minute {
		t.Fatalf("max timeout %s", p.MaxTimeout)
	}
	// The downshift: MaxTimeout 20m is below the 30m default, so the default
	// must follow it down or every run omitting timeout would be refused.
	if c.DefaultTimeout != 20*time.Minute {
		t.Fatalf("default timeout %s, want 20m after downshift", c.DefaultTimeout)
	}
	if c.MaxConcurrency != 2 {
		t.Fatalf("concurrency %d", c.MaxConcurrency)
	}
}

func TestResolveMaxTimeoutAboveDefaultKeepsDefault(t *testing.T) {
	// A MaxTimeout of 45m is above the 30m default, so no downshift: the
	// default stays 30m and only explicit longer requests are capped.
	root := dir(t)
	c, err := resolveFor(t, map[string]string{
		EnvAllowedRoots: root,
		EnvMaxTimeout:   "45m",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if c.DefaultTimeout != 30*time.Minute {
		t.Fatalf("default timeout downshifted to %s with MaxTimeout 45m", c.DefaultTimeout)
	}
	if c.Policy.MaxTimeout != 45*time.Minute {
		t.Fatalf("max timeout %s", c.Policy.MaxTimeout)
	}
}

func TestResolvePolicyErrors(t *testing.T) {
	root := dir(t)
	cases := []struct {
		name string
		set  map[string]string
		want string
	}{
		{"unknown profile", map[string]string{EnvProfile: "fortress"}, `want "pi" or unset`},
		{"bad bool", map[string]string{EnvForceSandbox: "maybe"}, "want a boolean"},
		{"empty root entry", map[string]string{EnvAllowedRoots: root + string(filepath.ListSeparator)}, "empty entry"},
		{"missing root dir", map[string]string{EnvAllowedRoots: filepath.Join(root, "gone")}, "allowed root"},
		{"file as root", func() map[string]string {
			file := filepath.Join(root, "f")
			if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return map[string]string{EnvAllowedRoots: file}
		}(), "not a directory"},
		{"bad session policy", map[string]string{EnvSessionPolicy: "sometimes"}, "unknown session policy"},
		{"empty session policy", map[string]string{EnvSessionPolicy: ""}, "set but empty"},
		{"bad max timeout", map[string]string{EnvMaxTimeout: "soon"}, "invalid duration"},
		{"negative max timeout", map[string]string{EnvMaxTimeout: "-5m"}, "positive duration"},
		{"over-ceiling max timeout", map[string]string{EnvMaxTimeout: "25h"}, "exceeds"},
		{"bad concurrency", map[string]string{EnvMaxConcurrency: "0"}, "positive integer"},
		{"non-numeric concurrency", map[string]string{EnvMaxConcurrency: "lots"}, "positive integer"},
		{"empty agent entry", map[string]string{EnvAllowedAgents: "a,,"}, "empty entry"},
		{"default cwd outside roots", map[string]string{EnvAllowedRoots: root, EnvDefaultCwd: dir(t)}, "default working directory"},
		{"empty-but-set instance id", map[string]string{EnvInstanceID: ""}, "set but empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveFor(t, tc.set)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestResolvePiProfile(t *testing.T) {
	env := piEnv(t)
	c, err := resolveFor(t, env)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	p := c.Policy
	if !p.Protected() || !p.Restricted() {
		t.Fatalf("profile pi not active: %+v", p)
	}
	// The profile's fixed switches come from the profile, not the environment:
	// this test sets none of them and all of them must hold.
	if !p.ForceSandbox || p.DisableSkipPermissions || p.InlineJSONSchemaOnly ||
		!p.DisableContinueLatest || !p.RequireHTTPToken || !p.DisableJSONSchema ||
		!p.Mode.DisableClientMode {
		t.Fatalf("profile defaults wrong: %+v", p)
	}
	if p.SessionPolicy != policy.SessionPolicyDisabled {
		t.Fatalf("session policy %q, want disabled", p.SessionPolicy)
	}
	if c.InstanceID != "inst-1" || c.ProjectID != "proj-1" {
		t.Fatalf("identity wrong: %q/%q", c.InstanceID, c.ProjectID)
	}
	if env[EnvStateDir] == "" || c.StateDir != env[EnvStateDir] {
		t.Fatalf("state dir %q, want %q", c.StateDir, env[EnvStateDir])
	}
	// The manifest's fingerprint is what ownership and replay bind to, and it
	// must match the launcher-written deployment record.
	want := "sha256:" + strings.Repeat("a", 64)
	if c.SnapshotFingerprint != want {
		t.Fatalf("snapshot fingerprint %q, want the manifest's %q", c.SnapshotFingerprint, want)
	}
	if c.Policy.SnapshotFingerprint != want {
		t.Fatalf("policy fingerprint %q, want the manifest's %q", c.Policy.SnapshotFingerprint, want)
	}
	if c.DefaultTimeout != 20*time.Minute || c.MaxConcurrency != 2 {
		t.Fatalf("timeout/concurrency %s/%d", c.DefaultTimeout, c.MaxConcurrency)
	}
}

func TestResolvePiProfileExplicitManagedOnlyAccepted(t *testing.T) {
	// managed-only is a Phase 3 value the profile accepts explicitly (it is
	// what a Phase 3 rollout sets); allow stays refused.
	env := piEnv(t)
	env[EnvSessionPolicy] = string(policy.SessionPolicyManagedOnly)
	c, err := resolveFor(t, env)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if c.Policy.SessionPolicy != policy.SessionPolicyManagedOnly {
		t.Fatalf("session policy %q", c.Policy.SessionPolicy)
	}
	// managed-only implies a handle TTL, which the profile defaults rather than
	// leaving at zero (a zero TTL would make every handle born expired).
	if c.SessionTTL != DefaultSessionTTL {
		t.Fatalf("session ttl %s, want the %s default", c.SessionTTL, DefaultSessionTTL)
	}
}

func TestResolvePiProfileConflicts(t *testing.T) {
	base := func() map[string]string {
		return piEnv(t)
	}
	cases := []struct {
		name string
		set  map[string]string
		want string
	}{
		{"sandbox opt-out", map[string]string{EnvForceSandbox: "false"}, "conflicts with profile"},
		{"skip-permissions opt-in", map[string]string{EnvDisableSkipPermissions: "true"}, "conflicts with profile"},
		{"inline schema knob", map[string]string{EnvInlineJSONSchemaOnly: "true"}, "conflicts with profile"},
		{"continue-latest opt-out", map[string]string{EnvDisableContinueLatest: "false"}, "conflicts with profile"},
		{"token optional", map[string]string{EnvRequireHTTPToken: "false"}, "conflicts with profile"},
		{"mode opt-out", map[string]string{EnvDisableMode: "false"}, "conflicts with profile"},
		{"session allow", map[string]string{EnvSessionPolicy: "allow"}, "conflicts with profile"},
		{"two roots", map[string]string{EnvAllowedRoots: "/workspace" + string(filepath.ListSeparator) + "/other"}, "exactly one root"},
		{"host root", map[string]string{EnvAllowedRoots: dir(t)}, "the only allowed root is /workspace"},
		{"no state dir", map[string]string{EnvStateDir: ""}, "AGY_MCP_STATE_DIR is required"},
		{"no instance id", map[string]string{EnvInstanceID: ""}, "AGY_MCP_INSTANCE_ID"},
		{"no project id", map[string]string{EnvProjectID: ""}, "AGY_MCP_PROJECT_ID"},
		{"no max timeout", map[string]string{EnvMaxTimeout: ""}, "AGY_MCP_MAX_TIMEOUT is set but empty"},
		{"no default cwd", map[string]string{EnvDefaultCwd: ""}, "AGY_MCP_DEFAULT_CWD is required"},
		{"no manifest", map[string]string{EnvProjectManifest: ""}, "AGY_MCP_PROJECT_MANIFEST is required"},
		{"no allowed hosts", map[string]string{EnvHTTPAllowedHosts: ""}, "AGY_MCP_HTTP_ALLOWED_HOSTS is required"},
		{"no sync wait cap", map[string]string{EnvSyncWaitCap: ""}, "AGY_MCP_SYNC_WAIT_CAP is required"},
		{"bad sync wait cap", map[string]string{EnvSyncWaitCap: "soon"}, "AGY_MCP_SYNC_WAIT_CAP"},
		{"agent selection open", map[string]string{EnvDisableAgentSelection: "false"}, "AGY_MCP_ALLOWED_AGENTS must name"}, {"fixed mode", map[string]string{EnvFixedMode: "accept-edits"}, "fixed mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := base()
			maps.Copy(set, tc.set)
			_, err := resolveFor(t, set)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestResolveSyncWaitCap(t *testing.T) {
	if got := ResolveSyncWaitCap(func(string) string { return "" }); got != DefaultSyncWaitCap {
		t.Fatalf("unset cap %s, want default %s", got, DefaultSyncWaitCap)
	}
	if got := ResolveSyncWaitCap(func(name string) string {
		if name == EnvSyncWaitCap {
			return "50s"
		}
		return ""
	}); got != 50*time.Second {
		t.Fatalf("override cap %s", got)
	}
	// An unparseable or non-positive value falls back silently; the doctor
	// reports which applied, but the ceiling never goes invalid.
	for _, bad := range []string{"soon", "-5m", "0s"} {
		if got := ResolveSyncWaitCap(func(name string) string {
			if name == EnvSyncWaitCap {
				return bad
			}
			return ""
		}); got != DefaultSyncWaitCap {
			t.Fatalf("cap %q resolved to %s, want default", bad, got)
		}
	}
}

func TestSanitizeEnvStripsControlPlaneVariables(t *testing.T) {
	// SanitizeEnv is the one filter every spawned process goes through; its
	// contract is "no AGY_MCP_* variable survives" while everything else (the
	// variables agy actually needs, HOME and PATH here) passes untouched.
	environ := []string{
		"HOME=/home/op",
		"PATH=/bin",
		EnvHTTPToken + "=super-secret",
		EnvStateDir + "=/var/lib/agy-mcp",
		EnvUsageInterval + "=5m",
		"OTHER=value",
	}
	got := SanitizeEnv(environ)
	for _, kv := range got {
		if strings.HasPrefix(kv, "AGY_MCP_") {
			t.Fatalf("control-plane variable leaked to a child: %s", kv)
		}
	}
	if !equalList(got, []string{"HOME=/home/op", "PATH=/bin", "OTHER=value"}) {
		t.Fatalf("sanitize kept %q, want HOME, PATH, OTHER", got)
	}
}

func TestSanitizeEnvIdempotent(t *testing.T) {
	// The supervisor sanitizes what the manager already sanitized; the second
	// pass must be a no-op, not a corruption.
	once := SanitizeEnv([]string{"A=1", "AGY_MCP_X=2"})
	twice := SanitizeEnv(once)
	if !equalList(once, twice) {
		t.Fatalf("double sanitize changed the result: %q vs %q", once, twice)
	}
}

func equalList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestResolvePiProfileRequiresDeploymentRecord pins the fail-closed tie
// between the profile and its controlled launcher: without a readable,
// matching deployment record in the state directory, a fully configured
// profile start is refused, so a bare start, two instances sharing a state
// directory, and a snapshot change reusing an old identity are all startup
// errors. Removing the verifyDeploymentRecord call in Resolve turns every
// subtest here green-when-broken.
func TestResolvePiProfileRequiresDeploymentRecord(t *testing.T) {
	base := func() map[string]string {
		return piEnv(t)
	}
	t.Run("missing record refused", func(t *testing.T) {
		env := base()
		// A fresh state dir with no deployment record: the launcher writes it, so
		// its absence means the server was started outside the controlled pipeline.
		env[EnvStateDir] = dir(t)
		if _, err := resolveFor(t, env); err == nil || !strings.Contains(err.Error(), "deployment record") {
			t.Fatalf("resolve without a record = %v, want a deployment-record refusal", err)
		}
	})
	t.Run("foreign identity refused", func(t *testing.T) {
		env := base()
		writeRecord(t, env[EnvStateDir], "other-project", "inst-1")
		if _, err := resolveFor(t, env); err == nil || !strings.Contains(err.Error(), "belongs to another deployment") {
			t.Fatalf("resolve against another project's record = %v", err)
		}
	})
	t.Run("unknown contract refused", func(t *testing.T) {
		env := base()
		if err := jobstore.WriteInstanceRecord(env[EnvStateDir], jobstore.InstanceRecord{
			Contract:            jobstore.InstanceContract + 1,
			ProjectID:           "proj-1",
			InstanceID:          "inst-1",
			SnapshotFingerprint: "sha256:" + strings.Repeat("a", 64),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveFor(t, env); err == nil || !strings.Contains(err.Error(), "contract") {
			t.Fatalf("resolve against a future contract = %v", err)
		}
	})
	t.Run("fingerprintless record refused", func(t *testing.T) {
		env := base()
		if err := jobstore.WriteInstanceRecord(env[EnvStateDir], jobstore.InstanceRecord{
			Contract:   jobstore.InstanceContract,
			ProjectID:  "proj-1",
			InstanceID: "inst-1",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveFor(t, env); err == nil || !strings.Contains(err.Error(), "snapshot fingerprint") {
			t.Fatalf("resolve against a fingerprintless record = %v", err)
		}
	})
	t.Run("record and manifest fingerprint disagree refused", func(t *testing.T) {
		// The deployment record and the manifest are two records of the same
		// snapshot version. When they disagree the instance is half-configured
		// and must refuse rather than pick one.
		env := base()
		writeRecordFingerprint(t, env[EnvStateDir], "proj-1", "inst-1", "sha256:"+strings.Repeat("b", 64))
		_, err := resolveFor(t, env)
		if err == nil || !strings.Contains(err.Error(), "does not match the project manifest's") {
			t.Fatalf("resolve with disagreeing fingerprints = %v, want a refusal", err)
		}
	})
}

// TestResolveMaxTimeoutExplicitNonPositiveRefused pins the explicit-value
// contract: an explicit zero or negative AGY_MCP_MAX_TIMEOUT is a startup
// error, not a silent read as "unset" (which would re-enable the 24h ceiling
// while the operator believes a cap is active). An unset variable keeps the
// upstream default, and set-but-empty is refused like the other variables.
func TestResolveMaxTimeoutExplicitNonPositiveRefused(t *testing.T) {
	for _, bad := range []string{"0s", "0", "-5m", ""} {
		_, err := resolveFor(t, map[string]string{EnvMaxTimeout: bad})
		want := "positive duration"
		if bad == "" {
			want = "set but empty"
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("AGY_MCP_MAX_TIMEOUT=%q err = %v, want an error containing %q", bad, err, want)
		}
	}
	// Unset keeps upstream: no error, no cap.
	if c, err := resolveFor(t, nil); err != nil || c.Policy.MaxTimeout != 0 {
		t.Fatalf("unset max timeout = %v, %v; want no cap and no error", c.Policy.MaxTimeout, err)
	}
}

// TestSanitizeEnvStrict pins the protected child environment: the strict
// filter is a positive allowlist, so a secret riding on any unconsidered name
// (not just the agy-mcp prefix) cannot reach a worker, a hook, or a probe.
func TestSanitizeEnvStrict(t *testing.T) {
	env := []string{
		"HOME=/h",
		"PATH=/bin",
		"LANG=C.UTF-8",
		"HTTPS_PROXY=http://proxy:3128",
		"AGY_MCP_HTTP_TOKEN=control-plane-token",
		"ACCEPTANCE_EXTRA_SECRET=SYNTHETIC_ONLY",
	}
	got := SanitizeEnvStrict(env)
	want := []string{"HOME=/h", "PATH=/bin", "LANG=C.UTF-8", "HTTPS_PROXY=http://proxy:3128"}
	if !equalList(sortedCopy(got), sortedCopy(want)) {
		t.Fatalf("SanitizeEnvStrict = %q, want %q", got, want)
	}
	for _, kv := range got {
		if strings.Contains(kv, "control-plane-token") || strings.Contains(kv, "SYNTHETIC_ONLY") {
			t.Fatalf("strict env leaked %q", kv)
		}
	}
}

func sortedCopy(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

// TestResolveUnsetLimitsKeepUpstreamOff extends the upstream-compat gate to
// the new limits: with no policy variable set, the HTTP guard is zero, the
// state budget is off, and no session TTL exists.
func TestResolveUnsetLimitsKeepUpstreamOff(t *testing.T) {
	c, err := resolveFor(t, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if c.HTTPGuard.Limited() || c.StateBudgetBytes != 0 || c.SessionTTL != 0 {
		t.Fatalf("unset environment produced limits: guard %+v budget %d ttl %s", c.HTTPGuard, c.StateBudgetBytes, c.SessionTTL)
	}
}

// TestResolvePiProfileLimitDefaults pins the profile defaults: an operator who
// sets no limit variable still gets bounded sessions, in-flight work, request
// rate and a disk budget, because the plan requires the caps by default, not
// by opt-in.
func TestResolvePiProfileLimitDefaults(t *testing.T) {
	c, err := resolveFor(t, piEnv(t))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	g := c.HTTPGuard
	if g.SessionTimeout != DefaultHTTPSessionTimeout || g.MaxSessions != DefaultHTTPMaxSessions ||
		g.MaxInflight != DefaultHTTPMaxInflight || g.RatePerSec != DefaultHTTPRatePerSec {
		t.Fatalf("profile guard defaults wrong: %+v", g)
	}
	if c.StateBudgetBytes != DefaultStateBudget {
		t.Fatalf("state budget %d, want %d", c.StateBudgetBytes, DefaultStateBudget)
	}
	if c.SessionTTL != 0 {
		t.Fatalf("session ttl %s set without managed-only", c.SessionTTL)
	}
	// The manifest's project identity is what the policy carries, and the
	// snapshot root it names is what the worker mount maps onto.
	if c.Policy.ProjectID != "proj-1" || c.Policy.SnapshotRoot == "" {
		t.Fatalf("manifest values missing from the policy: %+v", c.Policy)
	}
	if len(c.Policy.AllowedRoots) != 1 || c.Policy.AllowedRoots[0] != policy.WorkerMountPath {
		t.Fatalf("allowed roots %q, want only %s", c.Policy.AllowedRoots, policy.WorkerMountPath)
	}
	if !c.Policy.Mode.DisableClientMode {
		t.Fatal("mode not disabled under the profile")
	}
	if len(c.Policy.AllowedHosts) == 0 {
		t.Fatal("allowed hosts empty under the profile")
	}
	if c.SyncWaitCap != 50*time.Second || !c.SyncWaitCapSet {
		t.Fatalf("sync wait cap %s (set=%v), want 50s set", c.SyncWaitCap, c.SyncWaitCapSet)
	}
}

// TestResolveExplicitLimits parsed as set, independent of any profile.
func TestResolveExplicitLimits(t *testing.T) {
	c, err := resolveFor(t, map[string]string{
		EnvHTTPSessionTimeout: "12m",
		EnvHTTPMaxSessions:    "8",
		EnvHTTPMaxInflight:    "4",
		EnvHTTPRatePerSec:     "5.5",
		EnvStateBudget:        "512MiB",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	g := c.HTTPGuard
	if g.SessionTimeout != 12*time.Minute || g.MaxSessions != 8 || g.MaxInflight != 4 || g.RatePerSec != 5.5 {
		t.Fatalf("guard = %+v", g)
	}
	if c.StateBudgetBytes != 512<<20 {
		t.Fatalf("state budget %d, want 512MiB", c.StateBudgetBytes)
	}
}

// TestResolveManagedOnlySessionTTL pins the Phase 3 TTL rules: the profile
// with managed-only gets the default when unset, honors an explicit positive
// value, and anything else with the variable set is refused.
func TestResolveManagedOnlySessionTTL(t *testing.T) {
	profileEnv := func(extra map[string]string) map[string]string {
		set := piEnv(t)
		set[EnvSessionPolicy] = string(policy.SessionPolicyManagedOnly)
		maps.Copy(set, extra)
		return set
	}
	c, err := resolveFor(t, profileEnv(nil))
	if err != nil {
		t.Fatalf("managed-only resolve: %v", err)
	}
	if c.SessionTTL != DefaultSessionTTL {
		t.Fatalf("ttl %s, want default %s", c.SessionTTL, DefaultSessionTTL)
	}
	c, err = resolveFor(t, profileEnv(map[string]string{EnvSessionTTL: "48h"}))
	if err != nil {
		t.Fatalf("managed-only resolve with ttl: %v", err)
	}
	if c.SessionTTL != 48*time.Hour {
		t.Fatalf("ttl %s, want 48h", c.SessionTTL)
	}
	for _, tc := range []struct {
		name string
		set  map[string]string
		want string
	}{
		{"zero ttl", map[string]string{EnvSessionTTL: "0"}, "want a positive duration or unset"},
		{"negative ttl", map[string]string{EnvSessionTTL: "-5m"}, "want a positive duration or unset"},
		{"ttl without managed-only", map[string]string{EnvSessionTTL: "48h", EnvSessionPolicy: "disabled"}, "only valid together with"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := resolveFor(t, profileEnv(tc.set)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

// TestResolveManagedOnlyRequiresProfile pins that handles never resolve
// outside a protected deployment: their records name a project, an instance
// and a snapshot version, which an unprotected server cannot supply.
func TestResolveManagedOnlyRequiresProfile(t *testing.T) {
	_, err := resolveFor(t, map[string]string{EnvSessionPolicy: string(policy.SessionPolicyManagedOnly)})
	if err == nil || !strings.Contains(err.Error(), "requires profile") {
		t.Fatalf("want requires-profile error, got %v", err)
	}
}

// TestResolveLimitErrors covers the fail-closed parses of the new limits.
func TestResolveLimitErrors(t *testing.T) {
	cases := []struct {
		name string
		set  map[string]string
		want string
	}{
		{"zero session timeout", map[string]string{EnvHTTPSessionTimeout: "0"}, "want a positive duration or unset"},
		{"negative inflight", map[string]string{EnvHTTPMaxInflight: "-1"}, "want a positive integer or unset"},
		{"sessions without timeout", map[string]string{EnvHTTPMaxSessions: "8"}, "requires " + EnvHTTPSessionTimeout},
		{"bad rate", map[string]string{EnvHTTPRatePerSec: "fast"}, "want a positive number or unset"},
		{"zero rate", map[string]string{EnvHTTPRatePerSec: "0"}, "want a positive number or unset"},
		{"bad budget unit", map[string]string{EnvStateBudget: "5ligabytes"}, "KiB, MiB, GiB or TiB suffix"},
		{"zero budget", map[string]string{EnvStateBudget: "0"}, "want a positive byte count"},
		{"negative budget", map[string]string{EnvStateBudget: "-2GiB"}, "want a positive byte count"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := resolveFor(t, tc.set); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

// TestParseByteSize pins the byte-size grammar AGY_MCP_STATE_BUDGET accepts.
func TestParseByteSize(t *testing.T) {
	cases := []struct {
		raw  string
		want int64
	}{
		{"1024", 1024},
		{"1KiB", 1 << 10},
		{"512MiB", 512 << 20},
		{"2GiB", 2 << 30},
		{"2gib", 2 << 30},
		{"1TiB", 1 << 40},
		{" 3 MiB ", 3 << 20},
	}
	for _, tc := range cases {
		got, err := parseByteSize(EnvStateBudget, tc.raw)
		if err != nil || got != tc.want {
			t.Fatalf("parseByteSize(%q) = %d, %v; want %d", tc.raw, got, err, tc.want)
		}
	}
	for _, raw := range []string{"", "MiB", "5XB", "abc", "-1GiB", "0"} {
		if _, err := parseByteSize(EnvStateBudget, raw); err == nil {
			t.Fatalf("parseByteSize(%q) unexpectedly succeeded", raw)
		}
	}
}
