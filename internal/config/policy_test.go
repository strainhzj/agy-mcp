package config

import (
	"maps"
	"os"
	"path/filepath"
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
func clearPolicyEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		EnvProfile, EnvAllowedRoots, EnvDefaultCwd, EnvForceSandbox,
		EnvDisableSkipPermissions, EnvInlineJSONSchemaOnly, EnvSessionPolicy,
		EnvDisableContinueLatest, EnvDisableAgentSelection, EnvAllowedAgents,
		EnvAllowedModels, EnvMaxTimeout, EnvMaxConcurrency, EnvRequireHTTPToken,
		EnvInstanceID, EnvProjectID, EnvStateDir,
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
	root := dir(t)
	state := dir(t)
	writeRecord(t, state, "proj-1", "inst-1")
	c, err := resolveFor(t, map[string]string{
		EnvProfile:        policy.ProfilePi,
		EnvAllowedRoots:   root,
		EnvDefaultCwd:     root,
		EnvStateDir:       state,
		EnvInstanceID:     "inst-1",
		EnvProjectID:      "proj-1",
		EnvMaxTimeout:     "20m",
		EnvMaxConcurrency: "2",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	p := c.Policy
	if !p.Protected() || !p.Restricted() {
		t.Fatalf("profile pi not active: %+v", p)
	}
	// The profile's fixed switches come from the profile, not the environment:
	// this test sets none of them and all four must hold.
	if !p.ForceSandbox || p.DisableSkipPermissions || p.InlineJSONSchemaOnly ||
		!p.DisableContinueLatest || !p.RequireHTTPToken {
		t.Fatalf("profile defaults wrong: %+v", p)
	}
	if p.SessionPolicy != policy.SessionPolicyDisabled {
		t.Fatalf("session policy %q, want disabled", p.SessionPolicy)
	}
	if c.InstanceID != "inst-1" || c.ProjectID != "proj-1" {
		t.Fatalf("identity wrong: %q/%q", c.InstanceID, c.ProjectID)
	}
	if c.StateDir != state {
		t.Fatalf("state dir %q, want %q", c.StateDir, state)
	}
	if c.SnapshotFingerprint != "fp-inst-1" {
		t.Fatalf("snapshot fingerprint %q, want the record's", c.SnapshotFingerprint)
	}
	if c.DefaultTimeout != 20*time.Minute || c.MaxConcurrency != 2 {
		t.Fatalf("timeout/concurrency %s/%d", c.DefaultTimeout, c.MaxConcurrency)
	}
}

func TestResolvePiProfileExplicitManagedOnlyAccepted(t *testing.T) {
	// managed-only is a Phase 3 value the profile accepts explicitly (it is
	// what a Phase 3 rollout sets); allow stays refused.
	root := dir(t)
	state := dir(t)
	writeRecord(t, state, "p", "i")
	c, err := resolveFor(t, map[string]string{
		EnvProfile:       policy.ProfilePi,
		EnvAllowedRoots:  root,
		EnvDefaultCwd:    root,
		EnvStateDir:      state,
		EnvInstanceID:    "i",
		EnvProjectID:     "p",
		EnvMaxTimeout:    "20m",
		EnvSessionPolicy: string(policy.SessionPolicyManagedOnly),
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if c.Policy.SessionPolicy != policy.SessionPolicyManagedOnly {
		t.Fatalf("session policy %q", c.Policy.SessionPolicy)
	}
}

func TestResolvePiProfileConflicts(t *testing.T) {
	root := dir(t)
	base := func() map[string]string {
		return map[string]string{
			EnvProfile:      policy.ProfilePi,
			EnvAllowedRoots: root,
			EnvDefaultCwd:   root,
			EnvStateDir:     dir(t),
			EnvInstanceID:   "i",
			EnvProjectID:    "p",
			EnvMaxTimeout:   "20m",
		}
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
		{"session allow", map[string]string{EnvSessionPolicy: "allow"}, "conflicts with profile"},
		{"two roots", map[string]string{EnvAllowedRoots: root + string(filepath.ListSeparator) + dir(t)}, "exactly one root"},
		{"no state dir", map[string]string{EnvStateDir: ""}, "AGY_MCP_STATE_DIR is required"},
		{"no instance id", map[string]string{EnvInstanceID: ""}, "AGY_MCP_INSTANCE_ID"},
		{"no project id", map[string]string{EnvProjectID: ""}, "AGY_MCP_PROJECT_ID"},
		{"no max timeout", map[string]string{EnvMaxTimeout: ""}, "AGY_MCP_MAX_TIMEOUT is set but empty"},
		{"no default cwd", map[string]string{EnvDefaultCwd: ""}, "AGY_MCP_DEFAULT_CWD is required"},
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
	root := dir(t)
	state := dir(t)
	base := func() map[string]string {
		return map[string]string{
			EnvProfile:      policy.ProfilePi,
			EnvAllowedRoots: root,
			EnvDefaultCwd:   root,
			EnvStateDir:     state,
			EnvInstanceID:   "inst-1",
			EnvProjectID:    "proj-1",
			EnvMaxTimeout:   "20m",
		}
	}
	t.Run("missing record refused", func(t *testing.T) {
		if _, err := resolveFor(t, base()); err == nil || !strings.Contains(err.Error(), "deployment record") {
			t.Fatalf("resolve without a record = %v, want a deployment-record refusal", err)
		}
	})
	t.Run("foreign identity refused", func(t *testing.T) {
		writeRecord(t, state, "other-project", "inst-1")
		if _, err := resolveFor(t, base()); err == nil || !strings.Contains(err.Error(), "belongs to another deployment") {
			t.Fatalf("resolve against another project's record = %v", err)
		}
	})
	t.Run("unknown contract refused", func(t *testing.T) {
		if err := jobstore.WriteInstanceRecord(state, jobstore.InstanceRecord{
			Contract:            jobstore.InstanceContract + 1,
			ProjectID:           "proj-1",
			InstanceID:          "inst-1",
			SnapshotFingerprint: "fp",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveFor(t, base()); err == nil || !strings.Contains(err.Error(), "contract") {
			t.Fatalf("resolve against a future contract = %v", err)
		}
	})
	t.Run("fingerprintless record refused", func(t *testing.T) {
		if err := jobstore.WriteInstanceRecord(state, jobstore.InstanceRecord{
			Contract:   jobstore.InstanceContract,
			ProjectID:  "proj-1",
			InstanceID: "inst-1",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveFor(t, base()); err == nil || !strings.Contains(err.Error(), "snapshot fingerprint") {
			t.Fatalf("resolve against a fingerprintless record = %v", err)
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
