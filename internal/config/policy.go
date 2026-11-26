// Policy configuration plumbing: the AGY_MCP_* environment variables that
// build a policy.Policy, the pi profile requirements, and the child-process
// environment sanitizer. Resolve in config.go calls resolvePolicy; everything
// here is private to the package except the exported constants and
// SanitizeEnv, which the doctor and the process-spawning packages share.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tphakala/agy-mcp/v2/internal/jobstore"
	"github.com/tphakala/agy-mcp/v2/internal/policy"
)

// Policy and deployment-identity environment variables. Like the constants in
// config.go, they are exported so the doctor command names the same identifier
// config reads the setting from.
const (
	// EnvProfile selects a protected deployment profile ("pi"). Empty keeps
	// upstream behavior.
	EnvProfile = "AGY_MCP_PROFILE"
	// EnvAllowedRoots is a list-separator-separated list of absolute directory
	// roots every requested cwd and dir must resolve under.
	EnvAllowedRoots = "AGY_MCP_ALLOWED_ROOTS"
	// EnvDefaultCwd is the working directory used when a caller omits cwd.
	EnvDefaultCwd = "AGY_MCP_DEFAULT_CWD"
	// EnvForceSandbox passes --sandbox to agy on every run.
	EnvForceSandbox = "AGY_MCP_FORCE_SANDBOX"
	// EnvDisableSkipPermissions stops passing --dangerously-skip-permissions.
	EnvDisableSkipPermissions = "AGY_MCP_DISABLE_SKIP_PERMISSIONS"
	// EnvInlineJSONSchemaOnly restricts json_schema to inline JSON objects.
	EnvInlineJSONSchemaOnly = "AGY_MCP_INLINE_JSON_SCHEMA_ONLY"
	// EnvSessionPolicy is allow, managed-only or disabled.
	EnvSessionPolicy = "AGY_MCP_SESSION_POLICY"
	// EnvDisableContinueLatest refuses continue_latest=true.
	EnvDisableContinueLatest = "AGY_MCP_DISABLE_CONTINUE_LATEST"
	// EnvDisableAgentSelection refuses a non-empty agent parameter.
	EnvDisableAgentSelection = "AGY_MCP_DISABLE_AGENT_SELECTION"
	// EnvAllowedAgents is a comma-separated agent-name whitelist.
	EnvAllowedAgents = "AGY_MCP_ALLOWED_AGENTS"
	// EnvAllowedModels is a comma-separated model-id whitelist.
	EnvAllowedModels = "AGY_MCP_ALLOWED_MODELS"
	// EnvMaxTimeout caps a caller-supplied per-job timeout.
	EnvMaxTimeout = "AGY_MCP_MAX_TIMEOUT"
	// EnvMaxConcurrency caps concurrent jobs for the instance.
	EnvMaxConcurrency = "AGY_MCP_MAX_CONCURRENCY"
	// EnvRequireHTTPToken refuses an HTTP start with no bearer token.
	EnvRequireHTTPToken = "AGY_MCP_REQUIRE_HTTP_TOKEN"
	// EnvInstanceID is the deployment-assigned identity of this instance. It
	// never comes from a tool call; the protected deployment launcher sets it.
	EnvInstanceID = "AGY_MCP_INSTANCE_ID"
	// EnvProjectID is the deployment-assigned project this instance serves.
	EnvProjectID = "AGY_MCP_PROJECT_ID"
	// EnvSyncWaitCap overrides the inline-wait ceiling for agy_run_sync and
	// agy_wait. It lives here (not with its reader in mcptools) so the doctor
	// can report how it resolved without an import cycle.
	EnvSyncWaitCap = "AGY_MCP_SYNC_WAIT_CAP"
	// EnvHTTPSessionTimeout is the idle timeout after which the HTTP transport
	// closes a session that has sent no request. Zero (unset) keeps the SDK's
	// upstream behavior, where idle sessions are never closed.
	EnvHTTPSessionTimeout = "AGY_MCP_HTTP_SESSION_TIMEOUT"
	// EnvHTTPMaxSessions caps the distinct MCP sessions a server will track.
	// Zero (unset) means unlimited. It requires a session timeout: without one
	// a cap can never be relaxed because idle sessions never leave.
	EnvHTTPMaxSessions = "AGY_MCP_HTTP_MAX_SESSIONS"
	// EnvHTTPMaxInflight caps the HTTP requests the server processes at once.
	// Zero (unset) means unlimited.
	EnvHTTPMaxInflight = "AGY_MCP_HTTP_MAX_INFLIGHT"
	// EnvHTTPRatePerSec caps authenticated requests per second with a token
	// bucket whose burst equals the rate. Zero (unset) means unlimited.
	EnvHTTPRatePerSec = "AGY_MCP_HTTP_RATE_PER_SEC"
	// EnvStateBudget bounds the job store's total size on disk, for example
	// "2GiB". Zero (unset) disables the budget.
	EnvStateBudget = "AGY_MCP_STATE_BUDGET"
	// EnvSessionTTL is how long a managed-only session handle stays
	// resolvable, independent of JobTTL. It is only valid together with
	// AGY_MCP_SESSION_POLICY=managed-only.
	EnvSessionTTL = "AGY_MCP_SESSION_TTL"
)

// DefaultSyncWaitCap is the built-in inline-wait ceiling: below the ~120s
// per-call timeout common MCP clients impose, so the still-running result
// (carrying the job id) reaches the caller before the client abandons the
// call. mcptools clamps against ResolveSyncWaitCap, which returns this when
// EnvSyncWaitCap is unset or unparseable.
const DefaultSyncWaitCap = 90 * time.Second

// Defaults a protected profile applies when the corresponding limit is left
// unset. Upstream (no profile) every limit defaults to off, so none of these
// change an unprotected server's behavior.
const (
	DefaultHTTPSessionTimeout = 15 * time.Minute
	DefaultHTTPMaxSessions    = 16
	DefaultHTTPMaxInflight    = 8
	DefaultHTTPRatePerSec     = 20.0
	DefaultStateBudget        = int64(2) << 30 // 2 GiB
	DefaultSessionTTL         = 7 * 24 * time.Hour
)

// HTTPGuard carries the resolved HTTP transport limits. The zero value means
// every limit is off, which is upstream behavior; an unset limit under a
// protected profile takes the profile default instead.
type HTTPGuard struct {
	// SessionTimeout closes an idle MCP session after this long. Zero keeps
	// the SDK default (idle sessions are never closed).
	SessionTimeout time.Duration
	// MaxSessions caps the distinct MCP sessions the server tracks; it
	// requires SessionTimeout, because only a timeout ever retires a session.
	MaxSessions int
	// MaxInflight caps requests the server processes concurrently.
	MaxInflight int
	// RatePerSec caps authenticated requests per second (token bucket, burst
	// equal to the rate). Zero disables rate limiting.
	RatePerSec float64
}

// Limited reports whether any limit is active, so the HTTP layer can skip the
// guard middleware entirely for an unrestricted server.
func (g HTTPGuard) Limited() bool {
	return g.SessionTimeout > 0 || g.MaxSessions > 0 || g.MaxInflight > 0 || g.RatePerSec > 0
}

// ResolveSyncWaitCap resolves the effective inline-wait ceiling from getenv.
// An unparseable or non-positive value silently falls back to the default,
// matching the reader's historical behavior; the doctor reports which of the
// two applied.
func ResolveSyncWaitCap(getenv func(string) string) time.Duration {
	if v := getenv(EnvSyncWaitCap); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return DefaultSyncWaitCap
}

// boolValues are the accepted spellings of a boolean policy variable, mapped
// to their value. Anything else is a startup error rather than a silent
// guess, because these switches change what the server enforces.
var boolValues = map[string]bool{
	"1": true, "t": true, "true": true, "yes": true, "on": true,
	"0": false, "f": false, "false": false, "no": false, "off": false,
}

// lookupBool parses one boolean variable. An unset variable leaves def; a set
// variable must parse (case-insensitively) or the server refuses to start.
// The second return distinguishes "unset" from "explicitly set", which the
// pi profile conflict checks need.
func lookupBool(name string) (value, set bool, err error) {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return false, false, nil
	}
	v, known := boolValues[strings.ToLower(strings.TrimSpace(raw))]
	if !known {
		return false, true, fmt.Errorf("%s %q: want a boolean (%s)", name, raw, "1/t/true/yes/on or 0/f/false/no/off")
	}
	return v, true, nil
}

// splitPaths splits a list-separator-separated variable into trimmed absolute
// path entries. Empty entries are refused: a trailing separator or a doubled
// one is a typo, and silently dropping it would widen or narrow the allowlist
// without the operator noticing.
func splitPaths(name, raw string) ([]string, error) {
	var out []string
	for part := range strings.SplitSeq(raw, string(filepath.ListSeparator)) {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("%s contains an empty entry (check for doubled or trailing %q)", name, string(filepath.ListSeparator))
		}
		out = append(out, part)
	}
	return out, nil
}

// splitList splits a comma-separated whitelist into trimmed entries, refusing
// empty ones for the same reason splitPaths refuses them.
func splitList(name, raw string) ([]string, error) {
	var out []string
	for part := range strings.SplitSeq(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("%s contains an empty entry (check for doubled or trailing commas)", name)
		}
		out = append(out, part)
	}
	return out, nil
}

// profileRule is one pi-profile variable requirement: under the profile the
// variable must be unset (taking the profile default) or explicitly set to
// the required value. An explicit conflicting value is a configuration
// conflict the startup refuses, never a silent override.
type profileRule struct {
	name     string
	required bool
}

// resolvePolicy populates c.Policy, c.ProjectID and c.InstanceID from the
// environment and validates the result. Every failure is a startup failure.
//
// Under the pi profile the required settings have no defaults beyond the
// profile's own: the instance must be told its project root, its default
// working directory, its timeout budget, its identity, and a dedicated state
// directory. Missing or conflicting settings refuse the start rather than
// degrading into a half-protected server.
func resolvePolicy(c *Config) error {
	p := &c.Policy
	if v := os.Getenv(EnvProfile); v != "" {
		if v != policy.ProfilePi {
			return fmt.Errorf("%s %q: want %q or unset", EnvProfile, v, policy.ProfilePi)
		}
		p.Profile = v
	}
	var err error
	if p.ForceSandbox, _, err = lookupBool(EnvForceSandbox); err != nil {
		return err
	}
	if p.DisableSkipPermissions, _, err = lookupBool(EnvDisableSkipPermissions); err != nil {
		return err
	}
	if p.InlineJSONSchemaOnly, _, err = lookupBool(EnvInlineJSONSchemaOnly); err != nil {
		return err
	}
	if p.DisableContinueLatest, _, err = lookupBool(EnvDisableContinueLatest); err != nil {
		return err
	}
	if p.DisableAgentSelection, _, err = lookupBool(EnvDisableAgentSelection); err != nil {
		return err
	}
	if p.RequireHTTPToken, _, err = lookupBool(EnvRequireHTTPToken); err != nil {
		return err
	}
	if raw := os.Getenv(EnvAllowedRoots); raw != "" {
		if p.AllowedRoots, err = splitPaths(EnvAllowedRoots, raw); err != nil {
			return err
		}
	}
	if raw := os.Getenv(EnvAllowedAgents); raw != "" {
		if p.AllowedAgents, err = splitList(EnvAllowedAgents, raw); err != nil {
			return err
		}
	}
	if raw := os.Getenv(EnvAllowedModels); raw != "" {
		if p.AllowedModels, err = splitList(EnvAllowedModels, raw); err != nil {
			return err
		}
	}
	p.DefaultCwd = os.Getenv(EnvDefaultCwd)
	if raw, ok := os.LookupEnv(EnvSessionPolicy); ok {
		if raw == "" {
			return fmt.Errorf("%s is set but empty; want allow, managed-only or disabled", EnvSessionPolicy)
		}
		p.SessionPolicy = policy.SessionPolicy(raw)
		if p.SessionPolicy == policy.SessionPolicyManagedOnly && !p.Protected() {
			return fmt.Errorf("%s=%s requires profile %s: handles are bound to a deployment's project, instance and snapshot version", EnvSessionPolicy, policy.SessionPolicyManagedOnly, policy.ProfilePi)
		}
	}
	if raw, ok := os.LookupEnv(EnvMaxTimeout); ok {
		if raw == "" {
			return fmt.Errorf("%s is set but empty; want a positive Go duration (0 < d <= 24h) or unset", EnvMaxTimeout)
		}
		d, perr := time.ParseDuration(raw)
		if perr != nil {
			return fmt.Errorf("%s %q: %w", EnvMaxTimeout, raw, perr)
		}
		// An explicit zero is a configuration error, not "no limit": a silent
		// read as "unset" would re-enable the upstream 24h ceiling while the
		// operator believes a cap is active. Ceiling (> 24h) is checked in
		// ValidateAndNormalize below.
		if d <= 0 {
			return fmt.Errorf("%s %q: want a positive duration (0 < d <= 24h) or unset", EnvMaxTimeout, raw)
		}
		p.MaxTimeout = d
	}
	if c.InstanceID, err = requiredIdentity(EnvInstanceID); err != nil {
		return err
	}
	if c.ProjectID, err = requiredIdentity(EnvProjectID); err != nil {
		return err
	}
	if c.SessionTTL, err = resolveSessionTTL(p); err != nil {
		return err
	}
	if c.HTTPGuard, err = resolveHTTPGuard(p); err != nil {
		return err
	}
	if c.StateBudgetBytes, err = resolveStateBudget(p); err != nil {
		return err
	}

	if p.Protected() {
		if err := applyProfileRequirements(c); err != nil {
			return err
		}
	}
	return p.ValidateAndNormalize()
}

// resolveSessionTTL resolves the managed-only handle expiry. It is only
// valid together with the managed-only session policy: anywhere else an unset
// variable stays zero and a set one is refused, so a typo cannot silently
// attach an expiry to a policy that has no handles.
func resolveSessionTTL(p *policy.Policy) (time.Duration, error) {
	raw, set := os.LookupEnv(EnvSessionTTL)
	if !set || raw == "" {
		if p.SessionPolicy == policy.SessionPolicyManagedOnly {
			return DefaultSessionTTL, nil
		}
		return 0, nil
	}
	if p.SessionPolicy != policy.SessionPolicyManagedOnly {
		return 0, fmt.Errorf("%s is only valid together with %s=%s", EnvSessionTTL, EnvSessionPolicy, policy.SessionPolicyManagedOnly)
	}
	d, perr := time.ParseDuration(raw)
	if perr != nil {
		return 0, fmt.Errorf("%s %q: %w", EnvSessionTTL, raw, perr)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s %q: want a positive duration or unset", EnvSessionTTL, raw)
	}
	return d, nil
}

// resolveHTTPGuard resolves the HTTP transport limits. An unset limit is off
// upstream and takes the profile default under a protected profile; a set
// limit must be positive, because an explicit zero would read as "off" to an
// operator who believes a cap is active (the same reading MAX_TIMEOUT refuses).
func resolveHTTPGuard(p *policy.Policy) (HTTPGuard, error) {
	var g HTTPGuard
	var err error
	if g.SessionTimeout, _, err = lookupPositiveDuration(EnvHTTPSessionTimeout); err != nil {
		return g, err
	}
	if g.MaxSessions, _, err = lookupPositiveInt(EnvHTTPMaxSessions); err != nil {
		return g, err
	}
	if g.MaxInflight, _, err = lookupPositiveInt(EnvHTTPMaxInflight); err != nil {
		return g, err
	}
	if g.RatePerSec, _, err = lookupPositiveFloat(EnvHTTPRatePerSec); err != nil {
		return g, err
	}
	if p.Protected() {
		if g.SessionTimeout == 0 {
			g.SessionTimeout = DefaultHTTPSessionTimeout
		}
		if g.MaxSessions == 0 {
			g.MaxSessions = DefaultHTTPMaxSessions
		}
		if g.MaxInflight == 0 {
			g.MaxInflight = DefaultHTTPMaxInflight
		}
		if g.RatePerSec == 0 {
			g.RatePerSec = DefaultHTTPRatePerSec
		}
	}
	if g.MaxSessions > 0 && g.SessionTimeout <= 0 {
		return g, fmt.Errorf("%s requires %s: without an idle timeout a session is never retired, so the cap could only ever tighten", EnvHTTPMaxSessions, EnvHTTPSessionTimeout)
	}
	return g, nil
}

// resolveStateBudget resolves the job store's disk budget. Unset is off
// upstream and takes the profile default under a protected profile; an
// explicit value must parse and be positive.
func resolveStateBudget(p *policy.Policy) (int64, error) {
	raw, set := os.LookupEnv(EnvStateBudget)
	if !set || raw == "" {
		if p.Protected() {
			return DefaultStateBudget, nil
		}
		return 0, nil
	}
	n, err := parseByteSize(EnvStateBudget, raw)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// byteSizeUnits are the accepted binary size suffixes for AGY_MCP_STATE_BUDGET,
// longest first so "KiB" is never read as "B".
var byteSizeUnits = []struct {
	suffix string
	mult   int64
}{
	{"tib", 1 << 40}, {"gib", 1 << 30}, {"mib", 1 << 20}, {"kib", 1 << 10}, {"b", 1},
}

// parseByteSize parses a byte count like "512MiB", "2GiB" or a bare integer
// (bytes). A zero or negative value is a configuration error, not "off": the
// way to disable the budget is to leave the variable unset.
func parseByteSize(name, raw string) (int64, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	for _, u := range byteSizeUnits {
		if !strings.HasSuffix(s, u.suffix) {
			continue
		}
		num := strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
		if num == "" {
			break
		}
		f, perr := strconv.ParseFloat(num, 64)
		if perr != nil {
			break
		}
		n := int64(f * float64(u.mult))
		if n <= 0 || f <= 0 {
			return 0, fmt.Errorf("%s %q: want a positive byte count (for example 512MiB or 2GiB) or unset", name, raw)
		}
		return n, nil
	}
	// No usable suffix: a bare integer counts as bytes, and anything else is
	// the grammar error.
	if f, perr := strconv.ParseFloat(s, 64); perr == nil {
		if f <= 0 {
			return 0, fmt.Errorf("%s %q: want a positive byte count (for example 512MiB or 2GiB) or unset", name, raw)
		}
		return int64(f), nil
	}
	return 0, fmt.Errorf("%s %q: want a byte count with a B, KiB, MiB, GiB or TiB suffix (for example 512MiB or 2GiB), or unset", name, raw)
}

// lookupPositiveDuration parses one duration variable that must be positive
// when set. An unset variable returns (0, false, nil).
func lookupPositiveDuration(name string) (d time.Duration, set bool, err error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return 0, false, nil
	}
	d, perr := time.ParseDuration(raw)
	if perr != nil {
		return 0, true, fmt.Errorf("%s %q: %w", name, raw, perr)
	}
	if d <= 0 {
		return 0, true, fmt.Errorf("%s %q: want a positive duration or unset", name, raw)
	}
	return d, true, nil
}

// lookupPositiveInt parses one integer variable that must be positive when set.
func lookupPositiveInt(name string) (n int, set bool, err error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return 0, false, nil
	}
	var perr error
	n, perr = strconv.Atoi(strings.TrimSpace(raw))
	if perr != nil {
		return 0, true, fmt.Errorf("%s %q: %w", name, raw, perr)
	}
	if n <= 0 {
		return 0, true, fmt.Errorf("%s %q: want a positive integer or unset", name, raw)
	}
	return n, true, nil
}

// lookupPositiveFloat parses one float variable that must be positive when set.
func lookupPositiveFloat(name string) (f float64, set bool, err error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return 0, false, nil
	}
	var perr error
	f, perr = strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if perr != nil {
		return 0, true, fmt.Errorf("%s %q: want a positive number or unset", name, raw)
	}
	if f <= 0 {
		return 0, true, fmt.Errorf("%s %q: want a positive number or unset", name, raw)
	}
	return f, true, nil
}

// requiredIdentity reads a deployment-assigned identity. It is optional
// upstream (empty is fine and means no protected deployment) and required
// under the pi profile, which applyProfileRequirements checks separately, so
// this only rejects a set-but-empty value.
func requiredIdentity(name string) (string, error) {
	raw := os.Getenv(name)
	if raw == "" {
		if _, set := os.LookupEnv(name); set {
			return "", fmt.Errorf("%s is set but empty", name)
		}
	}
	return raw, nil
}

// applyProfileRequirements enforces the pi profile's fixed settings. Each
// rule is either taken as the profile default when unset, or, when set, must
// match the required value; a conflict refuses the start.
func applyProfileRequirements(c *Config) error {
	p := &c.Policy
	boolRules := []profileRule{
		{EnvForceSandbox, true},
		{EnvDisableSkipPermissions, false},
		{EnvInlineJSONSchemaOnly, false}, // json_schema is refused wholesale; the knob does not apply
		{EnvDisableContinueLatest, true},
		{EnvRequireHTTPToken, true},
	}
	for _, rule := range boolRules {
		v, set, err := lookupBool(rule.name)
		if err != nil {
			return err
		}
		if !set {
			v = rule.required
		}
		if v != rule.required {
			return fmt.Errorf("%s=%v conflicts with profile %s, which requires %v", rule.name, v, policy.ProfilePi, rule.required)
		}
		switch rule.name {
		case EnvForceSandbox:
			p.ForceSandbox = v
		case EnvDisableSkipPermissions:
			p.DisableSkipPermissions = v
		case EnvInlineJSONSchemaOnly:
			p.InlineJSONSchemaOnly = v
		case EnvDisableContinueLatest:
			p.DisableContinueLatest = v
		case EnvRequireHTTPToken:
			p.RequireHTTPToken = v
		}
	}
	if len(p.AllowedRoots) == 0 {
		return fmt.Errorf("%s is required under profile %s: name the single project root", EnvAllowedRoots, policy.ProfilePi)
	}
	if len(p.AllowedRoots) != 1 {
		return fmt.Errorf("%s must name exactly one root under profile %s (one instance serves one project); got %d", EnvAllowedRoots, policy.ProfilePi, len(p.AllowedRoots))
	}
	if p.DefaultCwd == "" {
		return fmt.Errorf("%s is required under profile %s: set it to the project snapshot root", EnvDefaultCwd, policy.ProfilePi)
	}
	if p.SessionPolicy == policy.SessionPolicyAllow {
		return fmt.Errorf("%s=%s conflicts with profile %s, which never exposes host conversation caches; use disabled, or managed-only (with %s) for Phase 3 continuation handles", EnvSessionPolicy, policy.SessionPolicyAllow, policy.ProfilePi, EnvSessionTTL)
	}
	if p.SessionPolicy == "" {
		p.SessionPolicy = policy.SessionPolicyDisabled
	}
	if p.MaxTimeout == 0 {
		return fmt.Errorf("%s is required under profile %s: set the per-job timeout budget (for example 20m)", EnvMaxTimeout, policy.ProfilePi)
	}
	if _, set := os.LookupEnv(EnvStateDir); !set || os.Getenv(EnvStateDir) == "" {
		return fmt.Errorf("%s is required under profile %s: give this instance its own job-state directory, never the default or a shared one", EnvStateDir, policy.ProfilePi)
	}
	if c.InstanceID == "" {
		return fmt.Errorf("%s is required under profile %s: the deployment launcher must assign the instance identity", EnvInstanceID, policy.ProfilePi)
	}
	if c.ProjectID == "" {
		return fmt.Errorf("%s is required under profile %s: the deployment launcher must assign the project identity", EnvProjectID, policy.ProfilePi)
	}
	return nil
}

// finishPolicy applies the policy to the shared defaults: the concurrency
// override and the default-timeout downshift. It runs after the policy is
// validated and only in Resolve (the wait subcommands never admit jobs).
//
// The downshift is not optional: DefaultTimeout is what a request without a
// timeout resolves to, and MaxTimeout is checked after that resolution, so a
// MaxTimeout below the default 30m would refuse every run that omits timeout.
func finishPolicy(c *Config) error {
	if raw := os.Getenv(EnvMaxConcurrency); raw != "" {
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || n < 1 {
			return fmt.Errorf("%s %q: want a positive integer", EnvMaxConcurrency, raw)
		}
		c.MaxConcurrency = n
	}
	if c.Policy.MaxTimeout > 0 && c.Policy.MaxTimeout < c.DefaultTimeout {
		c.DefaultTimeout = c.Policy.MaxTimeout
	}
	return nil
}

// controlPlaneEnvPrefix marks the variables that carry control-plane state:
// how this server authenticates its callers and which deployment it serves.
// No child process (the run-job supervisor, agy, agy's tools, hooks or MCP
// plugins) has any use for them, and MEASURED workspace hooks (agy 1.5.17,
// Phase 0 T3) execute with the spawning process's environment, so a workspace
// hook would otherwise read the bearer token straight out of env.
const controlPlaneEnvPrefix = "AGY_MCP_"

// SanitizeEnv returns environ with the agy-mcp control-plane variables
// removed. It is applied to every process agy-mcp spawns (the supervisor, the
// agy worker, and every probe), unconditionally: the token authorizes callers
// to this server, not anything a child could do with it, so there is no
// configuration in which a child should hold it. Everything else in the
// environment is passed through untouched, because agy needs HOME, PATH, its
// own OAuth or ADC configuration, and the host proxy settings.
func SanitizeEnv(environ []string) []string {
	kept := make([]string, 0, len(environ))
	for _, kv := range environ {
		name, _, found := strings.Cut(kv, "=")
		if found && strings.HasPrefix(name, controlPlaneEnvPrefix) {
			continue
		}
		kept = append(kept, kv)
	}
	return kept
}

// protectedChildEnvAllowlist is the whole environment a protected deployment
// passes to any child process: what agy and its tools genuinely need to run
// (a home, a path, locale and TLS trust, and the proxy that carries their
// controlled egress), and nothing else. Unlike the prefix strip above, this is
// a positive allowlist: a variable the control plane happens to hold (another
// credential, an unrelated secret, an internal endpoint) cannot reach a child
// by riding on an unconsidered name.
var protectedChildEnvAllowlist = map[string]bool{
	"HOME": true, "PATH": true,
	"LANG": true, "LC_ALL": true, "TZ": true,
	"SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true,
	"http_proxy": true, "https_proxy": true, "no_proxy": true,
}

// SanitizeEnvStrict returns environ reduced to the protected allowlist. It is
// applied to the worker environment of protected jobs (the supervisor decides
// from the job's ownership record) and to every probe a protected instance
// runs. Order is unstable like SanitizeEnv's, and os/exec does not care.
func SanitizeEnvStrict(environ []string) []string {
	kept := make([]string, 0, len(protectedChildEnvAllowlist))
	for _, kv := range environ {
		name, _, found := strings.Cut(kv, "=")
		if found && protectedChildEnvAllowlist[name] {
			kept = append(kept, kv)
		}
	}
	return kept
}

// verifyDeploymentRecord loads and checks the state directory's deployment
// record under a protected profile. It is the fail-closed tie between the
// server and its controlled launcher (deploy/launch-pi.sh): no record, a
// record from another contract, another identity, or one without a snapshot
// fingerprint refuses the start, so a bare start of the pi profile, two
// instances sharing one state directory, and a snapshot change reusing an old
// deployment's identity are all configuration errors, not degraded starts.
func verifyDeploymentRecord(c *Config) error {
	rec, err := jobstore.ReadInstanceRecord(c.StateDir)
	if err != nil {
		return fmt.Errorf("profile %s requires the deployment record %s in the state directory %s: %w; deploy the instance with its controlled launcher (deploy/launch-pi.sh), which writes the record before the server starts", policy.ProfilePi, jobstore.InstanceRecordFile, c.StateDir, err)
	}
	if rec.Contract != jobstore.InstanceContract {
		return fmt.Errorf("deployment record contract %d is not understood by this build (want %d); redeploy the instance with its launcher", rec.Contract, jobstore.InstanceContract)
	}
	if rec.ProjectID != c.ProjectID || rec.InstanceID != c.InstanceID {
		return fmt.Errorf("deployment record names project %q instance %q; this server is configured for project %q instance %q: the state directory belongs to another deployment", rec.ProjectID, rec.InstanceID, c.ProjectID, c.InstanceID)
	}
	if rec.SnapshotFingerprint == "" {
		return fmt.Errorf("deployment record carries no snapshot fingerprint; redeploy the instance so ownership and replays bind to a snapshot version")
	}
	c.SnapshotFingerprint = rec.SnapshotFingerprint
	return nil
}
