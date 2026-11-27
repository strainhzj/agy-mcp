// Package policy enforces the deployment-level restrictions a protected
// agy-mcp instance places on tool parameters and spawned agy processes.
//
// A Policy is built from AGY_MCP_* environment variables by internal/config
// (see resolvePolicy there) and carried on config.Config.Policy. With no
// policy configured the zero-value Policy plus the exported helpers leave
// upstream behavior untouched: Restricted() is false, CheckDir returns "",
// and CheckJSONSchema and CheckRunOptions pass everything through.
//
// The package is deliberately agnostic to where a Policy came from: it
// validates and applies, while internal/config owns the environment mapping
// and the profile requirements. Nothing here execs agy or touches job state.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// ProfilePi names the protected single-project deployment profile. A pi
// instance serves one project snapshot, requires HTTP bearer auth, refuses
// session continuation and json_schema, and is expected to run under a
// controlled OS-isolated launcher (see the deployment docs). The profile name
// is the value of the AGY_MCP_PROFILE environment variable.
const ProfilePi = "pi"

// SessionPolicy controls which agy conversation identifiers a caller may use.
//
// last_conversations.json, and any agy session id that appears in a historical
// job, is not an authorization grant: it names sessions agy created across the
// whole host, including ones this server never started. allow exists for
// upstream compatibility only.
type SessionPolicy string

const (
	// SessionPolicyAllow keeps upstream behavior: continue_latest and
	// list_sessions read agy's conversation cache, and any conversation_id is
	// accepted. Never combined with a protected profile.
	SessionPolicyAllow SessionPolicy = "allow"
	// SessionPolicyManagedOnly accepts only opaque conversation handles this
	// instance issued for its own project (the protected session index). It
	// requires the Phase 3 handle machinery, which is not implemented yet, so
	// a managed-only instance currently refuses every conversation_id and
	// keeps list_sessions disabled until that index exists.
	SessionPolicyManagedOnly SessionPolicy = "managed-only"
	// SessionPolicyDisabled turns session continuation off: list_sessions
	// returns a policy error, continue_latest is refused, and a non-empty
	// conversation_id is refused. No agy session id is ever returned to a
	// caller.
	SessionPolicyDisabled SessionPolicy = "disabled"
)

// MaxInlineJSONSchemaBytes bounds an inline json_schema accepted under
// InlineJSONSchemaOnly. A schema is caller-controlled text that the server
// hands to agy, so the size cap keeps one call from parking megabytes in argv.
const MaxInlineJSONSchemaBytes = 64 << 10 // 64 KiB

// MaxTimeoutCeiling is the largest MaxTimeout a Policy may set, and the
// largest timeout a caller may request. It matches the per-job ceiling
// mcptools enforces (its maxJobTimeout), so both boundaries move together.
const MaxTimeoutCeiling = 24 * time.Hour

// ModePolicy is the policy for the mode parameter and agy's --mode flag.
//
// The mode parameter is untrusted input: it reaches the CLI verbatim when it
// is accepted, and a mode that changes what agy is allowed to do is exactly
// the kind of knob a confused deputy must not hold. So the default is that a
// protected server removes the field from its schema and refuses any request
// carrying the key at all (an empty string, null, or a non-string all
// included), and the server alone decides whether --mode is passed.
type ModePolicy struct {
	// DisableClientMode removes the mode field from the tool schema and
	// refuses any request carrying the key. AGY_MCP_DISABLE_MODE.
	DisableClientMode bool
	// FixedMode is the value the server passes as --mode, when it passes one
	// at all. Empty means no --mode flag. A non-empty value must appear in
	// AllowedModes.
	FixedMode string
	// AllowedModes is the static whitelist FixedMode is checked against. It is
	// deliberately empty until the agy behavior a mode selects has been
	// measured (see the plan's T1 boundary note): a mode that changes tool
	// permissions or write gating is a security-relevant claim, and an
	// unmeasured value must not enter the whitelist.
	AllowedModes []string
}

// FixedModeArg returns the --mode flag pair the server should pass, or nil
// when it passes none. It is the single place that decides, so a caller's mode
// value can never reach the CLI: buildAgyArgs takes the pair from here, not
// from the request.
func (m ModePolicy) FixedModeArg() []string {
	if m.FixedMode == "" {
		return nil
	}
	return []string{"--mode", m.FixedMode}
}

// Validate checks the mode policy: a fixed mode must be whitelisted, and a
// whitelisted value must be one this build was told about.
func (m ModePolicy) Validate() error {
	if m.FixedMode == "" {
		return nil
	}
	if len(m.AllowedModes) == 0 {
		return fmt.Errorf("fixed mode %q is not allowed: the whitelist of measured modes is empty, so no fixed mode can be configured until the mode's effect on tool permissions and write gating has been measured", m.FixedMode)
	}
	if !slices.Contains(m.AllowedModes, m.FixedMode) {
		return fmt.Errorf("fixed mode %q is not in the whitelist (%s)", m.FixedMode, strings.Join(m.AllowedModes, ", "))
	}
	return nil
}

// Policy is the resolved deployment policy. Fields are documented with the
// environment variable that feeds them in internal/config.
type Policy struct {
	// AllowedRoots holds the canonical (Abs plus EvalSymlinks) root directories
	// a caller's cwd and dirs must resolve under. Empty means path checks are
	// disabled and upstream behavior applies. AGY_MCP_ALLOWED_ROOTS.
	AllowedRoots []string
	// DefaultCwd is the canonical directory used when a caller omits cwd. It
	// must be an allowed root itself. Empty means an omitted cwd is refused in
	// restricted mode and falls back to the server process directory upstream.
	// AGY_MCP_DEFAULT_CWD.
	DefaultCwd string
	// Profile records the selected deployment profile ("pi" or "" for none).
	// AGY_MCP_PROFILE.
	Profile string
	// ForceSandbox passes --sandbox to agy on every run regardless of the
	// caller's sandbox parameter. This is defense in depth only: MEASURED
	// against agy 1.5.17, --sandbox does not confine agy's built-in file tools
	// or workspace hooks, so it never replaces OS-level isolation.
	// AGY_MCP_FORCE_SANDBOX.
	ForceSandbox bool
	// DisableSkipPermissions stops passing --dangerously-skip-permissions to
	// agy. MEASURED against agy 1.5.17, runs then land in agy's
	// request-review permission mode; built-in read_file and write_file still
	// reach outside cwd, and compound shell commands are refused as
	// denied_actions, so this switch alone does not make a run read-only.
	// AGY_MCP_DISABLE_SKIP_PERMISSIONS.
	DisableSkipPermissions bool
	// InlineJSONSchemaOnly restricts json_schema to an inline JSON object,
	// refusing file paths and non-object JSON. A protected profile refuses
	// json_schema entirely before this check ever applies.
	// AGY_MCP_INLINE_JSON_SCHEMA_ONLY.
	InlineJSONSchemaOnly bool
	// SessionPolicy is the session access policy; see the SessionPolicy type.
	// AGY_MCP_SESSION_POLICY.
	SessionPolicy SessionPolicy
	// DisableContinueLatest refuses continue_latest=true. It can stand alone
	// under SessionPolicyAllow. AGY_MCP_DISABLE_CONTINUE_LATEST.
	DisableContinueLatest bool
	// DisableAgentSelection refuses a non-empty agent parameter and empties
	// the agent listing, so no host-configured agy agent name is exposed.
	// AGY_MCP_DISABLE_AGENT_SELECTION.
	DisableAgentSelection bool
	// AllowedAgents optionally whitelists agent names; empty means every name
	// agy lists is allowed. AGY_MCP_ALLOWED_AGENTS.
	AllowedAgents []string
	// AllowedModels optionally whitelists model ids; empty means every model
	// agy lists is allowed. AGY_MCP_ALLOWED_MODELS.
	AllowedModels []string
	// MaxTimeout caps a caller-supplied per-job timeout. Zero keeps the
	// upstream 24h ceiling. AGY_MCP_MAX_TIMEOUT.
	MaxTimeout time.Duration
	// RequireHTTPToken refuses an HTTP start with no bearer token configured.
	// AGY_MCP_REQUIRE_HTTP_TOKEN.
	RequireHTTPToken bool

	// Mode is the mode-parameter policy; see the ModePolicy type. AGY_MCP_DISABLE_MODE
	// and AGY_MCP_FIXED_MODE.
	Mode ModePolicy

	// ProjectManifestPath is the absolute path of the project manifest a
	// protected instance loads (AGY_MCP_PROJECT_MANIFEST). It is required under
	// the pi profile and ignored otherwise.
	ProjectManifestPath string
	// ProjectID is the manifest's project identity. Under the profile it must
	// equal AGY_MCP_PROJECT_ID when that is set, and it is what every job's
	// ownership record carries.
	ProjectID string
	// InstanceID is the deployment-assigned instance identity
	// (AGY_MCP_INSTANCE_ID), written into every ownership record.
	InstanceID string
	// SnapshotFingerprint is the manifest's snapshot fingerprint. Under the
	// profile it must equal AGY_MCP_SNAPSHOT_FINGERPRINT when that is set, and
	// it binds ownership and idempotent replay to one snapshot version.
	SnapshotFingerprint string
	// SnapshotRoot is the manifest's snapshot root, canonicalized (Abs plus
	// EvalSymlinks). It is the host side of the WorkerMount mapping: the
	// control plane runs in the host view, where no /workspace mount exists,
	// so it validates a caller's /workspace/... path against this directory.
	SnapshotRoot string
	// WorkerMount is the neutral worker-view mount point. It is fixed at
	// WorkerMountPath by the profile; a non-profile policy leaves it empty and
	// performs no mapping.
	WorkerMount string
	// DisableJSONSchema refuses every non-empty json_schema, including a valid
	// inline object. The pi profile sets it; other deployments use
	// InlineJSONSchemaOnly for the softer rule.
	DisableJSONSchema bool
	// AllowedHosts is the HTTP Host header allowlist a protected instance
	// enforces (AGY_MCP_HTTP_ALLOWED_HOSTS). It must name the published
	// endpoint and the instance's own listen address. Empty means no Host
	// restriction, which the pi profile refuses at startup.
	AllowedHosts []string
}

// Restricted reports whether the policy constrains request paths at all. It
// is the single switch every path check (cwd, dirs, list_agents cwd) hangs
// on: an empty AllowedRoots means every path decision stays upstream.
func (p Policy) Restricted() bool { return len(p.AllowedRoots) > 0 }

// Protected reports whether the policy selected a protected deployment
// profile. Only a protected instance records and verifies per-job ownership
// and refuses json_schema outright.
func (p Policy) Protected() bool { return p.Profile == ProfilePi }

// SessionsAllowed reports whether conversation identifiers may flow to and
// from callers. Under managed-only or disabled, no native agy session id is
// returned to a caller and none is accepted from one.
func (p Policy) SessionsAllowed() bool {
	return p.SessionPolicy == "" || p.SessionPolicy == SessionPolicyAllow
}

// ValidateAndNormalize validates the policy and rewrites its path fields to
// canonical form. It is fail closed: an unusable root, an unknown session
// policy value, or an out-of-range MaxTimeout is an error the caller must
// treat as a startup failure, not a warning.
//
// It must run where the policy is assembled (internal/config.Resolve) and
// can be re-run on an already normalized Policy: the normalized form
// validates the same way, which is what a doctor re-check relies on.
func (p *Policy) ValidateAndNormalize() error {
	switch p.Profile {
	case "", ProfilePi:
	default:
		return fmt.Errorf("unknown profile %q: want %q or unset", p.Profile, ProfilePi)
	}
	if p.Protected() {
		if err := p.normalizeProtected(); err != nil {
			return err
		}
	} else {
		roots := make([]string, 0, len(p.AllowedRoots))
		for _, root := range p.AllowedRoots {
			resolved, err := resolveExistingDir(root)
			if err != nil {
				return fmt.Errorf("allowed root %q: %w", root, err)
			}
			roots = append(roots, resolved)
		}
		p.AllowedRoots = roots
	}
	if p.DefaultCwd != "" {
		cwd, err := p.CheckDir(p.DefaultCwd)
		if err != nil {
			return fmt.Errorf("default working directory %q: %w", p.DefaultCwd, err)
		}
		if cwd == "" {
			// CheckDir returns "" only when no root is configured (path
			// checking is off), so the default is not containment-checked;
			// it must still exist and be a directory.
			if p.Restricted() {
				return fmt.Errorf("default working directory %q: no allowed root is configured", p.DefaultCwd)
			}
			resolved, err := resolveExistingDir(p.DefaultCwd)
			if err != nil {
				return fmt.Errorf("default working directory %q: %w", p.DefaultCwd, err)
			}
			p.DefaultCwd = resolved
		} else {
			p.DefaultCwd = cwd
		}
	}
	switch p.SessionPolicy {
	case "":
		p.SessionPolicy = SessionPolicyAllow
	case SessionPolicyAllow, SessionPolicyManagedOnly, SessionPolicyDisabled:
	default:
		return fmt.Errorf("unknown session policy %q: want allow, managed-only or disabled", string(p.SessionPolicy))
	}
	if p.MaxTimeout < 0 {
		return fmt.Errorf("max timeout %s is negative; set a positive duration or leave it unset", p.MaxTimeout)
	}
	if p.MaxTimeout > MaxTimeoutCeiling {
		return fmt.Errorf("max timeout %s exceeds the %s ceiling", p.MaxTimeout, MaxTimeoutCeiling)
	}
	if err := p.Mode.Validate(); err != nil {
		return err
	}
	return nil
}

// normalizeProtected is the pi-profile half of ValidateAndNormalize.
//
// The protected profile's caller-visible paths are worker-view paths
// (/workspace/...), and the host has no such mount: the control plane runs in
// the host view. So AllowedRoots is not resolved against the host filesystem
// (that would fail on a host where no /workspace exists) and is instead
// pinned to the manifest's WorkerMount; the host-side existence and symlink
// checks apply to the manifest's SnapshotRoot, which is what a /workspace
// path maps to.
func (p *Policy) normalizeProtected() error {
	if p.WorkerMount == "" {
		p.WorkerMount = WorkerMountPath
	}
	if p.WorkerMount != WorkerMountPath {
		return fmt.Errorf("worker mount %q: the protected profile fixes it at %s", p.WorkerMount, WorkerMountPath)
	}
	if p.SnapshotRoot == "" {
		return fmt.Errorf("profile %s requires the project manifest's snapshot root; the manifest is what maps %s onto the host snapshot", ProfilePi, WorkerMountPath)
	}
	resolved, err := resolveExistingDir(p.SnapshotRoot)
	if err != nil {
		return fmt.Errorf("snapshot root %q from the project manifest: %w", p.SnapshotRoot, err)
	}
	p.SnapshotRoot = resolved
	if len(p.AllowedRoots) == 0 {
		return fmt.Errorf("%s is required under profile %s: the single project root is %s", "AGY_MCP_ALLOWED_ROOTS", ProfilePi, WorkerMountPath)
	}
	for _, root := range p.AllowedRoots {
		if root != WorkerMountPath {
			return fmt.Errorf("allowed root %q: under profile %s every caller-visible path is a %s path mapped to the manifest's snapshot root, so the only allowed root is %s", root, ProfilePi, WorkerMountPath, WorkerMountPath)
		}
	}
	if len(p.AllowedHosts) == 0 {
		return fmt.Errorf("%s is required under profile %s: name the published endpoint and this instance's listen address", "AGY_MCP_HTTP_ALLOWED_HOSTS", ProfilePi)
	}
	for _, host := range p.AllowedHosts {
		if err := validateHostEntry(host); err != nil {
			return err
		}
	}
	if !p.Mode.DisableClientMode {
		return fmt.Errorf("%s must be true under profile %s: the mode parameter is untrusted input that reaches agy's --mode flag verbatim", "AGY_MCP_DISABLE_MODE", ProfilePi)
	}
	if !p.DisableJSONSchema {
		p.DisableJSONSchema = true
	}
	return nil
}

// validateHostEntry checks one AGY_MCP_HTTP_ALLOWED_HOSTS entry. An entry
// names a host, optionally with a port; anything else (a scheme, a path, a
// wildcard, whitespace) is refused, because the allowlist is compared against
// the Host header and a sloppy entry would either never match or match more
// than intended.
func validateHostEntry(host string) error {
	if host == "" {
		return fmt.Errorf("%s contains an empty entry", "AGY_MCP_HTTP_ALLOWED_HOSTS")
	}
	if strings.ContainsAny(host, " \t/") {
		return fmt.Errorf("allowed host %q: want host[:port] with no scheme, path or whitespace", host)
	}
	if strings.Contains(host, "*") {
		return fmt.Errorf("allowed host %q: wildcards are not accepted; name every endpoint explicitly", host)
	}
	return nil
}

// HostAllowed reports whether an HTTP Host header value is acceptable. An
// empty allowlist accepts anything, which is the unrestricted upstream
// behavior; the protected profile refuses to start without one, so in practice
// a protected server always has a non-empty list.
func (p Policy) HostAllowed(hostHeader string) bool {
	return p.hostAllowed(hostHeader)
}

// hostAllowed reports whether the Host header value is on the allowlist. The
// comparison is case-insensitive on the host part (DNS names are
// case-insensitive) and exact on the port. An entry that names no port matches
// that host on any port, which is what an operator means by "this host,
// whichever port the client reached it on"; an entry that names a port matches
// only that port, so a portless header (which means the default port, a
// different endpoint) does not pass on it.
func (p Policy) hostAllowed(hostHeader string) bool {
	if len(p.AllowedHosts) == 0 {
		return true
	}
	gotHost, gotPort := splitHostPort(hostHeader)
	for _, entry := range p.AllowedHosts {
		wantHost, wantPort := splitHostPort(entry)
		if !strings.EqualFold(gotHost, wantHost) {
			continue
		}
		if wantPort == "" || wantPort == gotPort {
			return true
		}
	}
	return false
}

// splitHostPort splits a host[:port] value. A missing port returns an empty
// port rather than an error, and an IPv6 literal keeps its brackets, so
// "[::1]:22" splits into "[::1]" and "22".
func splitHostPort(value string) (host, port string) {
	if i := strings.LastIndex(value, ":"); i >= 0 && !strings.Contains(value[i+1:], "]") {
		// Only treat the last colon as a port separator when what follows
		// looks like one: a bare IPv6 literal has several colons and no port.
		if !strings.Contains(value[:i], "]") || strings.Contains(value, "]:") {
			return value[:i], value[i+1:]
		}
	}
	return value, ""
}

// resolveExistingDir canonicalizes an absolute raw path (EvalSymlinks first,
// then Abs) and requires it to exist and be a directory. EvalSymlinks before
// Abs matters: Abs and Join fold ".." lexically, so "<allowed>/link-to-etc/.."
// would collapse back under <allowed> before any symlink is resolved.
// Resolving the raw path first follows the kernel's rule, where ".." climbs
// from the link's target.
func resolveExistingDir(raw string) (string, error) {
	if !filepath.IsAbs(raw) {
		return "", fmt.Errorf("path %q is not absolute", raw)
	}
	resolved, err := filepath.EvalSymlinks(raw)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("path %q is not a directory", raw)
	}
	return abs, nil
}

// CheckDir validates a caller-supplied working directory against the allowed
// roots and returns its canonical physical path.
//
// With no allowed roots configured it returns "" and no error: path checking
// is off and the caller applies upstream behavior (which resolves an omitted
// cwd to the server process's working directory, and a relative one against
// it; both are exactly what restricted mode exists to prevent).
//
// With roots configured, everything fails closed:
//
//   - an empty cwd resolves to DefaultCwd when one is configured and is
//     refused otherwise, so a request can never land in the server's own
//     working directory by omission;
//   - a relative cwd is refused outright, because it would be resolved
//     against the server process's working directory, a directory the caller
//     cannot see and did not name;
//   - the raw path is resolved with EvalSymlinks BEFORE any lexical cleanup
//     (see resolveExistingDir), so "<allowed>/link-to-etc" and
//     "<allowed>/link-to-etc/.." are judged from the link's target and
//     refused;
//   - the resolved path must be inside at least one root, compared with
//     filepath.Rel so a sibling named "<root>-evil" cannot pass on a shared
//     string prefix.
//
// Under the protected profile the caller-visible paths are worker-view paths
// (/workspace/...) and the host has no such mount, so the raw path is first
// mapped onto the manifest's snapshot root (see mapWorkerPath) and the
// containment root is that snapshot root. The value written back is the
// worker-view path, so meta.json, the request key and agy's --add-dir all
// carry the neutral spelling rather than a host path.
func (p Policy) CheckDir(raw string) (string, error) {
	if len(p.AllowedRoots) == 0 {
		return "", nil
	}
	if raw == "" {
		if p.DefaultCwd != "" {
			return p.DefaultCwd, nil
		}
		return "", fmt.Errorf("cwd is required: no default working directory is configured on this server")
	}
	if p.Protected() {
		return p.checkWorkerPath(raw)
	}
	resolved, err := resolveExistingDir(raw)
	if err != nil {
		return "", fmt.Errorf("resolve cwd %q: %w", raw, err)
	}
	if !p.contained(resolved) {
		return "", fmt.Errorf("cwd %q resolves to %s, outside the directories this server allows", raw, resolved)
	}
	return resolved, nil
}

// workerView reports whether this policy maps caller-visible paths onto the
// host snapshot. It is true only for a protected policy whose manifest
// supplied a snapshot root; the check is defensive, because
// ValidateAndNormalize already refuses a protected policy without one.
func (p Policy) workerView() bool {
	return p.Protected() && p.SnapshotRoot != ""
}

// checkWorkerPath validates one worker-view path (/workspace/...) and returns
// the worker-view path to persist.
//
// The mapping is the security-relevant part: filepath.Join and filepath.Clean
// fold ".." lexically, so mapping with Join would collapse
// "/workspace/link-to-etc/.." into the snapshot root before any symlink was
// resolved, which is precisely the escape the symlink-first rule exists to
// catch. joinAsWritten concatenates without cleaning, so the kernel resolves
// ".." from the link's target and EvalSymlinks sees the real path.
func (p Policy) checkWorkerPath(raw string) (string, error) {
	host, ok := p.mapWorkerPath(raw)
	if !ok {
		return "", fmt.Errorf("cwd %q is not inside the worker mount %s", raw, p.WorkerMount)
	}
	resolved, err := resolveExistingDir(host)
	if err != nil {
		return "", fmt.Errorf("resolve cwd %q: %w", raw, err)
	}
	if !p.containedInSnapshot(resolved) {
		return "", fmt.Errorf("cwd %q resolves outside the project snapshot this server serves", raw)
	}
	return p.workerViewPath(resolved)
}

// mapWorkerPath maps a worker-view path onto the host path it names. It
// returns false for anything that is not the mount itself or a path segment
// under it, so an adjacent prefix like "/workspace-evil" is refused rather
// than treated as a subdirectory.
func (p Policy) mapWorkerPath(raw string) (string, bool) {
	mount := p.WorkerMount
	if mount == "" {
		mount = WorkerMountPath
	}
	if raw == mount {
		return p.SnapshotRoot, true
	}
	if !strings.HasPrefix(raw, mount+"/") {
		return "", false
	}
	return joinAsWritten(p.SnapshotRoot, raw[len(mount):]), true
}

// containedInSnapshot reports whether a host path lies under the snapshot
// root. filepath.Rel is what makes a sibling named "<root>-evil" fail.
func (p Policy) containedInSnapshot(abs string) bool {
	rel, err := filepath.Rel(p.SnapshotRoot, abs)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return !filepath.IsAbs(rel)
}

// workerViewPath maps a host path back into the worker view. It is the
// inverse of mapWorkerPath, applied to an already-resolved (symlink-free,
// ".."-free) host path, so filepath.Join is safe here: the input cannot
// smuggle a traversal past it.
func (p Policy) workerViewPath(host string) (string, error) {
	rel, err := filepath.Rel(p.SnapshotRoot, host)
	if err != nil {
		return "", err
	}
	if rel == "." {
		return p.WorkerMount, nil
	}
	return filepath.Join(p.WorkerMount, rel), nil
}

// contained reports whether abs is one of the allowed roots or lies under
// one. filepath.Rel gives the containment answer a string prefix cannot: the
// root "/srv/workspaces/pi" must not swallow "/srv/workspaces/pi-evil", and
// "../sibling" must be rejected outright.
func (p Policy) contained(abs string) bool {
	for _, root := range p.AllowedRoots {
		rel, err := filepath.Rel(root, abs)
		if err != nil {
			continue
		}
		if rel == "." {
			return true
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		if filepath.IsAbs(rel) {
			continue
		}
		return true
	}
	return false
}

// CheckExtraDirs validates the caller's dirs against the allowed roots and
// returns their canonical physical paths, in order.
//
// With no allowed roots configured the input is returned unchanged (upstream
// behavior). With roots configured, an empty entry is refused (an empty dir
// names nothing, so under a restricted policy it can only be an attempt to
// smuggle an omission past the check), a rooted-but-not-absolute entry is
// refused (it resolves against a drive root the server does not model), and
// a relative entry is joined against the already-checked cwd as written, so
// ".." is resolved by the filesystem and cannot be folded past a symlink.
// Every entry must resolve to a directory inside the roots.
//
// Under the protected profile the same worker-view mapping applies as in
// CheckDir: an absolute entry is a /workspace/... path, a relative one is
// joined to the (worker-view) cwd as written, and the values written back are
// worker-view paths.
func (p Policy) CheckExtraDirs(cwd string, dirs []string) ([]string, error) {
	if len(p.AllowedRoots) == 0 {
		return dirs, nil
	}
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if d == "" {
			return nil, fmt.Errorf("dirs must not contain an empty entry")
		}
		if rootRelative(d) {
			return nil, fmt.Errorf("dirs entry %q is neither absolute nor relative to cwd", d)
		}
		raw := d
		if !filepath.IsAbs(d) {
			if cwd == "" {
				return nil, fmt.Errorf("dirs entry %q is relative but no cwd was accepted", d)
			}
			raw = joinAsWritten(cwd, d)
		}
		if p.workerView() {
			resolved, err := p.checkWorkerPath(raw)
			if err != nil {
				return nil, fmt.Errorf("dirs entry %q: %w", d, err)
			}
			out = append(out, resolved)
			continue
		}
		resolved, err := resolveExistingDir(raw)
		if err != nil {
			return nil, fmt.Errorf("resolve dirs entry %q: %w", d, err)
		}
		if !p.contained(resolved) {
			return nil, fmt.Errorf("dirs entry %q resolves to %s, outside the directories this server allows", d, resolved)
		}
		out = append(out, resolved)
	}
	return out, nil
}

// CheckJSONSchema validates a caller-supplied json_schema and returns the
// value to hand to agy.
//
// It is a no-op unless InlineJSONSchemaOnly is set. Under that mode the value
// must be an inline JSON object: MEASURED against agy 1.5.17, agy treats a
// --json-schema value that is not parseable JSON as a file path and dies
// reading it, and an arbitrary path therefore reads an arbitrary host file
// and leaks its content shape through the parse error. Refusing everything
// that is not an inline object closes that hole without claiming anything
// about what a schema may reference at run time. Whitespace around the object
// is trimmed and the trimmed form is returned, so the caller's value and the
// persisted request agree byte for byte.
//
// DisableJSONSchema (the protected profile) refuses every non-empty value
// before the inline check ever runs, including a valid inline object: a
// protected deployment does not need schemas, and the stricter reading keeps
// the two modes from being confused for one another.
func (p Policy) CheckJSONSchema(raw string) (string, error) {
	if raw == "" {
		return raw, nil
	}
	if p.DisableJSONSchema {
		return "", fmt.Errorf("json_schema is not accepted by this server; describe the expected output shape in the prompt instead")
	}
	if !p.InlineJSONSchemaOnly {
		return raw, nil
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("json_schema is empty after trimming whitespace")
	}
	if len(trimmed) > MaxInlineJSONSchemaBytes {
		return "", fmt.Errorf("json_schema is %d bytes, over the %d byte inline limit", len(trimmed), MaxInlineJSONSchemaBytes)
	}
	if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
		return "", fmt.Errorf("json_schema must be an inline JSON object starting with { and ending with }; this server does not accept schema file paths")
	}
	if !json.Valid([]byte(trimmed)) {
		return "", fmt.Errorf("json_schema is not valid JSON")
	}
	return trimmed, nil
}

// CheckRunOptions validates the caller's model, agent and timeout against
// the policy. It runs after the manager has resolved its own defaults (the
// default model fallback and the default timeout), so an empty model here
// means neither the caller nor the server configuration named one, and a
// zero timeout is impossible.
func (p Policy) CheckRunOptions(model, agent string, timeout time.Duration) error {
	if len(p.AllowedModels) > 0 && !slices.Contains(p.AllowedModels, model) {
		if model == "" {
			return fmt.Errorf("no model was resolved for this run and this server only allows %s; pass a model from the whitelist", strings.Join(p.AllowedModels, ", "))
		}
		return fmt.Errorf("model %q is not allowed by this server; pass a model from the whitelist", model)
	}
	if agent != "" {
		if p.DisableAgentSelection {
			return fmt.Errorf("agent selection is disabled on this server; omit agent")
		}
		if len(p.AllowedAgents) > 0 && !slices.Contains(p.AllowedAgents, agent) {
			return fmt.Errorf("agent %q is not allowed by this server; pass an agent from the whitelist", agent)
		}
	}
	if p.MaxTimeout > 0 && timeout > p.MaxTimeout {
		return fmt.Errorf("timeout %s exceeds this server's maximum of %s", timeout, p.MaxTimeout)
	}
	return nil
}

// FilterValues returns the entries of values whose key (as returned by key)
// is in allowed, preserving order. An empty allowed list returns the input
// unchanged: no whitelist configured means nothing to filter. List results
// (models, agents) route through it so the listing a caller sees can never
// advertise a value CheckRunOptions would refuse.
func FilterValues[T any](allowed []string, values []T, key func(T) string) []T {
	if len(allowed) == 0 {
		return values
	}
	filtered := make([]T, 0, len(values))
	for _, v := range values {
		if slices.Contains(allowed, key(v)) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

// joinAsWritten appends d to cwd with one separator and no cleaning, so ".."
// is left for the OS to resolve against the symlink target. A cwd that
// already ends in a separator (a filesystem root) gets none added, which
// would give "//dir". cwd must be non-empty. It mirrors the same-named helper
// in internal/manager: both exist so a joined path is evaluated exactly as
// written before anything canonicalizes it.
func joinAsWritten(cwd, d string) string {
	if os.IsPathSeparator(cwd[len(cwd)-1]) {
		return cwd + d
	}
	return cwd + string(filepath.Separator) + d
}

// rootRelative reports whether d is neither absolute nor relative to cwd: a
// rooted path without a volume ("\x") or one with a volume but no root
// ("C:repo"). These are Windows-only shapes; agy would resolve them against
// a drive root or a drive's current directory, which is not a path this
// server can bound, so they are refused rather than guessed at. On POSIX it
// is always false. d must be non-empty.
func rootRelative(d string) bool {
	return !filepath.IsAbs(d) && (filepath.VolumeName(d) != "" || os.IsPathSeparator(d[0]))
}
