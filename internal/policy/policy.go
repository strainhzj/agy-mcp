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
	roots := make([]string, 0, len(p.AllowedRoots))
	for _, root := range p.AllowedRoots {
		resolved, err := resolveExistingDir(root)
		if err != nil {
			return fmt.Errorf("allowed root %q: %w", root, err)
		}
		roots = append(roots, resolved)
	}
	p.AllowedRoots = roots
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
	return nil
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
	resolved, err := resolveExistingDir(raw)
	if err != nil {
		return "", fmt.Errorf("resolve cwd %q: %w", raw, err)
	}
	if !p.contained(resolved) {
		return "", fmt.Errorf("cwd %q resolves to %s, outside the directories this server allows", raw, resolved)
	}
	return resolved, nil
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
// persisted request agree byte for byte. A protected profile refuses
// json_schema entirely upstream of this check.
func (p Policy) CheckJSONSchema(raw string) (string, error) {
	if raw == "" || !p.InlineJSONSchemaOnly {
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
