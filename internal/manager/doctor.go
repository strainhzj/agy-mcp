package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tphakala/agy-mcp/v2/internal/agyver"
	"github.com/tphakala/agy-mcp/v2/internal/config"
	"github.com/tphakala/agy-mcp/v2/internal/jobstore"
	"github.com/tphakala/agy-mcp/v2/internal/policy"
)

// Check names, shared by each check and its tests (see doctor_test.go, which
// looks checks up by these constants) so the two cannot drift, and a name is
// written once rather than at every CheckResult it appears in. All carry the
// Name suffix so none collides with the like-named check method.
const (
	checkAgyBinaryName    = "agy binary"
	checkAgyVersionName   = "agy version"
	checkAgyReachableName = "agy reachable (auth)"
	checkStateDirName     = "state dir"
	checkConfigName       = "config"
	checkPolicyName       = "policy"
	checkJobsName         = "jobs"
	checkADCEnvName       = "ADC sign-in env"
)

// agy's own environment variables, read here only to spot setups that will not
// behave as intended; they are not agy-mcp configuration, so they do not belong
// in internal/config.
const (
	envADCAuth = "AGY_ADC_AUTH"
	envUseADC  = "USE_ADC"
)

// adcLoadFixVersion is the first agy release that loads skills, rules, custom
// agents, plugins, plugin MCP servers and hooks under ADC sign-in (agy's
// changelog, 1.4.7; see the release note in internal/agyver).
var adcLoadFixVersion = agyver.Version{Major: 1, Minor: 4, Patch: 7}

// CheckStatus is a preflight check's verdict. Only CheckFail makes the doctor
// command exit non-zero; CheckWarn reports something worth seeing (an ADC
// environment caveat, or stale jobs from a prior crash) without calling the
// install broken, so a fresh install with leftover state is not treated as a
// failure.
type CheckStatus int

const (
	CheckPass CheckStatus = iota
	CheckWarn
	CheckFail
)

// String renders the status as the fixed-width label the report prints.
func (s CheckStatus) String() string {
	switch s {
	case CheckPass:
		return "PASS"
	case CheckWarn:
		return "WARN"
	case CheckFail:
		return "FAIL"
	default:
		return "????"
	}
}

// CheckResult is one preflight check's outcome. Detail is a human-readable line
// (or lines) explaining the verdict and must never carry a secret value: the
// config check names where a setting came from, not what it is, so a token is
// reported as set/unset and never printed.
type CheckResult struct {
	Name   string
	Status CheckStatus
	Detail string
}

// DoctorReport is the full set of preflight checks, in the order they ran.
type DoctorReport struct {
	Checks []CheckResult
}

// OK reports whether the install is healthy: no check failed. A warning does not
// count as a failure, so the exit code a caller derives from this does not change
// when a check only warns.
func (r DoctorReport) OK() bool {
	for _, c := range r.Checks {
		if c.Status == CheckFail {
			return false
		}
	}
	return true
}

// Doctor runs the read-only preflight checks a run depends on and returns their
// results. It never mutates job state or starts a job: the one write it makes is
// a probe file in the state dir (removed immediately) to prove the dir is
// writable, which is the only way to actually verify that rather than guess from
// the mode bits.
//
// Every check runs regardless of earlier ones, so a report names every problem at
// once rather than stopping at the first: an operator fixing an install wants the
// whole list, not one error per re-run.
func (m *Manager) Doctor(ctx context.Context) DoctorReport {
	// Hoisted so the version check's parsed version can feed checkADCEnv. Both run
	// before checkAgyReachable, binary first.
	bin := m.checkAgyBinary()
	ver, agyV, agyVOK := m.checkAgyVersion(ctx)
	return DoctorReport{Checks: []CheckResult{
		bin,
		ver,
		m.checkAgyReachable(ctx),
		checkADCEnv(os.Getenv, agyV, agyVOK),
		m.checkStateDir(),
		m.checkConfigSources(),
		m.checkPolicy(),
		m.checkStaleJobs(),
	}}
}

// checkAgyBinary resolves the agy binary the same way every run does, so a PATH
// miss or a relative-only entry is reported here with the same guidance a job
// would get.
func (m *Manager) checkAgyBinary() CheckResult {
	agy, err := m.cfg.AgyBinary()
	if err != nil {
		return CheckResult{checkAgyBinaryName, CheckFail, err.Error()}
	}
	return CheckResult{checkAgyBinaryName, CheckPass, "found at " + agy}
}

// checkAgyVersion probes the version through the manager's own readAgyVersion
// seam (WaitDelay'd and ctx-checked) and compares it against the tracked floor,
// reusing agyver rather than duplicating the comparison. It reports the version
// it found so an operator sees how far off an outdated binary is, not just that
// it is outdated.
//
// On success it primes the version cache (markAgyVerified): this ran the same
// read+parse+floor check agyBinaryChecked would, so the checkAgyReachable that
// follows in the same Doctor run reuses the verdict instead of spawning a second
// `agy --version`. It primes only on the PASS branch, so a binary below the floor
// is never marked verified and checkAgyReachable re-probes and fails the same way.
//
// It also returns the parsed version, and true, only on PASS, so a
// version-dependent check never acts on a below-floor or unparsed version.
func (m *Manager) checkAgyVersion(ctx context.Context) (CheckResult, agyver.Version, bool) {
	agy, err := m.cfg.AgyBinary()
	if err != nil {
		return CheckResult{checkAgyVersionName, CheckFail, "cannot check: agy binary not resolved"}, agyver.Version{}, false
	}
	ctx, cancel := context.WithTimeout(ctx, versionCheckTimeout)
	defer cancel()
	raw, err := m.readAgyVersion(ctx, agy)
	if err != nil {
		return CheckResult{checkAgyVersionName, CheckFail, err.Error()}, agyver.Version{}, false
	}
	v, err := agyver.Parse(raw)
	if err != nil {
		return CheckResult{checkAgyVersionName, CheckFail, fmt.Sprintf("cannot parse version from %s: %v", versionOutputForMessage(raw), err)}, agyver.Version{}, false
	}
	if !v.AtLeast(agyver.Required) {
		return CheckResult{checkAgyVersionName, CheckFail, fmt.Sprintf("%s is below the required %s; upgrade agy", v, agyver.Required)}, agyver.Version{}, false
	}
	m.markAgyVerified(agy)
	return CheckResult{checkAgyVersionName, CheckPass, fmt.Sprintf("%s (>= required %s)", v, agyver.Required)}, v, true
}

// adcAuthOn reports whether AGY_ADC_AUTH selects ADC sign-in. MEASURED against
// agy 1.4.8: AGY_ADC_AUTH=1 and =true switch ADC sign-in on; =0, an empty value
// and =no leave it off. Other spellings are NOT MEASURED, so doctor treats them
// as off and never warns about 1.4.7 for them (issue #224).
func adcAuthOn(v string) bool {
	return v == "1" || v == "true"
}

// checkADCEnv flags two environment mistakes around ADC sign-in. It never
// FAILs, because the environment doctor sees may not be the server's, so it
// cannot change the exit code, and its detail names variables and versions,
// never a value. The version is used only when versionKnown, i.e.
// checkAgyVersion passed; with an unknown version the 1.4.7 caveat is not
// checked.
func checkADCEnv(getenv func(string) string, v agyver.Version, versionKnown bool) CheckResult {
	on := adcAuthOn(getenv(envADCAuth))
	switch {
	case !on && getenv(envUseADC) != "":
		// agy does not read USE_ADC (MEASURED against agy 1.4.8); a value here is a
		// leftover from README advice before issue #223.
		return CheckResult{checkADCEnvName, CheckWarn, envUseADC + " is set in this environment, but agy does not read it (MEASURED against agy 1.4.8); " +
			"ADC sign-in is selected with " + envADCAuth + "=1, which is not set to 1 or true here (see the auth note in the README)"}
	case !on:
		return CheckResult{checkADCEnvName, CheckPass, envADCAuth + " is not set to 1 or true in this environment (agy's normal sign-in)"}
	case !versionKnown:
		return CheckResult{checkADCEnvName, CheckPass, envADCAuth + " is set in this environment; the agy version is unknown (see the agy version check), so the " +
			adcLoadFixVersion.String() + " ADC fix was not checked"}
	case !v.AtLeast(adcLoadFixVersion):
		return CheckResult{checkADCEnvName, CheckWarn, fmt.Sprintf("%s is set in this environment and agy is %s; agy %s fixed skills, rules, custom agents, plugins and hooks not loading under ADC sign-in, "+
			"so project rules and the agent parameter may not take effect; upgrade agy (see the auth note in the README)", envADCAuth, v, adcLoadFixVersion)}
	default:
		return CheckResult{checkADCEnvName, CheckPass, fmt.Sprintf("%s is set in this environment; agy %s includes the %s ADC fix", envADCAuth, v, adcLoadFixVersion)}
	}
}

// checkAgyReachable lists models, which is the cheapest call that requires a
// working, authenticated agy: it execs the real binary and fails if agy is
// missing, too old, or not logged in, so it doubles as the auth and reachability
// check. The error agy prints (an auth prompt, say) is surfaced in the detail.
func (m *Manager) checkAgyReachable(ctx context.Context) CheckResult {
	models, err := m.ListModels(ctx)
	if err != nil {
		return CheckResult{checkAgyReachableName, CheckFail, err.Error()}
	}
	// ListModels already applied the whitelist, so an empty listing under a
	// configured whitelist means agy's catalog and the whitelist do not
	// intersect: every run naming a model would be refused, and so would every
	// run omitting one (CheckRunOptions refuses an empty model against a
	// whitelist). That is a warning, not a failure: agy itself is reachable,
	// and the operator may be mid-rename.
	if len(models) == 0 && len(m.cfg.Policy.AllowedModels) > 0 {
		return CheckResult{checkAgyReachableName, CheckWarn, fmt.Sprintf("model listing reachable, but the %s whitelist matched none of agy's models; every run would be refused until the whitelist names a model agy lists", config.EnvAllowedModels)}
	}
	return CheckResult{checkAgyReachableName, CheckPass, fmt.Sprintf("model listing reachable (%d model(s))", len(models))}
}

// checkStateDir verifies the job-store root is usable. An existing dir is proven
// writable by a probe file that is removed at once; a not-yet-created dir (a fresh
// install that has run no job) is healthy as long as the nearest existing
// ancestor is a writable directory, since the server creates the state dir on
// first use. Only a state dir that exists but cannot be written, or whose parent
// cannot be created into, is a failure.
func (m *Manager) checkStateDir() CheckResult {
	dir := m.cfg.StateDir
	if dir == "" {
		return CheckResult{checkStateDirName, CheckFail, "no state directory configured"}
	}
	info, err := os.Stat(dir)
	switch {
	case err == nil && info.IsDir():
		if perr := probeWritable(dir); perr != nil {
			return CheckResult{checkStateDirName, CheckFail, fmt.Sprintf("%s exists but is not writable: %v", dir, perr)}
		}
		return CheckResult{checkStateDirName, CheckPass, "writable at " + dir}
	case err == nil:
		return CheckResult{checkStateDirName, CheckFail, dir + " exists but is not a directory"}
	case os.IsNotExist(err):
		// Fresh install: the dir will be created on first use. Confirm the nearest
		// existing ancestor is a writable directory so that creation will succeed.
		anc, aerr := nearestExistingDir(dir)
		if aerr != nil {
			return CheckResult{checkStateDirName, CheckFail, fmt.Sprintf("cannot resolve a parent of %s: %v", dir, aerr)}
		}
		if perr := probeWritable(anc); perr != nil {
			return CheckResult{checkStateDirName, CheckFail, fmt.Sprintf("%s does not exist and its parent %s is not writable: %v", dir, anc, perr)}
		}
		return CheckResult{checkStateDirName, CheckPass, dir + " will be created on first run (parent writable)"}
	default:
		return CheckResult{checkStateDirName, CheckFail, fmt.Sprintf("cannot stat %s: %v", dir, err)}
	}
}

// probeWritable proves a directory is writable by creating and removing a uniquely
// named file in it. Statting the mode bits is not enough: a dir can be mode 0755
// and still unwritable to this user, and a read-only mount reports writable bits.
func probeWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".agy-mcp-doctor-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

// nearestExistingDir walks up from a non-existent path to the first ancestor that
// exists, returning an error if it is not a directory. It stops at the filesystem
// root, which always exists.
func nearestExistingDir(dir string) (string, error) {
	for {
		parent := filepath.Dir(dir)
		info, err := os.Stat(parent)
		if err == nil {
			if !info.IsDir() {
				return "", fmt.Errorf("%s is not a directory", parent)
			}
			return parent, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		if parent == dir {
			// filepath.Dir is idempotent at the root; guard against an infinite loop.
			return "", fmt.Errorf("reached filesystem root without finding an existing ancestor of %s", dir)
		}
		dir = parent
	}
}

// checkConfigSources names where each effective setting came from (an env var or
// the built-in default) without printing any secret value. The HTTP token in
// particular is reported as set or unset only, never echoed.
func (m *Manager) checkConfigSources() CheckResult {
	var b strings.Builder
	line := func(setting, source, value string) {
		fmt.Fprintf(&b, "\n    %-16s %s", setting+":", source)
		if value != "" {
			fmt.Fprintf(&b, " (%s)", value)
		}
	}
	// The AGY_MCP_* labels come from config's exported constants, the same
	// identifiers config reads each setting from, so a rename cannot leave doctor
	// naming a variable config no longer honours.
	//
	// agy path: an explicit override vs a PATH lookup.
	if p := os.Getenv(config.EnvAgyPath); p != "" {
		line("agy path", config.EnvAgyPath, m.cfg.AgyPath)
	} else {
		line("agy path", "PATH lookup", m.cfg.AgyPath)
	}
	// default model: env override vs agy's own default (an empty DefaultModel).
	if os.Getenv(config.EnvDefaultModel) != "" {
		line("default model", config.EnvDefaultModel, m.cfg.DefaultModel)
	} else {
		line("default model", "agy default (unset)", "")
	}
	// state dir: env override vs the XDG fallback.
	if os.Getenv(config.EnvStateDir) != "" {
		line("state dir", config.EnvStateDir, m.cfg.StateDir)
	} else {
		line("state dir", "XDG default", m.cfg.StateDir)
	}
	// HTTP token: reported as set/unset only, never the value.
	if m.cfg.HTTPToken != "" {
		line("http token", config.EnvHTTPToken, "set")
	} else {
		line("http token", "unset (HTTP mode unauthenticated)", "")
	}
	// Policy-facing settings with their source. Values here are not secrets
	// (paths, durations, counts, profile names); the token above stays the one
	// set/unset line.
	line("profile", config.EnvProfile, orUnset(m.cfg.Policy.Profile))
	if v := os.Getenv(config.EnvMaxConcurrency); v != "" {
		line("concurrency", config.EnvMaxConcurrency, strconv.Itoa(m.cfg.MaxConcurrency))
	} else {
		line("concurrency", "default", strconv.Itoa(m.cfg.MaxConcurrency))
	}
	if v := os.Getenv(config.EnvMaxTimeout); v != "" {
		line("max timeout", config.EnvMaxTimeout, m.cfg.Policy.MaxTimeout.String())
	} else {
		line("max timeout", "upstream ceiling (24h)", "")
	}
	// The resolved default a request without a timeout gets, whatever produced
	// it (upstream default or the policy downshift); the doctor acceptance
	// names this value explicitly.
	line("default timeout", "resolved", fmt.Sprintf("%s (%s)", m.cfg.DefaultTimeout, m.waitCapSource()))
	line("sync wait cap", config.EnvSyncWaitCap, syncWaitCapSource())
	line("session policy", config.EnvSessionPolicy, string(m.cfg.Policy.SessionPolicy))
	if len(m.cfg.Policy.AllowedRoots) > 0 {
		line("allowed roots", config.EnvAllowedRoots, strings.Join(m.cfg.Policy.AllowedRoots, string(filepath.ListSeparator)))
	} else {
		line("allowed roots", "unset (no path checks)", "")
	}
	if m.cfg.Policy.DefaultCwd != "" {
		line("default cwd", config.EnvDefaultCwd, m.cfg.Policy.DefaultCwd)
	}
	if m.cfg.InstanceID != "" || m.cfg.ProjectID != "" {
		line("identity", config.EnvProjectID+"/"+config.EnvInstanceID, m.cfg.ProjectID+"/"+m.cfg.InstanceID)
	}
	return CheckResult{checkConfigName, CheckPass, strings.TrimPrefix(b.String(), "\n")}
}

// orUnset renders an optional string setting's value or a marker for unset.
func orUnset(v string) string {
	if v == "" {
		return "unset (upstream behavior)"
	}
	return v
}

// syncWaitCapSource names how the inline-wait ceiling resolved: the variable,
// or the built-in default when the variable is unset or unparseable. The
// value itself is not secret, so it is shown.
func syncWaitCapSource() string {
	if v := os.Getenv(config.EnvSyncWaitCap); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return config.EnvSyncWaitCap + "=" + v
		}
		return "unset (unparseable value ignored), default " + config.DefaultSyncWaitCap.String()
	}
	return "unset, default " + config.DefaultSyncWaitCap.String()
}

// waitCapSource names what produced the effective default timeout: the policy
// downshift when MaxTimeout is set below the upstream default, or the upstream
// default. It is a one-line explanation, not a re-derivation: the resolved
// value is printed alongside it.
func (m *Manager) waitCapSource() string {
	if mt := m.cfg.Policy.MaxTimeout; mt > 0 && mt < 30*time.Minute {
		return "lowered to MaxTimeout"
	}
	return "upstream default"
}

// checkStaleJobs reports jobs the store still holds whose supervisor process is
// gone and that never recorded an exit code: orphans a prior crash left behind,
// which the periodic GC reaps on its own schedule but which are exactly what
// someone debugging odd behaviour wants to see now. It is a warning, not a
// failure: a healthy server GCs these in time, and a fresh install has none.
//
// It is strictly read-only, unlike GarbageCollect: it lists and inspects, and
// removes nothing.
//
// The staleness predicate here is deliberately simpler than gcEvaluate's, and the
// difference is intentional because this only REPORTS. gcEvaluate re-reads the
// exit code once after finding the supervisor dead (a race guard against a job
// that finished between the two reads) and separates a transient meta read error
// from a genuinely missing meta, because it is deciding whether to DELETE. A
// read-only WARN pays for neither: at worst it names a job that just finished, or
// a dir it momentarily could not read, and an operator eyeballing the list loses
// nothing by seeing it. Do not converge the two into a shared predicate on the
// strength of this: gcEvaluate's extra care exists for the deletion it drives.
func (m *Manager) checkStaleJobs() CheckResult {
	ids, err := m.store.List()
	if err != nil {
		// A List() error is not a stale-jobs warning: the store root is unreadable
		// (permissions, IO), the same condition startup RestoreAndCollect and
		// RestoreGate fail closed on, so the server itself would refuse to start.
		// Fail the check so doctor exits non-zero rather than reporting a healthy
		// exit 0 for an unusable state directory. A missing jobs dir is NOT this
		// case: Store.List returns an empty list and no error for a fresh install.
		return CheckResult{checkJobsName, CheckFail, "cannot list job store (state dir unreadable): " + err.Error()}
	}
	var stale []string
	for _, id := range ids {
		meta, err := m.store.Load(id)
		if err != nil {
			// A dir with no readable meta.json is itself an orphan (a crash between
			// mkdir and the first meta write); count it as stale by id.
			stale = append(stale, id)
			continue
		}
		if _, done := m.store.ExitCode(id); done {
			continue // finished cleanly; not stale
		}
		if m.processAlive(meta) {
			continue // still running under a live supervisor
		}
		stale = append(stale, id)
	}
	if len(stale) == 0 {
		return CheckResult{checkJobsName, CheckPass, fmt.Sprintf("no stale jobs (%d total in store)", len(ids))}
	}
	slices.Sort(stale)
	return CheckResult{checkJobsName, CheckWarn, fmt.Sprintf("%d stale job(s) from a prior crash (GC reaps them): %s", len(stale), strings.Join(stale, ", "))}
}

// checkPolicy reports the deployment policy's own health, distinct from the
// config check (which names where each setting came from) and from any OS
// isolation the deployment provides (which no check here can see).
//
// Unconfigured, it passes with "unrestricted (default)", so an upstream
// install gets the same doctor output and exit code as before this check
// existed. Configured, it re-validates what ValidateAndNormalize checked at
// startup (a root directory can be deleted or replaced after boot) and, for a
// protected profile, re-checks the profile's fixed requirements and scans the
// state dir for jobs this instance does not own: the same refusal startup
// applies, reported here so `doctor` explains a start that is about to fail.
//
// Every restricted verdict carries the standing reminder that parameter
// checks are not a filesystem boundary: agy's built-in tools, its workspace
// hooks, and even --sandbox (MEASURED against agy 1.5.17) can reach outside
// cwd, so isolation comes from the deployment's OS layer, never from this
// check passing.
func (m *Manager) checkPolicy() CheckResult {
	p := m.cfg.Policy
	if !p.Restricted() && p.Profile == "" && !p.RequireHTTPToken && p.SessionsAllowed() &&
		!p.ForceSandbox && !p.DisableSkipPermissions && !p.DisableContinueLatest &&
		p.MaxTimeout == 0 && len(p.AllowedModels) == 0 && len(p.AllowedAgents) == 0 {
		return CheckResult{checkPolicyName, CheckPass, "unrestricted (default)"}
	}
	// Re-validate a copy: ValidateAndNormalize rewrites path fields to
	// canonical form, and doctor must not mutate the live config. A failure
	// here mirrors what startup already refused (or will refuse on the next
	// boot), which is exactly what an operator debugging a refusal needs.
	recheck := p
	var b strings.Builder
	if err := recheck.ValidateAndNormalize(); err != nil {
		return CheckResult{checkPolicyName, CheckFail, err.Error()}
	}
	say := func(format string, args ...any) {
		fmt.Fprintf(&b, "\n    "+format, args...)
	}
	verdict := CheckPass
	if recheck.Restricted() {
		say("path checks on: %d allowed root(s), cwd and dirs must resolve inside them", len(recheck.AllowedRoots))
		for _, root := range recheck.AllowedRoots {
			say("root %s", root)
		}
	}
	if recheck.DefaultCwd != "" {
		say("default cwd %s", recheck.DefaultCwd)
	}
	say("session policy %s", recheck.SessionPolicy)
	if recheck.DisableContinueLatest {
		say("continue_latest disabled")
	}
	if recheck.Protected() {
		say("profile %s: json_schema refused, HTTP bearer token required, stdio refused", policy.ProfilePi)
		if m.cfg.InstanceID == "" || m.cfg.ProjectID == "" {
			verdict = CheckFail
			say("FAIL: the profile requires %s and %s; identity is empty", config.EnvProjectID, config.EnvInstanceID)
		}
		// The state dir must be attributable to this instance: any job whose
		// ownership record is missing or names another project or instance
		// means the directory is shared or reused, the same condition startup
		// (RestoreAndCollect) refuses on. Ids are named: doctor is the
		// operator's tool on the host, not a caller-facing surface.
		ids, err := m.store.List()
		if err != nil {
			verdict = CheckFail
			say("FAIL: cannot list the state dir to check job ownership: %v", err)
		} else {
			var foreign []string
			for _, id := range ids {
				dir, derr := m.store.Dir(id)
				if derr != nil {
					foreign = append(foreign, id)
					continue
				}
				rec, rerr := readOwnershipRecord(dir)
				if rerr != nil || rec.InstanceID != m.cfg.InstanceID || rec.ProjectID != m.cfg.ProjectID {
					foreign = append(foreign, id)
				}
			}
			if len(foreign) > 0 {
				verdict = CheckFail
				say("FAIL: %d job(s) in the state dir lack a matching ownership record (%s); the dir is shared or was reused, and startup will refuse it", len(foreign), strings.Join(foreign, ", "))
			}
		}
	}
	// The standing reminder, on every restricted verdict. It is the one claim
	// in this report the code cannot verify, so it is stated as what it is: a
	// boundary this check does not provide.
	say("note: parameter checks and --sandbox are not a filesystem boundary; agy's built-in tools and workspace hooks reach outside cwd (MEASURED against agy 1.5.17), so isolation is the deployment's OS layer, verified there, not here")
	return CheckResult{checkPolicyName, verdict, strings.TrimPrefix(b.String(), "\n")}
}

// readOwnershipRecord reads one job dir's ownership record for doctor's scan.
// It is doctor-side (diagnostic, operator-facing) and deliberately separate
// from ownershipRefused, whose contract is to say nothing about WHY a job was
// refused.
func readOwnershipRecord(dir string) (jobOwnership, error) {
	b, err := os.ReadFile(jobstore.OwnershipPath(dir))
	if err != nil {
		return jobOwnership{}, err
	}
	var rec jobOwnership
	if err := json.Unmarshal(b, &rec); err != nil {
		return jobOwnership{}, err
	}
	return rec, nil
}
