package mcptools

import (
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tphakala/agy-mcp/v2/internal/config"
	"github.com/tphakala/agy-mcp/v2/internal/manager"
	"github.com/tphakala/agy-mcp/v2/internal/policy"
)

// The built-in inline-wait ceiling for agy_run_sync and agy_wait now lives in
// config (DefaultSyncWaitCap, resolved by config.ResolveSyncWaitCap so the
// doctor reports the same value without an import cycle). It sits well below
// the ~120s per-call timeout common MCP clients (Claude Code among them)
// impose on a single tool call. Staying under that ceiling is what lets
// agy-mcp's own graceful still-running result reach the caller before the
// client abandons the call: that result carries the job_id needed to reconcile
// the run with agy_wait or agy_status, whereas the client's synthesized "timed
// out" failure discards agy-mcp's response and the job_id with it, orphaning a
// job that is still running under its detached supervisor. The measured client
// cap is not perfectly deterministic (in one session a call was abandoned at
// ~120s while another returned at ~157s), and progress notifications do not
// extend it, so the ceiling keeps a wide margin rather than sitting at the
// edge. See issue #178 for the characterization.

// maxSyncWait resolves the effective inline-wait ceiling: AGY_MCP_SYNC_WAIT_CAP
// when it parses as a positive Go duration, otherwise the built-in default
// (config.DefaultSyncWaitCap). The resolution lives in internal/config so the
// doctor can report the same value without an import cycle; this wrapper is
// both the clamp for a caller-supplied wait and the default when the caller
// names none (parseWait), so agy_run_sync and agy_wait cannot drift on either.
// Longer runs are for agy_run + agy_wait/agy_status, re-issued until the job
// is terminal.
//
// The reader takes the manager's resolved value when there is one, because
// config.Resolve refuses a missing or unparseable value under the pi profile:
// reading the environment directly here would silently fall back to the 90s
// default for exactly the deployment that must state its client-timeout
// budget, which is the failure mode the strict resolution exists to prevent.
//
// A zero resolved value means "not resolved" (a hand-built Config, or the
// nil-manager shape the tool-list tests use), and falls back to the
// environment/default path: a zero ceiling would make every inline wait expire
// before it started, which reads as a job that never finishes.
func maxSyncWait(mgr *manager.Manager) time.Duration {
	if mgr != nil {
		if resolved := mgr.SyncWaitCap(); resolved > 0 {
			return resolved
		}
	}
	return config.ResolveSyncWaitCap(os.Getenv)
}

// runSyncInput is runInput plus the inline wait cap.
type runSyncInput struct {
	runInput
	Wait string `json:"wait,omitempty" jsonschema:"max time to block inline (Go duration); a larger value is silently clamped to the inline-wait ceiling. That ceiling defaults to 90s, kept below common MCP clients' ~120s per-call timeout so the still-running result (carrying the job_id) is delivered inline, and is overridable with AGY_MCP_SYNC_WAIT_CAP, which can raise or lower it. Caps only the inline wait, not the job itself: on overrun the job keeps running and the returned job_id can be waited on with agy_wait or polled with agy_status, so never re-send the prompt"`
}

type runSyncOutput struct {
	JobID string `json:"job_id" jsonschema:"handle for this run; still valid after the inline wait runs out, for agy_wait, agy_status or agy_cancel"`
	statusOutput
	Note string `json:"note,omitempty" jsonschema:"set when the job outlived the inline wait, explaining that it is still running and how to collect it"`
}

// registerRunSync adds the agy_run_sync tool: start a job, wait inline for it
// (bounded), streaming progress notifications when the client asked for them.
//
// The registration itself lives in runfields.go, which selects the input
// schema the policy advertises (the unrestricted one, the protected one, or
// the managed-only one carrying the continuation handle) and applies the
// raw-key gate before a job is created. This wrapper only resolves the
// policy from the manager, keeping the nil-manager shape the tool-list tests
// rely on.
func registerRunSync(s *mcp.Server, mgr *manager.Manager) {
	// mgr may be nil (the tool-list tests connect without one); a nil manager
	// means the unrestricted description, like a zero policy would.
	pol := policy.Policy{}
	if mgr != nil {
		pol = mgr.Policy()
	}
	registerRunSyncTool(s, mgr, pol)
}
