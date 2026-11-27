package mcptools

// The protected (pi profile) run-tool inputs and the raw-key gate they need.
//
// Two things make a protected deployment's parameter surface different from
// the unrestricted one, and both are load-bearing:
//
//  1. The schema must not advertise a parameter the server refuses. A field
//     that always fails is not a constraint, it is a trap: the model reads the
//     schema, sends the field, and burns a tool call learning it was refused.
//     So a protected server registers a different input type whose fields stop
//     at what the policy accepts.
//
//  2. Presence must be detectable, not just value. Go's typed decode cannot
//     tell "absent" from "present and empty" from "present and null", so a
//     policy that refuses a key has to look at the raw JSON object before the
//     typed decode runs. rejectDisabledRunKeys is that check.
//
// The embedded protectedRunBase carries the shared fields; managedRunInput
// adds the one field a managed-only instance accepts (its own opaque
// continuation handle), which is why the session policy selects the type.

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tphakala/agy-mcp/v2/internal/manager"
	"github.com/tphakala/agy-mcp/v2/internal/policy"
)

// protectedRunBase is the run input a protected deployment advertises: the
// unrestricted runInput minus the parameters the profile refuses outright
// (mode, json_schema, continue_latest, and conversation_id unless the session
// policy is managed-only).
//
// The field descriptions are rewritten for the read-only single-project
// deployment rather than restated from the unrestricted ones: cwd is a path
// inside the served snapshot, dirs stay inside it, and nothing here claims the
// agent may edit anything.
type protectedRunBase struct {
	Prompt         string   `json:"prompt" jsonschema:"the complete task for the delegated agent: what to do, the context needed to do it, and the output wanted back; the agent cannot see this conversation, so the prompt must stand alone. It is sent to agy literally, so a leading slash-command or skill name (a prompt starting with /) is treated as text, not expanded"`
	Model          string   `json:"model,omitempty" jsonschema:"agy model id, e.g. gemini-3.1-pro-high; omit to use the server's default model, or agy's own default when the server sets none. Call list_models for the accepted values and pass one from its models field, not a display label from model_details, because agy rejects a display label whenever effort is also set. Not every id accepts every effort either, and some accept none, so omit effort unless you need a specific one"`
	Effort         string   `json:"effort,omitempty" jsonschema:"reasoning effort for this run (agy --effort): low, medium, high or xhigh. xhigh needs a model that offers it, such as gemini-4-hydrogen (agy 1.5.8 and later, per agy's changelog). Omit to use agy's default"`
	Agent          string   `json:"agent,omitempty" jsonschema:"name of a specific agy agent to run for this session (agy --agent). Refused on this server unless it publishes an agent whitelist; list_agents then names the accepted values, and returns nothing when agent selection is off"`
	Sandbox        bool     `json:"sandbox,omitempty" jsonschema:"run the agent with agy's sandbox (terminal restrictions) enabled (agy --sandbox). This server forces it on, so the value is ignored: passing it changes nothing"`
	Dirs           []string `json:"dirs,omitempty" jsonschema:"extra directories to grant the agent beyond cwd (agy --add-dir), e.g. a subdirectory of the served snapshot. Every entry must resolve inside the same snapshot; a path outside it, or a symlink leading outside it, is refused. Each entry is also an agy workspace, so its own rule files and hooks load regardless of project_rules"`
	ProjectRules   *bool    `json:"project_rules,omitempty" jsonschema:"load the snapshot's agy rule files (AGENTS.md) by passing cwd to agy as a workspace (agy --add-dir). On by default. Setting false only omits that --add-dir; agy 1.2.16 and 1.4.8 (measured) load cwd's rules and hooks regardless, so it does not keep a snapshot's rules out"`
	Cwd            string   `json:"cwd,omitempty" jsonschema:"absolute path inside the served project snapshot, in the worker view this server publishes (the snapshot root itself, or a subdirectory of it). Omit to run at the snapshot root; a relative path, a path outside the snapshot, or a path whose symlink leads outside it is refused. The snapshot is read-only, so a run is analysis to read, not file changes already made"`
	Timeout        string   `json:"timeout,omitempty" jsonschema:"max wall-clock duration for the whole run (Go duration, e.g. 20m); a value over the server's configured maximum, or over 24h, is rejected. On expiry the job normally ends in state failed with failure_reason timeout. Omit to use the server's default"`
	Priority       string   `json:"priority,omitempty" jsonschema:"normal (default) or optional. optional marks work that may be skipped, such as a peer review, a second opinion or a rubber-duck pass: when the run's model belongs to a quota group at low, critical or exhausted per agy_usage, the run is refused before any job starts, as a tool error naming the group, level, remaining percent and reset time, and the right response is to report the skip rather than retry. Quota that cannot be read, a stale reading, an omitted model with no server default, or a model outside a known group never refuses; normal always runs. Not forwarded to agy, and not part of idempotency_key matching: a retry whose key already names a job returns that job whatever the priority"`
	IdempotencyKey string   `json:"idempotency_key,omitempty" jsonschema:"optional retry token for agy-mcp job creation. Reusing the same key with the same normalized run request returns the existing job instead of starting another; reusing it with a different request is rejected. Keys are remembered while the job remains in the job store. Use this when a transport failure could leave it ambiguous whether a run already started"`
}

// toStartRequest converts the protected input into a StartRequest. It is the
// same conversion the unrestricted input performs, minus the fields the
// profile does not accept; the effort and priority validation is shared so the
// two surfaces cannot drift on a value both accept.
func (in protectedRunBase) toStartRequest() (manager.StartRequest, error) {
	req := manager.StartRequest{
		Prompt: in.Prompt, Model: in.Model, Dirs: in.Dirs,
		Cwd: in.Cwd, Effort: in.Effort, Agent: in.Agent,
		IdempotencyKey: in.IdempotencyKey,
		Priority:       in.Priority,
		// project_rules defaults to true, so only an explicit false opts out.
		SkipProjectRules: in.ProjectRules != nil && !*in.ProjectRules,
	}
	if in.Effort != "" && !slices.Contains(agyEfforts, in.Effort) {
		return manager.StartRequest{}, fmt.Errorf("invalid effort %q: want one of %s", in.Effort, strings.Join(agyEfforts, ", "))
	}
	if in.Priority != "" && in.Priority != manager.PriorityNormal && in.Priority != manager.PriorityOptional {
		return manager.StartRequest{}, fmt.Errorf("invalid priority %q: want %s or %s", in.Priority, manager.PriorityNormal, manager.PriorityOptional)
	}
	if in.Timeout != "" {
		d, err := parsePositiveDuration("timeout", in.Timeout, "20m")
		if err != nil {
			return manager.StartRequest{}, err
		}
		if d > maxJobTimeout {
			return manager.StartRequest{}, fmt.Errorf("timeout %q exceeds the maximum of %s", in.Timeout, maxJobTimeout)
		}
		req.Timeout = d
	}
	return req, nil
}

// protectedRunInput is the agy_run input under SessionPolicy=disabled: no
// continuation field at all, because a disabled policy accepts no conversation
// identifier in either direction.
type protectedRunInput struct {
	protectedRunBase
}

func (in protectedRunInput) toStartRequest() (manager.StartRequest, error) {
	return in.protectedRunBase.toStartRequest()
}

// managedRunInput is the agy_run input under SessionPolicy=managed-only: the
// only continuation field is the opaque handle this instance issued. A native
// agy id is refused by the manager's session policy, so the schema description
// says exactly what the field accepts.
type managedRunInput struct {
	protectedRunBase
	ConversationID string `json:"conversation_id,omitempty" jsonschema:"opaque continuation handle this server issued for a completed run in this project; pass it back to continue that conversation. Nothing else is accepted: a native agy conversation id, a handle from another project, instance or snapshot version, or an expired handle is refused, so start a fresh run and restate the context instead. Handles are bound to this server's project and snapshot version and expire"`
}

func (in managedRunInput) toStartRequest() (manager.StartRequest, error) {
	req, err := in.protectedRunBase.toStartRequest()
	if err != nil {
		return manager.StartRequest{}, err
	}
	req.ConversationID = in.ConversationID
	return req, nil
}

// protectedSyncInput is the agy_run_sync input under a disabled session policy.
type protectedSyncInput struct {
	protectedRunInput
	Wait string `json:"wait,omitempty" jsonschema:"max time to block inline (Go duration); a larger value is silently clamped to the inline-wait ceiling this server is configured with. Caps only the inline wait, not the job itself: on overrun the job keeps running and the returned job_id can be waited on with agy_wait or polled with agy_status, so never re-send the prompt"`
}

func (in protectedSyncInput) toStartRequest() (manager.StartRequest, error) {
	return in.protectedRunInput.toStartRequest()
}

// managedSyncInput is the agy_run_sync input under managed-only.
type managedSyncInput struct {
	managedRunInput
	Wait string `json:"wait,omitempty" jsonschema:"max time to block inline (Go duration); a larger value is silently clamped to the inline-wait ceiling this server is configured with. Caps only the inline wait, not the job itself: on overrun the job keeps running and the returned job_id can be waited on with agy_wait or polled with agy_status, so never re-send the prompt"`
}

func (in managedSyncInput) toStartRequest() (manager.StartRequest, error) {
	return in.managedRunInput.toStartRequest()
}

// disabledRunKeys maps a run parameter to the reason this deployment refuses
// it. The reasons are policy-derived rather than hard-coded per tool, so a
// deployment that relaxes one knob keeps the upstream field instead of losing
// it, and an unrestricted server produces an empty map (the gate is then a
// no-op).
func disabledRunKeys(pol policy.Policy) map[string]string {
	refused := map[string]string{}
	if pol.Mode.DisableClientMode {
		refused["mode"] = "this server does not accept the mode parameter; it decides whether agy runs with a mode"
	}
	if pol.DisableJSONSchema {
		refused["json_schema"] = "this server does not accept json_schema; describe the expected output shape in the prompt instead"
	}
	if pol.DisableContinueLatest {
		refused["continue_latest"] = "this server does not accept continue_latest; start a fresh run and restate the context you need"
	}
	if !pol.SessionsAllowed() {
		refused["conversation_id"] = "this server's session policy does not accept conversation_id; start a fresh run and restate the context you need"
	}
	return refused
}

// rejectDisabledRunKeys refuses a request that carries a key the policy does
// not accept, before any typed decode, before a StartRequest is built, and
// therefore before a job directory exists or a worker is spawned.
//
// It works on the raw JSON object because that is the only place presence is
// observable: "mode" present with an empty string, with null, or with a
// non-string value all decode to the same zero value a typed struct reports
// for an absent field, so a policy that only checked the decoded value would
// wave all three through. The schema no longer advertises the key, so a
// well-behaved client never sends it; this is the confused-deputy backstop for
// one that does.
func rejectDisabledRunKeys(pol policy.Policy, raw json.RawMessage) error {
	refused := disabledRunKeys(pol)
	if len(refused) == 0 || len(raw) == 0 {
		return nil
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) == nil {
		return refuseDisabledKeys(refused, keys)
	}
	// Not a JSON object: the typed decode reports the shape, and its error
	// names what is actually wrong, so there is nothing for this gate to
	// refuse. Stepping aside keeps the clearer error in front of the caller.
	return nil
}

// refuseDisabledKeys builds the refusal for a decoded request object that
// carries at least one disabled key. present is sorted so the message is
// deterministic, and each key names its reason, so a caller that sent two
// refused parameters learns both in one round trip.
func refuseDisabledKeys(refused map[string]string, keys map[string]json.RawMessage) error {
	var present []string
	for key := range refused {
		if _, ok := keys[key]; ok {
			present = append(present, key)
		}
	}
	if len(present) == 0 {
		return nil
	}
	slices.Sort(present)
	parts := make([]string, 0, len(present))
	for _, key := range present {
		parts = append(parts, fmt.Sprintf("%s (%s)", key, refused[key]))
	}
	return fmt.Errorf("this server refuses the request parameter(s) %s; the call was refused before any job was created", strings.Join(parts, ", "))
}

// managedSession reports whether the policy advertises the continuation-handle
// field (managed-only) rather than dropping the field entirely (disabled).
func managedSession(pol policy.Policy) bool {
	return pol.Protected() && pol.SessionPolicy == policy.SessionPolicyManagedOnly
}

// registerRun adds agy_run with the input schema the policy selects. The three
// registrations share one handler body (runHandler) so they cannot drift on
// what they do with a request they accept; only the input type, and therefore
// the schema, differs.
func registerRun(s *mcp.Server, mgr *manager.Manager, pol policy.Policy) {
	tool := &mcp.Tool{
		Name:        toolAgyRun,
		Title:       "Delegate to agy (async)",
		Annotations: annDelegate,
		Description: runDescription(pol, agyRunDefaultDescription, protectedAgyRunDescription, protectedAgyRunManagedDescription),
	}
	switch {
	case !pol.Protected():
		mcp.AddTool(s, tool, runHandler(mgr, pol, func(in runInput) (manager.StartRequest, error) { return in.toStartRequest() }))
	case managedSession(pol):
		mcp.AddTool(s, tool, runHandler(mgr, pol, func(in managedRunInput) (manager.StartRequest, error) { return in.toStartRequest() }))
	default:
		mcp.AddTool(s, tool, runHandler(mgr, pol, func(in protectedRunInput) (manager.StartRequest, error) { return in.toStartRequest() }))
	}
}

// registerRunSyncTool adds agy_run_sync with the policy-selected schema. The
// exported entry point is registerRunSync in run_sync.go, which resolves the
// policy from the manager (including its nil shape) and calls this.
func registerRunSyncTool(s *mcp.Server, mgr *manager.Manager, pol policy.Policy) {
	tool := &mcp.Tool{
		Name:        toolAgyRunSync,
		Title:       "Delegate to agy (wait inline)",
		Annotations: annDelegate,
		Description: runDescription(pol, agyRunSyncDefaultDescription, protectedAgyRunSyncDescription, protectedAgyRunSyncManagedDescription),
	}
	switch {
	case !pol.Protected():
		mcp.AddTool(s, tool, runSyncHandler(mgr, pol, func(in runSyncInput) (manager.StartRequest, time.Duration, error) {
			req, err := in.toStartRequest()
			if err != nil {
				return manager.StartRequest{}, 0, err
			}
			wait, err := parseWait(mgr, in.Wait)
			return req, wait, err
		}))
	case managedSession(pol):
		mcp.AddTool(s, tool, runSyncHandler(mgr, pol, func(in managedSyncInput) (manager.StartRequest, time.Duration, error) {
			req, err := in.toStartRequest()
			if err != nil {
				return manager.StartRequest{}, 0, err
			}
			wait, err := parseWait(mgr, in.Wait)
			return req, wait, err
		}))
	default:
		mcp.AddTool(s, tool, runSyncHandler(mgr, pol, func(in protectedSyncInput) (manager.StartRequest, time.Duration, error) {
			req, err := in.toStartRequest()
			if err != nil {
				return manager.StartRequest{}, 0, err
			}
			wait, err := parseWait(mgr, in.Wait)
			return req, wait, err
		}))
	}
}

// runHandler is the shared agy_run body. The raw-key gate runs first, so a
// request the policy refuses never reaches StartJob and leaves no job dir.
func runHandler[In any](mgr *manager.Manager, pol policy.Policy, conv func(In) (manager.StartRequest, error)) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, runOutput, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, runOutput, error) {
		if err := rejectDisabledRunKeys(pol, req.Params.Arguments); err != nil {
			return nil, runOutput{}, err
		}
		start, err := conv(in)
		if err != nil {
			return nil, runOutput{}, err
		}
		job, err := mgr.StartJob(start)
		if err != nil {
			return nil, runOutput{}, err
		}
		// agy_run returns before the job produces anything else, so this is the
		// one tool that waits for agy to name a fresh conversation. The tools
		// that report a run's conversation fill it from a Status read, which
		// costs nothing extra because they were reading the status anyway.
		return nil, runOutput{JobID: job.ID, ConversationID: mgr.AwaitConversationID(ctx, job), State: job.State, Quota: quotaFor(mgr)}, nil
	}
}

// runSyncHandler is the shared agy_run_sync body: the same gate, then the
// inline wait the caller asked for (clamped by parseWait).
func runSyncHandler[In any](mgr *manager.Manager, pol policy.Policy, conv func(In) (manager.StartRequest, time.Duration, error)) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, runSyncOutput, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, runSyncOutput, error) {
		if err := rejectDisabledRunKeys(pol, req.Params.Arguments); err != nil {
			return nil, runSyncOutput{}, err
		}
		start, wait, err := conv(in)
		if err != nil {
			return nil, runSyncOutput{}, err
		}
		job, err := mgr.StartJob(start)
		if err != nil {
			return nil, runSyncOutput{}, err
		}
		out, err := awaitJob(ctx, req, mgr, job.ID, time.Now().Add(wait))
		if err != nil {
			return nil, runSyncOutput{}, err
		}
		return nil, out, nil
	}
}
