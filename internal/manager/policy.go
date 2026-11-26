// Policy integration for the manager: the checks normalizeRequest and
// StartJob apply to a caller's request under the resolved deployment policy,
// and the per-job ownership records a protected instance writes and verifies.
// The zero-value policy path through every function here is the upstream
// behavior, byte for byte.
package manager

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"

	"github.com/tphakala/agy-mcp/v2/internal/jobstore"
	"github.com/tphakala/agy-mcp/v2/internal/policy"
)

// Policy returns the resolved deployment policy the manager enforces. The
// tool layer (internal/mcptools) reads it to describe the server honestly to
// clients: under a protected profile the instructions and tool descriptions
// must name what is refused there, not restate the unrestricted defaults.
func (m *Manager) Policy() policy.Policy { return m.cfg.Policy }

// checkSessionPolicy applies the session access policy to a run request
// before anything else resolves it. continue_latest must be refused before
// normalizeRequest resolves it against agy's conversation cache: under a
// policy that forbids continuation, reading the cache at all is the leak the
// policy exists to prevent.
func (m *Manager) checkSessionPolicy(req StartRequest) error {
	p := m.cfg.Policy
	if req.ContinueLatest && (p.DisableContinueLatest || !p.SessionsAllowed()) {
		return fmt.Errorf("continue_latest is disabled by this server's session policy; start a fresh run and restate any needed context")
	}
	if req.ConversationID != "" && !p.SessionsAllowed() {
		// managed-only would accept only a handle from this instance's own
		// protected session index; that index is the Phase 3 machinery and
		// does not exist yet, so until it lands a non-allow policy accepts no
		// conversation_id at all. Native agy session ids, for instance, are
		// never an authorization grant.
		return fmt.Errorf("conversation_id is not accepted by this server's session policy (%s); start a fresh run and restate any needed context", p.SessionPolicy)
	}
	return nil
}

// checkSchemaPolicy applies the json_schema policy, writing the accepted
// value back into the request so the args, the request key and the persisted
// meta all carry the same normalized text.
//
// A protected profile refuses json_schema outright: a schema value is
// caller-controlled text handed to agy, and MEASURED against agy 1.5.17, agy
// treats an unparseable value as a file path and dies reading it, which turns
// the parameter into an arbitrary host-file reader. The inline-only knob is
// the middle ground for other deployments; protected instances get the
// strictest reading because their deployment does not need schemas.
func (m *Manager) checkSchemaPolicy(req *StartRequest) error {
	if req.JSONSchema == "" {
		return nil
	}
	p := m.cfg.Policy
	if p.Protected() {
		return fmt.Errorf("json_schema is not accepted by this server; describe the expected output shape in the prompt instead")
	}
	trimmed, err := p.CheckJSONSchema(req.JSONSchema)
	if err != nil {
		return err
	}
	req.JSONSchema = trimmed
	return nil
}

// jobOwnership is the protected-instance ownership record stamped into every
// job dir at creation. ProjectID and InstanceID come from the deployment
// launcher (AGY_MCP_PROJECT_ID / AGY_MCP_INSTANCE_ID); no tool parameter can
// supply either. SnapshotFingerprint comes from the state directory's
// deployment record (jobstore.InstanceRecord, also launcher-written) and binds
// the job to one snapshot version: a redeployed snapshot is a new deployment,
// not a continuation of the old one, so replays and status reads against a
// changed snapshot refuse instead of serving stale results. Profile is
// recorded for the operator reading a state dir, not for the match itself.
type jobOwnership struct {
	Profile             string `json:"profile"`
	ProjectID           string `json:"project_id"`
	InstanceID          string `json:"instance_id"`
	SnapshotFingerprint string `json:"snapshot_fingerprint,omitempty"`
}

// writeOwnership stamps the ownership record onto a freshly created job dir.
// It runs between store.Create and the supervisor spawn, so no supervisor or
// agy process ever works in a dir a protected instance would refuse on a
// later read. On failure the caller removes the dir; a protected instance
// never keeps a job it could not attribute.
func (m *Manager) writeOwnership(dir string) error {
	if !m.cfg.Policy.Protected() {
		return nil
	}
	b, err := json.Marshal(jobOwnership{
		Profile:             m.cfg.Policy.Profile,
		ProjectID:           m.cfg.ProjectID,
		InstanceID:          m.cfg.InstanceID,
		SnapshotFingerprint: m.cfg.SnapshotFingerprint,
	})
	if err != nil {
		return err
	}
	return jobstore.WriteOwnershipFile(dir, b)
}

// ownershipRefused reports whether a protected instance must treat id as an
// unknown job. The error it returns is shaped exactly like a missing job
// (errors.Is(err, fs.ErrNotExist)): unknown and out-of-scope handles are
// indistinguishable to the caller, so probing job ids cannot tell "does not
// exist" from "exists but is not yours", and neither the result text, the
// conversation id, nor any state change of a foreign job leaks.
//
// Non-protected instances never consult ownership records: the file is
// absent for upstream jobs, and requiring it there would break every existing
// state dir and the wait subcommands.
func (m *Manager) ownershipRefused(id string) error {
	if !m.cfg.Policy.Protected() {
		return nil
	}
	dir, err := m.store.Dir(id)
	if err != nil {
		return unknownJobErr(id)
	}
	b, err := os.ReadFile(jobstore.OwnershipPath(dir))
	if err != nil {
		return unknownJobErr(id)
	}
	var own jobOwnership
	if err := json.Unmarshal(b, &own); err != nil {
		return unknownJobErr(id)
	}
	if own.InstanceID != m.cfg.InstanceID || own.ProjectID != m.cfg.ProjectID {
		return unknownJobErr(id)
	}
	// The snapshot version is part of ownership: a deployment's identity
	// covers the snapshot it serves, so a record from another snapshot is as
	// out of scope as one from another instance. An empty record fingerprint
	// only matches an instance without one, which a deployed instance cannot
	// be: verifyDeploymentRecord refuses a record without a fingerprint, so a
	// match here would mean a hand-built config, and the fail-closed reading
	// is to refuse.
	if own.SnapshotFingerprint != m.cfg.SnapshotFingerprint {
		return unknownJobErr(id)
	}
	return nil
}

// unknownJobErr returns the error shape a missing job already produces, so an
// ownership refusal is indistinguishable from a job that does not exist:
// unknown and out-of-scope handles must read identically to the caller, or
// probing job ids would reveal which ones belong to this instance. Callers
// that need the distinction for their own logs read the record directly (see
// checkPolicy in doctor.go), never through this error.
func unknownJobErr(id string) error {
	return fmt.Errorf("job %s: %w", id, fs.ErrNotExist)
}
