// Conversation continuation handles: the Phase 3 machinery a managed-only
// protected instance uses instead of native agy session ids. A handle is an
// opaque jobstore session record bound to this deployment's project, instance
// and snapshot fingerprint, issued only for a conversation a completed
// first-turn job of this instance produced, and resolved back to the native
// id only inside the manager, where it is handed to agy. A caller never sees
// a native id and can never admit one: resolution accepts only handles this
// instance wrote, and anything else reads as the same policy refusal.
//
// Upstream (SessionPolicy allow) none of this runs; disabled strips
// conversation ids entirely; managed-only is the middle path that keeps
// project-internal continuation without exposing host session state.
package manager

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/tphakala/agy-mcp/v2/internal/jobstore"
	"github.com/tphakala/agy-mcp/v2/internal/policy"
)

// sessionHandleEntropy is the random bytes behind one handle (32 hex chars).
const sessionHandleEntropy = 16

// resolveSessionHandle resolves one opaque handle to its native conversation
// id, refusing everything that is not exactly this deployment's own,
// unexpired record. Every refusal carries the same message: unknown,
// malformed, foreign and expired handles must be indistinguishable, or
// probing conversation_id values would reveal which ones this server holds.
func (m *Manager) resolveSessionHandle(raw string) (string, error) {
	policyErr := fmt.Errorf("conversation_id is not a valid session handle for this server (unknown, expired, or issued by another deployment or snapshot); start a fresh run and restate any needed context")
	if !jobstore.ValidSessionHandle(raw) {
		return "", policyErr
	}
	rec, err := jobstore.ReadSessionRecord(m.cfg.StateDir, raw)
	if err != nil {
		return "", policyErr
	}
	if rec.Contract != jobstore.SessionRecordContract ||
		rec.ProjectID != m.cfg.ProjectID ||
		rec.InstanceID != m.cfg.InstanceID ||
		rec.SnapshotFingerprint != m.cfg.SnapshotFingerprint {
		return "", policyErr
	}
	if m.now().After(rec.ExpiresAt) {
		return "", policyErr
	}
	return rec.NativeID, nil
}

// handleForNative returns the handle standing for nativeID, minting the
// record when allowMint is set and no record exists yet. It is the
// output-side counterpart of resolveSessionHandle: under managed-only, a
// completed first turn mints its handle here, and every later read of the
// same conversation returns the same handle.
//
// allowMint is true only where the manager knows the job is a DONE first
// turn (see presentConversationID); lookups (a running job, a continuation
// replay surfaced through AwaitConversationID) never mint, so a failed or
// still-running run can never produce a handle, and the record's provenance
// stays "a successful first turn of this instance".
//
// A write failure mints nothing and returns "": the caller then reports no
// conversation rather than one it cannot resolve later.
func (m *Manager) handleForNative(nativeID, jobID string, allowMint bool) string {
	if nativeID == "" || m.cfg.Policy.SessionPolicy != policy.SessionPolicyManagedOnly {
		return ""
	}
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()
	if h, ok := m.lookupSessionHandleLocked(nativeID); ok {
		return h
	}
	if !allowMint {
		return ""
	}
	handle, err := newSessionHandle()
	if err != nil {
		log.Printf("session handle: generate: %v", err)
		return ""
	}
	now := m.now()
	rec := jobstore.SessionRecord{
		Contract:            jobstore.SessionRecordContract,
		Handle:              handle,
		ProjectID:           m.cfg.ProjectID,
		InstanceID:          m.cfg.InstanceID,
		SnapshotFingerprint: m.cfg.SnapshotFingerprint,
		NativeID:            nativeID,
		FirstJobID:          jobID,
		CreatedAt:           now,
		ExpiresAt:           now.Add(m.cfg.SessionTTL),
	}
	if err := jobstore.WriteSessionRecord(m.cfg.StateDir, rec); err != nil {
		log.Printf("session handle: write: %v", err)
		return ""
	}
	return handle
}

// lookupSessionHandleLocked finds the unexpired, still-owned handle record
// for a native conversation id, if one exists. Callers hold sessionsMu. A
// record whose expiry passed is reported as absent (it no longer resolves)
// but is left on disk for the GC pass to reap.
func (m *Manager) lookupSessionHandleLocked(nativeID string) (string, bool) {
	handles, err := jobstore.ListSessionHandles(m.cfg.StateDir)
	if err != nil {
		log.Printf("session handle: list: %v", err)
		return "", false
	}
	for _, h := range handles {
		rec, err := jobstore.ReadSessionRecord(m.cfg.StateDir, h)
		if err != nil {
			continue
		}
		if rec.NativeID != nativeID ||
			rec.ProjectID != m.cfg.ProjectID ||
			rec.InstanceID != m.cfg.InstanceID ||
			rec.SnapshotFingerprint != m.cfg.SnapshotFingerprint ||
			m.now().After(rec.ExpiresAt) {
			continue
		}
		return rec.Handle, true
	}
	return "", false
}

// presentConversationID is the output-side gate every caller-facing
// conversation id passes through. allow keeps the native id (upstream);
// disabled strips it (no agy session identifier ever reaches a caller);
// managed-only maps it to the opaque handle, minting the record only when
// done is set, which is the manager's proof the first turn completed
// successfully (a failed or interrupted run leaves nothing to continue).
func (m *Manager) presentConversationID(jobID string, done bool, nativeID string) string {
	p := m.cfg.Policy
	switch {
	case p.SessionsAllowed():
		return nativeID
	case p.SessionPolicy == policy.SessionPolicyManagedOnly:
		if nativeID == "" {
			return ""
		}
		return m.handleForNative(nativeID, jobID, done)
	default:
		return ""
	}
}

// newSessionHandle returns a fresh handle string ("ah" plus 32 hex chars).
func newSessionHandle() (string, error) {
	b := make([]byte, sessionHandleEntropy)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "ah" + hex.EncodeToString(b), nil
}

// gcExpiredSessions removes session records whose expiry has passed. It runs
// on the same sweeps as job GC (and at startup), which is why a managed-only
// instance keeps JobTTL collection enabled: the ticker that reaps job dirs
// is the one that retires dead handles too. Records whose ownership no
// longer matches this deployment are kept, not reaped: they cannot resolve
// here, and deleting another deployment's state is not this sweep's call.
func (m *Manager) gcExpiredSessions() {
	handles, err := jobstore.ListSessionHandles(m.cfg.StateDir)
	if err != nil {
		log.Printf("session GC: list: %v", err)
		return
	}
	now := m.now()
	for _, h := range handles {
		rec, err := jobstore.ReadSessionRecord(m.cfg.StateDir, h)
		if err != nil {
			continue
		}
		if rec.ProjectID != m.cfg.ProjectID || rec.InstanceID != m.cfg.InstanceID {
			continue
		}
		if now.After(rec.ExpiresAt) {
			if err := jobstore.RemoveSessionRecord(m.cfg.StateDir, h); err != nil {
				log.Printf("session GC: remove %s: %v", h, err)
			}
		}
	}
}

// enforceStateBudget evicts the store's oldest removable terminal jobs until
// the job store fits the configured disk budget. It is the disk half of the
// protected deployment's resource bounds: output caps bound one job, the
// budget bounds their sum. Jobs a live supervisor still owns, jobs that are
// not terminal, and jobs whose ownership does not match this instance are
// never evicted; when nothing removable fits the budget the overrun is
// logged and left for the next sweep rather than deleting something live.
//
// The size walk is one stat pass per job dir; it runs on GC sweeps only, not
// on any request path.
func (m *Manager) enforceStateBudget() {
	if m.cfg.StateBudgetBytes <= 0 {
		return
	}
	ids, err := m.store.List()
	if err != nil {
		log.Printf("state budget: list jobs: %v", err)
		return
	}
	var total int64
	var removable []budgetCandidate
	for _, id := range ids {
		if m.ownershipRefused(id) != nil {
			continue // never reap what this instance cannot attribute
		}
		meta, err := m.store.Load(id)
		if err != nil {
			continue
		}
		_, terminal := m.store.ExitCode(id)
		if !terminal {
			if m.processAlive(meta) {
				// A running job is untouchable whatever its size.
				dir, derr := m.store.Dir(id)
				if derr == nil {
					total += dirSize(dir)
				}
			}
			// Dead but not yet terminal: the supervisor may be about to write
			// its sentinel; leave it to the TTL sweep as gcEvaluate does.
			continue
		}
		dir, derr := m.store.Dir(id)
		if derr != nil {
			continue
		}
		size := dirSize(dir)
		total += size
		at, atOK := m.store.CompletedAt(id)
		removable = append(removable, budgetCandidate{id: id, size: size, at: at, atOK: atOK, startedAt: meta.StartedAt})
	}
	if total <= m.cfg.StateBudgetBytes {
		return
	}
	// Oldest completion first; jobs with no computable completion time sort
	// last so an unknown age never wins the eviction race against a known one.
	sortCandidatesByAge(removable)
	over := total - m.cfg.StateBudgetBytes
	for _, c := range removable {
		if over <= 0 {
			break
		}
		if err := m.store.Remove(c.id); err != nil {
			log.Printf("state budget: remove %s: %v", c.id, err)
			continue
		}
		over -= c.size
		log.Printf("state budget: evicted job %s (%d bytes) to fit the %d byte budget", c.id, c.size, m.cfg.StateBudgetBytes)
	}
	if over > 0 {
		log.Printf("state budget: store is %d bytes over budget with nothing removable; running jobs hold the rest", over)
	}
}

// dirSize returns the total size of a directory tree's regular files. A walk
// error counts what was readable; the budget is a bound, not an audit.
func dirSize(dir string) int64 {
	var total int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if e.IsDir() {
			total += dirSize(filepath.Join(dir, e.Name()))
			continue
		}
		if info, err := e.Info(); err == nil {
			total += info.Size()
		}
	}
	return total
}

// budgetCandidate is one terminal job the state budget may evict: its id,
// its on-disk size, its completion time (known or not), and when it started.
type budgetCandidate struct {
	id        string
	size      int64
	at        time.Time
	atOK      bool
	startedAt time.Time
}

// sortCandidatesByAge orders eviction candidates oldest first: completion
// time when known, then start time, so two jobs whose sentinel files were
// written in the same instant still evict in launch order and an unknown age
// never wins the eviction race against a known one.
func sortCandidatesByAge(cs []budgetCandidate) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].atOK != cs[j].atOK {
			return cs[i].atOK
		}
		if cs[i].atOK && !cs[i].at.Equal(cs[j].at) {
			return cs[i].at.Before(cs[j].at)
		}
		return cs[i].startedAt.Before(cs[j].startedAt)
	})
}
