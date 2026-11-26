// Session continuation handles (Phase 3, managed-only) and the state disk
// budget: the control-plane session index, its output/input gates, its
// lifecycle across restarts, and the store-size bound. Each test names the
// production branch whose removal turns it red, per the repo's test rule.
package manager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tphakala/agy-mcp/v2/internal/jobstore"
	"github.com/tphakala/agy-mcp/v2/internal/policy"
	"github.com/tphakala/agy-mcp/v2/internal/streamjson"
)

// managedPol is restrictedPol with the Phase 3 session policy: continuation
// works, but only through this instance's own opaque handles.
func managedPol(root string) policy.Policy {
	p := restrictedPol(root)
	p.SessionPolicy = policy.SessionPolicyManagedOnly
	return p
}

// newManagedManager builds a managed-only Manager with a real session TTL
// (config.Resolve guarantees managed-only implies a positive TTL; this
// literal Config must mirror that or every handle would be born expired).
func newManagedManager(t *testing.T, root, project, instance, fingerprint string) *Manager {
	t.Helper()
	m := newManager(t, managerOpts{
		pol: managedPol(root), projectID: project, instanceID: instance,
		snapshotFingerprint: fingerprint,
	})
	m.cfg.SessionTTL = time.Hour
	return m
}

// stageDoneConversation creates a protected job whose ownership record names
// project/instance/fingerprint, whose terminal result carries nativeID, and
// whose exit sentinel marks a clean success: exactly what a completed first
// turn leaves behind.
func stageDoneConversation(t *testing.T, m *Manager, id, nativeID, project, instance, fingerprint string) {
	t.Helper()
	dir, err := m.store.Create(jobstore.Meta{ID: id, StartedAt: time.Now(), BootID: readBootID()})
	if err != nil {
		t.Fatalf("create job %s: %v", id, err)
	}
	writeOwnershipFingerprint(t, dir, project, instance, fingerprint)
	writeResultPayload(t, dir, streamjson.Result{ConversationID: nativeID, Status: streamjson.StatusSuccess, Response: "the answer"})
	if err := m.store.WriteExitCode(id, 0); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
}

// writeSessionRecordT is a test-facing WriteSessionRecord with a fixed
// creation time, so expiry tests do not sleep.
func writeSessionRecordT(t *testing.T, m *Manager, rec jobstore.SessionRecord) {
	t.Helper()
	if err := jobstore.WriteSessionRecord(m.cfg.StateDir, rec); err != nil {
		t.Fatalf("write session record: %v", err)
	}
}

// TestManagedOnlyHandleIssuedOnDoneFirstTurn pins the issuance rule: a
// completed first turn's Status carries an opaque handle, never the native
// id, and the same handle comes back on every later read of that job or the
// same native conversation (one record, not one per read). Removing the
// allowMint call in presentConversationID turns this red.
func TestManagedOnlyHandleIssuedOnDoneFirstTurn(t *testing.T) {
	root, _ := policyRoot(t)
	m := newManagedManager(t, root, "proj-1", "inst-1", "fp-1")
	stageDoneConversation(t, m, "first", "native-conv-1", "proj-1", "inst-1", "fp-1")

	st, err := m.Status("first")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.ConversationID == "" || st.ConversationID == "native-conv-1" {
		t.Fatalf("done first turn reported %q, want an opaque handle", st.ConversationID)
	}
	if !jobstore.ValidSessionHandle(st.ConversationID) {
		t.Fatalf("reported id %q is not in handle shape", st.ConversationID)
	}
	handle := st.ConversationID

	st, err = m.Status("first")
	if err != nil {
		t.Fatalf("second Status: %v", err)
	}
	if st.ConversationID != handle {
		t.Fatalf("second read reported %q, want the same handle %q", st.ConversationID, handle)
	}
	handles, err := jobstore.ListSessionHandles(m.cfg.StateDir)
	if err != nil {
		t.Fatalf("list handles: %v", err)
	}
	if len(handles) != 1 || handles[0] != handle {
		t.Fatalf("session index holds %v, want exactly [%s]", handles, handle)
	}
}

// TestManagedOnlyUndoneJobReportsNoHandle pins that a running (or failed)
// run never produces a handle: issuance is a completion event. Removing the
// done gate in presentConversationID turns this red.
func TestManagedOnlyUndoneJobReportsNoHandle(t *testing.T) {
	root, _ := policyRoot(t)
	m := newManager(t, managerOpts{pol: managedPol(root), projectID: "p", instanceID: "i", snapshotFingerprint: "fp"})
	dir, err := m.store.Create(jobstore.Meta{ID: "running", StartedAt: time.Now(), BootID: readBootID()})
	if err != nil {
		t.Fatal(err)
	}
	writeOwnershipFingerprint(t, dir, "p", "i", "fp")
	if err := jobstore.WriteProgressDir(dir, jobstore.Progress{ConversationID: "native-mid-run"}); err != nil {
		t.Fatal(err)
	}
	st, err := m.Status("running")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.ConversationID != "" {
		t.Fatalf("running job reported conversation %q, want nothing", st.ConversationID)
	}
	if err := m.store.WriteExitCode("running", 1); err != nil {
		t.Fatal(err)
	}
	st, err = m.Status("running")
	if err != nil {
		t.Fatalf("Status after failure: %v", err)
	}
	if st.ConversationID != "" {
		t.Fatalf("failed job reported conversation %q, want nothing", st.ConversationID)
	}
	handles, _ := jobstore.ListSessionHandles(m.cfg.StateDir)
	if len(handles) != 0 {
		t.Fatalf("session index holds %v after a failed run, want none", handles)
	}
}

// TestDisabledStripsConversationID keeps the Phase 1 rule pinned next to the
// managed-only code, so a refactor of presentConversationID cannot silently
// leak native ids under the disabled policy.
func TestDisabledStripsConversationID(t *testing.T) {
	root, _ := policyRoot(t)
	m := newManager(t, managerOpts{pol: restrictedPol(root), projectID: "p", instanceID: "i"})
	stageDoneConversation(t, m, "done", "native-x", "p", "i", "")
	st, err := m.Status("done")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.ConversationID != "" {
		t.Fatalf("disabled policy leaked %q", st.ConversationID)
	}
}

// TestManagedOnlyHandleRoundTrip covers the input gate: a valid handle
// resolves to its native id, and a native id, an unknown handle, a malformed
// value, a foreign deployment's handle and an expired handle all read as the
// same refusal. Removing the expiry, ownership or contract checks in
// resolveSessionHandle turns the corresponding row red.
func TestManagedOnlyHandleRoundTrip(t *testing.T) {
	root, _ := policyRoot(t)
	m := newManagedManager(t, root, "proj-1", "inst-1", "fp-1")
	stageDoneConversation(t, m, "first", "native-conv-1", "proj-1", "inst-1", "fp-1")
	st, err := m.Status("first")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	handle := st.ConversationID

	req, err := m.normalizeRequest(StartRequest{Prompt: "continue", ConversationID: handle, Timeout: time.Minute})
	if err != nil {
		t.Fatalf("valid handle refused: %v", err)
	}
	if req.ConversationID != "native-conv-1" {
		t.Fatalf("handle resolved to %q, want the native id", req.ConversationID)
	}
	foreignRec := jobstore.SessionRecord{
		Contract: jobstore.SessionRecordContract, Handle: "ah" + strings.Repeat("aa", 16),
		ProjectID: "other-project", InstanceID: "inst-1", SnapshotFingerprint: "fp-1",
		NativeID: "native-foreign", FirstJobID: "x",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}
	expiredRec := jobstore.SessionRecord{
		Contract: jobstore.SessionRecordContract, Handle: "ah" + strings.Repeat("bb", 16),
		ProjectID: "proj-1", InstanceID: "inst-1", SnapshotFingerprint: "fp-1",
		NativeID: "native-expired", FirstJobID: "x",
		CreatedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour),
	}
	writeSessionRecordT(t, m, foreignRec)
	writeSessionRecordT(t, m, expiredRec)

	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"native id", "native-conv-1"},
		{"unknown handle", "ah" + strings.Repeat("cc", 16)},
		{"foreign project", foreignRec.Handle},
		{"expired", expiredRec.Handle},
		{"path-like value", "../../etc/passwd"},
		{"empty-ish", "ah"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := m.normalizeRequest(StartRequest{Prompt: "p", ConversationID: tc.raw, Timeout: time.Minute})
			if err == nil {
				t.Fatalf("conversation_id %q accepted, want refusal", tc.raw)
			}
		})
	}
}

// TestManagedOnlyRestartKeepsHandles pins the restart rule: a new Manager
// over the same state dir, project, instance and snapshot resolves the
// previous run's handle, while one whose snapshot fingerprint changed refuses
// it (a redeployed snapshot is a new deployment). Removing the fingerprint
// comparison in resolveSessionHandle turns the second half red.
func TestManagedOnlyRestartKeepsHandles(t *testing.T) {
	root, _ := policyRoot(t)
	stateDir := t.TempDir()
	newManaged := func(fingerprint string) *Manager {
		m := newManager(t, managerOpts{
			stateDir: stateDir, pol: managedPol(root),
			projectID: "proj-1", instanceID: "inst-1", snapshotFingerprint: fingerprint,
		})
		m.cfg.SessionTTL = time.Hour
		return m
	}
	m := newManaged("fp-1")
	stageDoneConversation(t, m, "first", "native-conv-1", "proj-1", "inst-1", "fp-1")
	st, err := m.Status("first")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	handle := st.ConversationID

	restarted := newManaged("fp-1")
	req, err := restarted.normalizeRequest(StartRequest{Prompt: "p", ConversationID: handle, Timeout: time.Minute})
	if err != nil {
		t.Fatalf("handle did not survive a same-snapshot restart: %v", err)
	}
	if req.ConversationID != "native-conv-1" {
		t.Fatalf("restarted resolve = %q", req.ConversationID)
	}

	redeployed := newManaged("fp-2")
	if _, err := redeployed.normalizeRequest(StartRequest{Prompt: "p", ConversationID: handle, Timeout: time.Minute}); err == nil {
		t.Fatal("old snapshot's handle accepted after a redeploy")
	}
}

// TestSessionGCRemovesExpiredKeepsLive pins the expiry sweep: expired
// records of this instance are removed, unexpired ones and another
// deployment's records are kept.
func TestSessionGCRemovesExpiredKeepsLive(t *testing.T) {
	root, _ := policyRoot(t)
	m := newManager(t, managerOpts{pol: managedPol(root), projectID: "p", instanceID: "i", snapshotFingerprint: "fp"})
	now := time.Now()
	live := jobstore.SessionRecord{Contract: jobstore.SessionRecordContract, Handle: "ah" + strings.Repeat("11", 16),
		ProjectID: "p", InstanceID: "i", SnapshotFingerprint: "fp", NativeID: "n1", FirstJobID: "j1",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	expired := jobstore.SessionRecord{Contract: jobstore.SessionRecordContract, Handle: "ah" + strings.Repeat("22", 16),
		ProjectID: "p", InstanceID: "i", SnapshotFingerprint: "fp", NativeID: "n2", FirstJobID: "j2",
		CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	foreign := jobstore.SessionRecord{Contract: jobstore.SessionRecordContract, Handle: "ah" + strings.Repeat("33", 16),
		ProjectID: "other", InstanceID: "i", SnapshotFingerprint: "fp", NativeID: "n3", FirstJobID: "j3",
		CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	writeSessionRecordT(t, m, live)
	writeSessionRecordT(t, m, expired)
	writeSessionRecordT(t, m, foreign)

	m.gcExpiredSessions()
	if _, err := jobstore.ReadSessionRecord(m.cfg.StateDir, live.Handle); err != nil {
		t.Fatalf("live handle reaped: %v", err)
	}
	if _, err := jobstore.ReadSessionRecord(m.cfg.StateDir, foreign.Handle); err != nil {
		t.Fatalf("foreign handle reaped by this instance: %v", err)
	}
	if _, err := jobstore.ReadSessionRecord(m.cfg.StateDir, expired.Handle); err == nil {
		t.Fatal("expired handle survived GC")
	}
}

// TestAwaitConversationIDManagedOnly pins the agy_run output path: a
// continuation reports its handle at once, a fresh run reports nothing until
// its handle exists, and a handle-shaped id passes through untouched.
func TestAwaitConversationIDManagedOnly(t *testing.T) {
	root, _ := policyRoot(t)
	m := newManagedManager(t, root, "p", "i", "fp")
	stageDoneConversation(t, m, "first", "native-conv-1", "p", "i", "fp")
	st, err := m.Status("first")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	handle := st.ConversationID

	if got := m.AwaitConversationID(t.Context(), Job{ID: "first", ConversationID: "native-conv-1"}); got != handle {
		t.Fatalf("continuation await = %q, want handle %q", got, handle)
	}
	if got := m.AwaitConversationID(t.Context(), Job{ID: "first", ConversationID: handle}); got != handle {
		t.Fatalf("handle-shaped await = %q, want it unchanged", got)
	}
	if got := m.AwaitConversationID(t.Context(), Job{ID: "first"}); got != "" {
		t.Fatalf("fresh run await = %q, want empty before completion", got)
	}
}

// foreignDir returns the job directory for the test's staged foreign job.
func (m *Manager) foreignDir(t *testing.T) string { return m.jobDirT(t, "foreign") }

// jobDirT resolves a staged job's directory.
func (m *Manager) jobDirT(t *testing.T, id string) string {
	t.Helper()
	dir, err := m.store.Dir(id)
	if err != nil {
		t.Fatalf("job dir %s: %v", id, err)
	}
	return dir
}

// storeRootT returns the job store root.
func (m *Manager) storeRoot(t *testing.T) string { return filepath.Join(m.cfg.StateDir, "jobs") }

// TestStateBudgetEvictsOldestTerminal pins the disk bound: when the store
// exceeds the budget, the sweep evicts the oldest completable terminal jobs
// until it fits, never a running job and never a job this instance cannot
// attribute. Removing enforceStateBudget's eviction loop turns this red.
func TestStateBudgetEvictsOldestTerminal(t *testing.T) {
	root, _ := policyRoot(t)
	m := newManager(t, managerOpts{pol: restrictedPol(root), projectID: "p", instanceID: "i"})
	stage := func(id string, pad int64, age time.Duration) {
		t.Helper()
		dir, err := m.store.Create(jobstore.Meta{ID: id, StartedAt: time.Now().Add(-age), BootID: readBootID()})
		if err != nil {
			t.Fatal(err)
		}
		writeOwnershipFingerprint(t, dir, "p", "i", "")
		if err := os.WriteFile(jobstore.OutPath(dir), make([]byte, pad), 0o600); err != nil {
			t.Fatal(err)
		}
		writeResultPayload(t, dir, streamjson.Result{Status: streamjson.StatusSuccess, Response: "x"})
		if err := m.store.WriteExitCode(id, 0); err != nil {
			t.Fatal(err)
		}
	}
	stage("old", 600, 3*time.Hour)
	stage("new", 600, 1*time.Hour)
	stage("foreign", 100, 2*time.Hour)
	// "foreign" carries a record naming another project, so ownershipRefused
	// keeps it out of the removable set entirely.
	writeOwnershipFingerprint(t, m.foreignDir(t), "other", "i", "")

	// Budget exactly between "total minus old" and total: only evicting old
	// (the oldest completion) can bring the store under it.
	total := dirSize(m.storeRoot(t))
	oldSize := dirSize(m.jobDirT(t, "old"))
	m.cfg.StateBudgetBytes = total - oldSize + 1
	m.enforceStateBudget()

	if _, err := m.Status("old"); err == nil {
		t.Fatal("oldest terminal job survived the budget sweep")
	}
	if _, err := m.Status("new"); err != nil {
		t.Fatalf("newer terminal job evicted before the oldest: %v", err)
	}
	if _, err := m.Status("foreign"); err == nil {
		t.Fatal("foreign job evicted by a sweep that cannot attribute it")
	}

	// A job without its terminal sentinel is never evicted, whatever its
	// size: the sweep cannot know a supervisor is not about to write it.
	liveDir, err := m.store.Create(jobstore.Meta{ID: "live", StartedAt: time.Now(), BootID: readBootID()})
	if err != nil {
		t.Fatal(err)
	}
	writeOwnershipFingerprint(t, liveDir, "p", "i", "")
	if err := os.WriteFile(jobstore.OutPath(liveDir), make([]byte, 5000), 0o600); err != nil {
		t.Fatal(err)
	}
	m.cfg.StateBudgetBytes = 1
	m.enforceStateBudget()
	if _, err := m.Status("live"); err != nil {
		t.Fatalf("non-terminal job evicted: %v", err)
	}
}
