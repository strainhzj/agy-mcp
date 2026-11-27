// The state-budget eviction target: the acceptance criterion
// (docs/pi-sandbox-hardening.md section 5.D) is that a sweep leaves the store
// below 90% of AGY_MCP_STATE_BUDGET, not merely at or under it. The earlier
// implementation evicted only until total <= budget, which left a flooded
// store at 95% of the budget with removable jobs still present. Reverting to
// that (or to any target at 100%) turns the tests here red.

package manager

import (
	"os"
	"testing"
	"time"

	"github.com/tphakala/agy-mcp/v2/internal/jobstore"
	"github.com/tphakala/agy-mcp/v2/internal/streamjson"
)

// TestStateBudgetEvictTargetIsNinetyPercent pins the threshold arithmetic: 90%
// of the budget, in integer arithmetic so the comparison is exact and does not
// drift with floating point.
func TestStateBudgetEvictTargetIsNinetyPercent(t *testing.T) {
	for _, tc := range []struct {
		budget int64
		want   int64
	}{
		{1000, 900},
		{101, 90}, // truncated, not rounded up: the target must stay below 90%
		{99, 89},
		{1, 0},
	} {
		if got := stateBudgetEvictTarget(tc.budget); got != tc.want {
			t.Errorf("stateBudgetEvictTarget(%d) = %d, want %d", tc.budget, got, tc.want)
		}
	}
}

// TestStateBudgetEvictsBelowNinetyPercent is the criterion itself: with a
// budget chosen so that evicting only the oldest job leaves the store at ~95%
// of it, the sweep must keep going until the store is below the 90% target.
// The newest job must survive, because the sweep evicts oldest-first and stops
// once the target is met.
func TestStateBudgetEvictsBelowNinetyPercent(t *testing.T) {
	root, _ := policyRoot(t)
	m := newManager(t, managerOpts{pol: restrictedPol(root), projectID: "p", instanceID: "i"})
	stage := func(id string, pad int64, age time.Duration) {
		t.Helper()
		dir, err := m.store.Create(jobstore.Meta{ID: id, StartedAt: time.Now().Add(-age), BootID: readBootID()})
		if err != nil {
			t.Fatal(err)
		}
		writeOwnershipFingerprint(t, dir, "p", "i", m.cfg.SnapshotFingerprint)
		if err := os.WriteFile(jobstore.OutPath(dir), make([]byte, pad), 0o600); err != nil {
			t.Fatal(err)
		}
		writeResultPayload(t, dir, streamjson.Result{Status: streamjson.StatusSuccess, Response: "x"})
		if err := m.store.WriteExitCode(id, 0); err != nil {
			t.Fatal(err)
		}
	}
	stage("old", 8192, 3*time.Hour)
	stage("middle", 8192, 2*time.Hour)
	stage("new", 8192, time.Hour)

	total := dirSize(m.storeRoot(t))
	oldSize := dirSize(m.jobDirT(t, "old"))
	// Budget so that evicting only "old" leaves ~95% of it: enough to satisfy
	// "under budget", not enough to satisfy "under 90%".
	remainder := total - oldSize
	m.cfg.StateBudgetBytes = remainder*100/95 + 1

	m.enforceStateBudget()

	target := stateBudgetEvictTarget(m.cfg.StateBudgetBytes)
	after := dirSize(m.storeRoot(t))
	if after >= target {
		t.Fatalf("after GC total=%d, target=%d (budget=%d); the sweep must leave the store below 90%% of the budget", after, target, m.cfg.StateBudgetBytes)
	}
	if _, err := m.Status("new"); err != nil {
		t.Fatalf("newest job evicted by a sweep that had already met its target: %v", err)
	}
	if _, err := m.Status("old"); err == nil {
		t.Fatal("oldest job survived a sweep that was still over target")
	}
}

// TestStateBudgetUnremovableOverrunIsLeftAlone pins the other side: when
// nothing removable fits the target, the sweep logs and leaves the overrun
// rather than evicting a running or unattributable job. A target below the
// budget must not turn into a reason to delete something live.
func TestStateBudgetUnremovableOverrunIsLeftAlone(t *testing.T) {
	root, _ := policyRoot(t)
	m := newManager(t, managerOpts{pol: restrictedPol(root), projectID: "p", instanceID: "i"})
	liveDir, err := m.store.Create(jobstore.Meta{ID: "live", StartedAt: time.Now(), BootID: readBootID()})
	if err != nil {
		t.Fatal(err)
	}
	writeOwnershipFingerprint(t, liveDir, "p", "i", m.cfg.SnapshotFingerprint)
	if err := os.WriteFile(jobstore.OutPath(liveDir), make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	m.cfg.StateBudgetBytes = 1
	m.enforceStateBudget()
	if _, err := m.Status("live"); err != nil {
		t.Fatalf("non-terminal job evicted to chase the 90%% target: %v", err)
	}
}
