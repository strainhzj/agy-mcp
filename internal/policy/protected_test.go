//go:build linux || darwin

package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWorkerMountMappingRoundTrip pins the /workspace mapping contract the
// protected profile implements: the control plane runs in the host view (no
// /workspace mount exists there), a caller's worker-view path is mapped onto
// the manifest's snapshot root for the filesystem checks, and the value
// written back is the worker-view spelling. Removing the mapping (or mapping
// with filepath.Join instead of joinAsWritten) turns these red.
func TestWorkerMountMappingRoundTrip(t *testing.T) {
	root := dir(t)
	sub := filepath.Join(root, "sub")
	touchDir(t, sub)
	p := protectedPolicy(t, root)
	if err := p.ValidateAndNormalize(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	t.Run("mount itself", func(t *testing.T) {
		got, err := p.CheckDir(WorkerMountPath)
		if err != nil {
			t.Fatalf("CheckDir(/workspace): %v", err)
		}
		if got != WorkerMountPath {
			t.Fatalf("CheckDir(/workspace) = %q, want the mount itself", got)
		}
	})
	t.Run("subdirectory stays worker-view", func(t *testing.T) {
		got, err := p.CheckDir(WorkerMountPath + "/sub")
		if err != nil {
			t.Fatalf("CheckDir(/workspace/sub): %v", err)
		}
		if got != WorkerMountPath+"/sub" {
			t.Fatalf("CheckDir(/workspace/sub) = %q, want the worker-view path", got)
		}
	})
	t.Run("extra dirs round-trip too", func(t *testing.T) {
		got, err := p.CheckExtraDirs(WorkerMountPath, []string{"sub"})
		if err != nil {
			t.Fatalf("CheckExtraDirs: %v", err)
		}
		if len(got) != 1 || got[0] != WorkerMountPath+"/sub" {
			t.Fatalf("CheckExtraDirs = %q, want [/workspace/sub]", got)
		}
	})
	t.Run("default cwd resolves through the mapping", func(t *testing.T) {
		if p.DefaultCwd != WorkerMountPath {
			t.Fatalf("DefaultCwd = %q, want %s", p.DefaultCwd, WorkerMountPath)
		}
	})
}

// TestWorkerMountBoundaryRefusals pins the boundaries a worker-view path must
// not cross: an adjacent prefix, a parent traversal, and a symlink planted
// inside the snapshot that points outside it. The symlink cases are the ones
// joinAsWritten exists for: with filepath.Join the ".." would be folded
// lexically before EvalSymlinks ran, and "<mount>/link-to-etc/.." would
// collapse back onto the snapshot root and pass.
func TestWorkerMountBoundaryRefusals(t *testing.T) {
	root := dir(t)
	sub := filepath.Join(root, "sub")
	touchDir(t, sub)
	p := protectedPolicy(t, root)
	if err := p.ValidateAndNormalize(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	for _, tc := range []struct {
		name string
		path string
	}{
		{"adjacent prefix", "/workspace-evil"},
		{"adjacent prefix with slash", "/workspace-evil/x"},
		{"parent traversal", "/workspace/.."},
		{"double dot inside", "/workspace/sub/../.."},
		{"missing subdirectory", "/workspace/nope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := p.CheckDir(tc.path); err == nil {
				t.Fatalf("CheckDir(%q) accepted", tc.path)
			}
		})
	}

	t.Run("symlink escape", func(t *testing.T) {
		outside := dir(t)
		link := filepath.Join(root, "link-to-outside")
		if err := os.Symlink(outside, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		for _, raw := range []string{"/workspace/link-to-outside", "/workspace/link-to-outside/.."} {
			if _, err := p.CheckDir(raw); err == nil {
				t.Fatalf("CheckDir(%q) accepted; a symlink inside the snapshot must not escape it", raw)
			}
		}
		// The same shape through dirs, joined against the checked cwd.
		if _, err := p.CheckExtraDirs("/workspace", []string{"link-to-outside"}); err == nil {
			t.Fatal("CheckExtraDirs accepted a symlink pointing outside the snapshot")
		}
	})
}

// TestValidateAndNormalizeProtectedGates pins the fail-closed startup rules
// for the profile: a host allowed root (instead of the worker mount), a
// missing snapshot root, a missing Host allowlist, a client mode left enabled
// and an unmeasured fixed mode each refuse the start.
func TestValidateAndNormalizeProtectedGates(t *testing.T) {
	root := dir(t)
	t.Run("host root refused", func(t *testing.T) {
		p := protectedPolicy(t, root)
		p.AllowedRoots = []string{root}
		err := p.ValidateAndNormalize()
		if err == nil || !strings.Contains(err.Error(), "the only allowed root is /workspace") {
			t.Fatalf("host allowed root = %v, want a worker-mount refusal", err)
		}
	})
	t.Run("missing snapshot root refused", func(t *testing.T) {
		p := protectedPolicy(t, root)
		p.SnapshotRoot = ""
		if err := p.ValidateAndNormalize(); err == nil || !strings.Contains(err.Error(), "snapshot root") {
			t.Fatalf("missing snapshot root = %v, want a refusal", err)
		}
	})
	t.Run("missing host allowlist refused", func(t *testing.T) {
		p := protectedPolicy(t, root)
		p.AllowedHosts = nil
		err := p.ValidateAndNormalize()
		if err == nil || !strings.Contains(err.Error(), "ALLOWED_HOSTS") {
			t.Fatalf("missing allowed hosts = %v, want a refusal", err)
		}
	})
	t.Run("client mode left enabled refused", func(t *testing.T) {
		p := protectedPolicy(t, root)
		p.Mode.DisableClientMode = false
		if err := p.ValidateAndNormalize(); err == nil || !strings.Contains(err.Error(), "DISABLE_MODE") {
			t.Fatalf("client mode enabled = %v, want a refusal", err)
		}
	})
	t.Run("fixed mode refused while unmeasured", func(t *testing.T) {
		// MeasuredFixedModes is empty until a mode's effect on tool permissions
		// and write gating is measured, so any fixed mode is a startup error.
		p := protectedPolicy(t, root)
		p.Mode.FixedMode = "accept-edits"
		err := p.ValidateAndNormalize()
		if err == nil || !strings.Contains(err.Error(), "fixed mode") {
			t.Fatalf("fixed mode = %v, want a refusal naming the empty whitelist", err)
		}
	})
	t.Run("wildcard host refused", func(t *testing.T) {
		p := protectedPolicy(t, root)
		p.AllowedHosts = []string{"*"}
		if err := p.ValidateAndNormalize(); err == nil || !strings.Contains(err.Error(), "wildcards") {
			t.Fatalf("wildcard host = %v, want a refusal", err)
		}
	})
}

// TestHostAllowed pins the Host-header matching: exact on host and port, an
// entry without a port matching that host on any port, case-insensitive on
// the host, and an empty allowlist accepting anything (upstream behavior).
//
// A portless entry matching any port is deliberate: an operator who names a
// host without a port means "this host, whichever port the client reached it
// on", and the deployment's port is the bridge's, not something the Host
// header always carries.
func TestHostAllowed(t *testing.T) {
	p := Policy{AllowedHosts: []string{"192.168.5.45:8865", "127.0.0.8"}}
	for _, tc := range []struct {
		header string
		want   bool
	}{
		{"192.168.5.45:8865", true},
		{"127.0.0.8:8765", true},
		{"127.0.0.8", true},
		{"192.168.5.45", false}, // the entry named a port, so a portless header is a different endpoint
		{"192.168.5.45:9999", false},
		{"evil.example:8865", false},
	} {
		if got := p.HostAllowed(tc.header); got != tc.want {
			t.Errorf("HostAllowed(%q) = %v, want %v", tc.header, got, tc.want)
		}
	}
	if !(Policy{}).HostAllowed("anything:1234") {
		t.Error("an empty allowlist must accept any Host (unrestricted upstream behavior)")
	}
}
