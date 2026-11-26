//go:build linux || darwin

package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCheckDirSymlinkEscape covers the symlink-traversal order the package
// exists for: EvalSymlinks must run on the RAW caller path before any lexical
// cleanup, so "<allowed>/link-to-etc" and "<allowed>/link-to-etc/.." are
// judged from the link's TARGET and refused, never folded back under the
// root. Removing the EvalSymlinks-first ordering in resolveExistingDir (or
// replacing CheckDir's use of it with an Abs+Clean pass) must turn these red.
func TestCheckDirSymlinkEscape(t *testing.T) {
	root := dir(t)
	outside := dir(t)
	canary := filepath.Join(outside, "canary")
	if err := os.WriteFile(canary, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	p := Policy{AllowedRoots: []string{root}}

	for _, raw := range []string{
		link,         // symlink to a directory outside the root
		link + "/..", // lexical parent of the link resolves outside the root
		filepath.Join(link, "..", filepath.Base(outside)), // lands on the outside dir itself
	} {
		got, err := p.CheckDir(raw)
		if err == nil {
			t.Fatalf("symlink escape %q accepted as %q", raw, got)
		}
	}
}

func TestCheckDirSymlinkInsideIsFine(t *testing.T) {
	root := dir(t)
	target := filepath.Join(root, "real")
	touchDir(t, target)
	link := filepath.Join(root, "alias")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	p := Policy{AllowedRoots: []string{root}}
	got, err := p.CheckDir(link)
	if err != nil {
		t.Fatalf("internal symlink refused: %v", err)
	}
	if got != target {
		t.Fatalf("internal symlink stayed %q, want canonical %q", got, target)
	}
}

func TestCheckExtraDirsSymlinkEscape(t *testing.T) {
	root := dir(t)
	outside := dir(t)
	cwd := filepath.Join(root, "ws")
	touchDir(t, cwd)
	link := filepath.Join(cwd, "to-ssh")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	p := Policy{AllowedRoots: []string{root}}
	for _, raw := range []string{
		"to-ssh",    // relative entry that is a link outside the root
		"to-ssh/..", // lexical parent of the link, resolved from the target
		link,        // absolute path through the link
	} {
		got, err := p.CheckExtraDirs(cwd, []string{raw})
		if err == nil {
			t.Fatalf("dirs symlink escape %q accepted as %q", raw, got)
		}
	}
}

func TestValidateAndNormalizeRootThroughSymlink(t *testing.T) {
	// A configured root that is itself a symlink must normalize to its target
	// so every later containment check compares canonical paths.
	base := dir(t)
	target := filepath.Join(base, "real-root")
	touchDir(t, target)
	alias := filepath.Join(base, "alias-root")
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	p := Policy{AllowedRoots: []string{alias}}
	if err := p.ValidateAndNormalize(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if p.AllowedRoots[0] != target {
		t.Fatalf("root stayed %q, want %q", p.AllowedRoots[0], target)
	}
	// The symlink spelling must still be accepted as a cwd against the
	// canonical root, because CheckDir resolves it before comparing.
	got, err := p.CheckDir(alias)
	if err != nil || got != target {
		t.Fatalf("alias cwd returned %q, %v; want %q, nil", got, err, target)
	}
}
