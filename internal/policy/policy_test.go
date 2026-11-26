package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// dir returns an existing temporary directory path with its symlink-resolved
// spelling, so assertions compare canonical forms.
func dir(t *testing.T) string {
	t.Helper()
	return mustResolve(t, t.TempDir())
}

func mustResolve(t *testing.T, p string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("resolve %s: %v", p, err)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		t.Fatalf("abs %s: %v", resolved, err)
	}
	return abs
}

func touchDir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func TestValidateAndNormalizeRejectsUnknownProfile(t *testing.T) {
	p := Policy{Profile: "fortress"}
	// The profile switch at the top of ValidateAndNormalize is the guard this
	// test pins; without it an unknown profile would silently run unrestricted.
	err := p.ValidateAndNormalize()
	if err == nil || !strings.Contains(err.Error(), `unknown profile "fortress"`) {
		t.Fatalf("want unknown profile error, got %v", err)
	}
}

func TestValidateAndNormalizeAcceptsPiProfile(t *testing.T) {
	root := dir(t)
	p := Policy{Profile: ProfilePi, AllowedRoots: []string{root}}
	if err := p.ValidateAndNormalize(); err != nil {
		t.Fatalf("pi profile rejected: %v", err)
	}
	if !p.Protected() {
		t.Fatal("Protected() false after profile pi validated")
	}
}

func TestValidateAndNormalizeRejectsBadRoots(t *testing.T) {
	root := dir(t)
	mk := func(t *testing.T, roots ...string) *Policy {
		t.Helper()
		return &Policy{AllowedRoots: roots}
	}
	t.Run("relative root", func(t *testing.T) {
		err := mk(t, "relative/root").ValidateAndNormalize()
		if err == nil || !strings.Contains(err.Error(), "not absolute") {
			t.Fatalf("want not-absolute error, got %v", err)
		}
	})
	t.Run("missing root", func(t *testing.T) {
		err := mk(t, filepath.Join(root, "gone")).ValidateAndNormalize()
		if err == nil {
			t.Fatal("missing root accepted")
		}
	})
	t.Run("file as root", func(t *testing.T) {
		file := filepath.Join(root, "file")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := mk(t, file).ValidateAndNormalize()
		if err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("want not-a-directory error, got %v", err)
		}
	})
}

func TestValidateAndNormalizeCanonicalizesRoot(t *testing.T) {
	base := dir(t)
	linked := filepath.Join(base, "alias")
	if err := os.Symlink(base, linked); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	p := Policy{AllowedRoots: []string{linked}}
	if err := p.ValidateAndNormalize(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if p.AllowedRoots[0] != base {
		t.Fatalf("root stayed %q, want canonical %q", p.AllowedRoots[0], base)
	}
}

func TestValidateAndNormalizeDefaultCwd(t *testing.T) {
	root := dir(t)
	outside := dir(t)
	t.Run("inside accepted and canonical", func(t *testing.T) {
		p := Policy{AllowedRoots: []string{root}, DefaultCwd: root}
		if err := p.ValidateAndNormalize(); err != nil {
			t.Fatalf("validate: %v", err)
		}
		if p.DefaultCwd != root {
			t.Fatalf("default cwd %q, want %q", p.DefaultCwd, root)
		}
	})
	t.Run("outside refused", func(t *testing.T) {
		p := Policy{AllowedRoots: []string{root}, DefaultCwd: outside}
		err := p.ValidateAndNormalize()
		if err == nil || !strings.Contains(err.Error(), "default working directory") {
			t.Fatalf("want default-cwd error, got %v", err)
		}
	})
	t.Run("missing refused", func(t *testing.T) {
		p := Policy{AllowedRoots: []string{root}, DefaultCwd: filepath.Join(root, "gone")}
		if err := p.ValidateAndNormalize(); err == nil {
			t.Fatal("missing default cwd accepted")
		}
	})
}

func TestValidateAndNormalizeSessionPolicy(t *testing.T) {
	// NormalizeEmptyBecomesAllow pins the "" -> allow rewrite: a caller that
	// builds a Policy by hand (tests, Go constructors) gets upstream session
	// behavior, and SessionsAllowed must agree with it.
	p := Policy{}
	if err := p.ValidateAndNormalize(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if p.SessionPolicy != SessionPolicyAllow || !p.SessionsAllowed() {
		t.Fatalf("empty session policy: got %q, allowed=%v", p.SessionPolicy, p.SessionsAllowed())
	}
	for _, valid := range []SessionPolicy{SessionPolicyAllow, SessionPolicyManagedOnly, SessionPolicyDisabled} {
		p := Policy{SessionPolicy: valid}
		if err := p.ValidateAndNormalize(); err != nil {
			t.Fatalf("session policy %q rejected: %v", valid, err)
		}
	}
	p = Policy{SessionPolicy: SessionPolicy("sometimes")}
	if err := p.ValidateAndNormalize(); err == nil || !strings.Contains(err.Error(), "unknown session policy") {
		t.Fatalf("want unknown session policy error, got %v", err)
	}
}

func TestValidateAndNormalizeMaxTimeout(t *testing.T) {
	cases := []struct {
		name    string
		timeout time.Duration
		wantErr bool
	}{
		{"unset ok", 0, false},
		{"20m ok", 20 * time.Minute, false},
		{"24h ceiling ok", 24 * time.Hour, false},
		{"negative refused", -time.Minute, true},
		{"over ceiling refused", 25 * time.Hour, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := Policy{MaxTimeout: tc.timeout}
			err := p.ValidateAndNormalize()
			if tc.wantErr && err == nil {
				t.Fatalf("max timeout %s accepted", tc.timeout)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("max timeout %s refused: %v", tc.timeout, err)
			}
		})
	}
}

func TestCheckDirUnrestrictedIsNoOp(t *testing.T) {
	// CheckDir's first branch is the whole upstream-compat contract: with no
	// roots the check returns "" and no error, and the manager keeps its
	// os.Getwd fallback. Remove that branch and unrestricted deployments break.
	p := Policy{}
	got, err := p.CheckDir("/any/path/at/all")
	if err != nil || got != "" {
		t.Fatalf("unrestricted CheckDir returned %q, %v; want \"\", nil", got, err)
	}
}

func TestCheckDirEmpty(t *testing.T) {
	root := dir(t)
	t.Run("no default refused", func(t *testing.T) {
		p := Policy{AllowedRoots: []string{root}}
		if _, err := p.CheckDir(""); err == nil {
			t.Fatal("empty cwd accepted with no default configured")
		}
	})
	t.Run("default returned", func(t *testing.T) {
		p := Policy{AllowedRoots: []string{root}, DefaultCwd: root}
		got, err := p.CheckDir("")
		if err != nil || got != root {
			t.Fatalf("empty cwd returned %q, %v; want %q, nil", got, err, root)
		}
	})
}

func TestCheckDirRelativeRefused(t *testing.T) {
	root := dir(t)
	p := Policy{AllowedRoots: []string{root}}
	for _, raw := range []string{"subdir", "../outside", "./here"} {
		if _, err := p.CheckDir(raw); err == nil {
			t.Fatalf("relative cwd %q accepted", raw)
		}
	}
}

func TestCheckDirContainment(t *testing.T) {
	root := dir(t)
	outside := dir(t)
	inside := filepath.Join(root, "sub")
	touchDir(t, inside)
	p := Policy{AllowedRoots: []string{root}}
	t.Run("inside allowed and canonical", func(t *testing.T) {
		got, err := p.CheckDir(inside + string(filepath.Separator))
		if err != nil {
			t.Fatalf("inside cwd refused: %v", err)
		}
		if got != inside {
			t.Fatalf("cwd %q, want canonical %q", got, inside)
		}
	})
	t.Run("root itself allowed", func(t *testing.T) {
		if _, err := p.CheckDir(root); err != nil {
			t.Fatalf("root cwd refused: %v", err)
		}
	})
	t.Run("outside refused", func(t *testing.T) {
		if _, err := p.CheckDir(outside); err == nil {
			t.Fatal("outside cwd accepted")
		}
	})
	t.Run("parent traversal refused", func(t *testing.T) {
		if _, err := p.CheckDir(root + string(filepath.Separator) + ".."); err == nil {
			t.Fatal(".. above root accepted")
		}
	})
	t.Run("sibling prefix not confused", func(t *testing.T) {
		sibling := filepath.Join(filepath.Dir(root), filepath.Base(root)+"-evil")
		touchDir(t, sibling)
		t.Cleanup(func() { _ = os.RemoveAll(sibling) })
		if _, err := p.CheckDir(sibling); err == nil {
			t.Fatalf("sibling %s accepted on a shared string prefix", sibling)
		}
	})
}

func TestCheckExtraDirsUnrestrictedPassthrough(t *testing.T) {
	p := Policy{}
	in := []string{"/a", "rel", ""}
	got, err := p.CheckExtraDirs("/cwd", in)
	if err != nil || !equalStrings(got, in) {
		t.Fatalf("unrestricted CheckExtraDirs returned %q, %v; want input unchanged", got, err)
	}
}

func TestCheckExtraDirs(t *testing.T) {
	root := dir(t)
	outside := dir(t)
	sub := filepath.Join(root, "sub")
	other := filepath.Join(root, "other")
	touchDir(t, sub)
	touchDir(t, other)
	cwd := filepath.Join(root, "ws")
	touchDir(t, cwd)
	p := Policy{AllowedRoots: []string{root}}

	t.Run("relative resolved against cwd and normalized", func(t *testing.T) {
		got, err := p.CheckExtraDirs(cwd, []string{"../other", sub})
		if err != nil {
			t.Fatalf("valid dirs refused: %v", err)
		}
		if !equalStrings(got, []string{other, sub}) {
			t.Fatalf("dirs %q, want %q", got, []string{other, sub})
		}
	})
	t.Run("empty entry refused", func(t *testing.T) {
		if _, err := p.CheckExtraDirs(cwd, []string{sub, ""}); err == nil {
			t.Fatal("empty dirs entry accepted")
		}
	})
	t.Run("outside absolute refused", func(t *testing.T) {
		if _, err := p.CheckExtraDirs(cwd, []string{outside}); err == nil {
			t.Fatal("outside dirs entry accepted")
		}
	})
	t.Run("escaping relative refused", func(t *testing.T) {
		if _, err := p.CheckExtraDirs(cwd, []string{"../.."}); err == nil {
			t.Fatal("escaping relative dirs entry accepted")
		}
	})
	t.Run("rootRelative shape refused", func(t *testing.T) {
		// rootRelative is the guard for drive-rooted shapes; on POSIX it is
		// unreachable, so this case only runs where the shape is expressible.
		if !filepath.IsAbs("/x") && !strings.ContainsAny("/x", ":") {
			t.Skip("platform has no rootRelative shapes")
		}
		if _, err := p.CheckExtraDirs(cwd, []string{`\x`}); err == nil {
			t.Fatal("root-relative dirs entry accepted")
		}
	})
	t.Run("relative without cwd refused", func(t *testing.T) {
		if _, err := p.CheckExtraDirs("", []string{"sub"}); err == nil {
			t.Fatal("relative dirs entry accepted without a cwd")
		}
	})
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestCheckJSONSchemaUnrestrictedPassthrough(t *testing.T) {
	p := Policy{}
	raw := `{"type": "object"} `
	got, err := p.CheckJSONSchema(raw)
	if err != nil || got != raw {
		t.Fatalf("unrestricted CheckJSONSchema returned %q, %v; want input unchanged", got, err)
	}
}

func TestCheckJSONSchemaInlineOnly(t *testing.T) {
	p := Policy{InlineJSONSchemaOnly: true}
	t.Run("valid object trimmed", func(t *testing.T) {
		got, err := p.CheckJSONSchema("  {\"type\": \"object\"}  ")
		if err != nil {
			t.Fatalf("valid schema refused: %v", err)
		}
		if got != `{"type": "object"}` {
			t.Fatalf("schema %q not trimmed", got)
		}
	})
	t.Run("file path refused", func(t *testing.T) {
		for _, raw := range []string{"/etc/hosts", "~/.ssh/id_rsa", "./schema.json", "schema.json"} {
			if _, err := p.CheckJSONSchema(raw); err == nil {
				t.Fatalf("path-like schema %q accepted", raw)
			}
		}
	})
	t.Run("non-object json refused", func(t *testing.T) {
		for _, raw := range []string{`[]`, `"/etc/hosts"`, `3`, `null`, `true`} {
			if _, err := p.CheckJSONSchema(raw); err == nil {
				t.Fatalf("non-object schema %q accepted", raw)
			}
		}
	})
	t.Run("malformed json refused", func(t *testing.T) {
		if _, err := p.CheckJSONSchema(`{"type": `); err == nil {
			t.Fatal("malformed schema accepted")
		}
	})
	t.Run("oversized refused", func(t *testing.T) {
		big := `{"x":"` + strings.Repeat("a", MaxInlineJSONSchemaBytes) + `"}`
		if _, err := p.CheckJSONSchema(big); err == nil {
			t.Fatalf("%d byte schema accepted", len(big))
		}
	})
	t.Run("at-limit accepted", func(t *testing.T) {
		ok := `{"x":"` + strings.Repeat("a", MaxInlineJSONSchemaBytes-8) + `"}`
		if _, err := p.CheckJSONSchema(ok); err != nil {
			t.Fatalf("%d byte schema refused: %v", len(ok), err)
		}
	})
	t.Run("whitespace-only refused", func(t *testing.T) {
		if _, err := p.CheckJSONSchema("   "); err == nil {
			t.Fatal("whitespace-only schema accepted")
		}
	})
}

func TestCheckRunOptions(t *testing.T) {
	t.Run("model whitelist", func(t *testing.T) {
		p := Policy{AllowedModels: []string{"m1"}}
		if err := p.CheckRunOptions("m1", "", time.Minute); err != nil {
			t.Fatalf("whitelisted model refused: %v", err)
		}
		if err := p.CheckRunOptions("m2", "", time.Minute); err == nil {
			t.Fatal("unlisted model accepted")
		}
		if err := p.CheckRunOptions("", "", time.Minute); err == nil {
			t.Fatal("empty model accepted with a whitelist configured")
		}
	})
	t.Run("no whitelist accepts everything", func(t *testing.T) {
		p := Policy{}
		if err := p.CheckRunOptions("", "agent", time.Minute); err != nil {
			t.Fatalf("unrestricted options refused: %v", err)
		}
	})
	t.Run("agent selection disabled", func(t *testing.T) {
		p := Policy{DisableAgentSelection: true}
		if err := p.CheckRunOptions("m", "reviewer", time.Minute); err == nil {
			t.Fatal("agent accepted while selection is disabled")
		}
		if err := p.CheckRunOptions("m", "", time.Minute); err != nil {
			t.Fatalf("empty agent refused: %v", err)
		}
	})
	t.Run("agent whitelist", func(t *testing.T) {
		p := Policy{AllowedAgents: []string{"reviewer"}}
		if err := p.CheckRunOptions("m", "reviewer", time.Minute); err != nil {
			t.Fatalf("whitelisted agent refused: %v", err)
		}
		if err := p.CheckRunOptions("m", "other", time.Minute); err == nil {
			t.Fatal("unlisted agent accepted")
		}
		if err := p.CheckRunOptions("m", "", time.Minute); err != nil {
			t.Fatalf("empty agent refused under whitelist: %v", err)
		}
	})
	t.Run("max timeout", func(t *testing.T) {
		p := Policy{MaxTimeout: 20 * time.Minute}
		if err := p.CheckRunOptions("m", "", 20*time.Minute); err != nil {
			t.Fatalf("timeout at the cap refused: %v", err)
		}
		if err := p.CheckRunOptions("m", "", 21*time.Minute); err == nil {
			t.Fatal("timeout over the cap accepted")
		}
	})
}

func TestFilterValues(t *testing.T) {
	type row struct{ id string }
	values := []row{{"a"}, {"b"}, {"c"}}
	t.Run("no whitelist passthrough", func(t *testing.T) {
		got := FilterValues[string](nil, []string{"x"}, func(s string) string { return s })
		if len(got) != 1 || got[0] != "x" {
			t.Fatalf("empty whitelist filtered: %q", got)
		}
	})
	t.Run("filtered in order", func(t *testing.T) {
		got := FilterValues([]string{"c", "a"}, values, func(r row) string { return r.id })
		if len(got) != 2 || got[0].id != "a" || got[1].id != "c" {
			t.Fatalf("filter result %q, want a then c", got)
		}
	})
	t.Run("all filtered out", func(t *testing.T) {
		got := FilterValues([]string{"zzz"}, values, func(r row) string { return r.id })
		if len(got) != 0 {
			t.Fatalf("filter left %q", got)
		}
	})
}

func TestJoinAsWritten(t *testing.T) {
	// joinAsWritten must not clean: the whole point is that the OS, not
	// filepath.Join, resolves ".." past a symlink. The separator in the
	// expectation is the platform's own, because the function appends
	// filepath.Separator and the assertion must hold on Windows too.
	sep := string(filepath.Separator)
	if got := joinAsWritten("/root", "../up"); got != "/root"+sep+"../up" {
		t.Fatalf("joinAsWritten cleaned the path: %q", got)
	}
	if got := joinAsWritten("/root/", "../up"); got != "/root/../up" {
		t.Fatalf("trailing separator mishandled: %q", got)
	}
}

func TestSessionsAllowed(t *testing.T) {
	// SessionsAllowed treats the zero value as allow so a hand-built Policy
	// (no Resolve pass) keeps upstream session behavior.
	cases := map[SessionPolicy]bool{
		"":                       true,
		SessionPolicyAllow:       true,
		SessionPolicyManagedOnly: false,
		SessionPolicyDisabled:    false,
		SessionPolicy("bogus"):   false,
	}
	for sp, want := range cases {
		if got := (Policy{SessionPolicy: sp}).SessionsAllowed(); got != want {
			t.Fatalf("SessionsAllowed(%q) = %v, want %v", sp, got, want)
		}
	}
}
