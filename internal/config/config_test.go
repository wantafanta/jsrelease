package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	m, err := Parse(strings.NewReader("# c\n\ngithub_token: abc123  # note\nnvd_api_key: \"x y\"\n"), "f")
	if err != nil || m[KeyGitHub] != "abc123" || m[KeyNVD] != "x y" {
		t.Fatalf("%v %v", m, err)
	}
	if m, _ := Parse(strings.NewReader("github_token: 'it''s'\n"), "f"); m[KeyGitHub] != "it's" {
		t.Errorf("single quotes: %q", m[KeyGitHub])
	}
	for _, bad := range []string{"github_token\n", "token: x\n", "github_token: \"open\n", ": x\n"} {
		if _, err := Parse(strings.NewReader(bad), "f"); err == nil || !strings.Contains(err.Error(), "f line 1") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestSaveResolveAndPermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "config.yaml")
	if err := Save(p, map[string]string{KeyGitHub: "gh1"}); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", st.Mode().Perm())
		}
		if PermissionWarning(p) != "" {
			t.Error("unexpected warning")
		}
		os.Chmod(p, 0o644)
		if !strings.Contains(PermissionWarning(p), "chmod 600") {
			t.Error("missing permission warning")
		}
	}
	t.Setenv(EnvGitHub, "")
	t.Setenv(EnvNVD, "")
	k, err := Resolve(p)
	if err != nil || k.GitHub != "gh1" || !strings.HasPrefix(k.GitHubFrom, "config file ") || k.NVD != "" {
		t.Fatalf("%+v %v", k, err)
	}
	t.Setenv(EnvGitHub, "fromenv")
	if k, _ := Resolve(p); k.GitHub != "fromenv" || k.GitHubFrom != "environment variable GITHUB_TOKEN" {
		t.Errorf("env priority: %+v", k)
	}
	if k, err := Resolve(filepath.Join(t.TempDir(), "missing.yaml")); err != nil || k.NVD != "" {
		t.Errorf("missing file: %v", err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), `github_token: "gh1"`) || !strings.HasPrefix(string(b), "# jsrelease configuration") {
		t.Errorf("file:\n%s", b)
	}
}

func TestReadSecretFromPipe(t *testing.T) {
	var out strings.Builder
	s, err := ReadSecret(strings.NewReader("  tok \n"), &out, "prompt: ")
	if err != nil || s != "tok" || out.Len() != 0 {
		t.Fatalf("%q %v %q", s, err, out.String())
	}
}
