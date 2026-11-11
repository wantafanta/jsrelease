package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/source/jquery"
	"github.com/wantafanta/jsrelease/internal/testutil"
)

func fixtureConfig(s *testutil.Server) *jquery.Config {
	cfg := jquery.DefaultConfig(Version)
	cfg.Pages = []jquery.Page{
		{Name: "jQuery Core & Migrate", URL: s.URL + "/jquery/", Libraries: []catalog.Library{catalog.Core, catalog.Migrate}},
		{Name: "jQuery UI", URL: s.URL + "/ui/", Libraries: []catalog.Library{catalog.UI}},
		{Name: "jQuery Mobile", URL: s.URL + "/mobile/", Libraries: []catalog.Library{catalog.Mobile}},
	}
	cfg.AllowedHosts = []string{s.Host()}
	cfg.RetryBackoff = time.Millisecond
	return &cfg
}

// gh is a fake GitHub API shared by all tests, so no test ever reaches the
// real api.github.com.
var gh *testutil.GitHubServer

func TestMain(m *testing.M) {
	// Keep tests away from the real per-user data folder.
	if d, err := os.MkdirTemp("", "jsrelease-data"); err == nil {
		os.Setenv("XDG_DATA_HOME", d)
		os.Setenv("LocalAppData", d)
		defer os.RemoveAll(d)
	}
	gh = testutil.NewGitHubServer()
	code := m.Run()
	gh.Close()
	os.Exit(code)
}

// execText runs jsrelease with plain-text output (-text), which most of these
// tests check. It adds no -text with -json or -update, and "-md" in args is a
// test-only marker meaning "use the default Markdown output".
func execText(t *testing.T, cfg *jquery.Config, args ...string) (int, string, string) {
	t.Helper()
	var a []string
	md, skip := false, false
	for _, x := range args {
		switch x {
		case "-md", "-markdown":
			md = true
			continue
		case "-json", "-update", "-up":
			skip = true
		}
		a = append(a, x)
	}
	if !md && !skip {
		a = append(a, "-text")
	}
	return exec(t, cfg, a...)
}

func exec(t *testing.T, cfg *jquery.Config, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb, &hooks{releases: cfg, githubAPI: gh.URL, nvdAPI: gh.URL + "/nvd", rawBase: gh.URL + "/raw"})
	return code, out.String(), errb.String()
}

func updatedDB(t *testing.T) (string, *testutil.Server) {
	t.Helper()
	s := testutil.NewServer(t)
	path := filepath.Join(t.TempDir(), "jsrelease.json")
	code, _, stderr := exec(t, fixtureConfig(s), "-update", "-data", path)
	if code != 0 {
		t.Fatalf("update failed (%d): %s", code, stderr)
	}
	return path, s
}

// vulnPathFor is the file holding the vulnerability data: the same file.
func vulnPathFor(dbPath string) string { return dbPath }

// sectionOf returns one section of the data file at path, to check that a
// failed update left it unchanged.
func sectionOf(t *testing.T, path, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]json.RawMessage
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f[name]
}

// removeVulns deletes the vulnerability section of the data file at path.
func removeVulns(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]json.RawMessage
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	delete(f, "vulnerabilities")
	out, _ := json.MarshalIndent(f, "", "  ")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}
