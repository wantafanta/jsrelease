package runner

import (
	"bytes"
	"github.com/wantafanta/jsrelease/internal/catalog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestErrorsAndMisc(t *testing.T) {
	dir := t.TempDir()
	if code, _, stderr := execText(t, nil, "-list", "-data", filepath.Join(dir, "none.json")); code != 1 || !strings.Contains(stderr, "run 'jsrelease -update'") {
		t.Errorf("missing db: %d %s", code, stderr)
	}
	if code, _, stderr := execText(t, nil, "-library", "react"); code != 2 || !strings.Contains(stderr, "invalid library") {
		t.Errorf("bad library: %d %s", code, stderr)
	}
	if code, out, _ := execText(t, nil, "-version"); code != 0 || out != "jsrelease dev\n" {
		t.Errorf("version (source build): %d %q", code, out)
	}
	old := Version
	Version = "1.2.3"
	if _, out, _ := execText(t, nil, "-version"); out != "jsrelease v1.2.3\n" || generatedBy() != "jsrelease 1.2.3" {
		t.Errorf("version (release): %q", out)
	}
	Version = old
	if code, _, _ := execText(t, nil, "-h"); code != 0 {
		t.Errorf("help exit code %d", code)
	}
	if code, _, stderr := execText(t, nil, "-full"); code != 2 || !strings.Contains(stderr, "-full can only be used with -update") {
		t.Errorf("-full without -update: %d %s", code, stderr)
	}
	if code, _, _ := execText(t, nil, "-nosuchflag"); code != 2 {
		t.Errorf("unknown flag exit code %d", code)
	}

	empty := filepath.Join(dir, "empty.json")
	os.WriteFile(empty, []byte(`{"releases":{"updated_at":"","source":"https://releases.jquery.com/","releases":[]}}`), 0o644)
	code, out, stderr := execText(t, nil, "-data", empty, "-list")
	if code != 0 || out != "Library         Version          Release Date  Support\n" || !strings.Contains(stderr, "contains no releases") {
		t.Errorf("empty db: %d %q %s", code, out, stderr)
	}
	if code, out, _ := execText(t, nil, "-data", empty, "-json", "-list"); code != 0 || out != "[]\n" {
		t.Errorf("empty json: %q", out)
	}
}

func TestShortAliases(t *testing.T) {
	path, _ := updatedDB(t)
	outFile := filepath.Join(t.TempDir(), "r.txt")
	code, out, stderr := execText(t, nil, "-data", path, "-s", "-o", outFile, "-library", "core")
	if code != 0 || stderr != "" || len(strings.Split(strings.TrimSpace(out), "\n")) != 87 {
		t.Fatalf("aliases: %d %q", code, stderr)
	}
	if code, _, stderr := execText(t, nil, "-data", path, "-v", "-list"); code != 0 || !strings.Contains(stderr, "[DBG]") {
		t.Fatalf("-v produced no debug output")
	}
}

func TestHelp(t *testing.T) {
	code, out, stderr := exec(t, nil)
	if code != 0 || stderr != "" {
		t.Fatalf("no arguments: exit %d, stderr %q", code, stderr)
	}
	var want bytes.Buffer
	Usage(&want)
	if out != want.String() {
		t.Fatal("no-argument output is not the help text")
	}
	if !strings.Contains(out, "\nEXAMPLES:\n") || !strings.HasPrefix(out, "jsrelease lists the releases of jQuery") {
		t.Errorf("help layout:\n%s", out)
	}
	for _, e := range helpExamples {
		if !strings.Contains(out, e[0]) || !strings.Contains(out, e[1]) {
			t.Errorf("example %q missing", e[0])
		}
	}
	code, hout, _ := exec(t, nil, "-h")
	if code != 0 || hout != out {
		t.Error("-h output differs from no-argument help")
	}
}

// TestHelpExamplesWork runs every example from the help (except -update,
// covered elsewhere) so the help never shows a command that fails.
func TestHelpExamplesWork(t *testing.T) {
	path, _ := updatedDB(t)
	dir := t.TempDir()
	for _, e := range helpExamples {
		args := strings.Fields(e[0])[1:]
		if args[0] == "-update" || args[0] == "-up" || args[0] == "-keys" {
			continue // need the network, or read your own config
		}
		for i, a := range args {
			if (a == "-o" || a == "-output") && i+1 < len(args) {
				args[i+1] = filepath.Join(dir, args[i+1])
			}
		}
		args = append(args, "-data", path)
		code, out, stderr := exec(t, nil, args...)
		if code != 0 || out == "" {
			t.Errorf("example %q: exit %d\n%s", e[0], code, stderr)
		}
	}
}

// TestDefaultsAndNewSwitches covers Markdown as the default, -cols across
// both -check tables, and -keys / -set-key with -config.
func TestDefaultsAndNewSwitches(t *testing.T) {
	path, _ := updatedDB(t)
	_, out, _ := exec(t, nil, "-data", path, "-library", "migrate", "-s")
	if !strings.HasPrefix(out, "| Library        | Version | Release Date | Support        |\n") {
		t.Errorf("Markdown should be the default:\n%s", out[:120])
	}
	// One -cols list for both tables; each keeps the given order.
	_, out, _ = exec(t, nil, "-data", path, "-library", "core", "-check", "3.4.1", "-s", "-cols", "latest,support,cvss,advisory")
	if !strings.HasPrefix(out, "| Latest | Support       |\n|--------|---------------|\n| 4.0.0  | Security only |\n\n| CVSS | CVE / Advisory                       |\n") {
		t.Errorf("mixed -cols:\n%s", out)
	}
	// Only advisory columns named: the summary keeps its defaults.
	_, out, _ = exec(t, nil, "-data", path, "-library", "core", "-check", "3.4.1", "-s", "-text", "-cols", "advisory")
	if !strings.HasPrefix(out, "jQuery   3.4.1    01/05/2019    Security only  4.0.0   18/01/2026\n") {
		t.Errorf("summary defaults:\n%s", out)
	}
	// -keys and -set-key with -config.
	cfg := filepath.Join(t.TempDir(), "keys.yaml")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("NVD_API_KEY", "")
	var o, e bytes.Buffer
	code := run([]string{"-config", cfg, "-set-key", "github"}, &o, &e, &hooks{stdin: strings.NewReader("tok123\n")})
	if code != 0 || !strings.Contains(e.String(), "Saved the GitHub token to "+cfg) {
		t.Fatalf("-set-key: %d %s", code, e.String())
	}
	_, out, _ = exec(t, nil, "-config", cfg, "-keys")
	if !strings.Contains(out, "GitHub token: set (config file "+cfg+")") || !strings.Contains(out, "NVD API key:  not set") || strings.Contains(out, "tok123") {
		t.Errorf("-keys:\n%s", out)
	}
	if code, _, stderr := exec(t, nil, "-config", filepath.Join(t.TempDir(), "missing.yaml"), "-list"); code != 2 || !strings.Contains(stderr, "-config") {
		t.Errorf("missing -config file: %d %s", code, stderr)
	}
	if code, _, stderr := exec(t, nil, "-clear"); code != 2 || !strings.Contains(stderr, "-clear can only be used with -set-key") {
		t.Errorf("-clear alone: %d %s", code, stderr)
	}
}

// TestHelpListsEveryLibrary: the help's library lists come from the catalog.
func TestHelpListsEveryLibrary(t *testing.T) {
	_, out, _ := exec(t, nil)
	for _, d := range catalog.Libraries {
		if !strings.Contains(out, string(d.ID)) {
			t.Errorf("-library help misses %s", d.ID)
		}
	}
	if !strings.Contains(out, "jQuery (Core, Migrate, UI, Mobile), Bootstrap,") || strings.Contains(out, "all      ") {
		t.Errorf("help library text:\n%s", out[:400])
	}
}
