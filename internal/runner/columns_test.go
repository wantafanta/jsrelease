package runner

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestColumns(t *testing.T) {
	path, _ := updatedDB(t)

	code, out, _ := execText(t, nil, "-cols", "list")
	if code != 0 || !strings.Contains(out, "   link         GitHub advisory page") || !strings.Contains(out, "   notes        GitHub release-notes URL") ||
		!strings.Contains(out, "-check summary table columns (default: library,version,date,support,latest,latest-date):") ||
		!strings.Contains(out, "   latest-date  the latest version's release date") {
		t.Fatalf("-cols list:\n%s", out)
	}

	// Chosen columns, in the chosen order, with the GitHub link.
	_, out, _ = execText(t, nil, "-data", path, "-library", "core", "-check", "3.4.1", "-cols", "advisory,cvss,link", "-s")
	want := "" +
		"jQuery   3.4.1    01/05/2019    Security only  4.0.0   18/01/2026\n" +
		"\n" +
		"CVE-2020-11022                        6.9   https://github.com/advisories/GHSA-gxr4-xjj5-5px2\n" +
		"CVE-2020-11023 (also CVE-2020-23064)  6.9   https://github.com/advisories/GHSA-jpcq-cgw6-v4j6\n"
	if out != want {
		t.Errorf("text:\n%s\nwant:\n%s", out, want)
	}
	_, out, _ = execText(t, nil, "-data", path, "-library", "ui", "-check", "1.13.1", "-md", "-s", "-cols", "Link, Published")
	if !strings.Contains(out, "| Link                                              | Published  |\n") ||
		!strings.Contains(out, "| https://github.com/advisories/GHSA-h6gj-6jjq-h8g9 | 18/07/2022 |\n") {
		t.Errorf("markdown, case-insensitive, reordered:\n%s", out)
	}
	_, out, _ = execText(t, nil, "-data", path, "-library", "mobile", "-check", "1.4.5", "-s", "-cols", "advisory,summary,cvss")
	if !strings.Contains(out, "GHSA-fj93-7wm4-8x2g  Cross-Site Scripting in jquery-mobile  -") {
		t.Errorf("summary:\n%s", out)
	}

	// Release list: notes and cves columns load the vulnerability file
	// without -cve.
	_, out, _ = execText(t, nil, "-data", path, "-library", "migrate", "-s", "-cols", "version,notes")
	if !strings.HasPrefix(out, "4.0.2            https://github.com/jquery/jquery-migrate/releases/tag/4.0.2\n") ||
		!strings.Contains(out, "\n1.0.0            -\n") {
		t.Errorf("notes:\n%s", out)
	}
	_, out, _ = execText(t, nil, "-data", path, "-library", "core", "-s", "-cols", "cves,version")
	if !regexp.MustCompile(`(?m)^CVE-2020-11022, CVE-2020-11023 \(also CVE-2020-23064\) +3\.4\.1$`).MatchString(out) {
		t.Errorf("cves without -cve:\n%s", out)
	}

	// Errors are reported before anything is loaded, with exit code 2.
	for _, args := range [][]string{
		{"-library", "core", "-check", "3.4.1", "-cols", "cvss,foo"},
		{"-cols", "link"},
		{"-cols", "version,version"},
		{"-cols", "version,"},
	} {
		code, _, stderr := execText(t, nil, append(args, "-data", filepath.Join(t.TempDir(), "missing.json"))...)
		if code != 2 || !strings.Contains(stderr, "[ERR]") || strings.Contains(stderr, "not found") {
			t.Errorf("%v: exit %d\n%s", args, code, stderr)
		}
	}

	// JSON keeps every field.
	code, out, stderr := execText(t, nil, "-data", path, "-library", "core", "-check", "3.4.1", "-json", "-cols", "cvss")
	if code != 0 || !strings.Contains(stderr, "-cols does not change -json output") || !strings.Contains(out, `"summary"`) {
		t.Errorf("json: %d %s", code, stderr)
	}
}

func TestJoinColumnArgs(t *testing.T) {
	cases := []struct{ in, want string }{
		{"-cols library, version, date", "-cols library,version,date"},
		{"-cols library ,version", "-cols library,version"},
		{"-cols library, version -md", "-cols library,version -md"},
		{"-columns library, date", "-columns library,date"},
		{"-cols=library, date", "-cols library,date"},
		{"--cols library, date", "-cols library,date"},
		{"-cols library version", "-cols library version"}, // no comma: left for the stray-argument error
		{"-cols library,", "-cols library,"},               // nothing to join: ParseColumns reports it
		{"-library mobile -md", "-library mobile -md"},
		{"-cols", "-cols"},
	}
	for _, c := range cases {
		if got := strings.Join(joinColumnArgs(strings.Fields(c.in)), " "); got != c.want {
			t.Errorf("%q: got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestColumnsArgumentHandling(t *testing.T) {
	path, _ := updatedDB(t)
	// Spaces after the commas (the shell splits them) work, and later
	// switches are still read.
	_, spaced, _ := execText(t, nil, append([]string{"-data", path, "-s", "-library", "mobile", "-cols"}, strings.Fields("library, version, date -md")...)...)
	_, joined, _ := execText(t, nil, "-data", path, "-s", "-library", "mobile", "-cols", "library,version,date", "-md")
	if spaced != joined || !strings.HasPrefix(spaced, "| Library ") {
		t.Errorf("spaced -cols:\n%s", spaced)
	}
	// -cols -h shows the column list.
	code, out, _ := execText(t, nil, "-cols", "-h")
	if code != 0 || !strings.HasPrefix(out, "Release list columns") {
		t.Errorf("-cols -h: %d\n%s", code, out)
	}
	// Errors carry exactly one hint.
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-cols", "-s"}, "[ERR] -cols needs column names, for example -cols version,date (-cols list shows them all)\n"},
		{[]string{"-cols", "library", "version"}, "[ERR] unexpected argument \"version\" (see -h)\n"},
		{[]string{"-nosuch"}, "[ERR] flag provided but not defined: -nosuch (see -h)\n"},
	} {
		code, _, stderr := execText(t, nil, c.args...)
		if code != 2 || stderr != c.want {
			t.Errorf("%v: exit %d, stderr %q, want %q", c.args, code, stderr, c.want)
		}
	}
}

func TestAliasesAndRemovedSwitches(t *testing.T) {
	path, _ := updatedDB(t)
	// cve, cves and advisory name the CVE column of either table.
	for _, name := range []string{"cve", "cves", "advisory"} {
		_, out, _ := exec(t, nil, "-data", path, "-library", "core", "-s", "-text", "-cols", "version,"+name)
		if !strings.Contains(out, "3.4.1            CVE-2020-11022, CVE-2020-11023 (also CVE-2020-23064)\n") {
			t.Errorf("release list -cols %s:\n%s", name, out[:300])
		}
		_, out, _ = exec(t, nil, "-data", path, "-library", "core", "-check", "3.4.1", "-s", "-text", "-cols", name+",cvss")
		if !strings.Contains(out, "\nCVE-2020-11022                        6.9\n") {
			t.Errorf("-check -cols %s:\n%s", name, out)
		}
	}
	if code, _, stderr := exec(t, nil, "-data", path, "-list", "-cols", "cve,cves"); code != 2 || !strings.Contains(stderr, "listed twice") {
		t.Errorf("aliases of the same column twice: %d %s", code, stderr)
	}
	// Removed switches.
	for _, sw := range []string{"-cve", "-c", "-concurrency", "-retries"} {
		if code, _, stderr := exec(t, nil, "-data", path, "-list", sw, "1"); code != 2 || !strings.Contains(stderr, "flag provided but not defined") {
			t.Errorf("%s should be gone: %d %s", sw, code, stderr)
		}
	}
	// JSON listings always carry advisories and release notes.
	_, out, _ := exec(t, nil, "-data", path, "-library", "core", "-json", "-s")
	if !strings.Contains(out, `"advisories": [`) || !strings.Contains(out, `"release_notes_url": "https://github.com/jquery/jquery/releases/tag/3.7.1"`) {
		t.Error("JSON listing without advisories")
	}
	// ... and still work when the vulnerability file is missing.
	removeVulns(t, path)
	if code, out, _ := exec(t, nil, "-data", path, "-library", "core", "-json", "-s"); code != 0 || strings.Contains(out, `"advisories"`) || !strings.Contains(out, `"version": "4.0.0"`) {
		t.Errorf("JSON without the vulnerability file: %d", code)
	}
}
