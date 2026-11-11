package runner

import (
	"encoding/json"
	"github.com/wantafanta/jsrelease/internal/datafile"
	"github.com/wantafanta/jsrelease/internal/testutil"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/output"
)

func TestUpdateThenList(t *testing.T) {
	path, _ := updatedDB(t)
	db, err := datafile.ReadReleases(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Releases) != 577 || db.UpdatedAt == "" || db.Source != "https://releases.jquery.com/" {
		t.Fatalf("db: %d releases, updated %q", len(db.Releases), db.UpdatedAt)
	}

	code, out, stderr := execText(t, nil, "-data", path, "-list")
	if code != 0 {
		t.Fatalf("list failed: %s", stderr)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if lines[0] != "Library         Version          Release Date  Support" || len(lines) != 1+577+1+3 || lines[len(lines)-3] != output.TagDateFootnote ||
		lines[len(lines)-2] != output.ChangelogDateFootnote || lines[len(lines)-1] != output.InferredFootnote {
		t.Fatalf("unexpected table head %q (%d lines)", lines[0], len(lines))
	}
	if lines[1] != "jQuery          4.0.0            18/01/2026    Supported" || lines[2] != "jQuery          3.7.1            28/08/2023    Security only" {
		t.Fatalf("unexpected first rows:\n%s\n%s", lines[1], lines[2])
	}
	if !strings.HasPrefix(stderr, "[INF] Loaded 577 releases") {
		t.Errorf("stderr should start with the [INF] lines (no banner): %s", stderr)
	}
	// Library order: core, migrate, ui, mobile.
	order := []string{}
	for _, l := range lines[1 : len(lines)-4] { // table rows, without the footnotes
		name := strings.TrimSpace(l[:16])
		if len(order) == 0 || order[len(order)-1] != name {
			order = append(order, name)
		}
	}
	if strings.Join(order, ",") != "jQuery,jQuery Migrate,jQuery UI,jQuery Mobile,Bootstrap,Prototype,Moment.js,Underscore.js,Sizzle" {
		t.Errorf("library order = %v", order)
	}
}

func TestSilentJSONLibraryAndOutputFile(t *testing.T) {
	path, _ := updatedDB(t)

	code, out, stderr := execText(t, nil, "-data", path, "-silent", "-library", "migrate")
	if code != 0 || stderr != "" {
		t.Fatalf("silent: code %d stderr %q", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 22 || !strings.HasPrefix(lines[0], "jQuery Migrate  4.0.2") {
		t.Fatalf("silent migrate output:\n%s", out)
	}

	outFile := filepath.Join(t.TempDir(), "jsrelease.json")
	code, out, _ = execText(t, nil, "-data", path, "-json", "-library", "ui,mobile", "-o", outFile, "-s")
	if code != 0 {
		t.Fatal("json failed")
	}
	var rs []catalog.Release
	if err := json.Unmarshal([]byte(out), &rs); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(rs) != 108 || rs[0].Library != catalog.UI || rs[len(rs)-1].Library != catalog.Mobile {
		t.Fatalf("json: %d releases", len(rs))
	}
	file, _ := os.ReadFile(outFile)
	if string(file) != out {
		t.Fatal("-output file differs from stdout")
	}
	for _, r := range rs {
		if r.ReleaseDate == "" && r.DateNote == "" {
			t.Fatalf("undated release without note: %+v", r)
		}
	}
}

// TestShippedDatabase guards the database distributed with the project.
func TestShippedDatabase(t *testing.T) {
	db, err := datafile.ReadReleases(testutil.ShippedFile())
	if err != nil {
		t.Fatal(err)
	}
	counts := catalog.CountByLibrary(db.Releases)
	if counts[catalog.Core] < 87 || counts[catalog.Migrate] < 22 || counts[catalog.UI] < 66 || counts[catalog.Mobile] < 42 {
		t.Fatalf("shipped database incomplete: %v", counts)
	}
	if counts[catalog.Bootstrap] < 95 || counts[catalog.Prototype] < 28 || counts[catalog.Moment] < 96 {
		t.Fatalf("shipped database incomplete: %v", counts)
	}
	for _, r := range db.Releases {
		want := "https://code.jquery.com/"
		if !r.Library.IsJQuery() {
			want = "https://github.com/"
		}
		if !strings.HasPrefix(r.SourceURL, want) {
			t.Fatalf("unexpected source_url: %+v", r)
		}
	}
}

func TestCVEListing(t *testing.T) {
	path, _ := updatedDB(t)
	code, out, stderr := execText(t, nil, "-data", path, "-cols", "library,version,date,support,cves", "-library", "core")
	if code != 0 {
		t.Fatal(stderr)
	}
	lines := strings.Split(out, "\n")
	if !strings.HasPrefix(lines[0], "Library         Version          Release Date  Support        CVEs") {
		t.Fatalf("header: %q", lines[0])
	}
	cvesAt := strings.Index(lines[0], "CVEs")
	want := map[string]string{
		"4.0.0":  "-",
		"3.4.1":  "CVE-2020-11022, CVE-2020-11023 (also CVE-2020-23064)",
		"1.12.2": "CVE-2020-11022, CVE-2020-11023 (also CVE-2020-23064), CVE-2019-11358 (also CVE-2019-5428)",
	}
	for v, cves := range want {
		found := false
		for _, l := range lines {
			f := strings.Fields(l)
			if len(f) > 2 && f[1] == v {
				found = true
				if got := strings.TrimSpace(l[cvesAt:]); got != cves {
					t.Errorf("%s: CVEs = %q, want %q", v, got, cves)
				}
			}
		}
		if !found {
			t.Errorf("row %s missing", v)
		}
	}

	code, out, _ = execText(t, nil, "-data", path, "-json", "-s", "-library", "core")
	var rs []struct {
		Version         string  `json:"version"`
		ReleaseNotesURL *string `json:"release_notes_url"`
		Advisories      []struct {
			ID, CVE string
		} `json:"advisories"`
	}
	if err := json.Unmarshal([]byte(out), &rs); err != nil || code != 0 {
		t.Fatalf("json: %v", err)
	}
	for _, r := range rs {
		if r.Version == "3.7.1" && (r.ReleaseNotesURL == nil || *r.ReleaseNotesURL != "https://github.com/jquery/jquery/releases/tag/3.7.1" || len(r.Advisories) != 0) {
			t.Errorf("3.7.1: %+v", r)
		}
		if r.Version == "3.4.1" && (len(r.Advisories) != 2 || r.ReleaseNotesURL != nil) {
			t.Errorf("3.4.1: %+v", r)
		}
	}
}

func TestMarkdownOutput(t *testing.T) {
	path, _ := updatedDB(t)
	code, out, _ := execText(t, nil, "-data", path, "-md", "-s", "-library", "migrate")
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if code != 0 || len(lines) != 2+22 ||
		lines[0] != "| Library        | Version | Release Date | Support        |" ||
		lines[1] != "|----------------|---------|--------------|----------------|" ||
		lines[2] != "| jQuery Migrate | 4.0.2   | 21/01/2026   | Supported\u2020     |" {
		t.Fatalf("markdown:\n%s", out)
	}
	// -markdown is the long form; the heading is kept with or without -silent.
	_, long, _ := execText(t, nil, "-data", path, "-markdown", "-s", "-library", "migrate")
	if long != out {
		t.Fatal("-markdown and -md differ")
	}
	code, out, _ = execText(t, nil, "-data", path, "-md", "-s", "-cols", "library,version,date,support,cves", "-library", "ui")
	if code != 0 || !strings.HasPrefix(out, "| Library   | Version        | Release Date | Support      | CVEs") ||
		!strings.Contains(out, "| jQuery UI | 1.13.1         | 20/01/2022   | Unsupported† | CVE-2022-31160 ") {
		t.Fatalf("markdown -cve:\n%s", out)
	}
	// Every line has the same width and the same number of unescaped pipes.
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if utf8.RuneCountInString(l) != utf8.RuneCountInString(strings.Split(out, "\n")[0]) || strings.Count(strings.ReplaceAll(l, `\|`, ""), "|") != 6 {
			t.Fatalf("misaligned line: %q", l)
		}
	}
	if code, _, stderr := exec(t, nil, "-data", path, "-list", "-text", "-json"); code != 2 || !strings.Contains(stderr, "-json and -text cannot be used together") {
		t.Errorf("-text -json: %d %s", code, stderr)
	}
	if code, _, _ := exec(t, nil, "-data", path, "-md"); code != 2 {
		t.Errorf("-md should no longer exist, exit %d", code)
	}
	if code, _, _ := execText(t, nil, "-data", path, "-latex"); code != 2 {
		t.Errorf("-latex should no longer exist, exit %d", code)
	}
}

func TestTagDatesDisplay(t *testing.T) {
	path, _ := updatedDB(t)
	foot := output.TagDateFootnote

	_, out, _ := execText(t, nil, "-data", path, "-library", "ui")
	if !strings.Contains(out, "jQuery UI       1.8.18           20/02/2012*   Unsupported\u2020\n") ||
		!strings.Contains(out, "jQuery UI       1.7.3            N/A           Unsupported\u2020\n") ||
		!strings.Contains(out, "jQuery UI       1.8.19           16/04/2012    Unsupported\u2020\n") ||
		!strings.HasSuffix(out, "\n\n"+foot+"\n"+output.InferredFootnote+"\n") {
		t.Errorf("text:\n%s", out)
	}
	_, out, _ = execText(t, nil, "-data", path, "-library", "ui", "-s")
	if strings.Contains(out, "git tag") || !strings.Contains(out, "20/02/2012*") {
		t.Error("-s must keep the star but drop the footnote")
	}
	_, out, _ = execText(t, nil, "-data", path, "-library", "mobile", "-md")
	if !strings.HasSuffix(out, "|\n\n\\"+foot+"\\\n"+output.InferredFootnote+"\n") {
		t.Errorf("markdown footnote:\n%s", out[len(out)-200:])
	}
	_, out, _ = execText(t, nil, "-data", path, "-library", "core")
	if strings.Contains(out, "git tag") || strings.Contains(out, "inferred") {
		t.Error("footnote shown although no date is starred")
	}

	_, out, _ = execText(t, nil, "-data", path, "-library", "ui", "-check", "1.8.18", "-cols", "advisory")
	if !strings.HasPrefix(out, "Library    Version  Release Date  Support       Latest  Latest Release Date\n"+
		"jQuery UI  1.8.18   20/02/2012*   Unsupported\u2020  1.14.2  28/01/2026\n\n"+foot+"\n"+output.InferredFootnote+"\n\n") {
		t.Errorf("check:\n%s", out)
	}
	_, out, _ = execText(t, nil, "-data", path, "-library", "ui", "-check", "1.8.18", "-s", "-md")
	if strings.Contains(out, "git tag") {
		t.Error("check -s -md must not show the footnote")
	}

	_, out, _ = execText(t, nil, "-data", path, "-library", "ui", "-json", "-s")
	if !strings.Contains(out, `"tag_date": "20/02/2012",`) || !strings.Contains(out, `"tag_url": "https://github.com/jquery/jquery-ui/tree/1.8.18"`) ||
		strings.Contains(out, `2012*`) {
		t.Error("JSON tag fields")
	}
	_, out, _ = execText(t, nil, "-data", path, "-library", "ui", "-check", "1.8.18", "-json", "-s")
	if !strings.Contains(out, `"tag_date": "20/02/2012"`) {
		t.Error("check JSON tag_date")
	}
}

func TestFormatUpdated(t *testing.T) {
	ny := time.FixedZone("EST", -5*3600)
	bst := time.FixedZone("BST", 3600)
	cases := []struct {
		in   string
		loc  *time.Location
		want string
	}{
		{"2026-11-09T16:52:06Z", time.UTC, "09/11/2026 16:52:06"},
		{"2026-11-09T16:52:06Z", ny, "09/11/2026 11:52:06"},
		{"2026-07-01T23:30:00Z", bst, "02/07/2026 00:30:00"}, // crosses midnight
		{"", time.UTC, "never"},
		{"not a time", time.UTC, "not a time"},
	}
	for _, c := range cases {
		if got := formatUpdated(c.in, c.loc); got != c.want {
			t.Errorf("formatUpdated(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBlankLineBeforeResults(t *testing.T) {
	path, s := updatedDB(t)
	_, out, stderr := execText(t, nil, "-data", path, "-library", "mobile")
	if !regexp.MustCompile(`\[INF\] Loaded 577 releases from .* \(updated \d\d/\d\d/\d{4} \d\d:\d\d:\d\d\)\n\n$`).MatchString(stderr) {
		t.Errorf("stderr should end with the Loaded line and a blank line:\n%q", stderr)
	}
	if strings.HasPrefix(out, "\n") {
		t.Error("the blank line must go to stderr, not into the results")
	}
	_, _, stderr = execText(t, nil, "-data", path, "-library", "ui", "-check", "1.13.1")
	if !strings.HasSuffix(stderr, "1 advisories\n\n") {
		t.Errorf("check:\n%q", stderr)
	}
	if _, _, stderr = execText(t, nil, "-data", path, "-s", "-library", "mobile"); stderr != "" {
		t.Errorf("-s: %q", stderr)
	}
	// A plain update prints no results, so no blank line.
	_, _, stderr = execText(t, fixtureConfig(s), "-update", "-data", path)
	if strings.HasSuffix(stderr, "\n\n") {
		t.Error("blank line after an update without results")
	}
}

// TestFootnotesPlainOnTerminal: footnotes are plain text on a terminal, and
// escaped Markdown in -o files and pipes.
func TestFootnotesPlainOnTerminal(t *testing.T) {
	path, _ := updatedDB(t)
	outFile := filepath.Join(t.TempDir(), "ui.md")
	// Not a terminal (pipe): escaped.
	_, piped, _ := exec(t, nil, "-data", path, "-library", "ui")
	if !strings.Contains(piped, "\n\\"+output.TagDateFootnote+"\\\n"+output.InferredFootnote+"\n") {
		t.Fatalf("pipe should get escaped footnotes:\n%s", piped[len(piped)-200:])
	}
	// Terminal: plain, while the -o file is still escaped.
	old := isTerminal
	isTerminal = func(io.Writer) bool { return true }
	defer func() { isTerminal = old }()
	_, screen, _ := exec(t, nil, "-data", path, "-library", "ui", "-o", outFile)
	if !strings.HasSuffix(screen, "\n\n"+output.TagDateFootnote+"\n"+output.InferredFootnote+"\n") || strings.Contains(screen, "\\") {
		t.Errorf("terminal should get plain footnotes:\n%s", screen[len(screen)-200:])
	}
	if b, _ := os.ReadFile(outFile); string(b) != piped {
		t.Error("the -o file should keep the escaped Markdown")
	}
	// Table contents are untouched: only the footnote lines change.
	if strings.Count(screen, "\n") != strings.Count(piped, "\n") {
		t.Error("line count changed")
	}
}

// TestStaleHint: data more than 30 days old gets a one-line suggestion.
func TestStaleHint(t *testing.T) {
	path, _ := updatedDB(t)
	old := now
	defer func() { now = old }()
	now = func() time.Time { return time.Now().Add(47 * 24 * time.Hour) }
	_, _, stderr := exec(t, nil, "-data", path, "-library", "migrate")
	if !strings.Contains(stderr, "[INF] Data is 47 days old; run 'jsrelease -up' to refresh\n") {
		t.Errorf("no hint for old data:\n%s", stderr)
	}
	if _, _, stderr := exec(t, nil, "-data", path, "-stats", "-s"); stderr != "" {
		t.Errorf("-s must hide the hint: %q", stderr)
	}
	now = time.Now
	if _, _, stderr := exec(t, nil, "-data", path, "-library", "migrate"); strings.Contains(stderr, "days old") {
		t.Errorf("hint for fresh data:\n%s", stderr)
	}
}
