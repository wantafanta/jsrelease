package runner

import (
	"bytes"
	"encoding/json"
	"github.com/wantafanta/jsrelease/internal/datafile"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/output"
	"github.com/wantafanta/jsrelease/internal/testutil"
	"github.com/wantafanta/jsrelease/internal/vuln"
)

func TestFailedUpdateLeavesDatabaseUntouched(t *testing.T) {
	path, s := updatedDB(t)
	before := sectionOf(t, path, "releases")

	cases := map[string]func(){
		"file 404":      func() { s.Override("/jquery-3.7.1.js", testutil.Response{Status: 404}) },
		"page 500":      func() { s.Override("/mobile/", testutil.Response{Status: 500}) },
		"page redesign": func() { s.Override("/jquery/", testutil.Response{Status: 200, Body: "<html>new site</html>"}) },
		"bad date": func() {
			s.Override("/jquery-1.9.1.js", testutil.Response{Status: 200, Body: "/*! jQuery v1.9.1 | (c) jQuery\n * Date: tomorrow */"})
		},
		"html not js": func() {
			s.Override("/ui/1.14.2/jquery-ui.js", testutil.Response{Status: 200, Body: "<html>captive portal</html>"})
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			s.Reset()
			defer s.Reset()
			setup()
			cfg := fixtureConfig(s)
			// -full forces every file to be fetched so file-level faults are hit.
			code, _, stderr := execText(t, cfg, "-update", "-full", "-data", path)
			if code != 1 || !strings.Contains(stderr, "[ERR] release update failed") || !strings.Contains(stderr, "existing database was not modified") {
				t.Fatalf("code %d, stderr:\n%s", code, stderr)
			}
			for _, l := range strings.Split(stderr, "\n") {
				if strings.Contains(l, "[ERR]") {
					t.Log(l)
				}
			}
			after := sectionOf(t, path, "releases")
			if !bytes.Equal(before, after) {
				t.Fatal("database modified by failed update")
			}
			entries, _ := os.ReadDir(filepath.Dir(path))
			for _, e := range entries {
				if e.Name() != "jsrelease.json" && e.Name() != "jsrelease.json" {
					t.Fatalf("stray file: %s", e.Name())
				}
			}
		})
	}
}

func TestMissingReleaseProtection(t *testing.T) {
	path, s := updatedDB(t)
	db, _ := datafile.ReadReleases(path)
	db.Releases = append(db.Releases, catalog.Release{Library: catalog.Mobile, Name: "jQuery Mobile", Version: "9.9.9",
		ReleaseDate: "01/01/2020", SourceURL: "https://code.jquery.com/mobile/9.9.9/jquery.mobile-9.9.9.js"})
	if err := datafile.SaveReleases(path, db); err != nil {
		t.Fatal(err)
	}
	before := sectionOf(t, path, "releases")
	code, _, stderr := execText(t, fixtureConfig(s), "-update", "-data", path)
	if code != 1 || !strings.Contains(stderr, "not listed any more (jQuery Mobile 9.9.9)") {
		t.Fatalf("code %d stderr %s", code, stderr)
	}
	after := sectionOf(t, path, "releases")
	if !bytes.Equal(before, after) {
		t.Fatal("database modified")
	}
}

// TestSecondUpdateIsMinimal: once the database exists, -update only fetches
// the three release pages; -full downloads every file again.
func TestSecondUpdateIsMinimal(t *testing.T) {
	path, s := updatedDB(t)
	before, _ := datafile.ReadReleases(path)
	s.ClearRequests()
	code, out, stderr := execText(t, fixtureConfig(s), "-update", "-data", path)
	if code != 0 {
		t.Fatal(stderr)
	}
	if reqs := s.Requests(); len(reqs) != 3 {
		t.Fatalf("second update made %d requests: %v", len(reqs), reqs)
	}
	// A routine update prints exactly two summary lines: no
	// step-by-step lines, and no NVD requests (stored scores are reused).
	// Releases: 3 jQuery pages + 3 tag lists + 2 CHANGELOGs; the tag lists and
	// CHANGELOGs come back "unchanged" (the fake jQuery pages send no ETag).
	// Advisories: 1 batched GitHub list + 1 NVD search for Prototype, both
	// unchanged; no release lists (no new versions), no NVD score lookups.
	// The per-library table is the result (stdout); then a blank line and
	// the two summary lines (stderr). No step-by-step lines.
	wantOut := "\n[INF] Releases: 577, 0 new, 11 requests (8 unchanged), saved to " + path + "\n" +
		"[INF] Advisories: 36 (35 with a CVSS score), 417 releases affected, 122 with release notes, 2 requests (2 unchanged), saved to " + vulnPathFor(path) + "\n"
	if stderr != wantOut {
		t.Fatalf("update output:\n%s\nwant:\n%s", stderr, wantOut)
	}
	wantTable := "" +
		"| Library        | Releases | New | Latest | Advisories | Affects Latest |\n" +
		"|----------------|----------|-----|--------|------------|----------------|\n" +
		"| jQuery         | 87       | 0   | 4.0.0  | 8          | 0              |\n" +
		"| jQuery Migrate | 22       | 0   | 4.0.2  | 0          | 0              |\n" +
		"| jQuery UI      | 66       | 0   | 1.14.2 | 7          | 0              |\n" +
		"| jQuery Mobile  | 42       | 0   | 1.4.5  | 1          | 1              |\n" +
		"| Bootstrap      | 95       | 0   | 5.3.8  | 9          | 0              |\n" +
		"| Prototype      | 28       | 0   | 1.7.3  | 4          | 1              |\n" +
		"| Moment.js      | 96       | 0   | 2.31.0 | 5          | 0              |\n" +
		"| Underscore.js  | 83       | 0   | 1.13.8 | 2          | 0              |\n" +
		"| Sizzle         | 58       | 0   | 2.3.10 | 0          | 0              |\n"
	if out != wantTable {
		t.Fatalf("update table:\n%s\nwant:\n%s", out, wantTable)
	}
	after, _ := datafile.ReadReleases(path)
	if len(after.Releases) != len(before.Releases) {
		t.Fatal("release count changed")
	}
	for i := range before.Releases {
		if before.Releases[i] != after.Releases[i] {
			t.Fatalf("release changed: %+v", after.Releases[i])
		}
	}

	s.ClearRequests()
	if code, _, stderr := execText(t, fixtureConfig(s), "-update", "-full", "-data", path); code != 0 {
		t.Fatal(stderr)
	}
	if n := len(s.Requests()); n != 220 {
		t.Fatalf("-full made %d requests, want 220", n)
	}
}

// TestNewReleaseIsAdded simulates a release published after the last update.
func TestNewReleaseIsAdded(t *testing.T) {
	path, s := updatedDB(t)
	db, _ := datafile.ReadReleases(path)
	var kept []catalog.Release
	for _, r := range db.Releases {
		if !(r.Library == catalog.Core && r.Version == "4.0.0") {
			kept = append(kept, r)
		}
	}
	db.Releases = kept
	if err := datafile.SaveReleases(path, db); err != nil {
		t.Fatal(err)
	}
	s.ClearRequests()
	code, _, stderr := execText(t, fixtureConfig(s), "-update", "-data", path)
	if code != 0 {
		t.Fatal(stderr)
	}
	if reqs := s.Requests(); len(reqs) != 4 || reqs[3] != "/jquery-4.0.0.js" {
		t.Fatalf("requests = %v", reqs)
	}
	if !strings.Contains(stderr, "[INF] New: jQuery 4.0.0 (18/01/2026)") {
		t.Fatalf("new release not reported:\n%s", stderr)
	}

	// A failing download of a new release must leave the database unchanged.
	db.Releases = kept
	datafile.SaveReleases(path, db)
	before := sectionOf(t, path, "releases")
	s.Override("/jquery-4.0.0.js", testutil.Response{Status: 503})
	code, _, stderr = execText(t, fixtureConfig(s), "-update", "-data", path)
	if code != 1 || !strings.Contains(stderr, "HTTP 503") {
		t.Fatalf("code %d stderr %s", code, stderr)
	}
	after := sectionOf(t, path, "releases")
	if !bytes.Equal(before, after) {
		t.Fatal("database modified by failed incremental update")
	}
}

func TestCorruptDatabaseIsReplacedByUpdate(t *testing.T) {
	s := testutil.NewServer(t)
	path := filepath.Join(t.TempDir(), "db.json")
	os.WriteFile(path, []byte("{ truncated"), 0o644)
	code, _, stderr := execText(t, fixtureConfig(s), "-update", "-data", path)
	if code != 0 || !strings.Contains(stderr, "unreadable and will be rebuilt") {
		t.Fatalf("code %d stderr %s", code, stderr)
	}
	if _, err := datafile.ReadReleases(path); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateWritesVulnerabilityFile(t *testing.T) {
	gh.ClearRequests()
	path, _ := updatedDB(t)
	github, tags, nvd, raw := 0, 0, 0, 0
	for _, r := range gh.Requests() {
		switch {
		case strings.HasPrefix(r, "/nvd"):
			nvd++
		case strings.HasPrefix(r, "/raw/"):
			raw++
		case strings.Contains(r, "/tags") || strings.Contains(r, "/commits/"):
			tags++
		default:
			github++
		}
	}
	// A first update also looks up git tag dates: for the 41 undated jQuery
	// releases, 2 tag lists + 38 commits; for Bootstrap, Prototype and
	// Moment.js, 3 tag lists + 95 + 12 + 90 commits. GitHub: 1 batched
	// advisory list + 7 release lists. NVD: 1 Prototype search + 2 CVSS scores.
	if github != 10 || nvd != 3 || tags != 40+5+338 || raw != 3+77 {
		t.Errorf("requests: GitHub %d, tags %d, NVD %d, CHANGELOGs %d", github, tags, nvd, raw)
	}
	vdb, err := datafile.ReadVulns(vulnPathFor(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(vdb.Advisories) != 36 || len(vdb.Releases) != 577 {
		t.Fatalf("advisories %d, releases %d", len(vdb.Advisories), len(vdb.Releases))
	}
}

func TestSourcesUpdateIndependently(t *testing.T) {
	path, s := updatedDB(t)
	vpath := vulnPathFor(path)

	// GitHub down: the release database is still updated, the vulnerability
	// file is left as it was.
	db, _ := datafile.ReadReleases(path)
	var kept []catalog.Release
	for _, r := range db.Releases {
		if !(r.Library == catalog.Core && r.Version == "4.0.0") {
			kept = append(kept, r)
		}
	}
	db.Releases = kept
	datafile.SaveReleases(path, db)
	vBefore := sectionOf(t, vpath, "vulnerabilities")
	gh.FailWith(403)
	code, _, stderr := execText(t, fixtureConfig(s), "-update", "-data", path)
	gh.FailWith(0)
	if code != 1 || !strings.Contains(stderr, "vulnerability update failed") || !strings.Contains(stderr, "jsrelease -keys") {
		t.Fatalf("code %d stderr:\n%s", code, stderr)
	}
	if after, _ := datafile.ReadReleases(path); len(after.Releases) != 577 {
		t.Fatal("release database not updated while GitHub was failing")
	}
	if vAfter := sectionOf(t, vpath, "vulnerabilities"); !bytes.Equal(vBefore, vAfter) {
		t.Fatal("vulnerability file modified by failed update")
	}

	// Release pages down: advisories are still refreshed.
	rBefore := sectionOf(t, path, "releases")
	s.Override("/jquery/", testutil.Response{Status: 500})
	defer s.Reset()
	code, _, stderr = execText(t, fixtureConfig(s), "-update", "-data", path)
	if code != 1 || !strings.Contains(stderr, "release update failed") || !strings.Contains(stderr, "[INF] Advisories: 36 (35 with a CVSS score)") {
		t.Fatalf("code %d stderr:\n%s", code, stderr)
	}
	if rAfter := sectionOf(t, path, "releases"); !bytes.Equal(rBefore, rAfter) {
		t.Fatal("release database modified by failed update")
	}
}

func TestUpdateOutput(t *testing.T) {
	path, s := updatedDB(t)
	vpath := vulnPathFor(path)

	// -full re-checks NVD.
	gh.ClearRequests()
	_, _, stderr := execText(t, fixtureConfig(s), "-update", "-full", "-data", path)
	if !strings.Contains(stderr, "122 with release notes, 13 requests,") || strings.Contains(stderr, "|__/") {
		t.Errorf("-full:\n%s", stderr)
	}

	// A new advisory is reported with upper-case severity and its CVSS score.
	vdb, _ := datafile.ReadVulns(vpath)
	var kept []vuln.Advisory
	for _, a := range vdb.Advisories {
		if a.CVE != "CVE-2022-31160" {
			kept = append(kept, a)
		}
	}
	vdb.Advisories = kept
	vdb.Releases = nil
	vdb.GeneratedBy = "jsrelease 0.9.0" // as if written by an older version: its ETags must not be used
	if err := datafile.SaveVulns(vpath, vdb); err != nil {
		t.Fatal(err)
	}
	_, _, stderr = execText(t, fixtureConfig(s), "-update", "-data", path)
	if !strings.Contains(stderr, "[INF] New advisory: CVE-2022-31160 (Medium, CVSS 6.1) affecting jQuery UI < 1.13.2\n") ||
		strings.Count(stderr, "New advisory") != 1 {
		t.Errorf("new advisory:\n%s", stderr)
	}

	// No "New advisory" lines on a first update.
	os.Remove(vpath)
	_, _, stderr = execText(t, fixtureConfig(s), "-update", "-data", path)
	if strings.Contains(stderr, "New advisory") || !strings.Contains(stderr, "122 with release notes, 13 requests,") {
		t.Errorf("first update:\n%s", stderr)
	}

	// -v restores the step-by-step detail; -s prints nothing.
	_, _, stderr = execText(t, fixtureConfig(s), "-update", "-data", path, "-v")
	for _, want := range []string{"[DBG] Checking jQuery Core & Migrate releases", "[DBG] Checking advisories for npm packages jquery, jquery-migrate, jquery-ui",
		"[DBG] GitHub advisories unchanged", "[INF] Releases: 577"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("-v missing %q", want)
		}
	}
	code, out, stderr := execText(t, fixtureConfig(s), "-update", "-data", path, "-s")
	if code != 0 || !strings.HasPrefix(out, "| Library ") || stderr != "" { // -s: the table only
		t.Errorf("-s: exit %d, out %q, stderr %q", code, out, stderr)
	}

	// Severity: upper case when displayed, lowercase in JSON as GitHub supplies it.
	_, out, _ = execText(t, nil, "-data", path, "-library", "core", "-check", "3.4.1", "-json", "-s")
	if !strings.Contains(out, `"severity": "medium"`) || strings.Contains(out, "Medium") {
		t.Error("JSON severity must stay lowercase")
	}
	_, out, _ = execText(t, nil, "-data", path, "-library", "core", "-json", "-s")
	if !strings.Contains(out, `"severity": "medium"`) {
		t.Error("-cve JSON severity must stay lowercase")
	}
	if b, _ := os.ReadFile(vpath); strings.Contains(string(b), `"Medium"`) {
		t.Error("vulnerability file severity must stay lowercase")
	}
	_, out, _ = execText(t, nil, "-cols", "list")
	if !strings.Contains(out, "severity: Low, Medium, High or Critical") {
		t.Error("-cols list severity description")
	}
	// No command prints a banner.
	_, _, stderr = execText(t, nil, "-data", path, "-list")
	if !strings.HasPrefix(stderr, "[INF] ") || strings.Contains(stderr, "|__/") {
		t.Errorf("-list should start with its [INF] lines: %q", stderr)
	}
}

func TestTagDatesUpdate(t *testing.T) {
	path, s := updatedDB(t)

	// A newly listed undated release gets its tag date, shown on its New: line.
	db, _ := datafile.ReadReleases(path)
	var kept []catalog.Release
	for _, r := range db.Releases {
		if !(r.Library == catalog.UI && r.Version == "1.8.18") {
			kept = append(kept, r)
		}
	}
	db.Releases = kept
	datafile.SaveReleases(path, db)
	gh.ClearRequests()
	_, _, stderr := execText(t, fixtureConfig(s), "-update", "-data", path)
	if !strings.Contains(stderr, "[INF] New: jQuery UI 1.8.18 (20/02/2012*, from its git tag)") ||
		!strings.Contains(stderr, "Tag dates: 1 of 1 undated releases found from git tags") {
		t.Errorf("new undated release:\n%s", stderr)
	}

	// -full doesn't look tag dates up again: published tags don't change.
	gh.ClearRequests()
	_, _, stderr = execText(t, fixtureConfig(s), "-update", "-full", "-data", path)
	for _, r := range gh.Requests() {
		if strings.Contains(r, "/commits/") {
			t.Fatalf("-full looked up a tag date again: %s", r)
		}
	}
	if strings.Contains(stderr, "Tag dates:") {
		t.Errorf("-full:\n%s", stderr)
	}

	// GitHub failing during -full: the release update still succeeds and the
	// recorded tag dates are kept.
	gh.FailWith(403)
	code, _, stderr := execText(t, fixtureConfig(s), "-update", "-full", "-data", path)
	gh.FailWith(0)
	if code != 1 || !strings.Contains(stderr, "[WRN] Bootstrap, Prototype, Moment.js, Underscore.js and Sizzle not updated (360 previous releases kept)") {
		t.Errorf("exit %d:\n%s", code, stderr)
	}
	after, _ := datafile.ReadReleases(path)
	n := 0
	for _, r := range after.Releases {
		if r.Library.IsJQuery() && r.TagDate != "" {
			n++
		}
	}
	if n != 38 {
		t.Errorf("tag dates after failed lookup: %d, want 38", n)
	}
}

// TestStoredETagsOnlyForSameVersion: a file written by another jsrelease
// version is re-read in full, so changes in processing take effect.
func TestStoredETagsOnlyForSameVersion(t *testing.T) {
	path, s := updatedDB(t)
	_, _, stderr := execText(t, fixtureConfig(s), "-update", "-data", path)
	if !strings.Contains(stderr, "(8 unchanged)") || !strings.Contains(stderr, "2 requests (2 unchanged)") {
		t.Fatalf("same version should use stored ETags:\n%s", stderr)
	}
	db, _ := datafile.ReadReleases(path)
	db.GeneratedBy = "jsrelease 0.9.0"
	datafile.SaveReleases(path, db)
	vdb, _ := datafile.ReadVulns(vulnPathFor(path))
	vdb.GeneratedBy = "jsrelease 0.9.0"
	datafile.SaveVulns(vulnPathFor(path), vdb)
	_, _, stderr = execText(t, fixtureConfig(s), "-update", "-data", path)
	if strings.Contains(stderr, "unchanged") {
		t.Fatalf("other version's ETags were used:\n%s", stderr)
	}
	if db, _ = datafile.ReadReleases(path); db.GeneratedBy != generatedBy() || len(db.HTTPCache) == 0 {
		t.Fatalf("generated_by %q, %d ETags", db.GeneratedBy, len(db.HTTPCache))
	}
}

// TestUpdateTableAndStats: the update table marks new releases, follows the
// output format, and -stats prints the same table from the local files.
func TestUpdateTableAndStats(t *testing.T) {
	path, s := updatedDB(t)
	db, _ := datafile.ReadReleases(path)
	var kept []catalog.Release
	for _, r := range db.Releases {
		if !(r.Library == catalog.Bootstrap && r.Version == "5.3.8") {
			kept = append(kept, r)
		}
	}
	db.Releases = kept
	db.HTTPCache = nil // as if 5.3.8 were published after the last update
	datafile.SaveReleases(path, db)
	_, out, stderr := exec(t, fixtureConfig(s), "-update", "-data", path, "-text")
	if !strings.Contains(out, "\nBootstrap       95        1    5.3.8   9           0\n") ||
		!strings.Contains(stderr, "[INF] New: Bootstrap 5.3.8 (26/08/2025*, from its git tag)\n\n") {
		t.Errorf("new release in the table:\n%s\n%s", out, stderr)
	}
	outFile := filepath.Join(t.TempDir(), "update.json")
	_, out, _ = exec(t, fixtureConfig(s), "-update", "-data", path, "-json", "-s", "-o", outFile)
	var rows []output.StatsRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 9 || rows[4].Name != "Bootstrap" || rows[4].New != 0 {
		t.Fatalf("update JSON: %v %+v", err, rows)
	}
	if b, _ := os.ReadFile(outFile); string(b) != out {
		t.Error("-o file differs")
	}
	// -stats: no network, -library filter, all formats.
	gh.ClearRequests()
	code, out, _ := exec(t, nil, "-data", path, "-stats", "-library", "prototype,moment", "-s")
	if code != 0 || len(gh.Requests()) != 0 ||
		out != "| Library   | Releases | New | Latest | Advisories | Affects Latest |\n|-----------|----------|-----|--------|------------|----------------|\n| Prototype | 28       | 0   | 1.7.3  | 4          | 1              |\n| Moment.js | 96       | 0   | 2.31.0 | 5          | 0              |\n" {
		t.Errorf("-stats:\n%s", out)
	}
	// -update -list still lists instead of showing the table.
	_, out, _ = exec(t, fixtureConfig(s), "-update", "-list", "-data", path, "-s", "-library", "migrate")
	if !strings.HasPrefix(out, "| Library        | Version | Release Date | Support") {
		t.Errorf("-update -list:\n%s", out[:200])
	}
}

// TestFailedGitStepForgetsETags: if a git-published library's update fails
// after its tag list was fetched (e.g. a commit lookup is rate-limited), the
// tag list must not be remembered as seen, or the new release would be
// missed on every later update.
func TestFailedGitStepForgetsETags(t *testing.T) {
	path, s := updatedDB(t)
	db, _ := datafile.ReadReleases(path)
	var kept []catalog.Release
	for _, r := range db.Releases {
		if !(r.Library == catalog.Bootstrap && r.Version == "5.3.8") {
			kept = append(kept, r)
		}
	}
	db.Releases, db.HTTPCache = kept, nil // 5.3.8 is new upstream
	datafile.SaveReleases(path, db)

	gh.FailPrefix("/repos/twbs/bootstrap/commits/", 403)
	_, _, stderr := exec(t, fixtureConfig(s), "-update", "-data", path)
	gh.FailPrefix("", 0)
	if !strings.Contains(stderr, "not updated") {
		t.Fatalf("expected the git step to fail:\n%s", stderr)
	}
	_, _, stderr = exec(t, fixtureConfig(s), "-update", "-data", path)
	if !strings.Contains(stderr, "[INF] New: Bootstrap 5.3.8 (26/08/2025*, from its git tag)") {
		t.Fatalf("new release missed after a failed update:\n%s", stderr)
	}
}

// TestBlankLineBeforeUpdateTable: the table is separated from any messages
// printed above it (here -v detail or a warning), and from nothing otherwise.
func TestBlankLineBeforeUpdateTable(t *testing.T) {
	path, s := updatedDB(t)
	_, _, stderr := exec(t, fixtureConfig(s), "-update", "-data", path, "-v")
	if !regexp.MustCompile(`\[DBG\] [^\n]*\n\n\n\[INF\] Releases: `).MatchString(stderr) {
		t.Errorf("-v: the last [DBG] line needs a blank line before the table:\n%s", stderr[len(stderr)-400:])
	}
	gh.FailPrefix("/repos/jquery/sizzle/releases", 500) // a warning just before the table
	_, _, stderr = exec(t, fixtureConfig(s), "-update", "-data", path, "-full")
	gh.FailPrefix("", 0)
	if !strings.Contains(stderr, "\n\n\n[INF] Releases: ") {
		t.Errorf("warning: no blank line before the table:\n%s", stderr)
	}
	_, _, stderr = exec(t, fixtureConfig(s), "-update", "-data", path)
	if !strings.HasPrefix(stderr, "\n[INF] Releases: ") {
		t.Errorf("nothing printed before the table, so only the blank line after it:\n%q", stderr)
	}
}

// TestInstalledUse: with no data files anywhere, an installed jsrelease reads
// the bundled data, and -update saves to the per-user data folder.
func TestInstalledUse(t *testing.T) {
	_, s := updatedDB(t)
	Bundled, _ = os.ReadFile(testutil.ShippedFile())
	defer func() { Bundled = nil }()
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("LocalAppData", dataHome)

	_, out, stderr := exec(t, nil, "-library", "migrate")
	if !strings.Contains(stderr, "Loaded 577 releases from the bundled data") || !strings.Contains(out, "| jQuery Migrate | 4.0.2") {
		t.Fatalf("reading the bundled data:\n%s", stderr)
	}
	if _, err := os.Stat(filepath.Join(dataHome, "jsrelease")); err == nil {
		t.Fatal("reading must not write anything")
	}
	if _, _, stderr := exec(t, nil, "-stats"); !strings.Contains(stderr, "Loaded 36 advisories from the bundled data") {
		t.Errorf("-stats must say where the advisories came from:\n%s", stderr)
	}
	code, _, stderr := exec(t, fixtureConfig(s), "-update")
	dir, _ := userDataDir()
	if code != 0 || !strings.Contains(stderr, "saved to "+filepath.Join(dir, "jsrelease.json")) {
		t.Fatalf("update into the data folder: %d\n%s", code, stderr)
	}
	if _, err := datafile.ReadReleases(filepath.Join(dir, "jsrelease.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := datafile.ReadVulns(filepath.Join(dir, "jsrelease.json")); err != nil {
		t.Fatal(err)
	}
	// From now on that copy is used.
	_, _, stderr = exec(t, nil, "-library", "migrate")
	if !strings.Contains(stderr, "Loaded 577 releases from "+filepath.Join(dir, "jsrelease.json")) {
		t.Errorf("later runs should use the saved copy:\n%s", stderr)
	}
}

// TestVerboseOutputIsStable: two routine updates in a row print the same
// -v detail, in the same order (it used to vary with Go's map order).
func TestVerboseOutputIsStable(t *testing.T) {
	path, s := updatedDB(t)
	exec(t, fixtureConfig(s), "-update", "-data", path) // stores the ETags
	_, _, first := exec(t, fixtureConfig(s), "-update", "-data", path, "-v", "-nc")
	_, _, second := exec(t, fixtureConfig(s), "-update", "-data", path, "-v", "-nc")
	if first != second {
		t.Fatalf("-v output differs between identical runs:\n%s\n----\n%s", first, second)
	}
	for _, want := range []string{"[DBG] Data file: " + path + "\n", "[DBG] 217 jQuery releases already recorded in " + path + "\n",
		"[DBG] 41 jQuery releases have no release date"} {
		if !strings.Contains(first, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(first, "0 NVD score(s) reused") {
		t.Error("misleading '0 NVD score(s) reused' line")
	}
	// The jQuery no-date line belongs to the jQuery step, before the
	// libraries published through GitHub.
	if strings.Index(first, "41 jQuery releases have no release date") > strings.Index(first, "Checking Bootstrap tags") {
		t.Error("jQuery summary printed after the GitHub libraries")
	}
}
