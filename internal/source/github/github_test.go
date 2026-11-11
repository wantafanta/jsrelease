package github

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/testutil"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "vuln", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseUnderscoreChangelog(t *testing.T) {
	vs, dates := ParseUnderscoreChangelog(readFixture(t, "changelog-underscore.html"))
	if len(vs) != 81 || len(dates) != 81 || dates["1.13.8"].Format("02/01/2006") != "19/02/2026" || dates["0.1.0"].IsZero() {
		t.Fatalf("underscore: %d versions, %d dates", len(vs), len(dates))
	}
}

func TestParseChangelogs(t *testing.T) {
	vs, dates := ParsePrototypeChangelog(readFixture(t, "changelog-prototype.txt"))
	if len(vs) != 24 || len(dates) != 24 || dates["1.7"].Format("02/01/2006") != "16/11/2010" || dates["1.5.0_pre0"].Format("02/01/2006") != "18/01/2006" {
		t.Fatalf("prototype: %d versions, %d dates", len(vs), len(dates))
	}
	vs, dates = ParseMomentChangelog(readFixture(t, "changelog-moment.md"))
	if len(vs) != 92 || len(dates) != 85 || dates["2.31.0"].Format("02/01/2006") != "14/09/2026" || dates["2.14.0"].Format("02/01/2006") != "20/07/2016" {
		t.Fatalf("moment: %d versions, %d dates", len(vs), len(dates))
	}
	if dates["2.29.0"].Format("02/01/2006") != "22/09/2020" { // written "Sept 22, 2020"
		t.Error("2.29.0 Sept date not read")
	}
	if _, ok := dates["2.10.0"]; ok {
		t.Error("2.10.0 has no Released line in the CHANGELOG")
	}
	for _, s := range []string{"Sep 14, 2026", "Sept 14, 2026", "September 14 2026", "Sep. 14, 2026"} {
		if d, err := parseLongDate(s); err != nil || d.Format("02/01/2006") != "14/09/2026" {
			t.Errorf("parseLongDate(%q) = %v, %v", s, d, err)
		}
	}
}

func run(t *testing.T, g *testutil.GitHubServer, known []catalog.Release, full bool) *Result {
	t.Helper()
	res, err := Run(context.Background(), Config{APIBase: g.URL, RawBase: g.URL + "/raw", Known: known, Full: full})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func byKey(rs []catalog.Release) map[string]catalog.Release {
	m := map[string]catalog.Release{}
	for _, r := range rs {
		m[string(r.Library)+"@"+r.Version] = r
	}
	return m
}

func TestRunRealData(t *testing.T) {
	g := testutil.NewGitHubServer()
	defer g.Close()
	res := run(t, g, nil, false)
	counts := catalog.CountByLibrary(res.Releases)
	if counts[catalog.Bootstrap] != 95 || counts[catalog.Prototype] != 28 || counts[catalog.Moment] != 96 || counts[catalog.Underscore] != 83 || counts[catalog.Sizzle] != 58 || len(res.New) != 360 {
		t.Fatalf("counts %v, new %d", counts, len(res.New))
	}
	db := catalog.New()
	db.Releases = res.Releases
	if err := db.Validate(); err != nil {
		t.Fatal(err)
	}
	m := byKey(res.Releases)
	cases := []struct{ key, display, source string }{
		{"bootstrap@1.0.0", "18/08/2011*", "https://github.com/twbs/bootstrap/tree/v1.0.0"},
		{"bootstrap@5.3.8", "26/08/2025*", "https://github.com/twbs/bootstrap/tree/v5.3.8"},
		{"prototype@1.7", "16/11/2010\u2021", "https://github.com/prototypejs/prototype/tree/1.7"},
		{"prototype@1.5.0_pre0", "18/01/2006\u2021", "https://github.com/prototypejs/prototype/blob/HEAD/CHANGELOG"}, // no tag
		{"prototype@1.7.3", "23/09/2015*", "https://github.com/prototypejs/prototype/tree/1.7.3"},                    // after the CHANGELOG stopped
		{"moment@2.31.0", "14/09/2026\u2021", "https://github.com/moment/moment/tree/2.31.0"},
		{"moment@2.14.0", "20/07/2016\u2021", "https://github.com/moment/moment/tree/2.14.0"}, // CHANGELOG, though the tag says 03/07
		{"moment@2.29.0", "22/09/2020\u2021", "https://github.com/moment/moment/tree/2.29.0"},
	}
	for _, c := range cases {
		r, ok := m[c.key]
		if !ok {
			t.Errorf("%s missing", c.key)
			continue
		}
		if c.display != "" && (r.DisplayDate() != c.display || r.SourceURL != c.source) {
			t.Errorf("%s: %q %q", c.key, r.DisplayDate(), r.SourceURL)
		}
	}
	if r := m["moment@2.6.0"]; r.ChangelogDate != "" || !strings.HasSuffix(r.DisplayDate(), "*") {
		t.Errorf("moment 2.6.0 should fall back to its tag date: %+v", r)
	}
	if r := m["moment@2.10.0"]; r.DisplayDate() != "" || !r.TagChecked {
		t.Errorf("moment 2.10.0 has neither a CHANGELOG date nor a tag: %+v", r)
	}
	if r := m["moment@0.1.0"]; r.DisplayDate() != "" || r.SourceURL != "https://github.com/moment/moment/blob/HEAD/CHANGELOG.md" {
		t.Errorf("moment 0.1.0 is only in the CHANGELOG, with no date: %+v", r)
	}
	if r := m["underscore@1.13.8"]; r.DisplayDate() != "19/02/2026\u2021" || r.TagDate != "03/03/2026" {
		t.Errorf("underscore 1.13.8 (CHANGELOG first): %+v", r)
	}
	if r := m["underscore@1.3.2"]; r.ChangelogDate != "" || !strings.HasSuffix(r.DisplayDate(), "*") {
		t.Errorf("underscore 1.3.2 is only tagged: %+v", r)
	}
	// Sizzle: the date in its own release file, like jQuery's (no marker).
	if r := m["sizzle@2.3.10"]; r.DisplayDate() != "14/02/2023" || r.TagDate != "" || r.DateNote != "" ||
		r.SourceURL != "https://github.com/jquery/sizzle/blob/2.3.10/dist/sizzle.js" || r.TagURL != "https://github.com/jquery/sizzle/tree/2.3.10" {
		t.Errorf("sizzle 2.3.10: %+v", r)
	}
	if r := m["sizzle@1.0.0"]; r.ReleaseDate != "" || !strings.HasSuffix(r.DisplayDate(), "*") {
		t.Errorf("sizzle 1.0.0 has no date in its file, so its tag date: %+v", r)
	}
	if _, ok := m["sizzle@2.1.1-jquery.2.1.2"]; ok {
		t.Error("the jQuery build tag must not be a Sizzle release")
	}
	if len(res.Disagreements) != 11 || !strings.Contains(strings.Join(res.Disagreements, "\n"), "Sizzle 1.9.2: release file says 16/04/2013, git tag 18/04/2013") || !strings.Contains(strings.Join(res.Disagreements, "\n"), "Underscore.js 1.12.1: CHANGELOG says 15/03/2021, git tag 29/03/2021") || !strings.Contains(strings.Join(res.Disagreements, "\n"), "Moment.js 2.14.0: CHANGELOG says 20/07/2016, git tag 04/07/2016") {
		t.Errorf("disagreements: %v", res.Disagreements)
	}
	// 5 tag lists + 3 CHANGELOGs + one commit per tag (95 + 12 + 90 + 83 + 58)
	// + Sizzle's release files (77: older tags try two paths).
	if res.Requests != 5+3+95+12+90+83+58+77 {
		t.Errorf("first run requests = %d", res.Requests)
	}

	// Second run: tag dates reused, only the lists and CHANGELOGs are read.
	again := run(t, g, res.Releases, false)
	if again.Requests != 8 || len(again.New) != 0 {
		t.Errorf("second run: %d requests, %d new", again.Requests, len(again.New))
	}
	if again.Releases[0] != res.Releases[0] {
		t.Error("records changed on a second run")
	}
	// -full looks all tag dates up again.
	if full := run(t, g, res.Releases, true); full.Requests != res.Requests {
		t.Errorf("full run requests = %d", full.Requests)
	}
}

func TestRunErrors(t *testing.T) {
	g := testutil.NewGitHubServer()
	defer g.Close()
	res := run(t, g, nil, false)
	// A recorded release that is no longer listed is an error.
	known := append(res.Releases, catalog.Release{Library: catalog.Bootstrap, Name: "Bootstrap", Version: "9.9.9", DateNote: "x", SourceURL: "x"})
	if _, err := Run(context.Background(), Config{APIBase: g.URL, RawBase: g.URL + "/raw", Known: known}); err == nil || !strings.Contains(err.Error(), "bootstrap@9.9.9") {
		t.Errorf("missing release: %v", err)
	}
	g.FailWith(403)
	_, err := Run(context.Background(), Config{APIBase: g.URL, RawBase: g.URL + "/raw"})
	g.FailWith(0)
	if err == nil || !strings.Contains(err.Error(), "jsrelease -keys") {
		t.Errorf("rate limit: %v", err)
	}
	// An unreadable CHANGELOG is reported, not silently ignored.
	if _, err := Run(context.Background(), Config{APIBase: g.URL, RawBase: g.URL + "/missing"}); err == nil || !strings.Contains(err.Error(), "CHANGELOG") {
		t.Errorf("changelog: %v", err)
	}
}
