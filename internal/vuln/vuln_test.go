package vuln

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/wantafanta/jsrelease/internal/testutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/logger"
)

// The testdata files are real responses of the GitHub REST API
// (/advisories?ecosystem=npm&affects=<pkg> and /repos/jquery/<repo>/releases).

type ghServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []string
	auth     []string
	override map[string]func(w http.ResponseWriter, r *http.Request)
}

func newGHServer(t *testing.T) *ghServer {
	s := &ghServer{override: map[string]func(http.ResponseWriter, *http.Request){}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests = append(s.requests, r.URL.RequestURI())
		s.auth = append(s.auth, r.Header.Get("Authorization"))
		ov := s.override[r.URL.Path+"?"+r.URL.Query().Get("affects")]
		s.mu.Unlock()
		if ov != nil {
			ov(w, r)
			return
		}
		var name string
		switch {
		case strings.HasPrefix(r.URL.Path, "/raw/"):
			parts := strings.Split(r.URL.Path, "/") // /raw/<owner>/<repo>/HEAD/<file>
			name = map[string]string{"prototype": "changelog-prototype.txt", "moment": "changelog-moment.md", "underscore": "changelog-underscore.html"}[parts[3]]
		case r.URL.Path == "/nvd" && r.URL.Query().Get("virtualMatchString") != "":
			product := r.URL.Query().Get("virtualMatchString")
			name = "nvd-cpe-" + product[strings.LastIndex(product, ":")+1:] + ".json" // e.g. nvd-cpe-prototypejs.json
		case r.URL.Path == "/nvd":
			name = "nvd-" + r.URL.Query().Get("cveId") + ".json"
			if _, err := os.Stat(filepath.Join("testdata", name)); err != nil {
				w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"format":"NVD_CVE","version":"2.0","vulnerabilities":[]}`))
				return
			}
		case strings.HasPrefix(r.URL.Path, "/repos/") && strings.HasSuffix(r.URL.Path, "/tags"):
			parts := strings.Split(r.URL.Path, "/") // /repos/<owner>/<repo>/tags
			name = "tags-" + parts[3] + ".json"
			if _, err := os.Stat(filepath.Join("testdata", name)); err != nil {
				w.Write([]byte("[]"))
				return
			}
		case strings.HasPrefix(r.URL.Path, "/repos/") && strings.Contains(r.URL.Path, "/commits/"):
			parts := strings.Split(r.URL.Path, "/") // /repos/<owner>/<repo>/commits/<sha>
			var dates map[string]string
			b, _ := os.ReadFile(filepath.Join("testdata", "commits-"+parts[3]+".json"))
			json.Unmarshal(b, &dates)
			d, ok := dates[parts[5]]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte(`{"sha":"` + parts[5] + `","commit":{"committer":{"date":"` + d + `"}}}`))
			return
		case r.URL.Path == "/advisories" && strings.Contains(r.URL.Query().Get("affects"), ","):
			// Several packages in one request: the union of their responses.
			var all []map[string]any
			seenID := map[string]bool{}
			for _, pkg := range strings.Split(r.URL.Query().Get("affects"), ",") {
				var items []map[string]any
				b, _ := os.ReadFile(filepath.Join("testdata", "adv-"+pkg+".json"))
				json.Unmarshal(b, &items)
				for _, it := range items {
					if id, _ := it["ghsa_id"].(string); !seenID[id] {
						seenID[id] = true
						all = append(all, it)
					}
				}
			}
			b, _ := json.Marshal(all)
			writeWithETag(w, r, b)
			return
		case r.URL.Path == "/advisories":
			name = "adv-" + r.URL.Query().Get("affects") + ".json"
		case strings.HasPrefix(r.URL.Path, "/repos/") && strings.HasSuffix(r.URL.Path, "/releases"):
			parts := strings.Split(r.URL.Path, "/") // /repos/<owner>/<repo>/releases
			name = "rel-" + parts[3] + ".json"
		}
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		writeWithETag(w, r, b)
	}))
	t.Cleanup(s.Close)
	return s
}

func shippedReleases(t *testing.T) []catalog.Release {
	t.Helper()
	return testutil.ShippedReleases(t)
}

func fetchFixture(t *testing.T) *Database {
	t.Helper()
	s := newGHServer(t)
	res, err := Fetch(context.Background(), Config{APIBase: s.URL, NVDBase: s.URL + "/nvd", UserAgent: "test"}, shippedReleases(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Requests != 10 {
		t.Errorf("requests = %d, want 10 (1 batched advisory list + 9 release lists)", res.Requests)
	}
	return res.DB
}

func names(as []Advisory) string {
	var out []string
	for _, a := range as {
		out = append(out, a.Name())
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestInRange(t *testing.T) {
	cases := []struct {
		rng, v string
		want   bool
	}{
		{">= 1.12.0, < 3.5.0", "3.4.1", true}, {">= 1.12.0, < 3.5.0", "3.5.0", false},
		{">= 1.12.0, < 3.5.0", "1.11.3", false}, {">= 1.12.0, < 3.5.0", "1.12.0", true},
		{"<= 1.8.3", "1.8.3", true}, {"<= 1.8.3", "1.9.0", false},
		{"= 3.0.0-rc.1", "3.0.0-rc1", true}, {"= 3.0.0-rc.1", "3.0.0", false},
		{"< 3.5.0", "3.0.0-rc1", true}, {"< 1.13.0", "1.13.0-rc.1", true},
		{">= 0", "1.0.0-a1", true}, {">= 0", "1.4.5", true},
		{"> 1.2.0", "1.2.0", false}, {"< 1.10.0", "1.9.2", true},
	}
	for _, c := range cases {
		got, err := InRange(c.rng, c.v)
		if err != nil || got != c.want {
			t.Errorf("InRange(%q, %q) = %v, %v; want %v", c.rng, c.v, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "~1.2.0", "^3.0.0", "latest", ">= 1.0, foo"} {
		if _, err := ParseRange(bad); err == nil {
			t.Errorf("ParseRange(%q) accepted", bad)
		}
	}
}

func TestFetchRealData(t *testing.T) {
	db := fetchFixture(t)
	count := map[catalog.Library]int{}
	byID := map[string]Advisory{}
	for _, a := range db.Advisories {
		count[a.Library]++
		byID[a.ID] = a
	}
	// jquery: 10 returned, 2 withdrawn duplicates; jquery-ui: 8 returned, 1 withdrawn.
	if count[catalog.Core] != 8 || count[catalog.UI] != 7 || count[catalog.Migrate] != 0 || count[catalog.Mobile] != 1 ||
		count[catalog.Bootstrap] != 9 || count[catalog.Moment] != 5 || count[catalog.Prototype] != 4 || count[catalog.Underscore] != 2 || count[catalog.Sizzle] != 0 {
		t.Fatalf("advisory counts = %v", count)
	}
	for _, withdrawn := range []string{"GHSA-257q-pv89-v3xv", "GHSA-wv67-q8rr-grjp", "GHSA-g8q2-24jh-5hpc"} {
		if _, ok := byID[withdrawn]; ok {
			t.Errorf("withdrawn advisory %s kept", withdrawn)
		}
	}
	// Two npm ranges; NuGet/Maven/RubyGems entries ignored.
	a := byID["GHSA-rmxg-73gg-4p98"]
	if a.CVE != "CVE-2015-9251" || len(a.Ranges) != 2 || a.FixedText() != "1.12.2, 3.0.0" {
		t.Errorf("CVE-2015-9251: %+v", a)
	}
	// Duplicate npm entries collapse into one range.
	if a := byID["GHSA-gxr4-xjj5-5px2"]; len(a.Ranges) != 1 || a.Ranges[0].Vulnerable != ">= 1.12.0, < 3.5.0" {
		t.Errorf("CVE-2020-11022: %+v", a)
	}
	m := byID["GHSA-fj93-7wm4-8x2g"]
	if m.CVE != "" || m.Name() != "GHSA-fj93-7wm4-8x2g" || !m.Unfixed() || m.FixedText() != "none" || m.Severity != "high" {
		t.Errorf("jquery-mobile advisory: %+v", m)
	}
	if len(db.Releases) != 577 {
		t.Fatalf("release records = %d", len(db.Releases))
	}
}

func TestMatchingHandWorked(t *testing.T) {
	db := fetchFixture(t)
	cases := []struct {
		lib     catalog.Library
		version string
		want    string
	}{
		{catalog.Core, "4.0.0", ""},
		{catalog.Core, "3.5.0", ""},
		{catalog.Core, "3.4.1", "CVE-2020-11022,CVE-2020-11023"},
		{catalog.Core, "3.0.0", "CVE-2019-11358,CVE-2020-11022,CVE-2020-11023"},
		// 1.12.2 sits in the gap between CVE-2015-9251's two ranges.
		{catalog.Core, "1.12.2", "CVE-2019-11358,CVE-2020-11022,CVE-2020-11023"},
		{catalog.Core, "1.12.3", "CVE-2015-9251,CVE-2019-11358,CVE-2020-11022,CVE-2020-11023"},
		// 1.2.0 is just below CVE-2020-7656's ">= 1.2.1".
		{catalog.Core, "1.2.0", "CVE-2011-4969,CVE-2012-6708,CVE-2015-9251,CVE-2019-11358,CVE-2020-11023"},
		{catalog.UI, "1.13.2", ""},
		{catalog.UI, "1.13.1", "CVE-2022-31160"},
		{catalog.UI, "1.8.24", "CVE-2010-5312,CVE-2012-6662,CVE-2016-7103,CVE-2021-41182,CVE-2021-41183,CVE-2021-41184,CVE-2022-31160"},
		{catalog.Migrate, "1.0.0", ""},
		{catalog.Mobile, "1.4.5", "GHSA-fj93-7wm4-8x2g"},
	}
	for _, c := range cases {
		if got := names(db.Matching(c.lib, c.version)); got != c.want {
			t.Errorf("%s %s: got %q, want %q", c.lib, c.version, got, c.want)
		}
	}
	// The stored per-release mapping agrees with live matching.
	for _, r := range db.Releases {
		if len(r.Advisories) != len(db.Matching(r.Library, r.Version)) {
			t.Fatalf("%s %s: stored mapping differs", r.Library, r.Version)
		}
	}
}

func TestReleaseNotes(t *testing.T) {
	db := fetchFixture(t)
	if u := db.ReleaseNotes(catalog.Core, "3.7.1"); u != "https://github.com/jquery/jquery/releases/tag/3.7.1" {
		t.Errorf("core 3.7.1 notes = %q", u)
	}
	if u := db.ReleaseNotes(catalog.UI, "1.13.0"); u != "https://github.com/jquery/jquery-ui/releases/tag/1.13.0" {
		t.Errorf("ui 1.13.0 notes = %q", u)
	}
	if u := db.ReleaseNotes(catalog.Migrate, "3.5.2"); u != "https://github.com/jquery/jquery-migrate/releases/tag/3.5.2" {
		t.Errorf("migrate 3.5.2 notes = %q", u)
	}
	if u := db.ReleaseNotes(catalog.Core, "1.12.4"); u != "" {
		t.Errorf("core 1.12.4 has no GitHub release, got %q", u)
	}
	n := 0
	for _, r := range db.Releases {
		if r.ReleaseNotesURL != nil {
			n++
		}
	}
	t.Logf("%d of %d releases have GitHub release notes", n, len(db.Releases))
	// jQuery 21 (Core 9, Migrate 5, UI 7), Bootstrap 94, Moment.js 2, Sizzle 5.
	if n != 122 {
		t.Errorf("unexpected number of release-note links: %d", n)
	}
	if u := db.ReleaseNotes(catalog.Bootstrap, "3.4.1"); u != "https://github.com/twbs/bootstrap/releases/tag/v3.4.1" {
		t.Errorf("bootstrap 3.4.1 notes = %q", u)
	}
}

func TestCheckRangeSemantics(t *testing.T) {
	db := fetchFixture(t)
	rs := shippedReleases(t)
	cases := []struct {
		lib             catalog.Library
		version, latest string
		want            string
	}{
		{catalog.Core, "3.4.1", "4.0.0", "CVE-2020-11022,CVE-2020-11023"},
		{catalog.Core, "4.0.0", "4.0.0", ""},
		// 1.12.2 itself is not affected by CVE-2015-9251, but later versions
		// in the range up to the latest (1.12.3 to 2.x) are.
		{catalog.Core, "1.12.2", "4.0.0", "CVE-2015-9251,CVE-2019-11358,CVE-2020-11022,CVE-2020-11023"},
		{catalog.Core, "1.2", "4.0.0", "CVE-2011-4969,CVE-2012-6708,CVE-2015-9251,CVE-2019-11358,CVE-2020-11022,CVE-2020-11023,CVE-2020-7656"},
		{catalog.UI, "1.13.0-rc.1", "1.14.2", "CVE-2021-41182,CVE-2021-41183,CVE-2021-41184,CVE-2022-31160"},
		{catalog.Migrate, "1.0.0", "4.0.2", ""},
		// A pre-release newer than the latest stable release.
		{catalog.Mobile, "1.5.0-rc1", "1.4.5", "GHSA-fj93-7wm4-8x2g"},
	}
	for _, c := range cases {
		res, err := Check(rs, db, c.lib, c.version)
		if err != nil {
			t.Errorf("%s %s: %v", c.lib, c.version, err)
			continue
		}
		if res.Latest != c.latest || names(res.Advisories) != c.want {
			t.Errorf("%s %s: latest %s, advisories %q; want %s, %q", c.lib, c.version, res.Latest, names(res.Advisories), c.latest, c.want)
		}
	}
	res, _ := Check(rs, db, catalog.Core, "3.4.1")
	if strings.Join(res.Checked, " ") != "3.4.1 3.5.0 3.5.1 3.6.0 3.6.1 3.6.2 3.6.3 3.6.4 3.7.0 3.7.1 4.0.0" || res.ReleaseDate != "01/05/2019" {
		t.Errorf("checked = %v, date %s", res.Checked, res.ReleaseDate)
	}
	if _, err := Check(rs, db, catalog.Core, "9.9.9"); err == nil || !strings.Contains(err.Error(), "not a known release") {
		t.Errorf("unknown version: %v", err)
	}
}

func TestFetchErrors(t *testing.T) {
	rs := shippedReleases(t)

	s := newGHServer(t)
	s.override["/advisories?jquery,jquery-migrate,jquery-ui,jquery-mobile,bootstrap,moment,underscore,sizzle"] = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"message":"API rate limit exceeded for 1.2.3.4."}`))
	}
	_, err := Fetch(context.Background(), Config{APIBase: s.URL, NVDBase: s.URL + "/nvd"}, rs)
	if !errors.Is(err, ErrRateLimited) || !strings.Contains(err.Error(), "jsrelease -keys") {
		t.Errorf("rate limit: %v", err)
	}

	s = newGHServer(t)
	s.override["/repos/jquery/jquery-ui/releases?"] = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }
	if _, err := Fetch(context.Background(), Config{APIBase: s.URL, NVDBase: s.URL + "/nvd", Retries: 1, Backoff: time.Millisecond}, rs); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("server error: %v", err)
	}

	s = newGHServer(t)
	s.override["/advisories?jquery,jquery-migrate,jquery-ui,jquery-mobile,bootstrap,moment,underscore,sizzle"] = func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"ghsa_id":"GHSA-x","severity":"high","vulnerabilities":[{"package":{"ecosystem":"npm","name":"jquery"},"vulnerable_version_range":"~1.2.0"}]}]`))
	}
	if _, err := Fetch(context.Background(), Config{APIBase: s.URL, NVDBase: s.URL + "/nvd"}, rs); err == nil || !strings.Contains(err.Error(), "unrecognised version range") {
		t.Errorf("bad range: %v", err)
	}

	s = newGHServer(t)
	s.override["/advisories?jquery,jquery-migrate,jquery-ui,jquery-mobile,bootstrap,moment,underscore,sizzle"] = func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`<html>maintenance</html>`)) }
	if _, err := Fetch(context.Background(), Config{APIBase: s.URL, NVDBase: s.URL + "/nvd"}, rs); err == nil || !strings.Contains(err.Error(), "unexpected response") {
		t.Errorf("non-JSON: %v", err)
	}
}

func TestPaginationAndToken(t *testing.T) {
	s := newGHServer(t)
	s.override["/advisories?jquery,jquery-migrate,jquery-ui,jquery-mobile,bootstrap,moment,underscore,sizzle"] = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "" {
			w.Header().Set("Link", `<`+s.URL+`/advisories?ecosystem=npm&affects=jquery,jquery-migrate,jquery-ui,jquery-mobile,bootstrap,moment,underscore,sizzle&per_page=100&page=2>; rel="next", <x>; rel="last"`)
			w.Write([]byte(`[{"ghsa_id":"GHSA-aaaa","cve_id":"CVE-2099-0001","severity":"low","published_at":"2099-01-01T00:00:00Z","vulnerabilities":[{"package":{"ecosystem":"npm","name":"jquery-migrate"},"vulnerable_version_range":"< 1.1.0","first_patched_version":{"identifier":"1.1.0"}}]}]`))
			return
		}
		w.Write([]byte(`[{"ghsa_id":"GHSA-bbbb","severity":"low","vulnerabilities":[{"package":{"ecosystem":"npm","name":"jquery-migrate"},"vulnerable_version_range":"= 3.4.1","first_patched_version":null}]}]`))
	}
	res, err := Fetch(context.Background(), Config{APIBase: s.URL, NVDBase: s.URL + "/nvd", Token: "secret-token"}, shippedReleases(t))
	if err != nil {
		t.Fatal(err)
	}
	got := names(res.DB.ForLibrary(catalog.Migrate))
	if got != "CVE-2099-0001,GHSA-bbbb" || res.Requests != 11 { // 2 advisory pages + 9 release lists
		t.Fatalf("pagination: %q, %d requests", got, res.Requests)
	}
	if a := res.DB.ForLibrary(catalog.Migrate); a[0].FixedText() != "1.1.0" {
		t.Errorf("object-shaped first_patched_version not read: %+v", a[0])
	}
	nvd := 0
	for i, h := range s.auth {
		if strings.HasPrefix(s.requests[i], "/nvd") {
			nvd++
			if h != "" {
				t.Fatalf("GitHub token sent to NVD: %q", h)
			}
		} else if h != "Bearer secret-token" {
			t.Fatalf("Authorization header = %q for %s", h, s.requests[i])
		}
	}
	if nvd == 0 {
		t.Fatal("expected NVD lookups for advisories without a GitHub score")
	}
}

func TestSaveLoadAndValidate(t *testing.T) {
	db := fetchFixture(t)
	p := filepath.Join(t.TempDir(), "v.json")
	if err := Save(p, db); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Advisories) != len(db.Advisories) || len(got.Releases) != 577 {
		t.Fatal("round trip mismatch")
	}
	before, _ := os.ReadFile(p)
	bad := *got
	bad.Releases = append([]ReleaseInfo(nil), got.Releases...)
	bad.Releases[0].Advisories = []string{"GHSA-unknown"}
	if err := Save(p, &bad); err == nil {
		t.Fatal("unknown advisory reference accepted")
	}
	after, _ := os.ReadFile(p)
	if string(before) != string(after) {
		t.Fatal("file modified by failed save")
	}
}

func TestDuplicateAliases(t *testing.T) {
	db := fetchFixture(t)
	byID := map[string]Advisory{}
	for _, a := range db.Advisories {
		byID[a.ID] = a
	}
	cases := map[string]string{
		"GHSA-jpcq-cgw6-v4j6": "CVE-2020-11023 (also CVE-2020-23064)",
		"GHSA-6c3j-c64m-qhgq": "CVE-2019-11358 (also CVE-2019-5428)",
		"GHSA-gxr4-xjj5-5px2": "CVE-2020-11022",
		"GHSA-fj93-7wm4-8x2g": "GHSA-fj93-7wm4-8x2g",
	}
	for id, want := range cases {
		if got := byID[id].DisplayName(); got != want {
			t.Errorf("%s: %q, want %q", id, got, want)
		}
	}
	// Still 16 advisories: aliases don't add entries or matches.
	if len(db.Advisories) != 36 || len(db.Matching(catalog.Core, "3.4.1")) != 2 {
		t.Fatalf("advisories %d", len(db.Advisories))
	}
	// The withdrawn jQuery UI advisory has no CVE ID and names no target: dropped.
	for _, a := range db.ForLibrary(catalog.UI) {
		if len(a.Aliases) != 0 {
			t.Errorf("unexpected UI alias: %+v", a)
		}
	}
}

func TestAliasEdgeCases(t *testing.T) {
	if got := duplicateOf("This advisory has been withdrawn because it is a duplicate of [GHSA-jpcq-cgw6-v4j6](https://x)"); got != "GHSA-jpcq-cgw6-v4j6" {
		t.Errorf("duplicateOf = %q", got)
	}
	if got := duplicateOf("Withdrawn, accidental duplicate publish."); got != "" {
		t.Errorf("duplicateOf = %q", got)
	}
	s := newGHServer(t)
	s.override["/advisories?jquery,jquery-migrate,jquery-ui,jquery-mobile,bootstrap,moment,underscore,sizzle"] = func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
 {"ghsa_id":"GHSA-aaaa-aaaa-aaaa","cve_id":"CVE-2099-0001","severity":"low","published_at":"2099-01-01T00:00:00Z",
  "vulnerabilities":[{"package":{"ecosystem":"npm","name":"jquery-migrate"},"vulnerable_version_range":"< 1.1.0","first_patched_version":"1.1.0"}]},
 {"ghsa_id":"GHSA-bbbb-bbbb-bbbb","cve_id":"CVE-2099-0002","withdrawn_at":"2099-02-01T00:00:00Z",
  "description":"This advisory is a duplicate of [GHSA-aaaa-aaaa-aaaa](https://x).","vulnerabilities":[]},
 {"ghsa_id":"GHSA-cccc-cccc-cccc","cve_id":"CVE-2099-0003","withdrawn_at":"2099-02-01T00:00:00Z",
  "description":"duplicate of [GHSA-zzzz-zzzz-zzzz](https://x) which is not listed","vulnerabilities":[]},
 {"ghsa_id":"GHSA-dddd-dddd-dddd","cve_id":"CVE-2099-0001","withdrawn_at":"2099-02-01T00:00:00Z",
  "description":"duplicate of [GHSA-aaaa-aaaa-aaaa](https://x), same CVE","vulnerabilities":[]}
]`))
	}
	res, err := Fetch(context.Background(), Config{APIBase: s.URL, NVDBase: s.URL + "/nvd"}, shippedReleases(t))
	if err != nil {
		t.Fatal(err)
	}
	m := res.DB.ForLibrary(catalog.Migrate)
	if len(m) != 1 || m[0].DisplayName() != "CVE-2099-0001 (also CVE-2099-0002)" {
		t.Fatalf("migrate advisories: %+v", m)
	}
	p := filepath.Join(t.TempDir(), "v.json")
	if err := Save(p, res.DB); err != nil {
		t.Fatal(err)
	}
	if back, err := Load(p); err != nil || back.ForLibrary(catalog.Migrate)[0].Aliases[0] != "CVE-2099-0002" {
		t.Fatalf("aliases not saved: %v", err)
	}
}

func advByName(db *Database, name string) Advisory {
	for _, a := range db.Advisories {
		if a.Name() == name {
			return a
		}
	}
	return Advisory{}
}

func TestCVSSFromGitHubAndNVD(t *testing.T) {
	s := newGHServer(t)
	res, err := Fetch(context.Background(), Config{APIBase: s.URL, NVDBase: s.URL + "/nvd"}, shippedReleases(t))
	if err != nil {
		t.Fatal(err)
	}
	db := res.DB
	cases := []struct{ name, text, source, version string }{
		{"CVE-2020-11022", "6.9", "GitHub", "3.1"}, // GitHub's score is used, not NVD's 6.1
		{"CVE-2016-10707", "7.5", "GitHub", "3.0"},
		{"CVE-2020-7656", "6.1", "GitHub", "3.1"}, // v3 preferred over its v4 5.3
		{"CVE-2011-4969", "4.3 (v2.0)", "NVD", "2.0"},
		{"CVE-2012-6662", "4.3 (v2.0)", "NVD", "2.0"},
		{"GHSA-fj93-7wm4-8x2g", "-", "", ""}, // no CVE ID: cannot be looked up at NVD
	}
	for _, c := range cases {
		a := advByName(db, c.name)
		if got := a.CVSSText(); got != c.text {
			t.Errorf("%s: CVSS %q, want %q", c.name, got, c.text)
		}
		if p := a.PrimaryCVSS(); c.source != "" && (p == nil || p.Source != c.source || p.Version != c.version) {
			t.Errorf("%s: primary %+v", c.name, p)
		}
	}
	if a := advByName(db, "CVE-2020-7656"); len(a.CVSS) != 2 || a.CVSS[1].Version != "4.0" || a.CVSS[1].Score != 5.3 {
		t.Errorf("CVE-2020-7656 v4 not kept: %+v", a.CVSS)
	}
	if a := advByName(db, "CVE-2011-4969"); a.CVSS[0].Vector != "AV:N/AC:M/Au:N/C:N/I:P/A:N" {
		t.Errorf("NVD vector: %+v", a.CVSS)
	}
	// NVD: Prototype's 2 product searches, plus the two jQuery UI advisories
	// with a CVE ID but no GitHub score.
	if res.NVDRequests != 3 || res.NVDFailures != 0 || res.Requests != 10 { // NVD: 1 Prototype search + 2 scores
		t.Errorf("requests: GitHub %d, NVD %d (failures %d)", res.Requests, res.NVDRequests, res.NVDFailures)
	}
	scored := 0
	for _, a := range db.Advisories {
		if a.PrimaryCVSS() != nil {
			scored++
		}
	}
	if scored != 35 { // only the jQuery Mobile advisory has no score anywhere
		t.Errorf("%d of 36 advisories scored, want 35", scored)
	}
}

func TestNVDFailuresAreWarningsAndKeepPreviousScores(t *testing.T) {
	s := newGHServer(t)
	good, err := Fetch(context.Background(), Config{APIBase: s.URL, NVDBase: s.URL + "/nvd"}, shippedReleases(t))
	if err != nil {
		t.Fatal(err)
	}
	s.override["/nvd?"] = func(w http.ResponseWriter, r *http.Request) {
		if p := r.URL.Query().Get("virtualMatchString"); p != "" { // Prototype's CVE list still works
			b, _ := os.ReadFile(filepath.Join("testdata", "nvd-cpe-"+p[strings.LastIndex(p, ":")+1:]+".json"))
			w.Write(b)
			return
		}
		w.WriteHeader(403)
		w.Write([]byte(`{"message":"rate limit"}`))
	}
	var logs bytes.Buffer
	cfg := Config{APIBase: s.URL, NVDBase: s.URL + "/nvd", Logger: logger.New(&logs, false, false)}
	res, err := Fetch(context.Background(), cfg, shippedReleases(t))
	if err != nil {
		t.Fatalf("an NVD failure must not fail the update: %v", err)
	}
	if res.NVDFailures != 2 || advByName(res.DB, "CVE-2011-4969").CVSSText() != "-" ||
		!strings.Contains(logs.String(), "[WRN] NVD lookup for CVE-2011-4969 failed, so it has no CVSS score") ||
		!strings.Contains(logs.String(), "jsrelease -keys") {
		t.Fatalf("failures %d, logs:\n%s", res.NVDFailures, logs.String())
	}
	// With the previous file available and a forced refresh (-full), the
	// earlier NVD score is kept when the lookup fails.
	logs.Reset()
	cfg.Previous = good.DB
	cfg.RefreshNVD = true
	res, _ = Fetch(context.Background(), cfg, shippedReleases(t))
	if got := advByName(res.DB, "CVE-2011-4969").CVSSText(); got != "4.3 (v2.0)" ||
		!strings.Contains(logs.String(), "keeping the score from the previous update") {
		t.Fatalf("previous score not kept: %q\n%s", got, logs.String())
	}
	// GitHub scores are never replaced by previous or NVD data.
	if advByName(res.DB, "CVE-2020-11022").CVSSText() != "6.9" {
		t.Fatal("GitHub score changed")
	}
}

func TestNVDKeyAndOff(t *testing.T) {
	s := newGHServer(t)
	var nvdKeys []string
	s.override["/nvd?"] = func(w http.ResponseWriter, r *http.Request) {
		nvdKeys = append(nvdKeys, r.Header.Get("apiKey"))
		w.Write([]byte(`{"vulnerabilities":[]}`))
	}
	if _, err := Fetch(context.Background(), Config{APIBase: s.URL, NVDBase: s.URL + "/nvd", NVDKey: "k123", Token: "gh"}, shippedReleases(t)); err != nil {
		t.Fatal(err)
	}
	if len(nvdKeys) != 3 || nvdKeys[0] != "k123" { // 1 Prototype search + 2 score lookups
		t.Fatalf("NVD apiKey headers: %v", nvdKeys)
	}
	s.requests = nil
	res, err := Fetch(context.Background(), Config{APIBase: s.URL, NVDBase: "off"}, shippedReleases(t))
	if err != nil || res.NVDRequests != 0 || advByName(res.DB, "CVE-2011-4969").CVSSText() != "-" {
		t.Fatalf("off: %v %d", err, res.NVDRequests)
	}
}

func TestCVSSTextAndValidation(t *testing.T) {
	a := Advisory{CVSS: []CVSS{{Version: "4.0", Score: 5.3, Vector: "CVSS:4.0/x", Source: "GitHub"}}}
	if a.CVSSText() != "5.3 (v4.0)" {
		t.Errorf("v4 only: %q", a.CVSSText())
	}
	a.CVSS = append(a.CVSS, CVSS{Version: "3.0", Score: 7, Vector: "CVSS:3.0/x", Source: "GitHub"})
	if a.CVSSText() != "7.0" {
		t.Errorf("v3 preferred: %q", a.CVSSText())
	}
	if versionFromVector("CVSS:3.1/AV:N") != "3.1" || versionFromVector("AV:N/AC:M") != "" {
		t.Error("versionFromVector")
	}
	db := fetchFixture(t)
	db.Advisories[0].CVSS = []CVSS{{Version: "3.1", Score: 11, Source: "GitHub"}}
	if err := db.Validate(); err == nil {
		t.Error("score 11 accepted")
	}
}

// TestNVDScoresAreReused: a stored NVD score is not looked up again unless
// RefreshNVD (-full) is set; new advisories without a score are looked up.
func TestNVDScoresAreReused(t *testing.T) {
	s := newGHServer(t)
	first, err := Fetch(context.Background(), Config{APIBase: s.URL, NVDBase: s.URL + "/nvd"}, shippedReleases(t))
	if err != nil || first.NVDRequests != 3 {
		t.Fatalf("first: %v, %d NVD requests", err, first.NVDRequests)
	}
	again, err := Fetch(context.Background(), Config{APIBase: s.URL, NVDBase: s.URL + "/nvd", Previous: first.DB}, shippedReleases(t))
	// Only Prototype's CVE list is refreshed (1 request); no score lookups,
	// and no release lists (no new versions).
	if err != nil || again.NVDRequests != 1 || again.NVDReused != 2 || again.Requests != 1 {
		t.Fatalf("second: %v, %d NVD requests, %d reused", err, again.NVDRequests, again.NVDReused)
	}
	if advByName(again.DB, "CVE-2011-4969").CVSSText() != "4.3 (v2.0)" || advByName(again.DB, "CVE-2012-6662").CVSSText() != "4.3 (v2.0)" {
		t.Fatal("reused scores lost")
	}
	full, _ := Fetch(context.Background(), Config{APIBase: s.URL, NVDBase: s.URL + "/nvd", Previous: first.DB, RefreshNVD: true}, shippedReleases(t))
	if full.NVDRequests != 3 || full.NVDReused != 0 {
		t.Fatalf("refresh: %d NVD requests, %d reused", full.NVDRequests, full.NVDReused)
	}
	// An advisory whose stored score is missing (e.g. a new advisory) is looked up.
	prev := *first.DB
	prev.Advisories = append([]Advisory(nil), first.DB.Advisories...)
	for i := range prev.Advisories {
		if prev.Advisories[i].CVE == "CVE-2012-6662" {
			prev.Advisories[i].CVSS = nil
		}
	}
	part, _ := Fetch(context.Background(), Config{APIBase: s.URL, NVDBase: s.URL + "/nvd", Previous: &prev}, shippedReleases(t))
	if part.NVDRequests != 2 || part.NVDReused != 1 {
		t.Fatalf("partial: %d NVD requests, %d reused", part.NVDRequests, part.NVDReused)
	}
}

func TestNewLibrariesMatching(t *testing.T) {
	db := fetchFixture(t)
	cases := []struct {
		lib     catalog.Library
		version string
		want    string
	}{
		// Bootstrap (reviewed GitHub advisories)
		{catalog.Bootstrap, "5.3.8", ""},
		{catalog.Bootstrap, "4.3.1", ""},
		{catalog.Bootstrap, "3.4.1", "CVE-2024-6485,CVE-2025-1647"},
		{catalog.Bootstrap, "3.3.7", "CVE-2016-10735,CVE-2018-14040,CVE-2018-14042,CVE-2018-20676,CVE-2018-20677,CVE-2019-8331,CVE-2024-6485"},
		{catalog.Bootstrap, "4.0.0-beta", "CVE-2016-10735"},
		// Moment.js
		{catalog.Moment, "2.31.0", ""},
		{catalog.Moment, "2.29.4", "CVE-2026-17495"},
		{catalog.Moment, "2.29.1", "CVE-2022-24785,CVE-2022-31129"},
		{catalog.Moment, "2.19.2", "CVE-2017-18214,CVE-2022-24785,CVE-2022-31129"},
		{catalog.Moment, "2.11.1", "CVE-2016-4055,CVE-2017-18214,CVE-2022-24785"},
		// Prototype (NVD affected-product data, as published)
		{catalog.Prototype, "1.7.3", "CVE-2020-27511"},
		{catalog.Prototype, "1.7.2", ""},
		{catalog.Prototype, "1.6.0.1", "CVE-2008-7220,CVE-2020-7993"},
		{catalog.Prototype, "1.6.0.2", ""},
		{catalog.Prototype, "1.5.1_rc3", "CVE-2007-2383,CVE-2008-7220"},
		// Underscore.js
		{catalog.Underscore, "1.13.8", ""},
		{catalog.Underscore, "1.13.7", "CVE-2026-27601"},
		{catalog.Underscore, "1.12.0", "CVE-2021-23358,CVE-2026-27601"},
		{catalog.Underscore, "1.3.1", "CVE-2026-27601"}, // just below CVE-2021-23358's ">= 1.3.2"
	}
	for _, c := range cases {
		if got := names(db.Matching(c.lib, c.version)); got != c.want {
			t.Errorf("%s %s: got %q, want %q", c.lib, c.version, got, c.want)
		}
	}
}

func TestNVDProductAdvisories(t *testing.T) {
	db := fetchFixture(t)
	a := advByName(db, "CVE-2008-7220")
	if a.Source != "NVD" || a.RangeText() != "< 1.6.0.2 (NVD)" || a.FixedText() != "1.6.0.2" || a.Severity != "high" ||
		a.CVSSText() != "7.5 (v2.0)" || a.URL != "https://nvd.nist.gov/vuln/detail/CVE-2008-7220" {
		t.Errorf("CVE-2008-7220: %+v", a)
	}
	b := advByName(db, "CVE-2020-27511")
	if b.RangeText() != "= 1.7.3 (NVD)" || b.FixedText() != "unknown" || b.Unfixed() || b.CVSSText() != "7.5" || b.Severity != "high" {
		t.Errorf("CVE-2020-27511: %+v", b)
	}
	// Taken as NVD publishes it, although its description says "before 1.5.1 RC3".
	if c := advByName(db, "CVE-2007-2383"); c.RangeText() != "= 1.5.1_rc3 (NVD)" {
		t.Errorf("CVE-2007-2383: %q", c.RangeText())
	}
	if r, ok := cpeRange("cpe:2.3:a:x:y:*:*:*:*:*:*:*:*", "1.0", "", "", "2.0"); !ok || r.Vulnerable != ">= 1.0, < 2.0" || r.Patched != "2.0" {
		t.Errorf("cpeRange: %+v", r)
	}
	// A failed NVD product search keeps the previous Prototype advisories,
	// and fails only when there are none to keep.
	s := newGHServer(t)
	s.override["/nvd?"] = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }
	var logs bytes.Buffer
	res, err := Fetch(context.Background(), Config{APIBase: s.URL, NVDBase: s.URL + "/nvd", Previous: db,
		Logger: logger.New(&logs, false, false)}, shippedReleases(t))
	if err != nil || len(res.DB.ForLibrary(catalog.Prototype)) != 4 || !strings.Contains(logs.String(), "keeping the 4 from the previous update") {
		t.Fatalf("keep previous: %v\n%s", err, logs.String())
	}
	if _, err := Fetch(context.Background(), Config{APIBase: s.URL, NVDBase: s.URL + "/nvd"}, shippedReleases(t)); err == nil {
		t.Error("expected an error when there are no previous Prototype advisories")
	}
}

// writeWithETag sends body with an ETag derived from its content, or
// "304 Not Modified" when the request's If-None-Match matches it.
func writeWithETag(w http.ResponseWriter, r *http.Request, body []byte) {
	etag := fmt.Sprintf(`"%x"`, sha256.Sum256(body))
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(body)
}
