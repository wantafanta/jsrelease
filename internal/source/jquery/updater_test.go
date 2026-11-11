package jquery

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/testutil"
)

func testConfig(s *testutil.Server) Config {
	cfg := DefaultConfig("test")
	cfg.Pages = []Page{
		{Name: "jQuery Core & Migrate", URL: s.URL + "/jquery/", Libraries: []catalog.Library{catalog.Core, catalog.Migrate}},
		{Name: "jQuery UI", URL: s.URL + "/ui/", Libraries: []catalog.Library{catalog.UI}},
		{Name: "jQuery Mobile", URL: s.URL + "/mobile/", Libraries: []catalog.Library{catalog.Mobile}},
	}
	cfg.AllowedHosts = []string{s.Host()}
	cfg.RetryBackoff = 5 * time.Millisecond
	cfg.Timeout = 5 * time.Second
	return cfg
}

// expectedDates maps "<library>_<file version>.js" to the expected UK date.
func expectedDates(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join(testutil.TestdataDir(), "expected-dates.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) == 2 && !strings.HasPrefix(p[0], "#") {
			m[p[0]] = p[1]
		}
	}
	return m
}

func TestRunEndToEnd(t *testing.T) {
	s := testutil.NewServer(t)
	cfg := testConfig(s)
	cfg.Concurrency = 4
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	counts := catalog.CountByLibrary(res.Releases)
	if counts[catalog.Core] != 87 || counts[catalog.Migrate] != 22 || counts[catalog.UI] != 66 || counts[catalog.Mobile] != 42 {
		t.Fatalf("counts = %v", counts)
	}
	if res.Undated != 41 || len(res.Failures) != 0 || res.Downloaded != 217 || res.Reused != 0 || len(res.New) != 217 || res.Requests != 220 {
		t.Fatalf("undated %d, failures %d, downloaded %d, reused %d, new %d, requests %d",
			res.Undated, len(res.Failures), res.Downloaded, res.Reused, len(res.New), res.Requests)
	}

	// Every stored date must equal the independently computed one.
	want := expectedDates(t)
	for _, r := range res.Releases {
		u := strings.TrimPrefix(r.SourceURL, s.URL)
		var key string
		switch r.Library {
		case catalog.Core:
			key = "core_" + strings.TrimSuffix(strings.TrimPrefix(u, "/jquery-"), ".js") + ".js"
		case catalog.Migrate:
			key = "migrate_" + strings.TrimSuffix(strings.TrimPrefix(u, "/jquery-migrate-"), ".js") + ".js"
		case catalog.UI:
			key = "ui_" + strings.Split(u, "/")[2] + ".js"
		case catalog.Mobile:
			key = "mobile_" + strings.Split(u, "/")[2] + ".js"
		}
		exp, ok := want[key]
		if !ok {
			t.Fatalf("no expected date for %s (%s)", key, r.SourceURL)
		}
		if exp == "NONE" {
			if r.ReleaseDate != "" || r.DateNote == "" {
				t.Errorf("%s %s: expected undated, got %q", r.Library, r.Version, r.ReleaseDate)
			}
		} else if r.ReleaseDate != exp {
			t.Errorf("%s %s: date %s, want %s", r.Library, r.Version, r.ReleaseDate, exp)
		}
	}

	// Spot checks.
	find := func(l catalog.Library, v string) catalog.Release {
		for _, r := range res.Releases {
			if r.Library == l && r.Version == v {
				return r
			}
		}
		t.Fatalf("%s %s missing", l, v)
		return catalog.Release{}
	}
	for _, c := range []struct {
		l       catalog.Library
		v, date string
	}{
		{catalog.Core, "3.7.1", "28/08/2023"}, {catalog.Core, "4.0.0", "18/01/2026"}, {catalog.Core, "1.2.6", "24/05/2008"},
		{catalog.Migrate, "3.4.1", "23/02/2023"}, {catalog.UI, "1.13.2", "14/07/2022"}, {catalog.Mobile, "1.4.5", "31/10/2014"},
	} {
		if r := find(c.l, c.v); r.ReleaseDate != c.date {
			t.Errorf("%s %s = %s, want %s", c.l, c.v, r.ReleaseDate, c.date)
		}
	}

	// Request hygiene: no /migrate/ page, only uncompressed files.
	for _, p := range s.Requests() {
		if strings.HasPrefix(p, "/migrate") || strings.Contains(p, ".min.") || strings.Contains(p, ".slim.") ||
			strings.Contains(p, ".module.") || strings.Contains(p, "/git/") || strings.HasSuffix(p, ".css") {
			t.Errorf("unexpected request %s", p)
		}
	}
	if n := len(s.Requests()); n != 3+217 {
		t.Errorf("requests = %d, want 220 (3 pages + 217 files)", n)
	}
	if ua := s.UserAgents(); len(ua) != 1 || !strings.HasPrefix(ua[0], "jsrelease/test") {
		t.Errorf("User-Agent = %v", ua)
	}
	if m := s.MaxInFlight(); m > 4 {
		t.Errorf("concurrency limit exceeded: %d in flight", m)
	}
}

func TestRunPageHTTPError(t *testing.T) {
	s := testutil.NewServer(t)
	s.Override("/ui/", testutil.Response{Status: 404, Body: "not found"})
	res, err := Run(context.Background(), testConfig(s))
	if err == nil || res != nil {
		t.Fatal("expected failure")
	}
	if !strings.Contains(err.Error(), "HTTP 404 Not Found") || !strings.Contains(err.Error(), "jQuery UI") {
		t.Fatalf("unclear error: %v", err)
	}
	var he *HTTPError
	if !errors.As(err, &he) || he.StatusCode != 404 {
		t.Fatalf("expected *HTTPError, got %v", err)
	}
}

func TestRunFileFailuresAreReported(t *testing.T) {
	s := testutil.NewServer(t)
	s.Override("/jquery-3.7.1.js", testutil.Response{Status: 404})
	s.Override("/ui/1.13.2/jquery-ui.js", testutil.Response{Status: 200, Body: "/*! jQuery UI - v1.13.2\n* Copyright jQuery Foundation\n* Date: soon */\n"})
	s.Override("/jquery-migrate-3.4.1.js", testutil.Response{Status: 200, Body: "<!doctype html><title>Error</title>"})
	res, err := Run(context.Background(), testConfig(s))
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("expected ErrIncomplete, got %v", err)
	}
	if res == nil || len(res.Failures) != 3 {
		t.Fatalf("failures = %+v", res)
	}
	joined := ""
	for _, f := range res.Failures {
		joined += f.String() + "\n"
	}
	for _, want := range []string{"jQuery 3.7.1", "HTTP 404", "jQuery UI 1.13.2", "unrecognised date format", "jQuery Migrate 3.4.1", "HTML instead of JavaScript"} {
		if !strings.Contains(joined, want) {
			t.Errorf("failure report missing %q:\n%s", want, joined)
		}
	}
}

func TestRunRetriesTransientErrors(t *testing.T) {
	s := testutil.NewServer(t)
	s.Override("/jquery/", testutil.Response{Status: 503, Fails: 2})
	s.Override("/jquery-3.7.1.js", testutil.Response{Status: 500, Fails: 1})
	cfg := testConfig(s)
	cfg.Retries = 2
	if _, err := Run(context.Background(), cfg); err != nil {
		t.Fatalf("transient errors not retried: %v", err)
	}
	cfg.Retries = 0
	s.Override("/jquery/", testutil.Response{Status: 503, Fails: 1})
	if _, err := Run(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("expected 503 failure without retries, got %v", err)
	}
}

func TestRunNoRetryOn404(t *testing.T) {
	s := testutil.NewServer(t)
	s.Override("/mobile/", testutil.Response{Status: 404})
	cfg := testConfig(s)
	cfg.Retries = 3
	Run(context.Background(), cfg)
	n := 0
	for _, p := range s.Requests() {
		if p == "/mobile/" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("404 requested %d times, want 1", n)
	}
}

func TestRunSanityFloor(t *testing.T) {
	s := testutil.NewServer(t)
	cfg := testConfig(s)
	cfg.MinReleases = map[catalog.Library]int{catalog.Migrate: 500}
	_, err := Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "structure may have changed") {
		t.Fatalf("expected sanity-floor error, got %v", err)
	}
}

func TestRunStructureChange(t *testing.T) {
	s := testutil.NewServer(t)
	s.Override("/jquery/", testutil.Response{Status: 200, Body: "<html><body><h1>New design</h1></body></html>"})
	_, err := Run(context.Background(), testConfig(s))
	var se *StructureError
	if !errors.As(err, &se) {
		t.Fatalf("expected StructureError, got %v", err)
	}
}

func TestRunTimeout(t *testing.T) {
	s := testutil.NewServer(t)
	s.Hold = func() { time.Sleep(300 * time.Millisecond) }
	cfg := testConfig(s)
	cfg.Timeout = 50 * time.Millisecond
	cfg.Retries = 0
	if _, err := Run(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "Timeout") {
		t.Fatalf("expected timeout, got %v", err)
	}
}

// fullRun performs a complete first update against s and then clears the
// request log, so later assertions only see the next run's requests.
func fullRun(t *testing.T, s *testutil.Server) []catalog.Release {
	t.Helper()
	res, err := Run(context.Background(), testConfig(s))
	if err != nil {
		t.Fatal(err)
	}
	s.ClearRequests()
	return res.Releases
}

func without(rs []catalog.Release, drop ...string) []catalog.Release {
	var out []catalog.Release
	for _, r := range rs {
		keep := true
		for _, d := range drop {
			if string(r.Library)+"@"+r.Version == d {
				keep = false
			}
		}
		if keep {
			out = append(out, r)
		}
	}
	return out
}

func filesRequested(s *testutil.Server) []string {
	var out []string
	for _, p := range s.Requests() {
		if strings.HasSuffix(p, ".js") {
			out = append(out, p)
		}
	}
	return out
}

func TestIncrementalNothingNew(t *testing.T) {
	s := testutil.NewServer(t)
	known := fullRun(t, s)
	cfg := testConfig(s)
	cfg.Known = known
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Requests(); len(got) != 3 {
		t.Fatalf("requests = %v, want only the 3 release pages", got)
	}
	if res.Downloaded != 0 || res.Reused != 217 || len(res.New) != 0 || res.Requests != 3 || res.Undated != 41 {
		t.Fatalf("downloaded %d reused %d new %d requests %d undated %d", res.Downloaded, res.Reused, len(res.New), res.Requests, res.Undated)
	}
	if len(res.Releases) != len(known) {
		t.Fatalf("releases %d, want %d", len(res.Releases), len(known))
	}
	for i := range known {
		if res.Releases[i] != known[i] {
			t.Fatalf("release %d changed: %+v -> %+v", i, known[i], res.Releases[i])
		}
	}
}

func TestIncrementalDownloadsOnlyNewReleases(t *testing.T) {
	s := testutil.NewServer(t)
	all := fullRun(t, s)
	cfg := testConfig(s)
	cfg.Known = without(all, "core@4.0.0", "migrate@4.0.2", "ui@1.8.18")
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	files := filesRequested(s)
	if len(files) != 3 || res.Downloaded != 3 || res.Requests != 6 {
		t.Fatalf("files requested %v (downloaded %d, requests %d), want 3", files, res.Downloaded, res.Requests)
	}
	var got []string
	for _, r := range res.New {
		got = append(got, r.Name+" "+r.Version+" "+r.ReleaseDate)
	}
	want := "jQuery 4.0.0 18/01/2026|jQuery Migrate 4.0.2 21/01/2026|jQuery UI 1.8.18 "
	if strings.Join(got, "|") != want {
		t.Fatalf("new = %q, want %q", strings.Join(got, "|"), want)
	}
	if len(res.Releases) != 217 {
		t.Fatalf("releases = %d", len(res.Releases))
	}
}

func TestIncrementalRedownloadsChangedURL(t *testing.T) {
	s := testutil.NewServer(t)
	all := fullRun(t, s)
	for i := range all {
		if all[i].Library == catalog.Core && all[i].Version == "3.7.1" {
			all[i].SourceURL = "https://code.jquery.com/old-location/jquery-3.7.1.js"
		}
	}
	cfg := testConfig(s)
	cfg.Known = all
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if files := filesRequested(s); len(files) != 1 || files[0] != "/jquery-3.7.1.js" {
		t.Fatalf("files requested %v", files)
	}
	if len(res.New) != 1 || !strings.HasSuffix(res.New[0].SourceURL, s.URL[len(s.URL)-5:]+"/jquery-3.7.1.js") {
		t.Fatalf("new = %+v", res.New)
	}
}

func TestFullRedownloadsEverything(t *testing.T) {
	s := testutil.NewServer(t)
	all := fullRun(t, s)
	for i := range all {
		if all[i].Library == catalog.Migrate && all[i].Version == "3.4.1" {
			all[i].ReleaseDate = "01/01/2020" // corrupted value is corrected by -full
		}
	}
	cfg := testConfig(s)
	cfg.Known = all
	cfg.Full = true
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(filesRequested(s)) != 217 || res.Downloaded != 217 || res.Reused != 0 {
		t.Fatalf("full: %d files, downloaded %d, reused %d", len(filesRequested(s)), res.Downloaded, res.Reused)
	}
	if len(res.New) != 1 || res.New[0].Version != "3.4.1" || res.New[0].ReleaseDate != "23/02/2023" {
		t.Fatalf("changed = %+v", res.New)
	}
}

func TestMissingKnownReleaseIsAnError(t *testing.T) {
	s := testutil.NewServer(t)
	all := fullRun(t, s)
	all = append(all, catalog.Release{Library: catalog.Mobile, Name: "jQuery Mobile", Version: "9.9.9",
		ReleaseDate: "01/01/2020", SourceURL: "https://code.jquery.com/mobile/9.9.9/jquery.mobile-9.9.9.js"})
	cfg := testConfig(s)
	cfg.Known = all
	_, err := Run(context.Background(), cfg)
	if !errors.Is(err, ErrMissing) || !strings.Contains(err.Error(), "jQuery Mobile 9.9.9") {
		t.Fatalf("expected ErrMissing naming the release, got %v", err)
	}
	if len(filesRequested(s)) != 0 {
		t.Fatal("files downloaded despite missing-release error")
	}
}

func TestIncrementalFailureOnNewRelease(t *testing.T) {
	s := testutil.NewServer(t)
	all := fullRun(t, s)
	s.Override("/jquery-3.7.1.js", testutil.Response{Status: 404})
	cfg := testConfig(s)
	cfg.Known = without(all, "core@3.7.1")
	res, err := Run(context.Background(), cfg)
	if !errors.Is(err, ErrIncomplete) || len(res.Failures) != 1 || !strings.Contains(res.Failures[0].String(), "HTTP 404") {
		t.Fatalf("expected one 404 failure, got %v", err)
	}
}
