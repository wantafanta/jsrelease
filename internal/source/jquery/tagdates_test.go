package jquery

import (
	"context"
	"strings"
	"testing"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/testutil"
)

func shippedReleases(t *testing.T) []catalog.Release {
	t.Helper()
	return testutil.ShippedReleases(t)
}

func undatedCopy(t *testing.T) []catalog.Release {
	t.Helper()
	rs := shippedReleases(t)
	for i := range rs {
		rs[i].TagDate, rs[i].TagURL, rs[i].TagChecked = "", "", false
	}
	return rs
}

func findRelease(rs []catalog.Release, lib catalog.Library, v string) catalog.Release {
	for _, r := range rs {
		if r.Library == lib && r.Version == v {
			return r
		}
	}
	return catalog.Release{}
}

func TestFillTagDates(t *testing.T) {
	s := testutil.NewGitHubServer()
	defer s.Close()
	rs := undatedCopy(t)
	res, err := FillTagDates(context.Background(), TagConfig{APIBase: s.URL}, rs)
	if err != nil {
		t.Fatal(err)
	}
	if res.Searched != 41 || res.Found != 38 || res.Requests != 40 {
		t.Fatalf("searched %d, found %d, requests %d", res.Searched, res.Found, res.Requests)
	}
	cases := []struct {
		lib     catalog.Library
		v, date string
		tag     string
	}{
		{catalog.UI, "1.8.18", "20/02/2012", "https://github.com/jquery/jquery-ui/tree/1.8.18"},
		{catalog.UI, "1.8.0", "18/03/2010", "https://github.com/jquery/jquery-ui/tree/1.8"}, // tag "1.8"
		{catalog.UI, "1.7.0", "03/03/2009", "https://github.com/jquery/jquery-ui/tree/1.7"},
		{catalog.UI, "1.7.3", "", ""}, // no tag exists
		{catalog.Mobile, "1.0.0-a4.1", "07/04/2011", "https://github.com/jquery-archive/jquery-mobile/tree/1.0a4.1"},
		{catalog.Mobile, "1.0.0", "17/11/2011", "https://github.com/jquery-archive/jquery-mobile/tree/1.0"},
	}
	for _, c := range cases {
		r := findRelease(rs, c.lib, c.v)
		if r.TagDate != c.date || r.TagURL != c.tag || !r.TagChecked {
			t.Errorf("%s %s: %+v", c.lib, c.v, r)
		}
	}
	// Releases with an official date are never touched.
	for _, r := range rs {
		if r.ReleaseDate != "" && (r.TagDate != "" || r.TagChecked) {
			t.Fatalf("dated release changed: %+v", r)
		}
	}
	// Second run: nothing to search, no requests. -full searches again.
	again, _ := FillTagDates(context.Background(), TagConfig{APIBase: s.URL}, rs)
	if again.Searched != 0 || again.Requests != 0 {
		t.Errorf("second run: %+v", again)
	}
	full, _ := FillTagDates(context.Background(), TagConfig{APIBase: s.URL, Full: true}, rs)
	if full.Searched != 41 || full.Found != 38 {
		t.Errorf("full: %+v", full)
	}
}

func TestFillTagDatesFailureChangesNothing(t *testing.T) {
	s := testutil.NewGitHubServer()
	defer s.Close()
	s.FailPrefix("/repos/jquery-archive/jquery-mobile/tags", 403)
	rs := undatedCopy(t)
	before := append([]catalog.Release(nil), rs...)
	_, err := FillTagDates(context.Background(), TagConfig{APIBase: s.URL}, rs)
	if err == nil || !strings.Contains(err.Error(), "jsrelease -keys") {
		t.Fatalf("expected rate-limit error, got %v", err)
	}
	for i := range rs {
		if rs[i] != before[i] {
			t.Fatalf("release changed despite the error: %+v", rs[i])
		}
	}
}

func TestTagCandidates(t *testing.T) {
	r := catalog.Release{Library: catalog.Mobile, Version: "1.0.0-a4.1", SourceURL: "https://code.jquery.com/mobile/1.0a4.1/jquery.mobile-1.0a4.1.js"}
	if got := strings.Join(tagCandidates(r), " "); got != "1.0a4.1 1.0.0-a4.1 1.0-a4.1 v1.0a4.1 v1.0.0-a4.1 v1.0-a4.1" {
		t.Errorf("mobile: %s", got)
	}
	r = catalog.Release{Library: catalog.UI, Version: "1.8.0", SourceURL: "https://code.jquery.com/ui/1.8.0/jquery-ui.js"}
	if got := strings.Join(tagCandidates(r), " "); got != "1.8.0 1.8 v1.8.0 v1.8" {
		t.Errorf("ui: %s", got)
	}
}
