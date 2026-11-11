package catalog

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	ordered := []string{ // ascending
		"1.0.0-a1", "1.0.0-a4", "1.0.0-a4.1", "1.0.0-b1", "1.0.0-rc1", "1.0.0-rc3",
		"1.0.0", "1.2.0", "1.2.6", "1.9.1",
		"1.10.0-beta.1", "1.10.0-rc.1", "1.10.0", "1.10.2", "1.12.4",
		"3.0.0-alpha1", "3.0.0-beta1", "3.0.0-rc1", "3.0.0", "3.6.4", "3.7.1",
		"4.0.0-beta", "4.0.0-beta.2", "4.0.0",
	}
	for i := range ordered {
		for j := range ordered {
			want := cmpInt(i, j)
			if got := CompareVersions(ordered[i], ordered[j]); got != want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
	if CompareVersions("1.2", "1.2.0") != 0 || CompareVersions("v3.7.1", "3.7.1") != 0 {
		t.Error("equivalent versions should compare equal")
	}
}

func TestSortReleasesSemantic(t *testing.T) {
	rs := []Release{
		{Library: UI, Version: "1.9.2"}, {Library: Core, Version: "1.9.1"},
		{Library: Mobile, Version: "1.4.5"}, {Library: Core, Version: "1.10.0"},
		{Library: Migrate, Version: "3.4.1"}, {Library: Core, Version: "3.7.1"},
		{Library: UI, Version: "1.14.0-beta.1"}, {Library: UI, Version: "1.14.0"},
		{Library: Core, Version: "1.2.0"},
	}
	SortReleases(rs)
	var got []string
	for _, r := range rs {
		got = append(got, string(r.Library)+" "+r.Version)
	}
	want := "core 3.7.1|core 1.10.0|core 1.9.1|core 1.2.0|migrate 3.4.1|ui 1.14.0|ui 1.14.0-beta.1|ui 1.9.2|mobile 1.4.5"
	if strings.Join(got, "|") != want {
		t.Fatalf("got  %s\nwant %s", strings.Join(got, "|"), want)
	}
}

func TestParseLibraries(t *testing.T) {
	for in, want := range map[string]string{
		"": "core,migrate,ui,mobile,bootstrap,prototype,moment,underscore,sizzle", "all": "core,migrate,ui,mobile,bootstrap,prototype,moment,underscore,sizzle",
		"ALL": "core,migrate,ui,mobile,bootstrap,prototype,moment,underscore,sizzle", "underscore": "underscore", "sizzle": "sizzle", "moment,bootstrap": "bootstrap,moment", "prototype": "prototype",
		"core": "core", "migrate": "migrate", "ui": "ui", "mobile": "mobile",
		"mobile,core": "core,mobile", "jquery": "core", "ui, ui": "ui",
	} {
		libs, err := ParseLibraries(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		var s []string
		for _, l := range libs {
			s = append(s, string(l))
		}
		if strings.Join(s, ",") != want {
			t.Errorf("ParseLibraries(%q) = %v, want %s", in, s, want)
		}
	}
	for _, bad := range []string{"jqueryui", "core,foo", ","} {
		if _, err := ParseLibraries(bad); err == nil {
			t.Errorf("ParseLibraries(%q) should fail", bad)
		}
	}
}

func TestFilter(t *testing.T) {
	rs := []Release{{Library: Core, Version: "1"}, {Library: UI, Version: "1"}, {Library: Migrate, Version: "1"}}
	if got := Filter(rs, []Library{Migrate}); len(got) != 1 || got[0].Library != Migrate {
		t.Fatalf("Filter = %+v", got)
	}
}

func TestValidUKDate(t *testing.T) {
	for s, ok := range map[string]bool{
		"28/08/2023": true, "29/02/2024": true, "29/02/2023": false, "2023-08-28": false,
		"8/8/2023": false, "31/04/2020": false, "": false,
	} {
		if ValidUKDate(s) != ok {
			t.Errorf("ValidUKDate(%q) != %v", s, ok)
		}
	}
}

func sampleDB() *Database {
	db := New()
	db.UpdatedAt = "2026-11-09T12:00:00Z"
	db.Releases = []Release{
		{Library: Core, Name: "jQuery", Version: "3.7.1", ReleaseDate: "28/08/2023", SourceURL: "https://code.jquery.com/jquery-3.7.1.js"},
		{Library: Migrate, Name: "jQuery Migrate", Version: "3.7.1", ReleaseDate: "01/01/2024", SourceURL: "https://code.jquery.com/jquery-migrate-3.7.1.js"},
		{Library: UI, Name: "jQuery UI", Version: "1.8.18", SourceURL: "https://code.jquery.com/ui/1.8.18/jquery-ui.js", DateNote: "no date"},
	}
	return db
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "db.json")
	db := sampleDB() // identical version numbers across libraries are allowed
	if err := Save(path, db); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Releases) != 3 || got.Releases[1] != db.Releases[1] || got.Source != DefaultSource {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestSaveInvalidLeavesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.json")
	if err := Save(path, sampleDB()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)

	bad := sampleDB()
	bad.Releases = append(bad.Releases, bad.Releases[0]) // duplicate
	if err := Save(path, bad); err == nil {
		t.Fatal("duplicate records accepted")
	}
	bad = sampleDB()
	bad.Releases[0].ReleaseDate = "2023-08-28"
	if err := Save(path, bad); err == nil {
		t.Fatal("non-UK date accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("existing database modified by failed save")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestSaveUnwritableDirectoryLeavesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db.json")
	if err := Save(path, sampleDB()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	// A path whose parent is a regular file cannot be written.
	if err := Save(filepath.Join(path, "nested.json"), sampleDB()); err == nil {
		t.Fatal("expected failure")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("existing database modified")
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "missing.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	p := filepath.Join(dir, "broken.json")
	os.WriteFile(p, []byte(`{"releases": [`), 0o644)
	if _, err := Load(p); err == nil {
		t.Error("truncated JSON accepted")
	}
	os.WriteFile(p, []byte(`{"releases":[{"library":"core","name":"jQuery","version":"1","release_date":"99/99/2020","source_url":"x"}]}`), 0o644)
	if _, err := Load(p); err == nil {
		t.Error("invalid date accepted")
	}
	os.WriteFile(p, []byte(`{"updated_at":"","source":"https://releases.jquery.com/","releases":[]}`), 0o644)
	if db, err := Load(p); err != nil || len(db.Releases) != 0 {
		t.Errorf("empty database: %v", err)
	}
}

func TestTagDateValidationAndDisplay(t *testing.T) {
	db := sampleDB()
	u := &db.Releases[2] // undated jQuery UI 1.8.18
	u.TagDate, u.TagURL, u.TagChecked = "20/02/2012", "https://github.com/jquery/jquery-ui/tree/1.8.18", true
	if err := db.Validate(); err != nil {
		t.Fatal(err)
	}
	if u.DisplayDate() != "20/02/2012*" || db.Releases[0].DisplayDate() != "28/08/2023" {
		t.Error("DisplayDate")
	}
	db.Releases[0].TagDate, db.Releases[0].TagURL = "01/01/2020", "x" // dated release
	if err := db.Validate(); err == nil {
		t.Error("tag_date accepted on a release with an official date")
	}
	db = sampleDB()
	db.Releases[2].TagDate = "2012-02-20"
	if err := db.Validate(); err == nil {
		t.Error("non-UK tag_date accepted")
	}
}

func TestNewLibrariesAndMarkers(t *testing.T) {
	if Bootstrap.DisplayName() != "Bootstrap" || Moment.DisplayName() != "Moment.js" || Prototype.DisplayName() != "Prototype" {
		t.Error("display names")
	}
	if !UI.IsJQuery() || Bootstrap.IsJQuery() {
		t.Error("IsJQuery")
	}
	r := Release{ChangelogDate: "14/09/2026", ChangelogURL: "x", TagDate: "13/09/2026", TagURL: "y"}
	if r.DisplayDate() != "14/09/2026\u2021" {
		t.Errorf("changelog date takes precedence over the tag date: %q", r.DisplayDate())
	}
	r.ChangelogDate = ""
	if r.DisplayDate() != "13/09/2026*" {
		t.Errorf("tag date: %q", r.DisplayDate())
	}
	db := New()
	db.Releases = []Release{{Library: Moment, Name: "Moment.js", Version: "2.31.0", DateNote: "n", SourceURL: "u", ChangelogDate: "2026-09-14", ChangelogURL: "c"}}
	if db.Validate() == nil {
		t.Error("non-UK changelog_date accepted")
	}
	db.Releases[0].ChangelogDate, db.Releases[0].ChangelogURL = "14/09/2026", ""
	if db.Validate() == nil {
		t.Error("changelog_date without changelog_url accepted")
	}
}
