// Package catalog defines the local release database and the operations on it:
// loading, validation, atomic saving, filtering and sorting.
package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Library identifies one of the supported jQuery libraries.
type Library string

const (
	Core       Library = "core"
	Migrate    Library = "migrate"
	UI         Library = "ui"
	Mobile     Library = "mobile"
	Bootstrap  Library = "bootstrap"
	Prototype  Library = "prototype"
	Moment     Library = "moment"
	Underscore Library = "underscore"
	Sizzle     Library = "sizzle"
)

// AllLibraries lists the supported libraries in display order.
var AllLibraries = func() []Library {
	var out []Library
	for _, d := range Libraries {
		out = append(out, d.ID)
	}
	return out
}()

// IsJQuery reports whether l comes from releases.jquery.com.
func (l Library) IsJQuery() bool { return Get(l).Source == FromJQuerySite && Get(l).ID != "" }

// LibraryNames lists the -library keywords.
func LibraryNames() string {
	var out []string
	for _, l := range AllLibraries {
		out = append(out, string(l))
	}
	return strings.Join(out, ", ")
}

const (
	// DefaultSource is the official origin of all release information.
	DefaultSource = "https://releases.jquery.com/"
	// DateLayout is the UK date format used for every stored release date.
	DateLayout = "02/01/2006"
)

// DisplayName returns the human readable library name.
func (l Library) DisplayName() string {
	if d := Get(l); d.Name != "" {
		return d.Name
	}
	return string(l)
}

// Valid reports whether l is a supported library.
func (l Library) Valid() bool { return l.order() >= 0 }

func (l Library) order() int {
	for i, v := range AllLibraries {
		if v == l {
			return i
		}
	}
	return -1
}

// ParseLibraries parses a library selection such as "all", "core" or
// "core,migrate". The result is in display order and contains no duplicates.
func ParseLibraries(s string) ([]Library, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "all" {
		return append([]Library(nil), AllLibraries...), nil
	}
	want := map[Library]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		switch part {
		case "":
			continue
		case "all":
			return append([]Library(nil), AllLibraries...), nil
		case "jquery":
			part = string(Core)
		}
		lib := Library(part)
		if !lib.Valid() {
			return nil, fmt.Errorf("invalid library %q (valid: %s, all)", part, LibraryNames())
		}
		want[lib] = true
	}
	if len(want) == 0 {
		return nil, fmt.Errorf("no library selected (valid: %s, all)", LibraryNames())
	}
	var out []Library
	for _, l := range AllLibraries {
		if want[l] {
			out = append(out, l)
		}
	}
	return out, nil
}

// Release is one released version of a library.
type Release struct {
	Library     Library `json:"library"`
	Name        string  `json:"name"`
	Version     string  `json:"version"`
	ReleaseDate string  `json:"release_date"`
	SourceURL   string  `json:"source_url"`
	// DateNote explains why ReleaseDate is empty. It is set only when the
	// official uncompressed file carries no release date in its header.
	DateNote string `json:"date_note,omitempty"`
	// TagDate is the date (DD/MM/YYYY) of the release's git tag, recorded
	// only when the official file has no date. It never replaces ReleaseDate.
	TagDate string `json:"tag_date,omitempty"`
	// TagURL links to the tag on GitHub (set with TagDate).
	TagURL string `json:"tag_url,omitempty"`
	// TagChecked records that the git tags were searched for this release,
	// so a release without a tag is not searched again on every update.
	TagChecked bool `json:"tag_checked,omitempty"`
	// ChangelogDate is the release date (DD/MM/YYYY) stated in the project's
	// CHANGELOG, recorded when the release files carry no date.
	ChangelogDate string `json:"changelog_date,omitempty"`
	// ChangelogURL links to that CHANGELOG.
	ChangelogURL string `json:"changelog_url,omitempty"`
}

// Date markers: where a displayed date comes from when the release files
// carry none.
const (
	TagMarker       = "*"
	ChangelogMarker = "‡" // ‡
)

// DisplayDate is the date shown in tables: the date in the official release
// file; else the project's CHANGELOG date, marked "‡"; else the git tag date,
// marked "*"; else "".
func (r Release) DisplayDate() string {
	switch {
	case r.ReleaseDate != "":
		return r.ReleaseDate
	case r.ChangelogDate != "":
		return r.ChangelogDate + ChangelogMarker
	case r.TagDate != "":
		return r.TagDate + TagMarker
	}
	return ""
}

// Database is the on-disk JSON document.
type Database struct {
	UpdatedAt string    `json:"updated_at"`
	Source    string    `json:"source"`
	Releases  []Release `json:"releases"`
	// HTTPCache holds the ETag of the last response for each checked URL, so
	// the next update can ask "has this changed?" (If-None-Match).
	HTTPCache map[string]string `json:"http_cache,omitempty"`
	// GeneratedBy names the jsrelease version that wrote the file. HTTPCache
	// is only used by the same version, so data is re-read after an upgrade.
	GeneratedBy string `json:"generated_by,omitempty"`
}

// New returns an empty database.
func New() *Database {
	return &Database{Source: DefaultSource, Releases: []Release{}}
}

// Load reads and validates the database at path. A missing file is reported
// with an error that satisfies errors.Is(err, fs.ErrNotExist).
func Load(path string) (*Database, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, path)
}

// Parse reads a database from data; name is used in error messages.
func Parse(data []byte, path string) (*Database, error) {
	var db Database
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if db.Releases == nil {
		db.Releases = []Release{}
	}
	if err := db.Validate(); err != nil {
		return nil, fmt.Errorf("invalid database %s: %w", path, err)
	}
	return &db, nil
}

// Validate checks every record for consistency.
func (db *Database) Validate() error {
	var errs []error
	seen := map[string]bool{}
	for i, r := range db.Releases {
		where := fmt.Sprintf("release #%d (%s %s)", i+1, r.Library, r.Version)
		if !r.Library.Valid() {
			errs = append(errs, fmt.Errorf("%s: unknown library %q", where, r.Library))
		}
		if strings.TrimSpace(r.Version) == "" {
			errs = append(errs, fmt.Errorf("%s: empty version", where))
		}
		key := string(r.Library) + "@" + r.Version
		if seen[key] {
			errs = append(errs, fmt.Errorf("%s: duplicate record", where))
		}
		seen[key] = true
		switch {
		case r.ReleaseDate == "" && r.DateNote == "":
			errs = append(errs, fmt.Errorf("%s: empty release_date without date_note", where))
		case r.ReleaseDate != "" && !ValidUKDate(r.ReleaseDate):
			errs = append(errs, fmt.Errorf("%s: release_date %q is not a valid DD/MM/YYYY date", where, r.ReleaseDate))
		}
		if r.TagDate != "" {
			switch {
			case r.ReleaseDate != "":
				errs = append(errs, fmt.Errorf("%s: tag_date is only recorded when there is no release_date", where))
			case !ValidUKDate(r.TagDate):
				errs = append(errs, fmt.Errorf("%s: tag_date %q is not a valid DD/MM/YYYY date", where, r.TagDate))
			case r.TagURL == "":
				errs = append(errs, fmt.Errorf("%s: tag_date without tag_url", where))
			}
		}
		if r.ChangelogDate != "" {
			switch {
			case r.ReleaseDate != "":
				errs = append(errs, fmt.Errorf("%s: changelog_date is only recorded when there is no release_date", where))
			case !ValidUKDate(r.ChangelogDate):
				errs = append(errs, fmt.Errorf("%s: changelog_date %q is not a valid DD/MM/YYYY date", where, r.ChangelogDate))
			case r.ChangelogURL == "":
				errs = append(errs, fmt.Errorf("%s: changelog_date without changelog_url", where))
			}
		}
		if strings.TrimSpace(r.SourceURL) == "" {
			errs = append(errs, fmt.Errorf("%s: empty source_url", where))
		}
	}
	return errors.Join(errs...)
}

// ValidUKDate reports whether s is a real calendar date in DD/MM/YYYY form.
func ValidUKDate(s string) bool {
	t, err := time.Parse(DateLayout, s)
	return err == nil && t.Format(DateLayout) == s
}

// Save validates db and writes it to path atomically (see WriteFileAtomic).
func Save(path string, db *Database) error {
	if err := db.Validate(); err != nil {
		return fmt.Errorf("refusing to write invalid database: %w", err)
	}
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return fmt.Errorf("encode database: %w", err)
	}
	return WriteFileAtomic(path, append(data, '\n'))
}

// WriteFileAtomic writes data to a temporary file in the same directory,
// flushes it to disk and renames it over path. If anything fails, an existing
// file at path is left untouched.
func WriteFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".jsrelease-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err = os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod temporary file: %w", err)
	}
	// os.Rename replaces the destination atomically on Linux and uses
	// MoveFileEx(MOVEFILE_REPLACE_EXISTING) on Windows.
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// SortReleases orders releases by library (display order) and then by
// descending semantic version.
func SortReleases(rs []Release) {
	sort.SliceStable(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if a.Library != b.Library {
			return a.Library.order() < b.Library.order()
		}
		if c := CompareVersions(a.Version, b.Version); c != 0 {
			return c > 0
		}
		return a.Version > b.Version
	})
}

// Filter returns the releases that belong to one of libs.
func Filter(rs []Release, libs []Library) []Release {
	want := map[Library]bool{}
	for _, l := range libs {
		want[l] = true
	}
	out := make([]Release, 0, len(rs))
	for _, r := range rs {
		if want[r.Library] {
			out = append(out, r)
		}
	}
	return out
}

// CountByLibrary counts releases per library.
func CountByLibrary(rs []Release) map[Library]int {
	m := map[Library]int{}
	for _, r := range rs {
		m[r.Library]++
	}
	return m
}
