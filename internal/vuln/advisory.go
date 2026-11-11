// Package advisory holds security advisories (CVEs) and GitHub release-note
// links for the jQuery libraries, kept in a JSON file separate from the
// release database, and checks versions against them.
//
// Advisories come from the GitHub Advisory Database (reviewed advisories for
// the npm packages jquery, jquery-migrate, jquery-ui and jquery-mobile).
package vuln

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/support"
)

// Source maps a library to where its advisories and release notes come
// from: reviewed GitHub advisories for its npm package, or, for libraries
// not on npm, NVD's affected-product (CPE) data.
type Source struct {
	Library catalog.Library
	Package string // npm package ("" if not on npm)
	Repo    string // GitHub repository, for release notes
	// For a library not on npm: NVDVendor is the CPE vendor searched at NVD
	// (one request), and NVDProducts the product prefixes kept from it.
	NVDVendor   string
	NVDProducts []string
}

// Sources lists where advisories and release notes are looked up, from the
// catalog.
var Sources = func() []Source {
	var out []Source
	for _, d := range catalog.Libraries {
		out = append(out, Source{Library: d.ID, Package: d.NPM, Repo: d.Repo, NVDVendor: d.NVDVendor, NVDProducts: d.NVDProducts})
	}
	return out
}()

// Range is one vulnerable version range of an advisory.
type Range struct {
	// Vulnerable is the range as published, e.g. ">= 1.2.0, < 3.5.0".
	Vulnerable string `json:"vulnerable_range"`
	// Patched is the first fixed version, or "" if there is no fix.
	Patched string `json:"patched,omitempty"`
}

// Advisory is one security advisory affecting a library.
type Advisory struct {
	ID  string `json:"id"`
	CVE string `json:"cve,omitempty"`
	// Aliases are CVE IDs of withdrawn advisories that GitHub merged into
	// this one as duplicates (e.g. CVE-2020-23064 for CVE-2020-11023).
	Aliases  []string        `json:"aliases,omitempty"`
	Library  catalog.Library `json:"library"`
	Package  string          `json:"package"`
	Severity string          `json:"severity"`
	// CVSS lists the available scores: GitHub's, or NVD's when GitHub has none.
	CVSS      []CVSS  `json:"cvss,omitempty"`
	Summary   string  `json:"summary"`
	Published string  `json:"published"`
	URL       string  `json:"url"`
	Ranges    []Range `json:"ranges"`
	// Source is "NVD" when the advisory and its ranges come from NVD's
	// affected-product data (libraries not on npm); empty for GitHub.
	Source string `json:"source,omitempty"`
}

// TitleSeverity shows a severity with a capital first letter ("medium" ->
// "Medium"); JSON output keeps GitHub's lowercase value.
func TitleSeverity(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

// Name is the CVE ID, or the GHSA ID when no CVE has been assigned.
func (a Advisory) Name() string {
	if a.CVE != "" {
		return a.CVE
	}
	return a.ID
}

// DisplayName is Name plus any duplicate CVE IDs:
// "CVE-2020-11023 (also CVE-2020-23064)".
func (a Advisory) DisplayName() string {
	if len(a.Aliases) == 0 {
		return a.Name()
	}
	return a.Name() + " (also " + strings.Join(a.Aliases, ", ") + ")"
}

// Affects reports whether version falls in any of the advisory's ranges.
func (a Advisory) Affects(version string) bool {
	for _, r := range a.Ranges {
		if ok, err := InRange(r.Vulnerable, version); err == nil && ok {
			return true
		}
	}
	return false
}

// RangeText joins the vulnerable ranges for display.
func (a Advisory) RangeText() string {
	var out []string
	for _, r := range a.Ranges {
		out = append(out, r.Vulnerable)
	}
	s := strings.Join(out, " | ")
	if a.Source == "NVD" {
		s += " (NVD)"
	}
	return s
}

// FixedText joins the patched versions for display; "none" marks a range
// with no fix.
func (a Advisory) FixedText() string {
	var out []string
	seen := map[string]bool{}
	for _, r := range a.Ranges {
		p := r.Patched
		switch {
		case p == "" && a.Source == "NVD":
			p = "unknown" // NVD's data doesn't say whether a fix exists
		case p == "":
			p = "none"
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return strings.Join(out, ", ")
}

// Unfixed reports whether some range has no patched version. For NVD data
// this is unknown, so it reports false.
func (a Advisory) Unfixed() bool {
	if a.Source == "NVD" {
		return false
	}
	for _, r := range a.Ranges {
		if r.Patched == "" {
			return true
		}
	}
	return false
}

// ReleaseInfo is the per-release record of the file.
type ReleaseInfo struct {
	Library         catalog.Library `json:"library"`
	Version         string          `json:"version"`
	ReleaseNotesURL *string         `json:"release_notes_url"`
	Advisories      []string        `json:"advisories"`
}

// Database is the on-disk vulnerability file.
type Database struct {
	UpdatedAt  string        `json:"updated_at"`
	Sources    []string      `json:"sources"`
	Advisories []Advisory    `json:"advisories"`
	Releases   []ReleaseInfo `json:"releases"`
	// HTTPCache holds ETags of the last responses (see catalog.Database).
	HTTPCache map[string]string `json:"http_cache,omitempty"`
	// GeneratedBy names the jsrelease version that wrote the file.
	GeneratedBy string `json:"generated_by,omitempty"`
}

// Load reads and validates the file at path.
func Load(path string) (*Database, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, path)
}

// Parse reads a vulnerability database from data; name is used in errors.
func Parse(data []byte, path string) (*Database, error) {
	var db Database
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := db.Validate(); err != nil {
		return nil, fmt.Errorf("invalid vulnerability database %s: %w", path, err)
	}
	return &db, nil
}

// Save validates db and writes it atomically.
func Save(path string, db *Database) error {
	if err := db.Validate(); err != nil {
		return fmt.Errorf("refusing to write invalid vulnerability database: %w", err)
	}
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	return catalog.WriteFileAtomic(path, append(data, '\n'))
}

// Validate checks the file for consistency.
func (db *Database) Validate() error {
	var errs []error
	ids := map[string]bool{}
	for _, a := range db.Advisories {
		if a.ID == "" || ids[a.ID] {
			errs = append(errs, fmt.Errorf("advisory %q: missing or duplicate id", a.ID))
		}
		ids[a.ID] = true
		if !a.Library.Valid() {
			errs = append(errs, fmt.Errorf("advisory %s: unknown library %q", a.ID, a.Library))
		}
		if len(a.Ranges) == 0 {
			errs = append(errs, fmt.Errorf("advisory %s: no version ranges", a.ID))
		}
		for _, c := range a.CVSS {
			if c.Version == "" || c.Source == "" || c.Score < 0 || c.Score > 10 {
				errs = append(errs, fmt.Errorf("advisory %s: invalid CVSS entry %+v", a.ID, c))
			}
		}
		seenAlias := map[string]bool{}
		for _, al := range a.Aliases {
			if al == "" || al == a.CVE || seenAlias[al] {
				errs = append(errs, fmt.Errorf("advisory %s: empty or duplicate alias %q", a.ID, al))
			}
			seenAlias[al] = true
		}
		for _, r := range a.Ranges {
			if _, err := ParseRange(r.Vulnerable); err != nil {
				errs = append(errs, fmt.Errorf("advisory %s: %v", a.ID, err))
			}
		}
	}
	seen := map[string]bool{}
	for _, r := range db.Releases {
		k := string(r.Library) + "@" + r.Version
		if !r.Library.Valid() || r.Version == "" || seen[k] {
			errs = append(errs, fmt.Errorf("release %s: invalid or duplicate", k))
		}
		seen[k] = true
		for _, id := range r.Advisories {
			if !ids[id] {
				errs = append(errs, fmt.Errorf("release %s: unknown advisory %s", k, id))
			}
		}
	}
	return errors.Join(errs...)
}

// ForLibrary returns the advisories of lib.
func (db *Database) ForLibrary(lib catalog.Library) []Advisory {
	var out []Advisory
	for _, a := range db.Advisories {
		if a.Library == lib {
			out = append(out, a)
		}
	}
	return out
}

// Matching returns the advisories of lib that affect version.
func (db *Database) Matching(lib catalog.Library, version string) []Advisory {
	var out []Advisory
	for _, a := range db.ForLibrary(lib) {
		if a.Affects(version) {
			out = append(out, a)
		}
	}
	return out
}

// ReleaseNotes returns the GitHub release-notes URL recorded for a release.
func (db *Database) ReleaseNotes(lib catalog.Library, version string) string {
	for _, r := range db.Releases {
		if r.Library == lib && r.Version == version && r.ReleaseNotesURL != nil {
			return *r.ReleaseNotesURL
		}
	}
	return ""
}

// SortAdvisories orders advisories newest first, then by ID.
func SortAdvisories(as []Advisory) {
	sort.SliceStable(as, func(i, j int) bool {
		if as[i].Published != as[j].Published {
			return as[i].Published > as[j].Published
		}
		return as[i].ID < as[j].ID
	})
}

type constraint struct {
	op, version string
}

var constraintRe = regexp.MustCompile(`^(>=|<=|>|<|=)\s*(\d\S*)$`)

// ParseRange parses a GitHub Advisory Database range such as
// ">= 1.2.0, < 3.5.0", "<= 1.8.3", "= 3.0.0-rc.1" or ">= 0".
func ParseRange(s string) ([]constraint, error) {
	var out []constraint
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		m := constraintRe.FindStringSubmatch(part)
		if m == nil {
			return nil, fmt.Errorf("unrecognised version range %q", s)
		}
		out = append(out, constraint{m[1], m[2]})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty version range")
	}
	return out, nil
}

// InRange reports whether version satisfies every constraint of the range.
// Versions are compared with catalog.CompareVersions, so pre-releases are
// ordered exactly ("3.0.0-rc1" equals "3.0.0-rc.1" and is below "3.0.0").
func InRange(rng, version string) (bool, error) {
	cs, err := ParseRange(rng)
	if err != nil {
		return false, err
	}
	for _, c := range cs {
		cmp := catalog.CompareVersions(version, c.version)
		ok := false
		switch c.op {
		case ">=":
			ok = cmp >= 0
		case ">":
			ok = cmp > 0
		case "<=":
			ok = cmp <= 0
		case "<":
			ok = cmp < 0
		case "=":
			ok = cmp == 0
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// CheckResult is the outcome of a version check.
type CheckResult struct {
	Library           catalog.Library `json:"library"`
	Name              string          `json:"name"`
	Version           string          `json:"version"`
	ReleaseDate       string          `json:"release_date"`
	Latest            string          `json:"latest"`
	LatestReleaseDate string          `json:"latest_release_date"`
	// TagDate and LatestTagDate are git tag dates, set only when the
	// official file has no date.
	TagDate             string `json:"tag_date,omitempty"`
	LatestTagDate       string `json:"latest_tag_date,omitempty"`
	ChangelogDate       string `json:"changelog_date,omitempty"`
	LatestChangelogDate string `json:"latest_changelog_date,omitempty"`
	// SupportInfo is the chosen version's support status (Support is its
	// JSON form); both are set by the caller.
	SupportInfo support.Info  `json:"-"`
	Support     *support.JSON `json:"support,omitempty"`
	// Checked lists the versions considered: the chosen version and every
	// stable release after it, up to the latest.
	Checked    []string   `json:"versions_checked"`
	Advisories []Advisory `json:"advisories"`
}

// Check finds the chosen release of lib, the latest stable release, and every
// advisory affecting any version from the chosen one up to the latest.
func Check(releases []catalog.Release, db *Database, lib catalog.Library, version string) (*CheckResult, error) {
	var mine []catalog.Release
	for _, r := range releases {
		if r.Library == lib {
			mine = append(mine, r)
		}
	}
	if len(mine) == 0 {
		return nil, fmt.Errorf("no %s releases in the database", lib.DisplayName())
	}
	catalog.SortReleases(mine)

	var chosen *catalog.Release
	for i := range mine {
		if mine[i].Version == strings.TrimPrefix(version, "v") {
			chosen = &mine[i]
			break
		}
	}
	if chosen == nil {
		for i := range mine {
			if catalog.CompareVersions(mine[i].Version, version) == 0 {
				chosen = &mine[i]
				break
			}
		}
	}
	if chosen == nil {
		return nil, fmt.Errorf("%s %s is not a known release (list them with: jsrelease -library %s)", lib.DisplayName(), version, lib)
	}

	latest := mine[0] // newest overall, used if there is no stable release
	for _, r := range mine {
		if isStable(r.Version) {
			latest = r
			break
		}
	}

	res := &CheckResult{
		Library: lib, Name: lib.DisplayName(), Version: chosen.Version, ReleaseDate: chosen.ReleaseDate,
		Latest: latest.Version, LatestReleaseDate: latest.ReleaseDate, Advisories: []Advisory{},
		TagDate: chosen.TagDate, LatestTagDate: latest.TagDate,
		ChangelogDate: chosen.ChangelogDate, LatestChangelogDate: latest.ChangelogDate,
	}
	checked := []string{chosen.Version}
	for _, r := range mine {
		if r.Version != chosen.Version && isStable(r.Version) &&
			catalog.CompareVersions(r.Version, chosen.Version) > 0 && catalog.CompareVersions(r.Version, latest.Version) <= 0 {
			checked = append(checked, r.Version)
		}
	}
	sort.SliceStable(checked, func(i, j int) bool { return catalog.CompareVersions(checked[i], checked[j]) < 0 })
	res.Checked = checked

	for _, a := range db.ForLibrary(lib) {
		for _, v := range checked {
			if a.Affects(v) {
				res.Advisories = append(res.Advisories, a)
				break
			}
		}
	}
	SortAdvisories(res.Advisories)
	return res, nil
}

func isStable(v string) bool {
	_, pre := splitPre(v)
	return pre == ""
}

var numericHead = regexp.MustCompile(`^\d+(?:\.\d+)*`)

func splitPre(v string) (string, string) {
	head := numericHead.FindString(v)
	return head, strings.TrimLeft(v[len(head):], "-.")
}
