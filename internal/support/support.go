// Package support works out whether a release is supported, receives
// security fixes only, or is unsupported, from each project's own statements
// (official) or, where a project states no policy, from its release history
// (inferred). Statuses are computed from the release data, so they follow new
// releases without a tool update.
package support

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/wantafanta/jsrelease/internal/catalog"
)

// Status is a support status.
type Status string

const (
	Supported    Status = "Supported"
	SecurityOnly Status = "Security only"
	Unsupported  Status = "Unsupported"
)

// InferredMarker marks statuses not based on a project statement.
const InferredMarker = "\u2020" // †

// Info is the support status of one release.
type Info struct {
	Status Status `json:"-"`
	// Since is when the status began (DD/MM/YYYY), if known.
	Since string `json:"since,omitempty"`
	// Official is true when the status follows a statement by the project.
	Official bool   `json:"-"`
	Source   string `json:"source,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Text is the table cell: the status, with "†" when inferred.
func (i Info) Text() string {
	if i.Status == "" {
		return "-"
	}
	if !i.Official {
		return string(i.Status) + InferredMarker
	}
	return string(i.Status)
}

// JSON is the form used in JSON output.
type JSON struct {
	Status string `json:"status"` // supported, security-only, unsupported
	Basis  string `json:"basis"`  // official or inferred
	Info
}

// ToJSON converts i for JSON output.
func (i Info) ToJSON() *JSON {
	if i.Status == "" {
		return nil
	}
	basis := "inferred"
	if i.Official {
		basis = "official"
	}
	return &JSON{Status: strings.ReplaceAll(strings.ToLower(string(i.Status)), " ", "-"), Basis: basis, Info: i}
}

// JQueryMigrateURL is the compatibility table Migrate's status is inferred from.
const JQueryMigrateURL = "https://github.com/jquery/jquery-migrate#version-compatibility"

var numeric = regexp.MustCompile(`^(\d+)(?:\.(\d+))?`)

func major(v string) int {
	m := numeric.FindStringSubmatch(v)
	if m == nil {
		return -1
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// line is the major.minor release line, e.g. "1.14" for 1.14.2.
func line(v string) string {
	m := numeric.FindStringSubmatch(v)
	if m == nil {
		return v
	}
	return m[1] + "." + m[2]
}

// Key identifies a release in the result of Compute.
func Key(r catalog.Release) string { return string(r.Library) + "@" + r.Version }

// rawDate is the release's date without a source marker.
func rawDate(r catalog.Release) string {
	for _, d := range []string{r.ReleaseDate, r.ChangelogDate, r.TagDate} {
		if d != "" {
			return d
		}
	}
	return ""
}

// Compute returns the support status of every release in all.
func Compute(all []catalog.Release) map[string]Info {
	byLib := map[catalog.Library][]catalog.Release{}
	for _, r := range all {
		byLib[r.Library] = append(byLib[r.Library], r)
	}
	// The newest stable major of a library, and the first stable release
	// (by version) of each major and each minor line.
	latestMajor := map[catalog.Library]int{}
	firstOfLine := map[string]catalog.Release{} // lib@line -> first stable release
	for lib, rs := range byLib {
		latestMajor[lib] = -1
		for _, r := range rs {
			if !catalog.IsStable(r.Version) {
				continue
			}
			if m := major(r.Version); m > latestMajor[lib] {
				latestMajor[lib] = m
			}
			k := string(lib) + "@" + line(r.Version)
			if f, ok := firstOfLine[k]; !ok || catalog.CompareVersions(r.Version, f.Version) < 0 {
				firstOfLine[k] = r
			}
		}
	}
	latestLine := map[catalog.Library]string{}
	for lib, rs := range byLib {
		for _, r := range rs {
			if catalog.IsStable(r.Version) && (latestLine[lib] == "" || catalog.CompareVersions(line(r.Version)+".0", latestLine[lib]+".0") > 0) {
				latestLine[lib] = line(r.Version)
			}
		}
	}
	firstOfMajor := func(lib catalog.Library, m int) string {
		var best catalog.Release
		for _, r := range byLib[lib] {
			if catalog.IsStable(r.Version) && major(r.Version) == m && (best.Version == "" || catalog.CompareVersions(r.Version, best.Version) < 0) {
				best = r
			}
		}
		return rawDate(best)
	}
	// twoMajors: the latest major is supported, the previous one receives
	// security fixes only (jQuery's stated policy).
	twoMajors := func(lib catalog.Library, m int) Info {
		pol := catalog.Get(lib).Support
		M := latestMajor[lib]
		switch {
		case m == M:
			return Info{Status: Supported, Official: true, Source: pol.Source}
		case m == M-1:
			return Info{Status: SecurityOnly, Since: firstOfMajor(lib, M), Official: true, Source: pol.Source, Note: pol.Note}
		}
		return Info{Status: Unsupported, Official: true, Source: pol.Source}
	}

	out := map[string]Info{}
	for lib, rs := range byLib {
		for _, r := range rs {
			v := r.Version
			var info Info
			def := catalog.Get(lib)
			pol := def.Support
			switch {
			case !catalog.IsStable(v):
				info = Info{Status: Unsupported, Note: "pre-release: not intended for production use"}
			case pol.Policy == catalog.PolicyTwoMajors:
				info = twoMajors(lib, major(v))
			case pol.Policy == catalog.PolicyFollowCore:
				// Migrate N is for jQuery N, so it follows that jQuery line.
				info = twoMajors(catalog.Core, major(v))
				info.Official, info.Source = false, JQueryMigrateURL
				info.Note = "follows the support of the jQuery " + strconv.Itoa(major(v)) + ".x line it is used with"
			case pol.Policy == catalog.PolicyLatestLine:
				note := def.Name + " states no support policy; only its latest line receives releases"
				if line(v) == latestLine[lib] {
					info = Info{Status: Supported, Note: note}
				} else {
					info = Info{Status: Unsupported, Note: note}
					// Since: the first release of the next line.
					next := ""
					for k, f := range firstOfLine {
						if f.Library == lib && catalog.CompareVersions(strings.TrimPrefix(k, string(lib)+"@")+".0", line(v)+".0") > 0 &&
							(next == "" || catalog.CompareVersions(f.Version, next) < 0) {
							next = f.Version
							info.Since = rawDate(f)
						}
					}
				}
			case pol.Policy == catalog.PolicyDeprecated:
				info = Info{Status: Unsupported, Since: pol.Since, Official: true, Source: pol.Source, Note: pol.Note}
			case pol.Policy == catalog.PolicyMajorsWithEOL:
				m := major(v)
				switch eol, known := pol.EOL[m]; {
				case m == latestMajor[lib]:
					info = Info{Status: Supported, Official: true, Source: pol.Source}
				case known:
					info = Info{Status: Unsupported, Since: eol, Official: true, Source: pol.Source}
				case m == latestMajor[lib]-1:
					info = Info{Status: SecurityOnly, Source: pol.Source,
						Note: def.Name + " moves the previous major version to long-term support; no end date published yet"}
				default:
					info = Info{Status: Unsupported, Note: def.Name + " has published no end date for this major version"}
				}
			case pol.Policy == catalog.PolicyMaintenance:
				if major(v) == latestMajor[lib] {
					info = Info{Status: SecurityOnly, Official: true, Source: pol.Source, Note: pol.Note}
				} else {
					info = Info{Status: Unsupported, Note: "older " + def.Name + " major versions receive no fixes"}
				}
			case pol.Policy == catalog.PolicyInactive:
				// Inactive projects with no statement: unsupported (inferred).
				info = Info{Status: Unsupported, Note: "no release since " + lastReleaseYear(byLib[lib]) + "; the project has made no statement"}
			}
			out[Key(r)] = info
		}
	}
	return out
}

// lastReleaseYear is the year of a library's most recent release date.
func lastReleaseYear(rs []catalog.Release) string {
	best := ""
	for _, r := range rs {
		if d := rawDate(r); len(d) == 10 && (best == "" || d[6:]+d[3:5]+d[:2] > best[6:]+best[3:5]+best[:2]) {
			best = d
		}
	}
	if best == "" {
		return "unknown"
	}
	return best[6:]
}

// NewestInLine returns the newest stable release of v's major line.
func NewestInLine(all []catalog.Release, lib catalog.Library, v string) string {
	best := ""
	for _, r := range all {
		if r.Library == lib && catalog.IsStable(r.Version) && major(r.Version) == major(v) &&
			(best == "" || catalog.CompareVersions(r.Version, best) > 0) {
			best = r.Version
		}
	}
	return best
}
