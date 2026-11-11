package catalog

// This file is the one place that describes each library. Adding a library
// means adding a Def here (plus, for a new kind of release source, date rule
// or support policy, the code that implements it).

// Source is where a library's releases are found.
type Source int

const (
	// FromJQuerySite: releases.jquery.com pages; dates from the release file.
	FromJQuerySite Source = iota
	// FromGitHub: git tags (and CHANGELOG or release file) on GitHub.
	FromGitHub
)

// Support policy kinds (see package support).
const (
	PolicyTwoMajors     = "two-majors"      // latest major supported, previous security only
	PolicyFollowCore    = "follow-core"     // follows the jQuery line it is used with
	PolicyLatestLine    = "latest-line"     // only the latest major.minor line is supported
	PolicyDeprecated    = "deprecated"      // the whole project is deprecated
	PolicyMajorsWithEOL = "majors-with-eol" // latest major supported; published end dates
	PolicyMaintenance   = "maintenance"     // latest major receives security fixes only
	PolicyInactive      = "inactive"        // no release for years, no statement
)

// Support describes a library's support policy. Source is the project's
// statement; an empty Source means the status is inferred.
type Support struct {
	Policy string
	Source string
	Since  string         // PolicyDeprecated: since when (DD/MM/YYYY)
	EOL    map[int]string // PolicyMajorsWithEOL: published end dates per major
	Note   string
}

// Def describes one library.
type Def struct {
	ID     Library
	Name   string
	Source Source
	// Repo is the GitHub repository (release notes; tags for FromGitHub and
	// the tag-date fallback for FromJQuerySite).
	Repo string
	// NPM is the npm package, used for GitHub's advisories ("" if not on npm).
	NPM string
	// NVDVendor and NVDProducts find advisories at NVD for a library not on npm.
	NVDVendor   string
	NVDProducts []string

	// FromGitHub only.
	TagPattern      string   // regexp; the first group is the version
	Changelog       string   // path of the CHANGELOG in the repository, if any
	ChangelogFormat string   // how to read it: "prototype", "moment", "underscore"
	FilePaths       []string // release files whose "Date:" header is the official date
	DateNote        string   // shown when no date is found
	MinReleases     int      // sanity floor

	Support Support
}

// Libraries lists every library, in display order.
var Libraries = []Def{
	{ID: Core, Name: "jQuery", Source: FromJQuerySite, Repo: "jquery/jquery", NPM: "jquery",
		Support: Support{Policy: PolicyTwoMajors, Source: "https://jquery.com/support/",
			Note: "jQuery supports its two latest major versions; the older one receives security fixes only"}},
	{ID: Migrate, Name: "jQuery Migrate", Source: FromJQuerySite, Repo: "jquery/jquery-migrate", NPM: "jquery-migrate",
		Support: Support{Policy: PolicyFollowCore, Note: "follows the support of the jQuery line it is used with"}},
	{ID: UI, Name: "jQuery UI", Source: FromJQuerySite, Repo: "jquery/jquery-ui", NPM: "jquery-ui",
		Support: Support{Policy: PolicyLatestLine}},
	{ID: Mobile, Name: "jQuery Mobile", Source: FromJQuerySite, Repo: "jquery-archive/jquery-mobile", NPM: "jquery-mobile",
		Support: Support{Policy: PolicyDeprecated, Since: "07/10/2021", Note: "jQuery Mobile is deprecated",
			Source: "https://blog.jquerymobile.com/2021/10/07/jquery-maintainers-continue-modernization-initiative-with-deprecation-of-jquery-mobile/"}},
	{ID: Bootstrap, Name: "Bootstrap", Source: FromGitHub, Repo: "twbs/bootstrap", NPM: "bootstrap",
		TagPattern: `^v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)$`,
		DateNote:   "Bootstrap's release files carry no date", MinReleases: 60,
		Support: Support{Policy: PolicyMajorsWithEOL, Source: "https://github.com/twbs/release",
			EOL: map[int]string{4: "01/01/2023", 3: "24/07/2019", 2: "19/08/2013"}}},
	{ID: Prototype, Name: "Prototype", Source: FromGitHub, Repo: "prototypejs/prototype",
		NVDVendor: "cpe:2.3:a:prototypejs", NVDProducts: []string{"cpe:2.3:a:prototypejs:prototype", "cpe:2.3:a:prototypejs:prototype_framework"},
		TagPattern: `^(\d+\.\d+(?:\.\d+)*(?:_[0-9A-Za-z]+)?)$`, Changelog: "CHANGELOG", ChangelogFormat: "prototype",
		DateNote: "Prototype's release files carry no date", MinReleases: 20,
		Support: Support{Policy: PolicyInactive}},
	{ID: Moment, Name: "Moment.js", Source: FromGitHub, Repo: "moment/moment", NPM: "moment",
		TagPattern: `^(\d+\.\d+\.\d+)$`, Changelog: "CHANGELOG.md", ChangelogFormat: "moment",
		DateNote: "Moment.js's release files carry no date", MinReleases: 60,
		Support: Support{Policy: PolicyMaintenance, Source: "https://momentjs.com/docs/#/-project-status/",
			Note: "Moment.js is a legacy project in maintenance mode"}},
	{ID: Underscore, Name: "Underscore.js", Source: FromGitHub, Repo: "jashkenas/underscore", NPM: "underscore",
		TagPattern: `^(\d+\.\d+\.\d+(?:-\d+)?)$`, Changelog: "index.html", ChangelogFormat: "underscore",
		DateNote: "Underscore.js's release files carry no date", MinReleases: 60,
		Support: Support{Policy: PolicyLatestLine}},
	{ID: Sizzle, Name: "Sizzle", Source: FromGitHub, Repo: "jquery/sizzle", NPM: "sizzle",
		// Plain versions only: "2.1.1-jquery.2.1.2" is a build made for jQuery.
		TagPattern: `^v?(\d+\.\d+(?:\.\d+)?)$`, FilePaths: []string{"dist/sizzle.js", "sizzle.js"},
		DateNote: "this Sizzle release file carries no date", MinReleases: 40,
		Support: Support{Policy: PolicyInactive}},
}

// Get returns the definition of l (the zero Def if unknown).
func Get(l Library) Def {
	for _, d := range Libraries {
		if d.ID == l {
			return d
		}
	}
	return Def{}
}
