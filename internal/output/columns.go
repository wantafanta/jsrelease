package output

import (
	"fmt"
	"strings"
	"time"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/support"
	"github.com/wantafanta/jsrelease/internal/vuln"
)

// Context is what release columns may need besides the release itself.
type Context struct {
	Adv     *vuln.Database
	Support map[string]support.Info
}

// ReleaseColumn is a selectable column of the release list.
type ReleaseColumn struct {
	Name, Header, Description string
	MinWidth                  int
	// NeedsAdvisories means the vulnerability file must be loaded.
	NeedsAdvisories bool
	Value           func(r catalog.Release, c *Context) string
}

// AdvisoryColumn is a selectable column of the -check advisory table.
type AdvisoryColumn struct {
	Name, Header, Description string
	Value                     func(a vuln.Advisory) string
}

// ReleaseColumns lists the release-list columns.
var ReleaseColumns = []ReleaseColumn{
	{Name: "library", Header: "Library", MinWidth: 14, Description: "library name",
		Value: func(r catalog.Release, _ *Context) string { return r.Name }},
	{Name: "version", Header: "Version", MinWidth: 15, Description: "version, as shown on releases.jquery.com or in the git tag",
		Value: func(r catalog.Release, _ *Context) string { return r.Version }},
	{Name: "date", Header: "Release Date", Description: "release date (DD/MM/YYYY); * = git tag date, \u2021 = CHANGELOG date",
		Value: func(r catalog.Release, _ *Context) string { return dateOrNA(r.DisplayDate()) }},
	{Name: "support", Header: "Support", Description: "Supported, Security only or Unsupported (\u2020 = inferred: no stated policy)",
		Value: func(r catalog.Release, c *Context) string { return c.Support[support.Key(r)].Text() }},
	{Name: "cves", Header: "CVEs", NeedsAdvisories: true, Description: "CVEs (GitHub and NVD advisories) affecting the release",
		Value: func(r catalog.Release, c *Context) string {
			return advisoryNames(c.Adv.Matching(r.Library, r.Version))
		}},
	{Name: "notes", Header: "Release Notes", NeedsAdvisories: true, Description: "GitHub release-notes URL, - if there is none",
		Value: func(r catalog.Release, c *Context) string {
			if u := c.Adv.ReleaseNotes(r.Library, r.Version); u != "" {
				return u
			}
			return "-"
		}},
}

// AdvisoryColumns lists the -check advisory-table columns.
var AdvisoryColumns = []AdvisoryColumn{
	{Name: "advisory", Header: "CVE / Advisory", Description: "CVE ID (GHSA ID if none), with duplicate CVE IDs",
		Value: func(a vuln.Advisory) string { return a.DisplayName() }},
	{Name: "severity", Header: "Severity", Description: "severity: Low, Medium, High or Critical",
		Value: func(a vuln.Advisory) string { return vuln.TitleSeverity(a.Severity) }},
	{Name: "cvss", Header: "CVSS", Description: "CVSS score (version shown if not CVSS v3), - if none",
		Value: func(a vuln.Advisory) string { return a.CVSSText() }},
	{Name: "range", Header: "Vulnerable Range", Description: "affected versions",
		Value: func(a vuln.Advisory) string { return a.RangeText() }},
	{Name: "fixed", Header: "Fixed In", Description: "first fixed version, none if there is no fix",
		Value: func(a vuln.Advisory) string { return a.FixedText() }},
	{Name: "ghsa", Header: "GHSA", Description: "GitHub advisory ID",
		Value: func(a vuln.Advisory) string { return a.ID }},
	{Name: "link", Header: "Link", Description: "GitHub advisory page (NVD page for NVD-only advisories)",
		Value: func(a vuln.Advisory) string { return a.URL }},
	{Name: "summary", Header: "Summary", Description: "advisory title",
		Value: func(a vuln.Advisory) string { return a.Summary }},
	{Name: "published", Header: "Published", Description: "date GitHub published the advisory (DD/MM/YYYY)",
		Value: func(a vuln.Advisory) string { return ukDate(a.Published) }},
}

// DefaultReleaseColumns is the release list without -cols.
func DefaultReleaseColumns(withCVEs bool) []string {
	if withCVEs {
		return []string{"library", "version", "date", "support", "cves"}
	}
	return []string{"library", "version", "date", "support"}
}

// DefaultAdvisoryColumns is the -check advisory table without -cols.
var DefaultAdvisoryColumns = []string{"advisory", "severity", "cvss", "summary"}

// SummaryColumn is a selectable column of the -check summary table.
type SummaryColumn struct {
	Name, Header, Description string
	Value                     func(res *vuln.CheckResult) string
}

func checkDates(res *vuln.CheckResult) (string, string) {
	mine := catalog.Release{ReleaseDate: res.ReleaseDate, TagDate: res.TagDate, ChangelogDate: res.ChangelogDate}
	latest := catalog.Release{ReleaseDate: res.LatestReleaseDate, TagDate: res.LatestTagDate, ChangelogDate: res.LatestChangelogDate}
	return dateOrNA(mine.DisplayDate()), dateOrNA(latest.DisplayDate())
}

// SummaryColumns lists the -check summary-table columns.
var SummaryColumns = []SummaryColumn{
	{Name: "library", Header: "Library", Description: "library name",
		Value: func(res *vuln.CheckResult) string { return res.Name }},
	{Name: "version", Header: "Version", Description: "the version checked",
		Value: func(res *vuln.CheckResult) string { return res.Version }},
	{Name: "date", Header: "Release Date", Description: "its release date",
		Value: func(res *vuln.CheckResult) string { d, _ := checkDates(res); return d }},
	{Name: "support", Header: "Support", Description: "its support status",
		Value: func(res *vuln.CheckResult) string { return res.SupportInfo.Text() }},
	{Name: "latest", Header: "Latest", Description: "the latest stable version",
		Value: func(res *vuln.CheckResult) string { return res.Latest }},
	{Name: "latest-date", Header: "Latest Release Date", Description: "the latest version's release date",
		Value: func(res *vuln.CheckResult) string { _, d := checkDates(res); return d }},
}

// DefaultSummaryColumns is the -check summary table without -cols.
var DefaultSummaryColumns = []string{"library", "version", "date", "support", "latest", "latest-date"}

// SummaryColumnNames lists the -check summary column names.
func SummaryColumnNames() []string {
	var out []string
	for _, c := range SummaryColumns {
		out = append(out, c.Name)
	}
	return out
}

// CheckColumnNames lists every column name valid with -check (both tables).
func CheckColumnNames() []string { return append(SummaryColumnNames(), AdvisoryColumnNames()...) }

// SplitCheckColumns divides a -check column list between the two tables,
// keeping the given order. A table with no columns named gets nil (its
// defaults).
func SplitCheckColumns(cols []string) (summary, adv []string) {
	isSum := map[string]bool{}
	for _, n := range SummaryColumnNames() {
		isSum[n] = true
	}
	for _, c := range cols {
		if isSum[c] {
			summary = append(summary, c)
		} else {
			adv = append(adv, c)
		}
	}
	return summary, adv
}

// SummaryTable builds the -check summary table with the given columns.
func SummaryTable(res *vuln.CheckResult, cols []string) Table {
	if cols == nil {
		cols = DefaultSummaryColumns
	}
	t := Table{}
	var row, marked []string
	for _, n := range cols {
		for _, c := range SummaryColumns {
			if c.Name == n {
				t.Headers = append(t.Headers, c.Header)
				v := c.Value(res)
				row = append(row, v)
				if n == "date" || n == "latest-date" || n == "support" {
					marked = append(marked, v)
				}
			}
		}
	}
	t.Rows = [][]string{row}
	t.Footnote = footnotesFor(marked...)
	return t
}

func ukDate(iso string) string {
	t, err := time.Parse("2006-01-02", iso)
	if err != nil {
		return "-"
	}
	return t.Format(catalog.DateLayout)
}

// ParseColumns parses a comma-separated column list against the valid names.
// Names are case-insensitive; the order given is kept.
func ParseColumns(spec string, valid []string, table string) ([]string, error) {
	ok := map[string]bool{}
	for _, v := range valid {
		ok[v] = true
	}
	var out []string
	seen := map[string]bool{}
	// cve, cves and advisory name the CVE column of whichever table is meant.
	target := ""
	for _, v := range valid {
		if v == "cves" && target == "" {
			target = "cves"
		}
		if v == "advisory" {
			target = "advisory"
		}
	}
	for _, part := range strings.Split(spec, ",") {
		name := strings.ToLower(strings.TrimSpace(part))
		if target != "" && (name == "cve" || name == "cves" || name == "advisory") {
			name = target
		}
		switch {
		case name == "":
			return nil, fmt.Errorf("empty column name in -cols %q", spec)
		case !ok[name]:
			return nil, fmt.Errorf("unknown column %q for the %s (valid: %s; see -cols list)", name, table, strings.Join(valid, ", "))
		case seen[name]:
			return nil, fmt.Errorf("column %q listed twice in -cols", name)
		}
		seen[name] = true
		out = append(out, name)
	}
	return out, nil
}

// ReleaseColumnNames and AdvisoryColumnNames list the valid names.
func ReleaseColumnNames() []string {
	var out []string
	for _, c := range ReleaseColumns {
		out = append(out, c.Name)
	}
	return out
}

func AdvisoryColumnNames() []string {
	var out []string
	for _, c := range AdvisoryColumns {
		out = append(out, c.Name)
	}
	return out
}

// ColumnsNeedAdvisories reports whether any selected release column needs
// the vulnerability file.
func ColumnsNeedAdvisories(cols []string) bool {
	for _, n := range cols {
		for _, c := range ReleaseColumns {
			if c.Name == n && c.NeedsAdvisories {
				return true
			}
		}
	}
	return false
}

// ColumnsHelp describes the selectable columns (shown by -cols list).
func ColumnsHelp() string {
	var b strings.Builder
	b.WriteString("Release list columns (default: library,version,date,support):\n")
	for _, c := range ReleaseColumns {
		fmt.Fprintf(&b, "   %-12s %s\n", c.Name, c.Description)
		if c.Name == "cves" {
			b.WriteString("                (also: cve, advisory)\n")
		}
	}
	b.WriteString("\n-check summary table columns (default: " + strings.Join(DefaultSummaryColumns, ",") + "):\n")
	for _, c := range SummaryColumns {
		fmt.Fprintf(&b, "   %-12s %s\n", c.Name, c.Description)
	}
	b.WriteString("\n-check advisory table columns (default: " + strings.Join(DefaultAdvisoryColumns, ",") + "):\n")
	for _, c := range AdvisoryColumns {
		fmt.Fprintf(&b, "   %-12s %s\n", c.Name, c.Description)
		if c.Name == "advisory" {
			b.WriteString("                (also: cve, cves)\n")
		}
	}
	b.WriteString("\nWith -check, names for both tables can be mixed: each table shows the ones named\nfor it, in order, and a table with none named keeps its defaults.\n")
	b.WriteString("\nExample: jsrelease -library core -check 3.4.1 -cols version,support,latest,advisory,cvss\n")
	return b.String()
}

// ReleaseTableColumns builds the release list with the given columns.
func ReleaseTableColumns(rs []catalog.Release, c *Context, cols []string) Table {
	var defs []ReleaseColumn
	for _, n := range cols {
		for _, c := range ReleaseColumns {
			if c.Name == n {
				defs = append(defs, c)
			}
		}
	}
	t := Table{}
	for _, d := range defs {
		t.Headers = append(t.Headers, d.Header)
		t.MinWidths = append(t.MinWidths, d.MinWidth)
	}
	var marked []string
	for _, r := range rs {
		row := make([]string, 0, len(defs))
		for _, d := range defs {
			v := d.Value(r, c)
			if d.Name == "date" || d.Name == "support" {
				marked = append(marked, v)
			}
			row = append(row, v)
		}
		t.Rows = append(t.Rows, row)
	}
	t.Footnote = footnotesFor(marked...)
	return t
}

// AdvisoryTable builds the -check advisory table with the given columns.
func AdvisoryTable(as []vuln.Advisory, cols []string) Table {
	var defs []AdvisoryColumn
	for _, n := range cols {
		for _, c := range AdvisoryColumns {
			if c.Name == n {
				defs = append(defs, c)
			}
		}
	}
	t := Table{}
	for _, d := range defs {
		t.Headers = append(t.Headers, d.Header)
	}
	for _, a := range as {
		row := make([]string, 0, len(defs))
		for _, d := range defs {
			row = append(row, d.Value(a))
		}
		t.Rows = append(t.Rows, row)
	}
	return t
}
