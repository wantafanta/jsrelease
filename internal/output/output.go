// Package output renders releases and version checks as aligned text,
// Markdown pipe tables or JSON.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/support"
	"github.com/wantafanta/jsrelease/internal/vuln"
)

// NoDate is shown for releases with no date at all.
const NoDate = "N/A"

// Footnotes explaining the date markers.
const (
	TagDateFootnote       = "* date of the release's git tag (the release files carry no date)"
	ChangelogDateFootnote = "\u2021 date stated in the project's CHANGELOG (the release files carry no date)"
	InferredFootnote      = "\u2020 support status inferred: the project states no support policy for it"
)

// PlainFootnotes turns the Markdown-escaped footnotes in rendered output
// ("\\* …" and a trailing "\\" line break) back into plain text, for display
// on a terminal. Output without footnotes is returned unchanged.
func PlainFootnotes(data []byte) []byte {
	s := string(data)
	for _, f := range []string{TagDateFootnote, ChangelogDateFootnote, InferredFootnote} {
		if strings.HasPrefix(f, "*") {
			s = strings.ReplaceAll(s, "\\"+f, f)
		}
		s = strings.ReplaceAll(s, f+"\\\n", f+"\n")
	}
	return []byte(s)
}

// footnotesFor returns the footnotes for the markers used in dates.
func footnotesFor(cells ...string) string {
	var tag, cl, inf bool
	for _, d := range cells {
		tag = tag || strings.HasSuffix(d, catalog.TagMarker)
		cl = cl || strings.HasSuffix(d, catalog.ChangelogMarker)
		inf = inf || strings.HasSuffix(d, support.InferredMarker)
	}
	var out []string
	if tag {
		out = append(out, TagDateFootnote)
	}
	if cl {
		out = append(out, ChangelogDateFootnote)
	}
	if inf {
		out = append(out, InferredFootnote)
	}
	return strings.Join(out, "\n")
}

const columnGap = 2

// Table is a simple column table.
type Table struct {
	Headers []string
	Rows    [][]string
	// MinWidths are minimum text column widths (optional).
	MinWidths []int
	// Footnote is printed after the table (with a heading only).
	Footnote string
}

// Text writes t as aligned columns; the heading row is omitted when header
// is false.
func (t Table) Text(w io.Writer, header bool) error {
	n := len(t.Headers)
	widths := make([]int, n)
	for i := range widths {
		if i < len(t.MinWidths) {
			widths[i] = t.MinWidths[i]
		}
		widths[i] = max(widths[i], utf8.RuneCountInString(t.Headers[i]))
		for _, r := range t.Rows {
			widths[i] = max(widths[i], utf8.RuneCountInString(r[i]))
		}
	}
	var b strings.Builder
	line := func(cells []string) {
		for i, c := range cells {
			if i == n-1 {
				b.WriteString(c)
			} else {
				fmt.Fprintf(&b, "%-*s", widths[i]+columnGap, c)
			}
		}
		b.WriteString("\n")
	}
	if header {
		line(t.Headers)
	}
	for _, r := range t.Rows {
		line(r)
	}
	if header && t.Footnote != "" {
		b.WriteString("\n" + t.Footnote + "\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// Markdown writes t as an aligned Markdown (GitHub-flavoured) pipe table:
//
//	| LIBRARY | VERSION |
//	|---------|---------|
//	| jQuery  | 4.0.0   |
//
// The heading and separator are always written, because without them the
// rows are not a Markdown table. A "|" inside a value is escaped as "\|".
func (t Table) Markdown(w io.Writer) error {
	esc := func(c string) string {
		c = strings.ReplaceAll(c, "\n", " ")
		return strings.ReplaceAll(c, "|", `\|`)
	}
	n := len(t.Headers)
	widths := make([]int, n)
	for i := range widths {
		widths[i] = max(3, utf8.RuneCountInString(esc(t.Headers[i])))
		for _, r := range t.Rows {
			widths[i] = max(widths[i], utf8.RuneCountInString(esc(r[i])))
		}
	}
	var b strings.Builder
	line := func(cells []string) {
		b.WriteString("|")
		for i, c := range cells {
			c = esc(c)
			b.WriteString(" " + c + strings.Repeat(" ", widths[i]-utf8.RuneCountInString(c)) + " |")
		}
		b.WriteString("\n")
	}
	line(t.Headers)
	b.WriteString("|")
	for _, wd := range widths {
		b.WriteString(strings.Repeat("-", wd+2) + "|")
	}
	b.WriteString("\n")
	for _, r := range t.Rows {
		line(r)
	}
	if t.Footnote != "" {
		// Escape a leading "*" so it isn't read as a list bullet, and end
		// lines with a backslash so Markdown keeps the line breaks.
		lines := strings.Split(t.Footnote, "\n")
		for i, f := range lines {
			if strings.HasPrefix(f, "*") {
				f = `\` + f
			}
			if i < len(lines)-1 {
				f += `\`
			}
			lines[i] = f
		}
		b.WriteString("\n" + strings.Join(lines, "\n") + "\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// ReleaseTable builds the release listing with the default columns. With
// adv non-nil a CVE column is added, computed from the advisories.
func ReleaseTable(rs []catalog.Release, adv *vuln.Database) Table {
	return ReleaseTableColumns(rs, &Context{Adv: adv, Support: support.Compute(rs)}, DefaultReleaseColumns(adv != nil))
}

func advisoryNames(as []vuln.Advisory) string {
	if len(as) == 0 {
		return "-"
	}
	var out []string
	for _, a := range as {
		out = append(out, a.DisplayName())
	}
	return strings.Join(out, ", ")
}

// WriteTable writes releases as aligned columns.
func WriteTable(w io.Writer, rs []catalog.Release, header bool) error {
	return ReleaseTable(rs, nil).Text(w, header)
}

// WriteMarkdown writes releases as a Markdown pipe table (default columns).
func WriteMarkdown(w io.Writer, rs []catalog.Release, adv *vuln.Database) error {
	return ReleaseTable(rs, adv).Markdown(w)
}

type releaseJSON struct {
	catalog.Release
	Support *support.JSON `json:"support,omitempty"`
}

// WriteJSON writes releases, with their support status, as a JSON array.
func WriteJSON(w io.Writer, rs []catalog.Release) error {
	sup := support.Compute(rs)
	out := make([]releaseJSON, 0, len(rs))
	for _, r := range rs {
		out = append(out, releaseJSON{Release: r, Support: sup[support.Key(r)].ToJSON()})
	}
	return encode(w, out)
}

type advisoryRef struct {
	ID       string     `json:"id"`
	CVE      string     `json:"cve,omitempty"`
	Aliases  []string   `json:"aliases,omitempty"`
	Severity string     `json:"severity"`
	CVSS     *vuln.CVSS `json:"cvss"`
	URL      string     `json:"url"`
}

type releaseWithAdvisories struct {
	catalog.Release
	Support         *support.JSON `json:"support,omitempty"`
	ReleaseNotesURL *string       `json:"release_notes_url"`
	Advisories      []advisoryRef `json:"advisories"`
}

// WriteJSONWithAdvisories writes releases with their advisories and GitHub
// release-notes links.
func WriteJSONWithAdvisories(w io.Writer, rs []catalog.Release, adv *vuln.Database) error {
	sup := support.Compute(rs)
	out := make([]releaseWithAdvisories, 0, len(rs))
	for _, r := range rs {
		item := releaseWithAdvisories{Release: r, Support: sup[support.Key(r)].ToJSON(), Advisories: []advisoryRef{}}
		if u := adv.ReleaseNotes(r.Library, r.Version); u != "" {
			item.ReleaseNotesURL = &u
		}
		for _, a := range adv.Matching(r.Library, r.Version) {
			item.Advisories = append(item.Advisories, advisoryRef{ID: a.ID, CVE: a.CVE, Aliases: a.Aliases, Severity: a.Severity, CVSS: a.PrimaryCVSS(), URL: a.URL})
		}
		out = append(out, item)
	}
	return encode(w, out)
}

func encode(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func dateOrNA(s string) string {
	if s == "" {
		return NoDate
	}
	return s
}

// CheckTables returns the summary table (chosen and latest version) and the
// advisory table of a version check; nil column lists mean the defaults.
func CheckTables(res *vuln.CheckResult, sumCols, advCols []string) (Table, Table) {
	if advCols == nil {
		advCols = DefaultAdvisoryColumns
	}
	return SummaryTable(res, sumCols), AdvisoryTable(res.Advisories, advCols)
}

// NoAdvisoriesText describes an empty check result.
func NoAdvisoriesText(res *vuln.CheckResult) string {
	if res.Version == res.Latest {
		return fmt.Sprintf("No known advisories affect %s %s.", res.Name, res.Version)
	}
	return fmt.Sprintf("No known advisories affect %s %s or any later release up to %s.", res.Name, res.Version, res.Latest)
}

// WriteCheckText writes a version check as text.
func WriteCheckText(w io.Writer, res *vuln.CheckResult, header bool, sumCols, advCols []string) error {
	sum, adv := CheckTables(res, sumCols, advCols)
	if err := sum.Text(w, header); err != nil {
		return err
	}
	if len(adv.Rows) == 0 {
		if header {
			_, err := fmt.Fprintf(w, "\n%s\n", NoAdvisoriesText(res))
			return err
		}
		return nil
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return err
	}
	return adv.Text(w, header)
}

// WriteCheckMarkdown writes a version check as Markdown tables. When header
// is true and nothing is affected, a sentence saying so follows the summary.
func WriteCheckMarkdown(w io.Writer, res *vuln.CheckResult, header bool, sumCols, advCols []string) error {
	sum, adv := CheckTables(res, sumCols, advCols)
	if !header {
		sum.Footnote = ""
	}
	if err := sum.Markdown(w); err != nil {
		return err
	}
	if len(adv.Rows) == 0 {
		if header {
			_, err := fmt.Fprintf(w, "\n%s\n", NoAdvisoriesText(res))
			return err
		}
		return nil
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return err
	}
	return adv.Markdown(w)
}

// WriteCheckJSON writes a version check as JSON.
func WriteCheckJSON(w io.Writer, res *vuln.CheckResult) error { return encode(w, res) }
