package output

import (
	"io"
	"strconv"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/vuln"
)

// StatsRow summarises one library (the table shown by -update and -stats).
type StatsRow struct {
	Library    catalog.Library `json:"library"`
	Name       string          `json:"name"`
	Releases   int             `json:"releases"`
	New        int             `json:"new"`
	Latest     string          `json:"latest"`
	Advisories int             `json:"advisories"`
	// AffectsLatest counts advisories that affect the latest release.
	AffectsLatest int `json:"affects_latest"`
}

// Stats builds one row per library present in rs, in display order. adv may
// be nil (no advisory counts); isNew marks releases added by an update
// (keys "library@version"), and may be nil.
func Stats(rs []catalog.Release, adv *vuln.Database, isNew map[string]bool) []StatsRow {
	byLib := map[catalog.Library][]catalog.Release{}
	for _, r := range rs {
		byLib[r.Library] = append(byLib[r.Library], r)
	}
	var out []StatsRow
	for _, lib := range catalog.AllLibraries {
		list := byLib[lib]
		if len(list) == 0 {
			continue
		}
		row := StatsRow{Library: lib, Name: lib.DisplayName(), Releases: len(list)}
		latestAny := ""
		for _, r := range list {
			if isNew[string(r.Library)+"@"+r.Version] {
				row.New++
			}
			if catalog.IsStable(r.Version) && (row.Latest == "" || catalog.CompareVersions(r.Version, row.Latest) > 0) {
				row.Latest = r.Version
			}
			if latestAny == "" || catalog.CompareVersions(r.Version, latestAny) > 0 {
				latestAny = r.Version
			}
		}
		if row.Latest == "" {
			row.Latest = latestAny
		}
		if adv != nil {
			row.Advisories = len(adv.ForLibrary(lib))
			row.AffectsLatest = len(adv.Matching(lib, row.Latest))
		}
		out = append(out, row)
	}
	return out
}

// StatsTable renders the rows as a table.
func StatsTable(rows []StatsRow) Table {
	t := Table{Headers: []string{"Library", "Releases", "New", "Latest", "Advisories", "Affects Latest"}}
	for _, r := range rows {
		t.Rows = append(t.Rows, []string{r.Name, strconv.Itoa(r.Releases), strconv.Itoa(r.New), r.Latest,
			strconv.Itoa(r.Advisories), strconv.Itoa(r.AffectsLatest)})
	}
	return t
}

// WriteStatsJSON writes the rows as a JSON array.
func WriteStatsJSON(w io.Writer, rows []StatsRow) error {
	if rows == nil {
		rows = []StatsRow{}
	}
	return encode(w, rows)
}
