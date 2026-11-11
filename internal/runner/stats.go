package runner

import (
	"bytes"
	"io"
	"time"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/logger"
	"github.com/wantafanta/jsrelease/internal/output"
)

// stats writes the per-library table: the result of -update and of -stats.
// When announce is true the files loaded are reported as usual.
func stats(opts *Options, path, vulnPath string, libs []catalog.Library, newKeys map[string]bool, stdout io.Writer, log *logger.Logger, announce bool) error {
	var db *catalog.Database
	var err error
	if announce {
		db, err = loadReleases(path, log)
	} else {
		db, _, err = readReleases(path)
	}
	if err != nil {
		return err
	}
	vdb, vfrom, verr := readVulns(vulnPath)
	switch {
	case verr == nil && announce:
		log.Infof("Loaded %d advisories from %s (updated %s)", len(vdb.Advisories), vfrom, formatUpdated(vdb.UpdatedAt, time.Local))
	case verr != nil:
		vdb = nil
		log.Debugf("no advisory counts: %v", verr)
	}
	rows := output.Stats(catalog.Filter(db.Releases, libs), vdb, newKeys)
	var buf bytes.Buffer
	switch {
	case opts.JSON:
		err = output.WriteStatsJSON(&buf, rows)
	case opts.Text:
		err = output.StatsTable(rows).Text(&buf, !opts.Silent)
	default:
		err = output.StatsTable(rows).Markdown(&buf)
	}
	if err != nil {
		return err
	}
	if announce {
		return emit(opts, buf.Bytes(), len(rows), stdout, log)
	}
	// After an update: a blank line separates the table from any messages
	// printed above it (New:, warnings, -v detail); none if there were none.
	log.Separate()
	return write(opts, buf.Bytes(), stdout, log)
}
