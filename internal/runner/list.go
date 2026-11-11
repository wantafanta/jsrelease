package runner

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"time"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/logger"
	"github.com/wantafanta/jsrelease/internal/output"
	"github.com/wantafanta/jsrelease/internal/support"
	"github.com/wantafanta/jsrelease/internal/vuln"
)

func loadReleases(path string, log *logger.Logger) (*catalog.Database, error) {
	db, from, err := readReleases(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no release data in %s; run 'jsrelease -update' to create it, or use -data", path)
	}
	if err != nil {
		return nil, err
	}
	if len(db.Releases) == 0 {
		log.Warnf("The database at %s contains no releases; run 'jsrelease -update' to populate it", path)
	} else {
		log.Infof("Loaded %d releases from %s (updated %s)", len(db.Releases), from, formatUpdated(db.UpdatedAt, time.Local))
		staleHint(db.UpdatedAt, log)
	}
	return db, nil
}

func loadVulns(path string, log *logger.Logger) (*vuln.Database, error) {
	db, from, err := readVulns(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no vulnerability data in %s; run 'jsrelease -update' to add it, or use -data", path)
	}
	if err != nil {
		return nil, err
	}
	log.Infof("Loaded %d advisories from %s (updated %s)", len(db.Advisories), from, formatUpdated(db.UpdatedAt, time.Local))
	return db, nil
}

func list(opts *Options, path, vulnPath string, libs []catalog.Library, stdout io.Writer, log *logger.Logger) error {
	db, err := loadReleases(path, log)
	if err != nil {
		return err
	}
	cols := output.DefaultReleaseColumns(false)
	if opts.Columns != "" {
		if cols, err = output.ParseColumns(opts.Columns, output.ReleaseColumnNames(), "release list"); err != nil {
			return err
		}
		if opts.JSON {
			log.Warnf("-cols does not change -json output, which always includes every field")
		}
	}
	var vdb *vuln.Database
	switch {
	case output.ColumnsNeedAdvisories(cols):
		if vdb, err = loadVulns(vulnPath, log); err != nil {
			return err
		}
	case opts.JSON:
		// JSON always includes advisories and release notes when available.
		if v, _, verr := readVulns(vulnPath); verr == nil {
			vdb = v
		} else {
			log.Debugf("JSON without advisories: %v", verr)
		}
	}
	rs := catalog.Filter(db.Releases, libs)
	catalog.SortReleases(rs)

	var buf bytes.Buffer
	switch {
	case opts.JSON && vdb != nil:
		err = output.WriteJSONWithAdvisories(&buf, rs, vdb)
	case opts.JSON:
		err = output.WriteJSON(&buf, rs)
	case opts.Text:
		err = output.ReleaseTableColumns(rs, &output.Context{Adv: vdb, Support: support.Compute(db.Releases)}, cols).Text(&buf, !opts.Silent)
	default:
		t := output.ReleaseTableColumns(rs, &output.Context{Adv: vdb, Support: support.Compute(db.Releases)}, cols)
		if opts.Silent {
			t.Footnote = ""
		}
		err = t.Markdown(&buf)
	}
	if err != nil {
		return err
	}
	return emit(opts, buf.Bytes(), len(rs), stdout, log)
}

// staleAfter is how old the data may be before a refresh is suggested.
const staleAfter = 30 * 24 * time.Hour

// now is the current time (replaceable in tests).
var now = time.Now

// staleHint suggests an update when the data is more than staleAfter old.
func staleHint(updatedAt string, log *logger.Logger) {
	t, err := time.Parse(time.RFC3339, updatedAt)
	if err != nil {
		return
	}
	if age := now().Sub(t); age > staleAfter {
		log.Infof("Data is %d days old; run 'jsrelease -up' to refresh", int(age.Hours()/24))
	}
}
