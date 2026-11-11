package runner

import (
	"bytes"
	"fmt"
	"io"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/logger"
	"github.com/wantafanta/jsrelease/internal/output"
	"github.com/wantafanta/jsrelease/internal/support"
	"github.com/wantafanta/jsrelease/internal/vuln"
)

func check(opts *Options, path, vulnPath string, lib catalog.Library, stdout io.Writer, log *logger.Logger) error {
	db, err := loadReleases(path, log)
	if err != nil {
		return err
	}
	vdb, err := loadVulns(vulnPath, log)
	if err != nil {
		return err
	}
	var sumCols, advCols []string
	if opts.Columns != "" {
		cols, err := output.ParseColumns(opts.Columns, output.CheckColumnNames(), "-check tables")
		if err != nil {
			return err
		}
		sumCols, advCols = output.SplitCheckColumns(cols)
		if opts.JSON {
			log.Warnf("-cols does not change -json output, which always includes every field")
		}
	}
	res, err := vuln.Check(db.Releases, vdb, lib, opts.Check)
	if err != nil {
		return err
	}
	sup := support.Compute(db.Releases)
	res.SupportInfo = sup[string(lib)+"@"+res.Version]
	res.Support = res.SupportInfo.ToJSON()
	switch s := res.SupportInfo; s.Status {
	case support.SecurityOnly:
		newest := support.NewestInLine(db.Releases, lib, res.Version)
		msg := fmt.Sprintf("%s %s (%s): its line receives security fixes only", res.Name, res.Version, statusPhrase(s))
		if newest != "" && newest != res.Version {
			msg += fmt.Sprintf("; the newest release in its line is %s", newest)
		}
		if res.Latest != res.Version {
			msg += fmt.Sprintf(", the latest is %s", res.Latest)
		}
		log.Warnf("%s", msg)
	case support.Unsupported:
		msg := fmt.Sprintf("%s %s (%s)", res.Name, res.Version, statusPhrase(s))
		if res.Latest != res.Version {
			msg += fmt.Sprintf(": the latest is %s", res.Latest)
		}
		log.Warnf("%s", msg)
	}
	if catalog.CompareVersions(res.Version, res.Latest) > 0 {
		log.Warnf("%s %s is a pre-release newer than the latest stable release %s", res.Name, res.Version, res.Latest)
	}
	log.Infof("Checked %s %s and %d later release(s) up to %s: %d advisories", res.Name, res.Version,
		len(res.Checked)-1, res.Latest, len(res.Advisories))
	for _, a := range res.Advisories {
		if a.Affects(res.Latest) {
			fix := "it has no fixed version"
			switch {
			case a.FixedText() == "unknown":
				fix = "NVD gives no fixed version"
			case !a.Unfixed():
				fix = "fixed in " + a.FixedText()
			}
			log.Warnf("%s also affects the latest release %s %s (%s)", a.Name(), res.Name, res.Latest, fix)
		}
	}

	var buf bytes.Buffer
	switch {
	case opts.JSON:
		err = output.WriteCheckJSON(&buf, res)
	case opts.Text:
		err = output.WriteCheckText(&buf, res, !opts.Silent, sumCols, advCols)
	default:
		err = output.WriteCheckMarkdown(&buf, res, !opts.Silent, sumCols, advCols)
	}
	if err != nil {
		return err
	}
	return emit(opts, buf.Bytes(), len(res.Advisories), stdout, log)
}

// statusPhrase is the bracketed status in -check warnings, e.g.
// "Unsupported since 24/07/2019" or "Unsupported; inferred: ...".
func statusPhrase(s support.Info) string {
	p := string(s.Status)
	if s.Since != "" && s.Status == support.Unsupported {
		p += " since " + s.Since
	}
	if !s.Official {
		p += "; inferred: the project states no support policy for it"
	}
	return p
}
