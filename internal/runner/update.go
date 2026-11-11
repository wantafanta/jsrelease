package runner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/datafile"
	"github.com/wantafanta/jsrelease/internal/logger"
	"github.com/wantafanta/jsrelease/internal/source/github"
	"github.com/wantafanta/jsrelease/internal/source/jquery"
	"github.com/wantafanta/jsrelease/internal/vuln"
)

func update(ctx context.Context, opts *Options, path, savePath string, log *logger.Logger, base *jquery.Config, apiBase, rawBase string) (newKeys map[string]bool, summary string, err error) {
	log.Debugf("Updating releases from releases.jquery.com")
	cfg := jquery.DefaultConfig(Version)
	if base != nil {
		cfg = *base
	}
	cfg.Concurrency = opts.Concurrency
	cfg.Retries = opts.Retries
	cfg.Timeout = time.Duration(opts.Timeout) * time.Second
	cfg.Logger = log
	cfg.Full = opts.Full

	// Releases already recorded are reused: only files of new releases are
	// downloaded, unless -full is given.
	old, _, lerr := readReleases(path)
	switch {
	case lerr == nil:
		for _, r := range old.Releases {
			if r.Library.IsJQuery() {
				cfg.Known = append(cfg.Known, r)
			}
		}
		log.Debugf("%d jQuery releases already recorded in %s", len(cfg.Known), path)
	case errors.Is(lerr, fs.ErrNotExist):
		log.Infof("No database at %s yet; every release file will be downloaded", path)
	default:
		log.Warnf("Existing database is unreadable and will be rebuilt from scratch: %v", lerr)
	}

	// Conditional requests: ETags from the last update (none with -full,
	// which re-checks everything).
	etags := map[string]string{}
	if old != nil && !opts.Full && old.GeneratedBy == generatedBy() {
		for k, v := range old.HTTPCache {
			etags[k] = v
		}
	}
	cfg.ETags = etags
	res, err := jquery.Run(ctx, cfg)
	if err != nil {
		if res != nil {
			for _, f := range res.Failures {
				log.Errorf("  %s", f)
			}
		}
		return nil, "", fmt.Errorf("%v; the existing database was not modified", err)
	}

	// Git tag dates for releases whose official file has no date. Tag dates
	// already recorded are carried over first (a -full run re-creates the
	// records), so a failed lookup never loses them.
	if old != nil {
		prev := map[string]catalog.Release{}
		for _, r := range old.Releases {
			prev[string(r.Library)+"@"+r.Version] = r
		}
		for i := range res.Releases {
			r := &res.Releases[i]
			if p, ok := prev[string(r.Library)+"@"+r.Version]; ok && r.ReleaseDate == "" && !r.TagChecked && p.SourceURL == r.SourceURL {
				r.TagDate, r.TagURL, r.TagChecked = p.TagDate, p.TagURL, p.TagChecked
			}
		}
	}
	tres, terr := jquery.FillTagDates(ctx, jquery.TagConfig{
		APIBase:    apiBase,
		Token:      opts.githubToken,
		UserAgent:  cfg.UserAgent,
		Retries:    opts.Retries,
		Backoff:    cfg.RetryBackoff,
		HTTPClient: &http.Client{Timeout: time.Duration(opts.Timeout) * time.Second},
		Logger:     log,
		Full:       false, // published tags don't change: only missing dates are looked up
	}, res.Releases)
	if terr != nil {
		log.Warnf("Git tag dates not updated (previous ones kept): %v", terr)
	} else if tres.Searched > 0 {
		log.Infof("Tag dates: %d of %d undated releases found from git tags, %d GitHub requests", tres.Found, tres.Searched, tres.Requests)
	}

	if res.Undated > 0 {
		log.Debugf("%d jQuery releases have no release date in their official uncompressed file (stored with an empty release_date and a date_note)", res.Undated)
	}
	log.Debugf("%d jQuery files downloaded", res.Downloaded)

	// Libraries published through GitHub.
	// If GitHub fails, their previously recorded releases are kept.
	var gitKnown []catalog.Release
	if old != nil {
		for _, r := range old.Releases {
			if !r.Library.IsJQuery() {
				gitKnown = append(gitKnown, r)
			}
		}
	}
	// The git step gets its own copy of the ETags, kept only if it succeeds:
	// otherwise a tag list fetched before a failure would be remembered as
	// "seen", and a new release in it would never be picked up.
	gitETags := map[string]string{}
	for k, v := range etags {
		gitETags[k] = v
	}
	gres, gerr := github.Run(ctx, github.Config{
		APIBase: apiBase, RawBase: rawBase,
		Token:      opts.githubToken,
		UserAgent:  cfg.UserAgent,
		Retries:    opts.Retries,
		Backoff:    cfg.RetryBackoff,
		HTTPClient: &http.Client{Timeout: time.Duration(opts.Timeout) * time.Second},
		Logger:     log,
		Known:      gitKnown,
		Full:       false, // published tags don't change: only new tags are looked up
		ETags:      gitETags,
	})
	gitReleases, gitRequests, gitUnchanged := gitKnown, 0, 0
	if gerr != nil {
		log.Warnf("%s not updated (%d previous releases kept): %v", github.Names(), len(gitKnown), gerr)
	} else {
		for k, v := range gitETags {
			etags[k] = v
		}
		gitReleases, gitRequests, gitUnchanged = gres.Releases, gres.Requests, gres.NotModified
		res.New = append(res.New, gres.New...)
	}
	all := append(append([]catalog.Release(nil), res.Releases...), gitReleases...)
	catalog.SortReleases(all)
	catalog.SortReleases(res.New)

	db := catalog.New()
	db.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	db.Releases = all
	db.GeneratedBy = generatedBy()
	if len(etags) > 0 {
		db.HTTPCache = etags
	}
	if err := os.MkdirAll(filepath.Dir(savePath), 0o755); err != nil {
		return nil, "", err
	}
	if err := datafile.SaveReleases(savePath, db); err != nil {
		return nil, "", err
	}

	tagged := map[string]catalog.Release{}
	for _, r := range all {
		tagged[string(r.Library)+"@"+r.Version] = r
	}
	for _, r := range res.New {
		r = tagged[string(r.Library)+"@"+r.Version]
		date := r.ReleaseDate
		switch {
		case date == "" && r.ChangelogDate != "":
			date = r.DisplayDate() + ", from the project's CHANGELOG"
		case date == "" && r.TagDate != "":
			date = r.DisplayDate() + ", from its git tag"
		case date == "":
			date = "no date found"
		}
		log.Infof("New: %s %s (%s)", r.Name, r.Version, date)
	}
	newKeys = map[string]bool{}
	for _, r := range res.New {
		newKeys[string(r.Library)+"@"+r.Version] = true
	}
	summary = fmt.Sprintf("Releases: %d, %d new, %s, saved to %s",
		len(all), len(res.New), requestsText(res.Requests+gitRequests+tres.Requests, res.NotModified+gitUnchanged), savePath)
	return newKeys, summary, nil
}

func updateVulns(ctx context.Context, opts *Options, relPath, vulnPath, savePath string, log *logger.Logger, apiBase, nvdBase string) (string, error) {
	log.Debugf("Updating advisories and release notes from GitHub")
	rel, _, err := readReleases(relPath)
	if err != nil {
		return "", fmt.Errorf("cannot read the release database to map advisories: %v", err)
	}
	cfg := vuln.Config{
		APIBase:    apiBase,
		Token:      opts.githubToken,
		UserAgent:  jquery.DefaultConfig(Version).UserAgent,
		Retries:    opts.Retries,
		Backoff:    time.Second,
		HTTPClient: &http.Client{Timeout: time.Duration(opts.Timeout) * time.Second},
		Logger:     log,
		NVDBase:    nvdBase,
		NVDKey:     opts.nvdKey,
	}
	cfg.RefreshNVD = opts.Full
	cfg.RefreshNotes = opts.Full
	cfg.ETags = map[string]string{}
	if prev, _, err := readVulns(vulnPath); err == nil {
		cfg.Previous = prev
		if !opts.Full && prev.GeneratedBy == generatedBy() {
			for k, v := range prev.HTTPCache {
				cfg.ETags[k] = v
			}
		}
	}
	if apiBase != "" {
		cfg.Backoff = time.Millisecond
	}
	res, err := vuln.Fetch(ctx, cfg, rel.Releases)
	if err != nil {
		return "", fmt.Errorf("%v; the existing vulnerability database was not modified", err)
	}
	res.DB.GeneratedBy = generatedBy()
	if err := os.MkdirAll(filepath.Dir(savePath), 0o755); err != nil {
		return "", err
	}
	if err := datafile.SaveVulns(savePath, res.DB); err != nil {
		return "", err
	}
	affected, notes, scored := 0, 0, 0
	for _, a := range res.DB.Advisories {
		if a.PrimaryCVSS() != nil {
			scored++
		}
	}
	for _, r := range res.DB.Releases {
		if len(r.Advisories) > 0 {
			affected++
		}
		if r.ReleaseNotesURL != nil {
			notes++
		}
	}
	// Report advisories that weren't in the previous file (not on the first
	// update, when every advisory would be new).
	if cfg.Previous != nil {
		known := map[string]bool{}
		for _, a := range cfg.Previous.Advisories {
			known[a.ID] = true
		}
		for _, a := range res.DB.Advisories {
			if !known[a.ID] {
				log.Infof("New advisory: %s (%s, CVSS %s) affecting %s %s", a.DisplayName(),
					vuln.TitleSeverity(a.Severity), a.CVSSText(), a.Library.DisplayName(), a.RangeText())
			}
		}
	}
	if res.NVDReused > 0 {
		log.Debugf("%d NVD score(s) reused from the previous update", res.NVDReused)
	}
	return fmt.Sprintf("Advisories: %d (%d with a CVSS score), %d releases affected, %d with release notes, %s, saved to %s",
		len(res.DB.Advisories), scored, affected, notes, requestsText(res.Requests+res.NVDRequests, res.NotModified), savePath), nil
}

// requestsText describes request counts: "9 requests (7 unchanged)".
func requestsText(n, unchanged int) string {
	word := "requests"
	if n == 1 {
		word = "request"
	}
	if unchanged == 0 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %s (%d unchanged)", n, word, unchanged)
}
