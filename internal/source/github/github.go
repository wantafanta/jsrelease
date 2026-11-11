// Package gitlib finds the releases of libraries published through GitHub
// (Bootstrap, Prototype, Moment.js), whose files carry no release date.
//
// Versions come from the repository's git tags and, where the project keeps
// one, its CHANGELOG. Dates come from the CHANGELOG ("‡") where it states one,
// otherwise from the commit date of the release's git tag ("*").
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/httpx"
	"github.com/wantafanta/jsrelease/internal/logger"
	"github.com/wantafanta/jsrelease/internal/source/jquery"
)

const (
	// APIBase is the GitHub REST API; RawBase serves repository files.
	APIBase = "https://api.github.com"
	RawBase = "https://raw.githubusercontent.com"
)

// Changelog describes a project's CHANGELOG.
type Changelog struct {
	Path string
	// Parse returns every version listed and, where stated, its date.
	Parse func(text string) (versions []string, dates map[string]time.Time)
}

// Library is one git-published library.
type Library struct {
	Library   catalog.Library
	Repo      string
	TagRe     *regexp.Regexp // the first group is the version
	Changelog *Changelog
	DateNote  string
	// MinReleases is a sanity floor: far fewer means something went wrong.
	MinReleases int
	// FilePaths, if set, are release files (tried in order) whose header
	// "Date:" is the official release date, read at each tag like jQuery's.
	FilePaths []string
}

// Libraries lists the git-published libraries, from the catalog.
var Libraries = func() []Library {
	parsers := map[string]func(string) ([]string, map[string]time.Time){
		"prototype": ParsePrototypeChangelog, "moment": ParseMomentChangelog, "underscore": ParseUnderscoreChangelog,
	}
	var out []Library
	for _, d := range catalog.Libraries {
		if d.Source != catalog.FromGitHub {
			continue
		}
		l := Library{Library: d.ID, Repo: d.Repo, TagRe: regexp.MustCompile(d.TagPattern), DateNote: d.DateNote,
			MinReleases: d.MinReleases, FilePaths: d.FilePaths}
		if d.Changelog != "" {
			l.Changelog = &Changelog{Path: d.Changelog, Parse: parsers[d.ChangelogFormat]}
		}
		out = append(out, l)
	}
	return out
}()

// Names lists the git-published libraries for messages, e.g.
// "Bootstrap, Prototype, Moment.js and Underscore.js".
func Names() string {
	var n []string
	for _, l := range Libraries {
		n = append(n, l.Library.DisplayName())
	}
	if len(n) < 2 {
		return strings.Join(n, "")
	}
	return strings.Join(n[:len(n)-1], ", ") + " and " + n[len(n)-1]
}

// ForLibrary returns the definition of lib.
func ForLibrary(lib catalog.Library) (Library, bool) {
	for _, l := range Libraries {
		if l.Library == lib {
			return l, true
		}
	}
	return Library{}, false
}

var prototypeEntry = regexp.MustCompile(`(?m)^\*(\d[^*\s]*)\*\s*\(([A-Za-z]+ \d{1,2}, \d{4})\)`)

// ParsePrototypeChangelog reads entries such as "*1.7* (November 16, 2010)".
func ParsePrototypeChangelog(text string) ([]string, map[string]time.Time) {
	var vs []string
	dates := map[string]time.Time{}
	for _, m := range prototypeEntry.FindAllStringSubmatch(text, -1) {
		if t, err := parseLongDate(m[2]); err == nil {
			vs = append(vs, m[1])
			dates[m[1]] = t
		}
	}
	return vs, dates
}

var (
	momentHeading  = regexp.MustCompile(`^###\s+\[?v?(\d+\.\d+\.\d+)\]?(?:\s+.*)?$`)
	momentReleased = regexp.MustCompile(`^\s*_Released ([A-Za-z]+\.? \d{1,2},? \d{4})_\s*$`)
)

// ParseMomentChangelog reads "### 2.31.0" headings, each optionally followed
// within a few lines by "_Released Sep 14, 2026_".
func ParseMomentChangelog(text string) ([]string, map[string]time.Time) {
	var vs []string
	dates := map[string]time.Time{}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		m := momentHeading.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		vs = append(vs, m[1])
		for j := i + 1; j < len(lines) && j <= i+4; j++ {
			if strings.HasPrefix(lines[j], "#") {
				break
			}
			if d := momentReleased.FindStringSubmatch(lines[j]); d != nil {
				if t, err := parseLongDate(d[1]); err == nil {
					dates[m[1]] = t
				}
				break
			}
		}
	}
	return vs, dates
}

var underscoreEntry = regexp.MustCompile(`<b class="header">(\d[^<]*)</b>\s*&mdash;\s*<small><i>([^<]*)</i></small>`)

// ParseUnderscoreChangelog reads the CHANGELOG in underscorejs.org's page
// source (index.html): "<b class="header">1.13.8</b> &mdash; <small><i>February 19, 2026</i></small>".
func ParseUnderscoreChangelog(text string) ([]string, map[string]time.Time) {
	var vs []string
	dates := map[string]time.Time{}
	for _, m := range underscoreEntry.FindAllStringSubmatch(text, -1) {
		vs = append(vs, m[1])
		if t, err := parseLongDate(m[2]); err == nil {
			dates[m[1]] = t
		}
	}
	return vs, dates
}

// parseLongDate parses "November 16, 2010", "Sep 14, 2026" and "Sept 14 2026".
func parseLongDate(s string) (time.Time, error) {
	s = strings.NewReplacer(",", "", ".", "", "Sept ", "Sep ").Replace(strings.TrimSpace(s))
	for _, layout := range []string{"January 2 2006", "Jan 2 2006"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised date %q", s)
}

// Config controls a run.
type Config struct {
	APIBase, RawBase string
	Token, UserAgent string
	Retries          int
	Backoff          time.Duration
	HTTPClient       *http.Client
	Logger           *logger.Logger
	// Known are the releases already recorded; their tag dates are reused.
	Known []catalog.Release
	// Full looks every tag date up again.
	Full bool
	// ETags of the tag lists and CHANGELOGs from the last update (nil to
	// fetch them unconditionally). Updated in place.
	ETags map[string]string
}

// Result of a run.
type Result struct {
	Releases []catalog.Release
	New      []catalog.Release
	// Requests counts requests made; NotModified those answered "unchanged".
	Requests, NotModified int
	// Disagreements lists versions whose CHANGELOG and tag dates are more
	// than a day apart.
	Disagreements []string
}

type ghTag struct {
	Name   string `json:"name"`
	Commit struct {
		SHA string `json:"sha"`
	} `json:"commit"`
}

// Run finds the releases of every git-published library. Any error aborts
// the whole run, so no partial data is produced.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.APIBase == "" {
		cfg.APIBase = APIBase
	}
	if cfg.RawBase == "" {
		cfg.RawBase = RawBase
	}
	if cfg.Logger == nil {
		cfg.Logger = logger.Discard()
	}
	log := cfg.Logger
	hdr := http.Header{}
	hdr.Set("Accept", "application/vnd.github+json")
	hdr.Set("X-GitHub-Api-Version", "2022-11-28")
	if cfg.Token != "" {
		hdr.Set("Authorization", "Bearer "+cfg.Token)
	}
	api := &httpx.Fetcher{Client: cfg.HTTPClient, UserAgent: cfg.UserAgent, Retries: cfg.Retries, Backoff: cfg.Backoff, Header: hdr, Log: log, ETags: cfg.ETags}
	raw := &httpx.Fetcher{Client: cfg.HTTPClient, UserAgent: cfg.UserAgent, Retries: cfg.Retries, Backoff: cfg.Backoff, Log: log, ETags: cfg.ETags}

	known := map[string]catalog.Release{}
	for _, r := range cfg.Known {
		known[string(r.Library)+"@"+r.Version] = r
	}
	res := &Result{}
	for _, lib := range Libraries {
		rs, news, dis, err := runLibrary(ctx, cfg, api, raw, lib, known)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", lib.Library.DisplayName(), err)
		}
		res.Releases = append(res.Releases, rs...)
		res.New = append(res.New, news...)
		res.Disagreements = append(res.Disagreements, dis...)
	}
	res.Requests = api.Requests() + raw.Requests()
	res.NotModified = api.NotModified() + raw.NotModified()
	return res, nil
}

func runLibrary(ctx context.Context, cfg Config, api, raw *httpx.Fetcher, lib Library, known map[string]catalog.Release) ([]catalog.Release, []catalog.Release, []string, error) {
	log := cfg.Logger
	log.Debugf("Checking %s tags of %s", lib.Library.DisplayName(), lib.Repo)
	var tags []ghTag
	unchanged, err := getAllConditional(ctx, api, fmt.Sprintf("%s/repos/%s/tags?per_page=100", cfg.APIBase, lib.Repo), &tags)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("list tags of %s: %w", lib.Repo, err)
	}
	if unchanged {
		// The tag list hasn't changed: rebuild it from the recorded tags.
		for _, r := range known {
			if r.Library == lib.Library && r.TagURL != "" {
				tags = append(tags, ghTag{Name: r.TagURL[strings.LastIndex(r.TagURL, "/")+1:]})
			}
		}
		log.Debugf("%s tags unchanged (%d recorded)", lib.Library.DisplayName(), len(tags))
	}
	tagOf := map[string]ghTag{}
	var versions []string
	for _, t := range tags {
		if m := lib.TagRe.FindStringSubmatch(t.Name); m != nil {
			if _, dup := tagOf[m[1]]; !dup {
				versions = append(versions, m[1])
			}
			tagOf[m[1]] = t
		}
	}

	var clDates map[string]time.Time
	clURL := ""
	if lib.Changelog != nil {
		u := fmt.Sprintf("%s/%s/HEAD/%s", cfg.RawBase, lib.Repo, lib.Changelog.Path)
		clURL = fmt.Sprintf("https://github.com/%s/blob/HEAD/%s", lib.Repo, lib.Changelog.Path)
		log.Debugf("Reading the %s CHANGELOG", lib.Library.DisplayName())
		body, _, err := raw.GetConditional(ctx, u, 8<<20, nil)
		var clVersions []string
		switch {
		case errors.Is(err, httpx.ErrNotModified):
			// Unchanged: use the CHANGELOG versions and dates recorded.
			clDates = map[string]time.Time{}
			for _, r := range known {
				if r.Library == lib.Library && (r.ChangelogDate != "" || r.TagURL == "") {
					clVersions = append(clVersions, r.Version)
					if t, perr := time.Parse(catalog.DateLayout, r.ChangelogDate); perr == nil {
						clDates[r.Version] = t
					}
				}
			}
			log.Debugf("%s CHANGELOG unchanged", lib.Library.DisplayName())
		case err != nil:
			return nil, nil, nil, fmt.Errorf("read CHANGELOG: %w", err)
		default:
			clVersions, clDates = lib.Changelog.Parse(string(body))
		}
		if len(clVersions) == 0 {
			return nil, nil, nil, fmt.Errorf("no versions found in %s; its format may have changed", u)
		}
		for _, v := range clVersions {
			if _, ok := tagOf[v]; !ok && !contains(versions, v) {
				versions = append(versions, v)
			}
		}
	}
	// Newest first, so the output (and -v detail) is in the same order on
	// every run, whatever order the tags or recorded releases came in.
	sort.SliceStable(versions, func(i, j int) bool { return catalog.CompareVersions(versions[i], versions[j]) > 0 })
	if len(versions) < lib.MinReleases {
		return nil, nil, nil, fmt.Errorf("only %d releases found (expected at least %d); the repository layout may have changed", len(versions), lib.MinReleases)
	}

	listed := map[string]bool{}
	for _, v := range versions {
		listed[v] = true
	}
	var missing []string
	for k, r := range known {
		if r.Library == lib.Library && !listed[r.Version] {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, nil, nil, fmt.Errorf("%d recorded releases are no longer listed (%s)", len(missing), strings.Join(missing, ", "))
	}

	var out, news []catalog.Release
	var dis []string
	for _, v := range versions {
		prev, seen := known[string(lib.Library)+"@"+v]
		r := catalog.Release{Library: lib.Library, Name: lib.Library.DisplayName(), Version: v, DateNote: lib.DateNote}
		if t, ok := clDates[v]; ok {
			r.ChangelogDate, r.ChangelogURL = t.Format(catalog.DateLayout), clURL
		}
		tag, tagged := tagOf[v]
		switch {
		case tagged:
			tagURL := fmt.Sprintf("https://github.com/%s/tree/%s", lib.Repo, url.PathEscape(tag.Name))
			r.SourceURL = tagURL
			if seen && prev.TagChecked && prev.TagURL == tagURL && !cfg.Full {
				// Recorded before: release files and tags don't change.
				r.ReleaseDate, r.TagDate, r.TagURL, r.SourceURL = prev.ReleaseDate, prev.TagDate, tagURL, prev.SourceURL
				if r.ReleaseDate != "" {
					r.DateNote = ""
				}
			} else {
				date, err := commitDate(ctx, api, cfg.APIBase, lib.Repo, tag.Commit.SHA)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("read tag %s: %w", tag.Name, err)
				}
				r.TagDate, r.TagURL = date.Format(catalog.DateLayout), tagURL
				if len(lib.FilePaths) > 0 {
					fileDate, fileURL, err := releaseFileDate(ctx, raw, cfg.RawBase, lib, tag.Name)
					if err != nil {
						return nil, nil, nil, fmt.Errorf("read release file at %s: %w", tag.Name, err)
					}
					if fileDate != "" {
						// The official date; the tag date is only compared.
						a, _ := time.Parse(catalog.DateLayout, fileDate)
						if d := a.Sub(date.Truncate(24*time.Hour)).Hours() / 24; d > 1.5 || d < -1.5 {
							msg := fmt.Sprintf("%s %s: release file says %s, git tag %s", r.Name, v, fileDate, r.TagDate)
							dis = append(dis, msg)
							log.Debugf("%s", msg)
						}
						r.ReleaseDate, r.TagDate, r.DateNote, r.SourceURL = fileDate, "", "", fileURL
					}
				}
			}
			r.TagChecked = true
		default:
			r.SourceURL = clURL
			r.TagChecked = true // no tag exists
		}
		if r.ChangelogDate != "" && r.TagDate != "" {
			a, _ := time.Parse(catalog.DateLayout, r.ChangelogDate)
			b, _ := time.Parse(catalog.DateLayout, r.TagDate)
			if d := a.Sub(b).Hours() / 24; d > 1 || d < -1 {
				msg := fmt.Sprintf("%s %s: CHANGELOG says %s, git tag %s", r.Name, v, r.ChangelogDate, r.TagDate)
				dis = append(dis, msg)
				log.Debugf("%s", msg)
			}
		}
		out = append(out, r)
		if !seen {
			news = append(news, r)
		}
	}
	return out, news, dis, nil
}

// releaseFileDate reads the "Date:" header of the library's release file at
// tag (first of FilePaths that exists). It returns "" when no file has a
// date, and an error only for a date that can't be understood.
func releaseFileDate(ctx context.Context, raw *httpx.Fetcher, rawBase string, lib Library, tag string) (string, string, error) {
	for _, p := range lib.FilePaths {
		body, err := raw.Get(ctx, fmt.Sprintf("%s/%s/%s/%s", rawBase, lib.Repo, url.PathEscape(tag), p), 16<<20)
		var he *httpx.HTTPError
		if errors.As(err, &he) && he.StatusCode == 404 {
			continue
		}
		if err != nil {
			return "", "", err
		}
		fileURL := fmt.Sprintf("https://github.com/%s/blob/%s/%s", lib.Repo, url.PathEscape(tag), p)
		info, err := jquery.ExtractDate(body)
		switch {
		case err == nil:
			return info.UK(), fileURL, nil
		case errors.Is(err, jquery.ErrNoDate), errors.Is(err, jquery.ErrNoHeader):
			return "", "", nil
		default:
			return "", "", err
		}
	}
	return "", "", nil
}

type ghCommit struct {
	Commit struct {
		Committer struct {
			Date string `json:"date"`
		} `json:"committer"`
	} `json:"commit"`
}

func commitDate(ctx context.Context, f *httpx.Fetcher, base, repo, sha string) (time.Time, error) {
	body, err := f.Get(ctx, fmt.Sprintf("%s/repos/%s/commits/%s", base, repo, sha), 4<<20)
	if err != nil {
		return time.Time{}, rateLimitHint(err)
	}
	var c ghCommit
	if err := json.Unmarshal(body, &c); err != nil {
		return time.Time{}, fmt.Errorf("unexpected response for commit %s: %w", sha, err)
	}
	t, err := time.Parse(time.RFC3339, c.Commit.Committer.Date)
	if err != nil {
		return time.Time{}, fmt.Errorf("unreadable commit date %q", c.Commit.Committer.Date)
	}
	return t.UTC(), nil
}

var nextLinkRe = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="next"`)

// getAllConditional is getAll whose first request is conditional. It reports
// unchanged (and returns no items) when the server answers "not modified".
// Only single-page lists keep an ETag: a later page could change on its own.
func getAllConditional[T any](ctx context.Context, f *httpx.Fetcher, u string, out *[]T) (bool, error) {
	body, hdr, err := f.GetConditional(ctx, u, 16<<20, func(h http.Header) bool { return h.Get("Link") == "" })
	if errors.Is(err, httpx.ErrNotModified) {
		return true, nil
	}
	if err != nil {
		return false, rateLimitHint(err)
	}
	var items []T
	if err := json.Unmarshal(body, &items); err != nil {
		return false, fmt.Errorf("unexpected response from %s: %w", u, err)
	}
	*out = append(*out, items...)
	if m := nextLinkRe.FindStringSubmatch(hdr.Get("Link")); m != nil {
		return false, getAll(ctx, f, m[1], out)
	}
	return false, nil
}

func getAll[T any](ctx context.Context, f *httpx.Fetcher, u string, out *[]T) error {
	for page := 0; u != "" && page < 20; page++ {
		body, hdr, err := f.GetWithHeader(ctx, u, 16<<20)
		if err != nil {
			return rateLimitHint(err)
		}
		var items []T
		if err := json.Unmarshal(body, &items); err != nil {
			return fmt.Errorf("unexpected response from %s: %w", u, err)
		}
		*out = append(*out, items...)
		u = ""
		if m := nextLinkRe.FindStringSubmatch(hdr.Get("Link")); m != nil {
			u = m[1]
		}
	}
	return nil
}

func rateLimitHint(err error) error {
	var he *httpx.HTTPError
	if errors.As(err, &he) && (he.StatusCode == 403 || he.StatusCode == 429) {
		return fmt.Errorf("%w (GitHub may be rate-limiting; run jsrelease -keys to set a GitHub token)", err)
	}
	return err
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
