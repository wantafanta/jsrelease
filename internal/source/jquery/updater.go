// Package updater retrieves release information from the official
// releases.jquery.com pages and the uncompressed files they link to.
package jquery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/httpx"
	"github.com/wantafanta/jsrelease/internal/logger"
)

// Official release pages. jQuery Migrate is listed on the Core page; there is
// no separate Migrate release page.
const (
	CorePageURL   = "https://releases.jquery.com/jquery/"
	UIPageURL     = "https://releases.jquery.com/ui/"
	MobilePageURL = "https://releases.jquery.com/mobile/"
	// CDNHost serves every file linked from the release pages.
	CDNHost = "code.jquery.com"
)

// NoDateNote is stored for releases whose official file carries no date.
const NoDateNote = "no release date in the header of the official uncompressed file"

const (
	maxPageBytes   = 8 << 20
	maxScriptBytes = 32 << 20
)

// DefaultPages returns the official release pages.
func DefaultPages() []Page {
	return []Page{
		{Name: "jQuery Core & Migrate", URL: CorePageURL, Libraries: []catalog.Library{catalog.Core, catalog.Migrate}},
		{Name: "jQuery UI", URL: UIPageURL, Libraries: []catalog.Library{catalog.UI}},
		{Name: "jQuery Mobile", URL: MobilePageURL, Libraries: []catalog.Library{catalog.Mobile}},
	}
}

// DefaultMinReleases are sanity floors: far fewer releases than this means the
// pages were not parsed correctly (at the time of writing the pages list 87
// Core, 22 Migrate, 66 UI and 42 Mobile releases).
func DefaultMinReleases() map[catalog.Library]int {
	return map[catalog.Library]int{catalog.Core: 40, catalog.Migrate: 10, catalog.UI: 30, catalog.Mobile: 20}
}

// Config controls an update run.
type Config struct {
	Pages        []Page
	AllowedHosts []string
	Concurrency  int
	Retries      int
	Timeout      time.Duration
	UserAgent    string
	MinReleases  map[catalog.Library]int
	Logger       *logger.Logger
	HTTPClient   *http.Client
	// RetryBackoff is the delay before the first retry; it doubles each time.
	RetryBackoff time.Duration

	// Known holds the releases already in the local database. A release that
	// is still listed with the same uncompressed file URL is reused as is, so
	// its file is not downloaded again.
	Known []catalog.Release
	// Full re-downloads every file, ignoring Known (Known is still used for
	// the missing-release check).
	Full bool
	// ETags of the release pages from the last update (nil to fetch them
	// unconditionally). Updated in place.
	ETags map[string]string
}

// DefaultConfig returns the production configuration.
func DefaultConfig(toolVersion string) Config {
	return Config{
		Pages:        DefaultPages(),
		AllowedHosts: []string{CDNHost},
		Concurrency:  10,
		Retries:      2,
		Timeout:      30 * time.Second,
		UserAgent:    fmt.Sprintf("jsrelease/%s (+release-date and CVE indexer for JavaScript libraries)", toolVersion),
		MinReleases:  DefaultMinReleases(),
		RetryBackoff: time.Second,
	}
}

// Failure is a release that could not be processed.
type Failure struct {
	Library catalog.Library
	Version string
	URL     string
	Err     error
}

func (f Failure) String() string {
	return fmt.Sprintf("%s %s (%s): %v", f.Library.DisplayName(), f.Version, f.URL, f.Err)
}

// Result is the outcome of an update run.
type Result struct {
	// Releases holds every release listed on the pages, sorted. Undated
	// releases are included with an empty ReleaseDate and a DateNote.
	Releases []catalog.Release
	// New lists releases that were not in Known (or whose file URL changed).
	New []catalog.Release
	// Undated counts releases whose official file has no date.
	Undated int
	// Reused and Downloaded count releases taken from Known and fetched.
	Reused, Downloaded int
	// Requests counts HTTP requests made (excluding retries); NotModified
	// counts those answered "unchanged".
	Requests, NotModified int
	// Failures lists releases that could not be downloaded or whose date
	// could not be understood. Any failure makes Run return an error.
	Failures []Failure
}

// HTTPError is a non-200 HTTP response.
type HTTPError = httpx.HTTPError

var (
	// ErrIncomplete is returned (wrapped) when some releases failed.
	ErrIncomplete = errors.New("update incomplete")
	// ErrMissing is returned (wrapped) when releases in the local database
	// are no longer listed on the official pages.
	ErrMissing = errors.New("releases missing from the official pages")
)

func key(l catalog.Library, v string) string { return string(l) + "@" + v }

// Run fetches the three release pages and compares them with cfg.Known. Only
// the uncompressed files of releases not already known are downloaded (all
// of them with cfg.Full). It returns an error, and no data should be stored,
// if a page cannot be fetched or parsed, if fewer releases than expected are
// found, if a known release has disappeared from the pages, or if any
// download or date extraction fails.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	cfg = withDefaults(cfg)
	log := cfg.Logger
	f := &httpx.Fetcher{Client: cfg.HTTPClient, UserAgent: cfg.UserAgent, Retries: cfg.Retries, Backoff: cfg.RetryBackoff, Log: log, ETags: cfg.ETags}

	var entries []Entry
	for _, p := range cfg.Pages {
		log.Debugf("Checking %s releases at %s", p.Name, p.URL)
		body, _, err := f.GetConditional(ctx, p.URL, maxPageBytes, nil)
		if errors.Is(err, httpx.ErrNotModified) {
			// Unchanged since the last update: its releases are the ones
			// already recorded.
			n := 0
			for _, k := range cfg.Known {
				for _, l := range p.Libraries {
					if k.Library == l {
						entries = append(entries, Entry{Library: l, Version: k.Version, FileVersion: k.Version, URL: k.SourceURL})
						n++
					}
				}
			}
			log.Debugf("%s release page unchanged (%d releases recorded)", p.Name, n)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("fetch %s release page: %w", p.Name, err)
		}
		es, err := ParsePage(body, p, cfg.AllowedHosts)
		if err != nil {
			return nil, fmt.Errorf("parse %s release page: %w", p.Name, err)
		}
		counts := map[catalog.Library]int{}
		for _, e := range es {
			counts[e.Library]++
		}
		for _, l := range p.Libraries {
			log.Debugf("%s: %d releases listed on %s", l.DisplayName(), counts[l], p.URL)
		}
		entries = append(entries, es...)
	}

	found := map[catalog.Library]int{}
	listed := map[string]bool{}
	for _, e := range entries {
		found[e.Library]++
		listed[key(e.Library, e.Version)] = true
	}
	for _, l := range catalog.AllLibraries {
		if floor, ok := cfg.MinReleases[l]; ok && found[l] < floor {
			return nil, fmt.Errorf("only %d %s releases found (expected at least %d); the release page structure may have changed",
				found[l], l.DisplayName(), floor)
		}
	}

	// Releases are never withdrawn from releases.jquery.com, so a known
	// release that is no longer listed means the pages were not read correctly.
	known := map[string]catalog.Release{}
	var missing []string
	for _, r := range cfg.Known {
		known[key(r.Library, r.Version)] = r
		if !listed[key(r.Library, r.Version)] {
			missing = append(missing, r.Name+" "+r.Version)
		}
	}
	if len(missing) > 0 {
		shown := missing
		if len(shown) > 10 {
			shown = append(shown[:10:10], fmt.Sprintf("... and %d more", len(missing)-10))
		}
		return nil, fmt.Errorf("%w: %d releases in the local database are not listed any more (%s); the release page structure may have changed",
			ErrMissing, len(missing), strings.Join(shown, ", "))
	}

	res := &Result{Requests: f.Requests(), NotModified: f.NotModified()}
	var todo []int
	reused := make([]bool, len(entries))
	outcomes := make([]outcome, len(entries))
	for i, e := range entries {
		k, ok := known[key(e.Library, e.Version)]
		if ok && !cfg.Full && k.SourceURL == e.URL {
			reused[i] = true
			outcomes[i] = outcome{release: k}
			continue
		}
		todo = append(todo, i)
	}

	if len(todo) == 0 {
		log.Debugf("Found %d releases; no new releases, nothing to download", len(entries))
	} else {
		log.Debugf("Found %d releases; downloading %d uncompressed file(s) (concurrency %d)", len(entries), len(todo), cfg.Concurrency)
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < cfg.Concurrency && w < len(todo); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				outcomes[i] = process(ctx, f, entries[i], log)
			}
		}()
	}
feed:
	for _, i := range todo {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("update interrupted: %w", err)
	}
	res.Requests = f.Requests()

	for i, o := range outcomes {
		e := entries[i]
		if o.err != nil {
			res.Failures = append(res.Failures, Failure{Library: e.Library, Version: e.Version, URL: e.URL, Err: o.err})
			continue
		}
		res.Releases = append(res.Releases, o.release)
		if o.release.ReleaseDate == "" {
			res.Undated++
		}
		if reused[i] {
			res.Reused++
			continue
		}
		res.Downloaded++
		if k, ok := known[key(e.Library, e.Version)]; !ok || k.SourceURL != e.URL || k.ReleaseDate != o.release.ReleaseDate {
			res.New = append(res.New, o.release)
		}
	}
	catalog.SortReleases(res.Releases)
	catalog.SortReleases(res.New)
	if len(res.Failures) > 0 {
		return res, fmt.Errorf("%w: %d of %d downloads failed", ErrIncomplete, len(res.Failures), len(todo))
	}
	return res, nil
}

type outcome struct {
	release catalog.Release
	err     error
}

func process(ctx context.Context, f *httpx.Fetcher, e Entry, log *logger.Logger) outcome {
	body, err := f.Get(ctx, e.URL, maxScriptBytes)
	if err != nil {
		return outcome{err: err}
	}
	if looksLikeHTML(body) {
		return outcome{err: fmt.Errorf("GET %s returned HTML instead of JavaScript", e.URL)}
	}
	r := catalog.Release{Library: e.Library, Name: e.Library.DisplayName(), Version: e.Version, SourceURL: e.URL}
	info, err := ExtractDate(body)
	switch {
	case err == nil:
		r.ReleaseDate = info.UK()
		log.Debugf("%s %s: %s %q -> %s (%s)", r.Name, r.Version, info.Source, info.Raw, r.ReleaseDate, e.URL)
	case errors.Is(err, ErrNoDate):
		r.DateNote = NoDateNote
		log.Debugf("%s %s: no date in file header (%s)", r.Name, r.Version, e.URL)
	default:
		return outcome{err: fmt.Errorf("extract date from %s: %w", e.URL, err)}
	}
	if !HeaderMentionsVersion(body, e.FileVersion) {
		log.Debugf("%s %s: header of %s does not mention version %q", r.Name, r.Version, e.URL, e.FileVersion)
	}
	return outcome{release: r}
}

func looksLikeHTML(b []byte) bool {
	b = bytes.TrimLeft(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), " \t\r\n")
	return len(b) > 0 && b[0] == '<'
}

func withDefaults(cfg Config) Config {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "jsrelease"
	}
	if cfg.Logger == nil {
		cfg.Logger = logger.Discard()
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.Timeout}
	}
	if len(cfg.AllowedHosts) == 0 {
		cfg.AllowedHosts = []string{CDNHost}
	}
	if len(cfg.Pages) == 0 {
		cfg.Pages = DefaultPages()
	}
	return cfg
}
