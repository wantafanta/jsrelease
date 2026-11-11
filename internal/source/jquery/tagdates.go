package jquery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/httpx"
)

// TagConfig controls a tag-date lookup.
type TagConfig struct {
	APIBase    string
	Token      string
	UserAgent  string
	Retries    int
	Backoff    time.Duration
	HTTPClient *http.Client
	Logger     interface {
		Debugf(string, ...any)
	}
	// Full searches the tags of every undated release again.
	Full bool
}

// TagResult summarises a lookup.
type TagResult struct {
	Searched, Found, Requests int
}

type ghTag struct {
	Name   string `json:"name"`
	Commit struct {
		SHA string `json:"sha"`
	} `json:"commit"`
}

type ghCommit struct {
	Commit struct {
		Committer struct {
			Date string `json:"date"`
		} `json:"committer"`
	} `json:"commit"`
}

var twoPartZero = regexp.MustCompile(`^(\d+\.\d+)\.0(.*)$`)

// tagCandidates lists the tag names a release may use: the version in its
// file name (jQuery Mobile "1.0a4.1"), the version shown on the release page,
// and both without a ".0" patch level (jQuery UI "1.8" for 1.8.0).
func tagCandidates(r catalog.Release) []string {
	var vs []string
	if u, err := url.Parse(r.SourceURL); err == nil {
		if fv, ok := FileVersion(r.Library, u); ok {
			vs = append(vs, fv)
		}
	}
	vs = append(vs, r.Version)
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, v := range vs {
		add(v)
		if m := twoPartZero.FindStringSubmatch(v); m != nil {
			add(m[1] + m[2])
		}
	}
	for _, v := range append([]string(nil), out...) {
		add("v" + v)
	}
	return out
}

// FillTagDates records, for releases whose official file has no date, the
// date of their git tag (the commit date of the tagged release commit, in
// UTC). Releases already searched are skipped unless cfg.Full is set. On any
// error nothing is changed, so previously recorded tag dates are kept.
func FillTagDates(ctx context.Context, cfg TagConfig, rs []catalog.Release) (TagResult, error) {
	var res TagResult
	if cfg.APIBase == "" {
		cfg.APIBase = gitHubAPI
	}
	byLib := map[catalog.Library][]int{}
	for i, r := range rs {
		// Only jQuery releases: the git-published libraries get their tag
		// dates from package gitlib.
		if r.Library.IsJQuery() && r.ReleaseDate == "" && (cfg.Full || !r.TagChecked) {
			byLib[r.Library] = append(byLib[r.Library], i)
		}
	}
	if len(byLib) == 0 {
		return res, nil
	}
	hdr := http.Header{}
	hdr.Set("Accept", "application/vnd.github+json")
	hdr.Set("X-GitHub-Api-Version", "2022-11-28")
	if cfg.Token != "" {
		hdr.Set("Authorization", "Bearer "+cfg.Token)
	}
	f := &httpx.Fetcher{Client: cfg.HTTPClient, UserAgent: cfg.UserAgent, Retries: cfg.Retries,
		Backoff: cfg.Backoff, Header: hdr}
	type update struct {
		i         int
		date, url string
	}
	var updates []update
	for _, src := range tagRepos {
		idx := byLib[src.Library]
		if len(idx) == 0 {
			continue
		}
		var tags []ghTag
		if err := getAll(ctx, f, fmt.Sprintf("%s/repos/%s/tags?per_page=100", cfg.APIBase, src.Repo), &tags); err != nil {
			return TagResult{Requests: f.Requests()}, fmt.Errorf("list tags of %s: %w", src.Repo, err)
		}
		shas := map[string]string{}
		for _, t := range tags {
			shas[t.Name] = t.Commit.SHA
		}
		for _, i := range idx {
			res.Searched++
			u := update{i: i}
			for _, name := range tagCandidates(rs[i]) {
				sha, ok := shas[name]
				if !ok {
					continue
				}
				body, err := f.Get(ctx, fmt.Sprintf("%s/repos/%s/commits/%s", cfg.APIBase, src.Repo, sha), 4<<20)
				if err != nil {
					return TagResult{Requests: f.Requests()}, fmt.Errorf("read tag %s of %s: %w", name, src.Repo, rateLimitHint(err))
				}
				var c ghCommit
				if err := json.Unmarshal(body, &c); err != nil {
					return TagResult{Requests: f.Requests()}, fmt.Errorf("unexpected response for tag %s of %s: %w", name, src.Repo, err)
				}
				t, err := time.Parse(time.RFC3339, c.Commit.Committer.Date)
				if err != nil {
					return TagResult{Requests: f.Requests()}, fmt.Errorf("tag %s of %s: unreadable commit date %q", name, src.Repo, c.Commit.Committer.Date)
				}
				u.date = t.UTC().Format(catalog.DateLayout)
				u.url = fmt.Sprintf("https://github.com/%s/tree/%s", src.Repo, url.PathEscape(name))
				break
			}
			if cfg.Logger != nil {
				if u.date != "" {
					cfg.Logger.Debugf("%s %s: git tag date %s", rs[i].Name, rs[i].Version, u.date)
				} else {
					cfg.Logger.Debugf("%s %s: no git tag found", rs[i].Name, rs[i].Version)
				}
			}
			updates = append(updates, u)
		}
	}
	for _, u := range updates {
		rs[u.i].TagChecked = true
		rs[u.i].TagDate, rs[u.i].TagURL = u.date, u.url
		if u.date != "" {
			res.Found++
		}
	}
	res.Requests = f.Requests()
	return res, nil
}

// gitHubAPI is the GitHub REST API.
const gitHubAPI = "https://api.github.com"

// tagRepos are the GitHub repositories of the jQuery libraries.
var tagRepos = func() []struct {
	Library catalog.Library
	Repo    string
} {
	var out []struct {
		Library catalog.Library
		Repo    string
	}
	for _, d := range catalog.Libraries {
		if d.Source == catalog.FromJQuerySite {
			out = append(out, struct {
				Library catalog.Library
				Repo    string
			}{d.ID, d.Repo})
		}
	}
	return out
}()

var nextLinkRe = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="next"`)

// getAll fetches a paginated JSON array, following Link: rel="next".
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
	if strings.Contains(strings.ToLower(err.Error()), "403") || strings.Contains(err.Error(), "429") {
		return fmt.Errorf("%w (GitHub may be rate-limiting; run jsrelease -keys to set a GitHub token)", err)
	}
	return err
}
