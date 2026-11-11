package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/wantafanta/jsrelease/internal/catalog"
	"github.com/wantafanta/jsrelease/internal/httpx"
	"github.com/wantafanta/jsrelease/internal/logger"
)

const (
	// APIBase is the GitHub REST API.
	APIBase = "https://api.github.com"
	// AdvisorySource and ReleaseSource describe the sources in the file.
	AdvisorySource = "https://github.com/advisories (GitHub Advisory Database, reviewed npm advisories)"
	ReleaseSource  = "https://github.com/jquery and https://github.com/jquery-archive (GitHub Releases)"

	maxPages     = 10
	maxPageBytes = 16 << 20
)

// Config controls a fetch.
type Config struct {
	APIBase    string
	Token      string // optional GitHub token (GITHUB_TOKEN)
	UserAgent  string
	Retries    int
	Backoff    time.Duration
	HTTPClient *http.Client
	Logger     *logger.Logger

	// NVDBase is the NVD CVE API used for scores GitHub lacks (default
	// NVDAPIBase; "off" disables NVD lookups).
	NVDBase string
	// NVDKey is an optional NVD API key (NVD_API_KEY).
	NVDKey string
	// Previous is the existing vulnerability file, if any. A score it holds
	// from NVD is reused instead of being looked up again, and is kept if a
	// lookup fails.
	Previous *Database
	// RefreshNVD looks every NVD score up again instead of reusing the
	// previous file's (-update -full).
	RefreshNVD bool
	// RefreshNotes reads every repository's GitHub releases (-update -full).
	RefreshNotes bool
	// ETags from the previous file's http_cache (nil: no conditional
	// requests). Updated in place and saved in the new file.
	ETags map[string]string
}

// Result of a fetch.
type Result struct {
	DB *Database
	// Requests and NVDRequests count GitHub and NVD requests; NotModified
	// counts those answered "unchanged".
	Requests, NVDRequests, NotModified int
	// NVDReused counts NVD scores taken from the previous file without a lookup.
	NVDReused int
	// NVDFailures counts NVD lookups that failed (reported as warnings).
	NVDFailures int
}

// ErrRateLimited is returned (wrapped) when GitHub refuses requests because
// the API rate limit is exhausted.
var ErrRateLimited = errors.New("GitHub API rate limit exceeded")

// Fetch downloads advisories and release lists for all libraries and builds
// the vulnerability database for the given releases. Any failure aborts the
// whole fetch, so no partial data is produced.
func Fetch(ctx context.Context, cfg Config, releases []catalog.Release) (*Result, error) {
	if cfg.APIBase == "" {
		cfg.APIBase = APIBase
	}
	if cfg.Logger == nil {
		cfg.Logger = logger.Discard()
	}
	hdr := http.Header{}
	hdr.Set("Accept", "application/vnd.github+json")
	hdr.Set("X-GitHub-Api-Version", "2022-11-28")
	if cfg.Token != "" {
		hdr.Set("Authorization", "Bearer "+cfg.Token)
	}
	f := &httpx.Fetcher{Client: cfg.HTTPClient, UserAgent: cfg.UserAgent, Retries: cfg.Retries,
		Backoff: cfg.Backoff, Header: hdr, Log: cfg.Logger, ETags: cfg.ETags}
	log := cfg.Logger

	db := &Database{
		UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
		Sources:    []string{AdvisorySource, ReleaseSource},
		Advisories: []Advisory{},
		Releases:   []ReleaseInfo{},
	}
	notes := map[string]string{} // library@version -> release notes URL

	nvdCPERequests, nvdUnchanged := 0, 0

	// 1. GitHub advisories for every npm package, in one request.
	var pkgs []string
	for _, src := range Sources {
		if src.Package != "" {
			pkgs = append(pkgs, src.Package)
		}
	}
	u := fmt.Sprintf("%s/advisories?ecosystem=npm&affects=%s&per_page=100", cfg.APIBase, strings.Join(pkgs, ","))
	log.Debugf("Checking advisories for npm packages %s", strings.Join(pkgs, ", "))
	var raw []ghAdvisory
	unchanged, err := getAllConditional(ctx, f, u, &raw)
	if err != nil {
		return nil, fmt.Errorf("fetch advisories: %w", err)
	}
	if unchanged && cfg.Previous != nil {
		for _, a := range cfg.Previous.Advisories {
			if a.Source != "NVD" {
				db.Advisories = append(db.Advisories, a)
			}
		}
		log.Debugf("GitHub advisories unchanged (%d recorded)", len(db.Advisories))
	} else {
		duplicates := map[string][]string{} // target GHSA -> CVE IDs of withdrawn duplicates
		seen := map[string]bool{}
		for _, ga := range raw {
			if ga.WithdrawnAt != nil && *ga.WithdrawnAt != "" {
				target := duplicateOf(ga.Description)
				if target != "" && ga.CVEID != nil && *ga.CVEID != "" {
					duplicates[target] = append(duplicates[target], *ga.CVEID)
				} else {
					log.Debugf("ignoring withdrawn advisory %s (not a duplicate with its own CVE ID)", ga.GHSAID)
				}
				continue
			}
			for _, src := range Sources {
				if src.Package == "" {
					continue
				}
				a, ok, err := convert(ga, src)
				if err != nil {
					return nil, err
				}
				if !ok {
					continue
				}
				if seen[a.ID] {
					log.Debugf("%s affects more than one library; recorded once", a.ID)
					continue
				}
				seen[a.ID] = true
				db.Advisories = append(db.Advisories, a)
			}
		}
		attachAliases(db.Advisories, duplicates, "npm", log)
		log.Debugf("%d active GitHub advisories (%d returned)", len(db.Advisories), len(raw))
	}

	// 2. NVD for libraries not on npm (one search per library).
	for _, src := range Sources {
		if src.NVDVendor == "" || cfg.NVDBase == "off" {
			continue
		}
		as, n, nm, err := fetchNVDProducts(ctx, cfg, src)
		nvdCPERequests += n
		nvdUnchanged += nm
		var prev []Advisory
		if cfg.Previous != nil {
			for _, a := range cfg.Previous.Advisories {
				if a.Library == src.Library && a.Source == "NVD" {
					prev = append(prev, a)
				}
			}
		}
		switch {
		case errors.Is(err, httpx.ErrNotModified) && len(prev) > 0:
			as = prev
			log.Debugf("%s NVD advisories unchanged (%d recorded)", src.Library.DisplayName(), len(prev))
		case err != nil && len(prev) > 0:
			// NVD is this library's only advisory source: keep the previous
			// advisories rather than showing none.
			log.Warnf("NVD lookup for %s advisories failed, keeping the %d from the previous update: %v", src.Library.DisplayName(), len(prev), err)
			as = prev
		case err != nil:
			return nil, fmt.Errorf("fetch NVD advisories for %s: %w", src.Library.DisplayName(), err)
		}
		db.Advisories = append(db.Advisories, as...)
		log.Debugf("%s: %d advisories from NVD", src.Library.DisplayName(), len(as))
	}

	// 3. Release notes: a repository's GitHub releases are read only when its
	// library has a version not seen before (or with -full).
	prevNotes, prevKnown := map[string]string{}, map[string]bool{}
	if cfg.Previous != nil {
		for _, r := range cfg.Previous.Releases {
			k := string(r.Library) + "@" + r.Version
			prevKnown[k] = true
			if r.ReleaseNotesURL != nil {
				prevNotes[k] = *r.ReleaseNotesURL
			}
		}
	}
	for _, src := range Sources {
		need := cfg.Previous == nil || cfg.RefreshNotes
		for _, r := range releases {
			if r.Library == src.Library && !prevKnown[string(r.Library)+"@"+r.Version] {
				need = true
				break
			}
		}
		if !need {
			for k, v := range prevNotes {
				if strings.HasPrefix(k, string(src.Library)+"@") {
					notes[k] = v
				}
			}
			continue
		}
		u := fmt.Sprintf("%s/repos/%s/releases?per_page=100", cfg.APIBase, src.Repo)
		log.Debugf("Checking GitHub releases of %s", src.Repo)
		var rels []ghRelease
		if err := getAll(ctx, f, u, &rels); err != nil {
			return nil, fmt.Errorf("fetch releases of %s: %w", src.Repo, err)
		}
		for _, gr := range rels {
			if gr.Draft || gr.HTMLURL == "" {
				continue
			}
			tag := strings.TrimPrefix(gr.TagName, "v")
			for _, r := range releases {
				if r.Library == src.Library && (r.Version == tag || catalog.CompareVersions(r.Version, tag) == 0) {
					k := string(r.Library) + "@" + r.Version
					if _, dup := notes[k]; !dup || r.Version == tag {
						notes[k] = gr.HTMLURL
					}
				}
			}
		}
		log.Debugf("%s: %d GitHub releases", src.Repo, len(rels))
	}
	SortAdvisories(db.Advisories)

	nvdReqs, nvdReused, nvdFails, err := fillFromNVD(ctx, cfg, db)
	if err != nil {
		return nil, err
	}

	sorted := append([]catalog.Release(nil), releases...)
	catalog.SortReleases(sorted)
	for _, r := range sorted {
		ri := ReleaseInfo{Library: r.Library, Version: r.Version, Advisories: []string{}}
		if u, ok := notes[string(r.Library)+"@"+r.Version]; ok {
			u := u
			ri.ReleaseNotesURL = &u
		}
		for _, a := range db.Matching(r.Library, r.Version) {
			ri.Advisories = append(ri.Advisories, a.ID)
		}
		db.Releases = append(db.Releases, ri)
	}
	if err := db.Validate(); err != nil {
		return nil, err
	}
	db.HTTPCache = cfg.ETags
	return &Result{DB: db, Requests: f.Requests(), NVDRequests: nvdReqs + nvdCPERequests, NVDReused: nvdReused,
		NVDFailures: nvdFails, NotModified: f.NotModified() + nvdUnchanged}, nil
}

// fillFromNVD fills CVSS scores from NVD for advisories that have a CVE ID
// but no score on GitHub. A score already obtained from NVD by a previous
// update is reused without a request, unless cfg.RefreshNVD is set. NVD is a
// supplementary source: a failed lookup is a warning, and the previous score
// is kept.
func fillFromNVD(ctx context.Context, cfg Config, db *Database) (requests, reused, fails int, err error) {
	if cfg.NVDBase == "off" {
		return 0, 0, 0, nil
	}
	base := cfg.NVDBase
	if base == "" {
		base = NVDAPIBase
	}
	log := cfg.Logger
	previousNVD := func(id string) []CVSS {
		if cfg.Previous == nil {
			return nil
		}
		for _, a := range cfg.Previous.Advisories {
			if a.ID == id {
				var kept []CVSS
				for _, c := range a.CVSS {
					if c.Source == "NVD" {
						kept = append(kept, c)
					}
				}
				return kept
			}
		}
		return nil
	}
	var need []int
	for i := range db.Advisories {
		a := &db.Advisories[i]
		if len(a.CVSS) > 0 || a.CVE == "" {
			continue
		}
		if prev := previousNVD(a.ID); len(prev) > 0 && !cfg.RefreshNVD {
			a.CVSS = prev
			reused++
			log.Debugf("%s: reusing CVSS %s from NVD (previous update)", a.CVE, a.CVSSText())
			continue
		}
		need = append(need, i)
	}
	if len(need) == 0 {
		return 0, reused, 0, nil
	}
	hdr := http.Header{}
	hdr.Set("Accept", "application/json")
	if cfg.NVDKey != "" {
		hdr.Set("apiKey", cfg.NVDKey)
	}
	f := &httpx.Fetcher{Client: cfg.HTTPClient, UserAgent: cfg.UserAgent, Retries: cfg.Retries,
		Backoff: cfg.Backoff, Header: hdr, Log: log}
	log.Debugf("Looking up %d CVSS score(s) at NVD", len(need))
	for n, i := range need {
		a := &db.Advisories[i]
		if n > 0 && cfg.NVDKey == "" && len(need) > 5 {
			select {
			case <-time.After(nvdPause):
			case <-ctx.Done():
				return f.Requests(), reused, fails, ctx.Err()
			}
		}
		cs, lerr := nvdLookup(ctx, f, base, a.CVE)
		switch {
		case lerr != nil:
			fails++
			a.CVSS = previousNVD(a.ID)
			if len(a.CVSS) > 0 {
				log.Warnf("NVD lookup for %s failed, keeping the score from the previous update: %v", a.CVE, lerr)
			} else {
				log.Warnf("NVD lookup for %s failed, so it has no CVSS score: %v", a.CVE, lerr)
			}
		case len(cs) == 0:
			log.Debugf("NVD has no CVSS score for %s", a.CVE)
		default:
			a.CVSS = cs
			log.Debugf("%s: CVSS %s from NVD", a.CVE, a.CVSSText())
		}
	}
	return f.Requests(), reused, fails, nil
}

type ghAdvisory struct {
	GHSAID          string        `json:"ghsa_id"`
	CVEID           *string       `json:"cve_id"`
	HTMLURL         string        `json:"html_url"`
	Summary         string        `json:"summary"`
	Description     string        `json:"description"`
	CVSSSeverities  *ghSeverities `json:"cvss_severities"`
	CVSSLegacy      *ghScore      `json:"cvss"`
	Severity        string        `json:"severity"`
	PublishedAt     string        `json:"published_at"`
	WithdrawnAt     *string       `json:"withdrawn_at"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string          `json:"vulnerable_version_range"`
		FirstPatchedVersion    json.RawMessage `json:"first_patched_version"`
	} `json:"vulnerabilities"`
}

var duplicateRe = regexp.MustCompile(`(?i)duplicate of \[?(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})`)

// duplicateOf returns the GHSA ID a withdrawn advisory names as the one it
// duplicates ("... withdrawn because it is a duplicate of [GHSA-...]").
func duplicateOf(description string) string {
	if m := duplicateRe.FindStringSubmatch(description); m != nil {
		return m[1]
	}
	return ""
}

// attachAliases records the CVE IDs of withdrawn duplicates on the advisory
// they duplicate. Duplicates of advisories not in the list are dropped.
func attachAliases(as []Advisory, duplicates map[string][]string, pkg string, log *logger.Logger) {
	byID := map[string]*Advisory{}
	for i := range as {
		byID[as[i].ID] = &as[i]
	}
	for target, cves := range duplicates {
		a, ok := byID[target]
		if !ok {
			log.Debugf("%s: withdrawn duplicate(s) %v point to %s, which is not an active advisory for this package", pkg, cves, target)
			continue
		}
		for _, c := range cves {
			if c != a.CVE && !contains(a.Aliases, c) {
				a.Aliases = append(a.Aliases, c)
			}
		}
		sort.Strings(a.Aliases)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Draft   bool   `json:"draft"`
}

// convert keeps the npm ranges of src.Package. Withdrawn advisories and
// advisories with no range for the package are skipped (ok == false).
func convert(ga ghAdvisory, src Source) (Advisory, bool, error) {
	if ga.WithdrawnAt != nil && *ga.WithdrawnAt != "" {
		return Advisory{}, false, nil
	}
	a := Advisory{ID: ga.GHSAID, Library: src.Library, Package: src.Package, Severity: ga.Severity,
		Summary: strings.TrimSpace(ga.Summary), URL: ga.HTMLURL, CVSS: gitHubCVSS(ga.CVSSSeverities, ga.CVSSLegacy)}
	if ga.CVEID != nil {
		a.CVE = *ga.CVEID
	}
	if len(ga.PublishedAt) >= 10 {
		a.Published = ga.PublishedAt[:10]
	}
	seen := map[Range]bool{}
	for _, v := range ga.Vulnerabilities {
		if !strings.EqualFold(v.Package.Ecosystem, "npm") || v.Package.Name != src.Package {
			continue
		}
		r := Range{Vulnerable: strings.TrimSpace(v.VulnerableVersionRange), Patched: patchedVersion(v.FirstPatchedVersion)}
		if _, err := ParseRange(r.Vulnerable); err != nil {
			return Advisory{}, false, fmt.Errorf("advisory %s: %w", ga.GHSAID, err)
		}
		if !seen[r] {
			seen[r] = true
			a.Ranges = append(a.Ranges, r)
		}
	}
	if a.ID == "" || len(a.Ranges) == 0 {
		return Advisory{}, false, nil
	}
	sort.SliceStable(a.Ranges, func(i, j int) bool { return a.Ranges[i].Vulnerable < a.Ranges[j].Vulnerable })
	return a, true, nil
}

// patchedVersion accepts both API shapes: "3.5.0" and {"identifier": "3.5.0"}.
func patchedVersion(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var o struct {
		Identifier string `json:"identifier"`
	}
	if json.Unmarshal(raw, &o) == nil {
		return o.Identifier
	}
	return ""
}

var nextLinkRe = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="next"`)

// getAll fetches a paginated JSON array, following Link: rel="next".
func getAll[T any](ctx context.Context, f *httpx.Fetcher, u string, out *[]T) error {
	for page := 0; u != "" && page < maxPages; page++ {
		body, hdr, err := f.GetWithHeader(ctx, u, maxPageBytes)
		if err != nil {
			var he *httpx.HTTPError
			if errors.As(err, &he) && (he.StatusCode == 403 || he.StatusCode == 429) &&
				strings.Contains(strings.ToLower(he.Body), "rate limit") {
				return fmt.Errorf("%w (run jsrelease -keys to set a GitHub token): %v", ErrRateLimited, err)
			}
			return err
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

// getAllConditional is getAll whose first request is conditional; it reports
// unchanged when the server answers "not modified". Only a single-page list
// keeps its ETag.
func getAllConditional[T any](ctx context.Context, f *httpx.Fetcher, u string, out *[]T) (bool, error) {
	body, hdr, err := f.GetConditional(ctx, u, maxPageBytes, func(h http.Header) bool { return h.Get("Link") == "" })
	if errors.Is(err, httpx.ErrNotModified) {
		return true, nil
	}
	if err != nil {
		var he *httpx.HTTPError
		if errors.As(err, &he) && (he.StatusCode == 403 || he.StatusCode == 429) &&
			strings.Contains(strings.ToLower(he.Body), "rate limit") {
			return false, fmt.Errorf("%w (run jsrelease -keys to set a GitHub token): %v", ErrRateLimited, err)
		}
		return false, err
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
