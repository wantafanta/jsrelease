package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/wantafanta/jsrelease/internal/httpx"
)

type nvdCPEResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string                         `json:"id"`
			Published    string                         `json:"published"`
			Descriptions []struct{ Lang, Value string } `json:"descriptions"`
			Metrics      map[string][]struct {
				Source       string `json:"source"`
				BaseSeverity string `json:"baseSeverity"` // CVSS v2 keeps it here
				CVSSData     struct {
					Version      string  `json:"version"`
					VectorString string  `json:"vectorString"`
					BaseScore    float64 `json:"baseScore"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssData"`
			} `json:"metrics"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Vulnerable            bool   `json:"vulnerable"`
						Criteria              string `json:"criteria"`
						VersionStartIncluding string `json:"versionStartIncluding"`
						VersionStartExcluding string `json:"versionStartExcluding"`
						VersionEndIncluding   string `json:"versionEndIncluding"`
						VersionEndExcluding   string `json:"versionEndExcluding"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// fetchNVDProducts builds advisories for a library that is not on npm from
// NVD's affected-product (CPE) data. The version ranges are taken exactly as
// NVD publishes them, including its mistakes; they are marked Source "NVD".
func fetchNVDProducts(ctx context.Context, cfg Config, src Source) ([]Advisory, int, int, error) {
	base := cfg.NVDBase
	if base == "" {
		base = NVDAPIBase
	}
	hdr := http.Header{}
	hdr.Set("Accept", "application/json")
	if cfg.NVDKey != "" {
		hdr.Set("apiKey", cfg.NVDKey)
	}
	f := &httpx.Fetcher{Client: cfg.HTTPClient, UserAgent: cfg.UserAgent, Retries: cfg.Retries,
		Backoff: cfg.Backoff, Header: hdr, Log: cfg.Logger, ETags: cfg.ETags}
	byID := map[string]*Advisory{}
	var order []string
	// One search for the vendor covers all its products.
	u := base + "?virtualMatchString=" + url.QueryEscape(src.NVDVendor)
	body, _, err := f.GetConditional(ctx, u, 16<<20, nil)
	if err != nil {
		return nil, f.Requests(), f.NotModified(), err
	}
	var r nvdCPEResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, f.Requests(), 0, fmt.Errorf("unexpected response from %s: %w", u, err)
	}
	for _, product := range src.NVDProducts {
		for _, v := range r.Vulnerabilities {
			c := v.CVE
			var ranges []Range
			for _, cfgs := range c.Configurations {
				for _, n := range cfgs.Nodes {
					for _, m := range n.CPEMatch {
						if !m.Vulnerable || !strings.HasPrefix(m.Criteria, product+":") {
							continue
						}
						if rg, ok := cpeRange(m.Criteria, m.VersionStartIncluding, m.VersionStartExcluding, m.VersionEndIncluding, m.VersionEndExcluding); ok {
							ranges = append(ranges, rg)
						}
					}
				}
			}
			if len(ranges) == 0 {
				continue
			}
			a, seen := byID[c.ID]
			if !seen {
				a = &Advisory{ID: c.ID, CVE: c.ID, Library: src.Library, Source: "NVD",
					URL: "https://nvd.nist.gov/vuln/detail/" + c.ID}
				if len(c.Published) >= 10 {
					a.Published = c.Published[:10]
				}
				for _, d := range c.Descriptions {
					if d.Lang == "en" {
						a.Summary = firstSentence(d.Value)
						break
					}
				}
				for _, key := range []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
					for _, m := range c.Metrics[key] {
						if m.Source != "nvd@nist.gov" || m.CVSSData.VectorString == "" {
							continue
						}
						a.CVSS = append(a.CVSS, CVSS{Version: m.CVSSData.Version, Score: m.CVSSData.BaseScore, Vector: m.CVSSData.VectorString, Source: "NVD"})
						if a.Severity == "" {
							a.Severity = strings.ToLower(m.CVSSData.BaseSeverity + m.BaseSeverity)
						}
					}
				}
				byID[c.ID] = a
				order = append(order, c.ID)
			}
			for _, rg := range ranges {
				dup := false
				for _, e := range a.Ranges {
					dup = dup || e == rg
				}
				if !dup {
					a.Ranges = append(a.Ranges, rg)
				}
			}
		}
	}
	var out []Advisory
	for _, id := range order {
		a := byID[id]
		sort.SliceStable(a.Ranges, func(i, j int) bool { return a.Ranges[i].Vulnerable < a.Ranges[j].Vulnerable })
		if a.Severity == "" {
			a.Severity = "unknown"
		}
		out = append(out, *a)
	}
	return out, f.Requests(), 0, nil
}

// cpeRange converts an NVD cpeMatch into a version range: a specific version
// in the CPE ("…:prototype:1.7.3:…") becomes "= 1.7.3"; otherwise the
// versionStart/End fields become ">= / > / <= / <" constraints. The first
// fixed version is known only from versionEndExcluding.
func cpeRange(criteria, startIncl, startExcl, endIncl, endExcl string) (Range, bool) {
	parts := strings.Split(criteria, ":")
	if len(parts) < 6 {
		return Range{}, false
	}
	if v := parts[5]; v != "*" && v != "-" && v != "" {
		return Range{Vulnerable: "= " + v}, true
	}
	var cs []string
	if startIncl != "" {
		cs = append(cs, ">= "+startIncl)
	}
	if startExcl != "" {
		cs = append(cs, "> "+startExcl)
	}
	if endIncl != "" {
		cs = append(cs, "<= "+endIncl)
	}
	if endExcl != "" {
		cs = append(cs, "< "+endExcl)
	}
	if len(cs) == 0 {
		cs = []string{">= 0"}
	}
	return Range{Vulnerable: strings.Join(cs, ", "), Patched: endExcl}, true
}

func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ". "); i > 0 && i < 200 {
		return s[:i+1]
	}
	if len(s) > 200 {
		return s[:197] + "..."
	}
	return s
}
