package vuln

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/wantafanta/jsrelease/internal/httpx"
)

// NVDAPIBase is the NVD CVE API 2.0 endpoint.
const NVDAPIBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// CVSS is one CVSS score of an advisory.
type CVSS struct {
	Version string  `json:"version"` // "3.1", "3.0", "4.0" or "2.0"
	Score   float64 `json:"score"`
	Vector  string  `json:"vector"`
	Source  string  `json:"source"` // "GitHub" or "NVD"
}

// cvssRank orders versions by preference for display: CVSS v3 first (the
// version most advisories are scored with, so scores stay comparable), then
// v4, then v2.
func cvssRank(v string) int {
	switch {
	case strings.HasPrefix(v, "3.1"):
		return 0
	case strings.HasPrefix(v, "3"):
		return 1
	case strings.HasPrefix(v, "4"):
		return 2
	case strings.HasPrefix(v, "2"):
		return 3
	}
	return 4
}

// PrimaryCVSS returns the score shown in tables, or nil if there is none.
func (a Advisory) PrimaryCVSS() *CVSS {
	var best *CVSS
	for i := range a.CVSS {
		c := &a.CVSS[i]
		if best == nil || cvssRank(c.Version) < cvssRank(best.Version) {
			best = c
		}
	}
	return best
}

// CVSSText is the table cell: "6.1" for a CVSS v3 score, "5.3 (v4.0)" or
// "4.3 (v2.0)" for other versions (their scales differ), "-" for none.
func (a Advisory) CVSSText() string {
	c := a.PrimaryCVSS()
	if c == nil {
		return "-"
	}
	s := strconv.FormatFloat(c.Score, 'f', 1, 64)
	if !strings.HasPrefix(c.Version, "3") {
		s += " (v" + c.Version + ")"
	}
	return s
}

// versionFromVector reads "3.1" from "CVSS:3.1/AV:N/...".
func versionFromVector(v string) string {
	if strings.HasPrefix(v, "CVSS:") {
		if i := strings.IndexByte(v, '/'); i > 5 {
			return v[5:i]
		}
	}
	return ""
}

type ghScore struct {
	Score        float64 `json:"score"`
	VectorString *string `json:"vector_string"`
}

type ghSeverities struct {
	V3 *ghScore `json:"cvss_v3"`
	V4 *ghScore `json:"cvss_v4"`
}

// gitHubCVSS extracts scores from an advisory. GitHub reports a missing score
// as 0.0 with no vector, which is not a real score and is skipped.
func gitHubCVSS(sev *ghSeverities, legacy *ghScore) []CVSS {
	var out []CVSS
	add := func(s *ghScore) {
		if s == nil || s.VectorString == nil || *s.VectorString == "" {
			return
		}
		ver := versionFromVector(*s.VectorString)
		if ver == "" || s.Score < 0 || s.Score > 10 {
			return
		}
		for _, c := range out {
			if c.Vector == *s.VectorString {
				return
			}
		}
		out = append(out, CVSS{Version: ver, Score: s.Score, Vector: *s.VectorString, Source: "GitHub"})
	}
	if sev != nil {
		add(sev.V3)
		add(sev.V4)
	}
	add(legacy)
	return out
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID      string                  `json:"id"`
			Metrics map[string][]nvdMetrics `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdMetrics struct {
	Source   string `json:"source"`
	Type     string `json:"type"`
	CVSSData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
	} `json:"cvssData"`
}

// nvdLookup fetches the CVSS scores NVD itself assigned to cve (metrics with
// source nvd@nist.gov; other sources' scores are only used when NVD has none).
func nvdLookup(ctx context.Context, f *httpx.Fetcher, base, cve string) ([]CVSS, error) {
	u := base + "?cveId=" + url.QueryEscape(cve)
	body, err := f.Get(ctx, u, 4<<20)
	if err != nil {
		var he *httpx.HTTPError
		if errors.As(err, &he) && (he.StatusCode == 403 || he.StatusCode == 429) {
			return nil, fmt.Errorf("NVD refused the request (rate limit; run jsrelease -keys to set an NVD API key): %w", err)
		}
		return nil, err
	}
	var r nvdResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("unexpected response from %s: %w", u, err)
	}
	var own, other []CVSS
	for _, v := range r.Vulnerabilities {
		if v.CVE.ID != cve {
			continue
		}
		for _, ms := range v.CVE.Metrics {
			for _, m := range ms {
				d := m.CVSSData
				if d.Version == "" || d.VectorString == "" || d.BaseScore < 0 || d.BaseScore > 10 {
					continue
				}
				c := CVSS{Version: d.Version, Score: d.BaseScore, Vector: d.VectorString, Source: "NVD"}
				if m.Source == "nvd@nist.gov" {
					own = append(own, c)
				} else {
					other = append(other, c)
				}
			}
		}
	}
	if len(own) > 0 {
		return own, nil
	}
	return other, nil
}

// nvdPause is the gap kept between NVD requests without an API key (NVD
// allows 5 requests per rolling 30 seconds).
var nvdPause = 6 * time.Second
