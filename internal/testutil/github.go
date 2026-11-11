package testutil

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// GitHubServer imitates the GitHub REST API endpoints used by the advisory
// updater, serving the real responses stored in internal/advisory/testdata.
type GitHubServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []string
	failAll  int // HTTP status to return for every request (0 = serve normally)

	failPrefix       string
	failPrefixStatus int
}

// NewGitHubServer starts a fake GitHub API. Call Close when done.
func NewGitHubServer() *GitHubServer {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(file), "..", "vuln", "testdata")
	g := &GitHubServer{}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.requests = append(g.requests, r.URL.RequestURI())
		fail := g.failAll
		if g.failPrefix != "" && strings.HasPrefix(r.URL.Path, g.failPrefix) {
			fail = g.failPrefixStatus
		}
		g.mu.Unlock()
		if fail != 0 {
			w.WriteHeader(fail)
			w.Write([]byte(`{"message":"API rate limit exceeded for 127.0.0.1."}`))
			return
		}
		var name string
		switch {
		case strings.HasPrefix(r.URL.Path, "/raw/jquery/sizzle/"):
			// /raw/jquery/sizzle/<tag>/<path>: the release file at a tag.
			rest := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/raw/jquery/sizzle/"), "/", 2)
			if len(rest) != 2 {
				http.NotFound(w, r)
				return
			}
			name = filepath.Join("sizzle", rest[0], strings.ReplaceAll(rest[1], "/", "__"))
		case strings.HasPrefix(r.URL.Path, "/raw/"):
			parts := strings.Split(r.URL.Path, "/") // /raw/<owner>/<repo>/HEAD/<file>
			name = map[string]string{"prototype": "changelog-prototype.txt", "moment": "changelog-moment.md", "underscore": "changelog-underscore.html"}[parts[3]]
		case r.URL.Path == "/nvd" && r.URL.Query().Get("virtualMatchString") != "":
			product := r.URL.Query().Get("virtualMatchString")
			name = "nvd-cpe-" + product[strings.LastIndex(product, ":")+1:] + ".json" // e.g. nvd-cpe-prototypejs.json
		case r.URL.Path == "/nvd":
			name = "nvd-" + r.URL.Query().Get("cveId") + ".json"
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"format":"NVD_CVE","version":"2.0","vulnerabilities":[]}`))
				return
			}
		case strings.HasPrefix(r.URL.Path, "/repos/") && strings.HasSuffix(r.URL.Path, "/tags"):
			parts := strings.Split(r.URL.Path, "/") // /repos/<owner>/<repo>/tags
			name = "tags-" + parts[3] + ".json"
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				w.Write([]byte("[]"))
				return
			}
		case strings.HasPrefix(r.URL.Path, "/repos/") && strings.Contains(r.URL.Path, "/commits/"):
			parts := strings.Split(r.URL.Path, "/") // /repos/<owner>/<repo>/commits/<sha>
			var dates map[string]string
			b, _ := os.ReadFile(filepath.Join(dir, "commits-"+parts[3]+".json"))
			json.Unmarshal(b, &dates)
			d, ok := dates[parts[5]]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte(`{"sha":"` + parts[5] + `","commit":{"committer":{"date":"` + d + `"}}}`))
			return
		case r.URL.Path == "/advisories" && strings.Contains(r.URL.Query().Get("affects"), ","):
			// Several packages in one request: the union of their responses.
			var all []map[string]any
			seenID := map[string]bool{}
			for _, pkg := range strings.Split(r.URL.Query().Get("affects"), ",") {
				var items []map[string]any
				b, _ := os.ReadFile(filepath.Join(dir, "adv-"+pkg+".json"))
				json.Unmarshal(b, &items)
				for _, it := range items {
					if id, _ := it["ghsa_id"].(string); !seenID[id] {
						seenID[id] = true
						all = append(all, it)
					}
				}
			}
			b, _ := json.Marshal(all)
			writeWithETag(w, r, b)
			return
		case r.URL.Path == "/advisories":
			name = "adv-" + r.URL.Query().Get("affects") + ".json"
		case strings.HasPrefix(r.URL.Path, "/repos/") && strings.HasSuffix(r.URL.Path, "/releases"):
			parts := strings.Split(r.URL.Path, "/") // /repos/<owner>/<repo>/releases
			name = "rel-" + parts[3] + ".json"
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		writeWithETag(w, r, b)
	}))
	return g
}

// FailPrefix makes requests whose path starts with prefix return status
// ("" restores normal service).
func (g *GitHubServer) FailPrefix(prefix string, status int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.failPrefix, g.failPrefixStatus = prefix, status
}

// FailWith makes every request return status (0 restores normal service).
func (g *GitHubServer) FailWith(status int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.failAll = status
}

// Requests returns the request URIs seen so far.
func (g *GitHubServer) Requests() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.requests...)
}

// ClearRequests empties the request log.
func (g *GitHubServer) ClearRequests() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests = nil
}

// writeWithETag sends body with an ETag derived from its content, or
// "304 Not Modified" when the request's If-None-Match matches it.
func writeWithETag(w http.ResponseWriter, r *http.Request, body []byte) {
	etag := fmt.Sprintf(`"%x"`, sha256.Sum256(body))
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(body)
}
