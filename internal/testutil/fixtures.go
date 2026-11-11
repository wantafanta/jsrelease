// Package testutil provides a local HTTP server that imitates
// releases.jquery.com and code.jquery.com for tests.
//
// The release pages in internal/parser/testdata were produced by running the
// official page generator (Gruntfile.js and templates of the
// jquery/codeorigin.jquery.com repository) over that repository's real cdn/
// file list. The JavaScript fixtures are the first 4 KB of the real
// uncompressed files from the same repository.
package testutil

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// Response overrides what the server returns for a path.
type Response struct {
	Status int
	Body   string
	// Fails is how many times to return Status before serving normally
	// (0 means always).
	Fails int
}

// Server is a fake releases.jquery.com + code.jquery.com.
type Server struct {
	*httptest.Server
	mu        sync.Mutex
	requests  []string
	agents    map[string]bool
	overrides map[string]*Response
	inFlight  int
	maxFlight int
	// Hold, if set, is called on every request (e.g. to slow responses).
	Hold func()
}

// TestdataDir returns the absolute path of internal/parser/testdata.
func TestdataDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "source", "jquery", "testdata")
}

var (
	coreRe    = regexp.MustCompile(`^/jquery-([^/]+)\.js$`)
	migrateRe = regexp.MustCompile(`^/jquery-migrate-([^/]+)\.js$`)
	uiRe      = regexp.MustCompile(`^/ui/([^/]+)/jquery-ui\.js$`)
	mobileRe  = regexp.MustCompile(`^/mobile/([^/]+)/jquery\.mobile-([^/]+)\.js$`)
)

// NewServer starts a fixture server.
func NewServer(t testing.TB) *Server {
	t.Helper()
	s := &Server{agents: map[string]bool{}, overrides: map[string]*Response{}}
	dir := TestdataDir()
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests = append(s.requests, r.URL.Path)
		s.agents[r.UserAgent()] = true
		s.inFlight++
		if s.inFlight > s.maxFlight {
			s.maxFlight = s.inFlight
		}
		ov := s.overrides[r.URL.Path]
		serveOverride := ov != nil
		if ov != nil && ov.Fails > 0 {
			ov.Fails--
			if ov.Fails == 0 {
				delete(s.overrides, r.URL.Path) // serve normally afterwards
			}
		}
		hold := s.Hold
		s.mu.Unlock()
		defer func() { s.mu.Lock(); s.inFlight--; s.mu.Unlock() }()
		if hold != nil {
			hold()
		}
		if serveOverride {
			w.WriteHeader(ov.Status)
			_, _ = w.Write([]byte(ov.Body))
			return
		}
		s.serve(w, r, dir)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request, dir string) {
	p := r.URL.Path
	pages := map[string]string{"/jquery/": "releases-jquery.html", "/ui/": "releases-ui.html", "/mobile/": "releases-mobile.html"}
	if name, ok := pages[p]; ok {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		html := strings.ReplaceAll(string(b), "https://code.jquery.com", s.URL)
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		_, _ = w.Write([]byte(html))
		return
	}
	var fixture string
	switch {
	case migrateRe.MatchString(p):
		fixture = "migrate_" + migrateRe.FindStringSubmatch(p)[1] + ".js"
	case coreRe.MatchString(p):
		v := coreRe.FindStringSubmatch(p)[1]
		if v == "1.7" { // jquery-1.7.js is a symlink to jquery-1.7.0.js on the CDN
			v = "1.7.0"
		}
		fixture = "core_" + v + ".js"
	case uiRe.MatchString(p):
		fixture = "ui_" + uiRe.FindStringSubmatch(p)[1] + ".js"
	case mobileRe.MatchString(p):
		m := mobileRe.FindStringSubmatch(p)
		if m[1] == m[2] {
			fixture = "mobile_" + m[1] + ".js"
		}
	}
	if fixture == "" {
		http.NotFound(w, r)
		return
	}
	b, err := os.ReadFile(filepath.Join(dir, "headers", fixture))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = w.Write(b)
}

// Override makes the server return resp for path.
func (s *Server) Override(path string, resp Response) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := resp
	s.overrides[path] = &r
}

// Requests returns the paths requested so far.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// UserAgents returns the distinct User-Agent values seen.
func (s *Server) UserAgents() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for a := range s.agents {
		out = append(out, a)
	}
	return out
}

// MaxInFlight returns the highest number of concurrent requests observed.
func (s *Server) MaxInFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxFlight
}

// Host returns the server's host name (without port).
func (s *Server) Host() string {
	h := strings.TrimPrefix(s.URL, "http://")
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	return h
}

// Reset removes all overrides.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.overrides = map[string]*Response{}
}

// ClearRequests empties the request log.
func (s *Server) ClearRequests() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = nil
}
