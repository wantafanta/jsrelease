package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConditionalRequests(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("If-None-Match"))
		if r.URL.Path == "/paged" {
			w.Header().Set("Link", `<x>; rel="next"`)
		}
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte("data"))
	}))
	defer srv.Close()
	f := &Fetcher{ETags: map[string]string{}}
	single := func(h http.Header) bool { return h.Get("Link") == "" }

	body, _, err := f.GetConditional(context.Background(), srv.URL+"/a", 100, single)
	if err != nil || string(body) != "data" || f.ETags[srv.URL+"/a"] != `"v1"` {
		t.Fatalf("first: %v %q %v", err, body, f.ETags)
	}
	_, _, err = f.GetConditional(context.Background(), srv.URL+"/a", 100, single)
	if !errors.Is(err, ErrNotModified) || f.NotModified() != 1 || seen[1] != `"v1"` {
		t.Fatalf("second: %v, %d not modified, sent %q", err, f.NotModified(), seen[1])
	}
	// A multi-page list's ETag is not kept (later pages could change).
	f.GetConditional(context.Background(), srv.URL+"/paged", 100, single)
	if _, ok := f.ETags[srv.URL+"/paged"]; ok {
		t.Fatal("ETag of a multi-page response kept")
	}
	// Plain Get never sends If-None-Match.
	f.Get(context.Background(), srv.URL+"/a", 100)
	if seen[len(seen)-1] != "" || f.Requests() != 4 {
		t.Fatalf("plain Get: %q, %d requests", seen[len(seen)-1], f.Requests())
	}
	// Without an ETag map, nothing is conditional.
	g := &Fetcher{}
	if _, _, err := g.GetConditional(context.Background(), srv.URL+"/a", 100, nil); err != nil {
		t.Fatal(err)
	}
}
