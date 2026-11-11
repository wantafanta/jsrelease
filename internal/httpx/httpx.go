// Package httpx is the HTTP client used by the updaters: timeouts, a fixed
// User-Agent, bounded response sizes and retries for transient errors.
package httpx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wantafanta/jsrelease/internal/logger"
)

// HTTPError is a non-200 HTTP response.
type HTTPError struct {
	URL        string
	StatusCode int
	Status     string
	// Body holds the start of the response body, for diagnostics.
	Body string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("GET %s: HTTP %s", e.URL, e.Status) }

// Fetcher downloads URLs.
type Fetcher struct {
	Client    *http.Client
	UserAgent string
	// Retries is how many times network errors, HTTP 429 and HTTP 5xx are retried.
	Retries int
	// Backoff is the delay before the first retry; it doubles each time.
	Backoff time.Duration
	// Header is added to every request.
	Header http.Header
	Log    *logger.Logger
	// ETags maps URLs to the ETag of their last response. GetConditional
	// sends it as If-None-Match and records new ones; nil disables this.
	ETags map[string]string

	requests    atomic.Int64
	notModified atomic.Int64
	mu          sync.Mutex
}

// ErrNotModified is returned by GetConditional when the server answers
// "304 Not Modified": the caller should reuse what it stored last time.
var ErrNotModified = errors.New("not modified")

// NotModified returns how many requests were answered "304 Not Modified".
func (f *Fetcher) NotModified() int { return int(f.notModified.Load()) }

// GetConditional is GetWithHeader with an If-None-Match header when an ETag
// is known for url. It returns ErrNotModified for a 304 answer. The response's
// ETag is recorded only when keep returns true for its headers (e.g. not for
// the first page of a multi-page list).
func (f *Fetcher) GetConditional(ctx context.Context, url string, limit int64, keep func(http.Header) bool) ([]byte, http.Header, error) {
	f.mu.Lock()
	etag := ""
	if f.ETags != nil {
		etag = f.ETags[url]
	}
	f.mu.Unlock()
	body, hdr, err := f.get(ctx, url, limit, etag)
	if err != nil {
		return nil, hdr, err
	}
	f.mu.Lock()
	if f.ETags != nil {
		if e := hdr.Get("ETag"); e != "" && (keep == nil || keep(hdr)) {
			f.ETags[url] = e
		} else {
			delete(f.ETags, url)
		}
	}
	f.mu.Unlock()
	return body, hdr, nil
}

// Requests returns the number of requests made, excluding retries.
func (f *Fetcher) Requests() int { return int(f.requests.Load()) }

// Get downloads url, reading at most limit bytes.
func (f *Fetcher) Get(ctx context.Context, url string, limit int64) ([]byte, error) {
	b, _, err := f.GetWithHeader(ctx, url, limit)
	return b, err
}

// GetWithHeader downloads url and also returns the response headers.
func (f *Fetcher) GetWithHeader(ctx context.Context, url string, limit int64) ([]byte, http.Header, error) {
	return f.get(ctx, url, limit, "")
}

func (f *Fetcher) get(ctx context.Context, url string, limit int64, etag string) ([]byte, http.Header, error) {
	f.requests.Add(1)
	var lastErr error
	delay := f.Backoff
	for attempt := 0; attempt <= f.Retries; attempt++ {
		if attempt > 0 {
			f.Log.Debugf("retrying %s (attempt %d/%d) after: %v", url, attempt+1, f.Retries+1, lastErr)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
			delay *= 2
		}
		body, hdr, retryable, err := f.once(ctx, url, limit, etag)
		if err == nil {
			return body, hdr, nil
		}
		if errors.Is(err, ErrNotModified) {
			f.notModified.Add(1)
			return nil, hdr, err
		}
		lastErr = err
		if !retryable || ctx.Err() != nil {
			break
		}
	}
	return nil, nil, lastErr
}

func (f *Fetcher) once(ctx context.Context, url string, limit int64, etag string) ([]byte, http.Header, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, false, err
	}
	for k, vs := range f.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("User-Agent", f.UserAgent)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "*/*")
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, true, err // *url.Error already reads: Get "<url>": <cause>
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified && etag != "" {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, resp.Header, false, ErrNotModified
	}
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, resp.Header, retry, &HTTPError{URL: url, StatusCode: resp.StatusCode, Status: resp.Status, Body: string(snippet)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, nil, true, fmt.Errorf("GET %s: read body: %w", url, err)
	}
	if int64(len(body)) > limit {
		return nil, nil, false, fmt.Errorf("GET %s: response larger than %d bytes", url, limit)
	}
	if len(body) == 0 {
		return nil, nil, true, fmt.Errorf("GET %s: empty response", url)
	}
	return body, resp.Header, false, nil
}
