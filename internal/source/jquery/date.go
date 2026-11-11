package jquery

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/wantafanta/jsrelease/internal/catalog"
)

var (
	// ErrNoHeader means no licence/copyright banner comment was found near the
	// top of the file, so the content is not a recognisable jQuery build.
	ErrNoHeader = errors.New("no header comment found at the top of the file")
	// ErrNoDate means the header exists but carries no release date. Some
	// genuine early releases (e.g. jQuery UI 1.7.x/1.8.0-1.8.18, jQuery Mobile
	// 1.0 alpha to 1.1.2) are published this way.
	ErrNoDate = errors.New("the file header contains no release date")
)

// headerSearchWindow is how far into the file the header comment may start.
// In real releases it starts at offset 0-103 (some old builds open with a
// one-line guard or an eslint directive).
const headerSearchWindow = 2048

var (
	blockCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
	bannerRe       = regexp.MustCompile(`(?i)copyright|licen[cs]e|\(c\)`)
	// "Date: 2023-08-28T13:37Z", "$Date: 2008-05-24 14:22:17 -0400 (...) $",
	// "... <> Date: Fri Oct 31 2014 17:33:30 UTC". The leading class prevents
	// matching identifiers such as "maxDate:".
	dateFieldRe = regexp.MustCompile(`(?m)(?:^|[^A-Za-z0-9_$])\$?Date:[ \t]*([^\r\n]*)`)
	// "jQuery Migrate - v3.4.1 - 2023-02-23T15:31Z", "jQuery UI - v1.13.2 - 2022-07-14"
	bannerDateRe = regexp.MustCompile(`\s-\s+v?\d[0-9A-Za-z.\-+]*\s+-\s+(\d{4}-\d{1,2}-\d{1,2}(?:T\d{1,2}:\d{2}(?::\d{2})?Z)?)`)
	parenRe      = regexp.MustCompile(`\([^)]*\)`)
)

// Date layouts observed in official jQuery builds (all verified against the
// real files listed on releases.jquery.com):
var dateLayouts = []string{
	"2006-01-02T15:04Z",                // 2023-08-28T13:37Z (Core 1.10+, Migrate 3.3+)
	"2006-1-2T15:04Z",                  //
	"2006-01-02T15:04:05Z",             //
	time.RFC3339,                       //
	"2006-01-02 15:04:05 -0700",        // 2008-05-24 14:22:17 -0400 (SVN $Date$, Core 1.0-1.3)
	"Mon Jan 2 15:04:05 2006 -0700",    // Wed Mar 21 12:46:34 2012 -0700 (Core 1.4-1.7, Mobile 1.0rc3-1.3.0)
	"Mon Jan 2 2006 15:04:05 GMT-0700", // Thu Aug 09 2012 16:24:48 GMT-0400 (Core 1.8.x)
	"Mon Jan 2 2006 15:04:05 MST",      // Fri Oct 31 2014 17:33:30 UTC (Mobile 1.3.1+)
	"Mon Jan 2 2006 15:04:05 -0700",    //
	"Mon Jan 2 15:04:05 MST 2006",      //
	"2006-1-2",                         // 2013-2-4 (Core 1.9.x), 2013-04-18
}

// DateInfo is a release date found in a file header.
type DateInfo struct {
	Date time.Time
	// Raw is the date text exactly as found in the header.
	Raw string
	// Source is "Date field" or "banner".
	Source string
}

// UK returns the date in DD/MM/YYYY form.
func (d DateInfo) UK() string { return FormatUK(d.Date) }

// FormatUK formats t as DD/MM/YYYY.
func FormatUK(t time.Time) string { return t.Format(catalog.DateLayout) }

// Header returns the licence/copyright banner comment of a JavaScript file:
// the first block comment that starts near the top of the file and contains a
// copyright or licence notice.
func Header(js []byte) (string, error) {
	js = bytes.TrimPrefix(js, []byte("\xef\xbb\xbf"))
	window := js
	if len(window) > headerSearchWindow+64*1024 {
		window = window[:headerSearchWindow+64*1024]
	}
	for _, loc := range blockCommentRe.FindAllIndex(window, -1) {
		if loc[0] > headerSearchWindow {
			break
		}
		c := window[loc[0]:loc[1]]
		if bannerRe.Match(c) {
			return string(c), nil
		}
	}
	return "", ErrNoHeader
}

// ExtractDate finds the release date in the header of an uncompressed jQuery
// file. The "Date:" field is used when present; otherwise the date in the
// "<name> - vX.Y.Z - <date>" banner line (used by Migrate and UI builds).
//
// The returned date is the calendar date exactly as written in the header; it
// is not converted to another time zone.
//
// It returns ErrNoHeader or ErrNoDate when the file carries no date, and a
// different error when a date is present but cannot be understood.
func ExtractDate(js []byte) (DateInfo, error) {
	hdr, err := Header(js)
	if err != nil {
		return DateInfo{}, err
	}
	if m := dateFieldRe.FindStringSubmatch(hdr); m != nil {
		raw := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(m[1]), "*/"))
		t, err := ParseDate(raw)
		if err != nil {
			return DateInfo{}, err
		}
		return DateInfo{Date: t, Raw: raw, Source: "Date field"}, nil
	}
	if m := bannerDateRe.FindStringSubmatch(hdr); m != nil {
		t, err := ParseDate(m[1])
		if err != nil {
			return DateInfo{}, err
		}
		return DateInfo{Date: t, Raw: m[1], Source: "banner"}, nil
	}
	return DateInfo{}, ErrNoDate
}

// ParseDate parses one of the date formats used in jQuery file headers.
func ParseDate(raw string) (time.Time, error) {
	s := strings.ReplaceAll(raw, "*/", "")
	s = parenRe.ReplaceAllString(s, "")
	s = strings.TrimSpace(s)
	s = strings.TrimSpace(strings.TrimSuffix(s, "$"))
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return time.Time{}, fmt.Errorf("empty date value in header (%q)", raw)
	}
	for _, layout := range dateLayouts {
		t, err := time.Parse(layout, s)
		if err != nil {
			continue
		}
		if y := t.Year(); y < 2005 || y > time.Now().Year()+1 {
			return time.Time{}, fmt.Errorf("implausible year %d in header date %q", y, raw)
		}
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unrecognised date format %q in header", raw)
}

var versionMention = regexp.MustCompile(`[0-9A-Za-z.\-]+`)

// HeaderMentionsVersion reports whether the header of js mentions version.
// It is used only as a diagnostic.
func HeaderMentionsVersion(js []byte, version string) bool {
	hdr, err := Header(js)
	if err != nil {
		return false
	}
	for _, tok := range versionMention.FindAllString(hdr, -1) {
		if strings.TrimPrefix(tok, "v") == version {
			return true
		}
	}
	return false
}
