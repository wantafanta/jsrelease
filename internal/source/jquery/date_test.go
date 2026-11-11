package jquery

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestExtractDateRealHeaders checks every release file listed on
// releases.jquery.com (first 4 KB of the real uncompressed files) against
// dates computed independently in testdata/expected-dates.txt.
func TestExtractDateRealHeaders(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "expected-dates.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n, undated := 0, 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		name, want := parts[0], parts[1]
		js, err := os.ReadFile(filepath.Join("testdata", "headers", name))
		if err != nil {
			t.Fatal(err)
		}
		info, err := ExtractDate(js)
		n++
		if want == "NONE" {
			undated++
			if !errors.Is(err, ErrNoDate) {
				t.Errorf("%s: want ErrNoDate, got date %q err %v", name, info.UK(), err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := info.UK(); got != want {
			t.Errorf("%s: got %s (from %s %q), want %s", name, got, info.Source, info.Raw, want)
		}
	}
	if n != 217 || undated != 41 {
		t.Fatalf("checked %d files (%d undated), want 217 (41 undated)", n, undated)
	}
}

func TestExtractDateFormats(t *testing.T) {
	cases := []struct{ header, want string }{
		{"/*!\n * jQuery JavaScript Library v3.7.1\n * Released under the MIT license\n *\n * Date: 2023-08-28T13:37Z\n */", "28/08/2023"},
		{"/*\n * jQuery 1.2.6 - New Wave Javascript\n * Copyright (c) 2008 John Resig\n * $Date: 2008-05-24 14:22:17 -0400 (Sat, 24 May 2008) $\n */", "24/05/2008"},
		{"/*!\n * jQuery JavaScript Library v1.8.3\n * Copyright 2012 jQuery Foundation\n * Date: Tue Nov 13 2012 08:20:33 GMT-0500 (Eastern Standard Time)\n */", "13/11/2012"},
		{"/*!\n * jQuery JavaScript Library v1.9.1\n * Released under the MIT license\n * Date: 2013-2-4\n */", "04/02/2013"},
		{"/*!\n * jQuery JavaScript Library v1.7.2\n * Copyright 2011, John Resig\n * Date: Wed Mar 21 12:46:34 2012 -0700\n */", "21/03/2012"},
		{"/*!\n* jQuery Mobile 1.4.5\n* Git HEAD hash: 68e55e78 <> Date: Fri Oct 31 2014 17:33:30 UTC\n* Copyright 2010, 2014 jQuery Foundation\n*/", "31/10/2014"},
		{"/*!\n * jQuery Migrate - v3.4.1 - 2023-02-23T15:31Z\n * Copyright OpenJS Foundation and other contributors\n */", "23/02/2023"},
		{"/*! jQuery UI - v1.13.2 - 2022-07-14\n* http://jqueryui.com\n* Copyright jQuery Foundation and other contributors; Licensed MIT */", "14/07/2022"},
		// Header preceded by a guard comment and code (jQuery 1.0.x-1.2.x).
		{"/* prevent execution of jQuery if included more then once */\nif(typeof window.jQuery == \"undefined\") {\n/*\n * jQuery 1.0.2\n * Copyright (c) 2006 John Resig\n * $Date: 2006-10-09 21:59:20 -0400 (Mon, 09 Oct 2006) $\n */", "09/10/2006"},
		// The calendar date is kept as written, not converted to UTC.
		{"/*!\n * jQuery JavaScript Library v1.7.2\n * Copyright 2011\n * Date: Wed Mar 21 23:46:34 2012 -0700\n */", "21/03/2012"},
	}
	for _, c := range cases {
		info, err := ExtractDate([]byte(c.header + "\n(function(){})();\n"))
		if err != nil {
			t.Errorf("%q: %v", c.header, err)
			continue
		}
		if got := info.UK(); got != c.want {
			t.Errorf("%q: got %s, want %s", c.header, got, c.want)
		}
	}
}

func TestExtractDateMissingOrInvalid(t *testing.T) {
	// Header without date; later code and comments must not be used.
	noDate := "/*!\n * jQuery UI 1.8.18\n * Copyright 2011, AUTHORS.txt\n */\n" +
		"$.datepicker = { maxDate: null, minDate: null };\n" +
		"/*!\n * jQuery UI Widget\n * Copyright 2010\n * Date: 2010-01-01\n */\n"
	if _, err := ExtractDate([]byte(noDate)); !errors.Is(err, ErrNoDate) {
		t.Errorf("missing date: want ErrNoDate, got %v", err)
	}
	if _, err := ExtractDate([]byte("(function(){ var x = 1; })();")); !errors.Is(err, ErrNoHeader) {
		t.Errorf("no header: want ErrNoHeader, got %v", err)
	}
	if _, err := ExtractDate([]byte("<!doctype html><html><body>404</body></html>")); !errors.Is(err, ErrNoHeader) {
		t.Errorf("html: want ErrNoHeader, got %v", err)
	}
	bad := "/*!\n * jQuery JavaScript Library v9.9.9\n * Released under the MIT license\n * Date: sometime next week\n */"
	_, err := ExtractDate([]byte(bad))
	if err == nil || errors.Is(err, ErrNoDate) || errors.Is(err, ErrNoHeader) {
		t.Errorf("unparseable date must be a hard error, got %v", err)
	}
	implausible := "/*!\n * jQuery v1\n * Released under the MIT license\n * Date: 1999-01-01\n */"
	if _, err := ExtractDate([]byte(implausible)); err == nil {
		t.Error("implausible year accepted")
	}
}

func TestFormatUK(t *testing.T) {
	d := time.Date(2026, time.January, 7, 23, 0, 0, 0, time.UTC)
	if got := FormatUK(d); got != "07/01/2026" {
		t.Fatalf("FormatUK = %s", got)
	}
}

func TestHeaderMentionsVersion(t *testing.T) {
	js := []byte("/*!\n * jQuery JavaScript Library v3.7.1\n * Released under the MIT license\n */")
	if !HeaderMentionsVersion(js, "3.7.1") || HeaderMentionsVersion(js, "3.7") {
		t.Fatal("HeaderMentionsVersion mismatch")
	}
}
