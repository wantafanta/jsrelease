package logger

import (
	"bytes"
	"os"
	"testing"
)

func TestColouredTags(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, false, true)
	l.SetColor(true)
	l.Infof("a")
	l.Warnf("b")
	l.Errorf("c")
	l.Debugf("d")
	want := "\033[34m[INF]\033[0m a\n\033[31m[WRN]\033[0m b\n\033[1;91m[ERR]\033[0m c\n\033[90m[DBG]\033[0m d\n"
	if b.String() != want {
		t.Fatalf("got %q", b.String())
	}
	b.Reset()
	l.SetColor(false)
	l.Infof("a")
	if b.String() != "[INF] a\n" {
		t.Fatalf("plain: %q", b.String())
	}
}

func TestColorWanted(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "x")
	defer f.Close()
	if ColorWanted(f, false) {
		t.Error("a regular file is not a terminal")
	}
	t.Setenv("NO_COLOR", "1")
	if ColorWanted(os.Stderr, false) {
		t.Error("NO_COLOR must disable colour")
	}
	if ColorWanted(os.Stderr, true) {
		t.Error("-nc must disable colour")
	}
}
