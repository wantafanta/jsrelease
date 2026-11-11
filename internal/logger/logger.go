// Package logger is a minimal leveled logger in the style of
// projectdiscovery/gologger: "[INF] message" lines written to stderr.
package logger

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// Logger writes leveled messages. Errors are always shown; informational and
// warning messages are hidden in silent mode; debug messages need verbose
// mode (and are hidden in silent mode).
type Logger struct {
	mu      sync.Mutex
	w       io.Writer
	silent  bool
	verbose bool
	color   bool
	wrote   bool // a line was written since the last blank line
}

// ANSI colours for the message tags (only the tag is coloured).
var tagColors = map[string]string{
	"INF": "\033[34m",   // blue
	"WRN": "\033[31m",   // red
	"ERR": "\033[1;91m", // bold bright red
	"DBG": "\033[90m",   // grey
}

// SetColor turns coloured tags on or off.
func (l *Logger) SetColor(on bool) {
	if l != nil {
		l.color = on
	}
}

// Tag returns "[TAG]", coloured when color is true.
func Tag(tag string, color bool) string {
	if !color {
		return "[" + tag + "]"
	}
	return tagColors[tag] + "[" + tag + "]\033[0m"
}

// ColorWanted reports whether colour should be used on f: f is a terminal,
// NO_COLOR is not set and noColor (-nc) is false. On Windows it also turns on
// the console's colour support, and reports false if that isn't possible.
func ColorWanted(f *os.File, noColor bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" || f == nil {
		return false
	}
	st, err := f.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return enableVT(f)
}

// New returns a Logger writing to w.
func New(w io.Writer, silent, verbose bool) *Logger {
	return &Logger{w: w, silent: silent, verbose: verbose}
}

// Discard returns a Logger that writes nothing.
func Discard() *Logger { return New(io.Discard, true, false) }

func (l *Logger) printf(tag, format string, args ...any) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s %s\n", Tag(tag, l.color), fmt.Sprintf(format, args...))
	l.wrote = true
}

// Infof logs an informational message.
func (l *Logger) Infof(format string, args ...any) {
	if l != nil && !l.silent {
		l.printf("INF", format, args...)
	}
}

// Warnf logs a warning.
func (l *Logger) Warnf(format string, args ...any) {
	if l != nil && !l.silent {
		l.printf("WRN", format, args...)
	}
}

// Errorf logs an error. Errors are shown even in silent mode.
func (l *Logger) Errorf(format string, args ...any) { l.printf("ERR", format, args...) }

// Blank writes an empty line, separating the log messages from the results
// that follow. Nothing is written in silent mode.
func (l *Logger) Blank() {
	if l != nil && !l.silent {
		l.mu.Lock()
		defer l.mu.Unlock()
		fmt.Fprintln(l.w)
		l.wrote = false
	}
}

// Separate writes an empty line only if a message was written since the
// last one, e.g. before results that may or may not follow log lines.
func (l *Logger) Separate() {
	if l != nil && !l.silent {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.wrote {
			fmt.Fprintln(l.w)
			l.wrote = false
		}
	}
}

// Debugf logs a verbose message.
func (l *Logger) Debugf(format string, args ...any) {
	if l != nil && l.verbose && !l.silent {
		l.printf("DBG", format, args...)
	}
}
