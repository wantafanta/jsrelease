package runner

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/wantafanta/jsrelease/internal/logger"
	"github.com/wantafanta/jsrelease/internal/output"
)

// formatUpdated shows a stored RFC 3339 timestamp as dd/mm/yyyy hh:mm:ss in
// the given (local) time zone.
func formatUpdated(stamp string, loc *time.Location) string {
	if stamp == "" {
		return "never"
	}
	t, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return stamp
	}
	return t.In(loc).Format("02/01/2006 15:04:05")
}

func emit(opts *Options, data []byte, n int, stdout io.Writer, log *logger.Logger) error {
	log.Blank() // separates the [INF] lines (stderr) from the results
	return write(opts, data, stdout, log)
}

// isTerminal reports whether w is a terminal (replaceable in tests).
var isTerminal = func(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// write sends results to stdout and, with -o, to a file. On a terminal the
// Markdown footnotes are shown plainly; files and pipes get them escaped, so
// they render correctly as Markdown.
func write(opts *Options, data []byte, stdout io.Writer, log *logger.Logger) error {
	screen := data
	if isTerminal(stdout) {
		screen = output.PlainFootnotes(data)
	}
	if _, err := stdout.Write(screen); err != nil {
		return err
	}
	if opts.Output != "" {
		if err := os.WriteFile(opts.Output, data, 0o644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		log.Infof("Wrote results to %s", opts.Output)
	}
	return nil
}
