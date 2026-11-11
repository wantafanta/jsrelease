package runner

import (
	"flag"
	"fmt"
	"github.com/wantafanta/jsrelease/internal/catalog"
	"io"
	"strings"
)

// Options holds the parsed command-line options.
type Options struct {
	Update  bool
	Full    bool
	List    bool
	Stats   bool
	Library string
	Data    string
	Output  string
	JSON    bool
	Text    bool
	NoColor bool
	Config  string
	Keys    bool
	SetKey  string
	Clear   bool
	Columns string
	// Action is true when a switch that produces results was given: -list,
	// -library, -cve, -check, -update or -version. Switches that only change
	// how results look (-v, -s, -md, -json, -cols, -o, -data, ...) don't
	// produce anything on their own, so without an action the help is shown.
	Action bool

	// Keys resolved from the environment and config file (not switches).
	githubToken, nvdKey string
	CVE                 bool
	Check               string
	Silent              bool
	Verbose             bool
	Version             bool
	Concurrency         int
	Timeout             int
	Retries             int
}

type flagDoc struct {
	names string
	usage string
}

type flagGroup struct {
	title string
	flags []flagDoc
}

// ParseOptions parses args (without the program name). Flags follow the
// ProjectDiscovery convention: single dash, long and short aliases.
func ParseOptions(args []string, stderr io.Writer) (*Options, error) {
	o := &Options{Concurrency: 10, Retries: 2} // fixed: no switches
	fs := flag.NewFlagSet("jsrelease", flag.ContinueOnError)

	fs.StringVar(&o.Library, "library", "all", "")
	fs.StringVar(&o.Data, "data", "", "")
	fs.BoolVar(&o.List, "list", false, "")
	fs.BoolVar(&o.Stats, "stats", false, "")
	fs.StringVar(&o.Check, "check", "", "")

	fs.BoolVar(&o.Update, "update", false, "")
	fs.BoolVar(&o.Update, "up", false, "")
	fs.BoolVar(&o.Full, "full", false, "")
	fs.IntVar(&o.Timeout, "timeout", 30, "")

	fs.StringVar(&o.Output, "output", "", "")
	fs.StringVar(&o.Output, "o", "", "")
	fs.BoolVar(&o.JSON, "json", false, "")
	fs.BoolVar(&o.Text, "text", false, "")
	fs.BoolVar(&o.NoColor, "nc", false, "")
	fs.BoolVar(&o.NoColor, "no-color", false, "")
	fs.StringVar(&o.Config, "config", "", "")
	fs.BoolVar(&o.Keys, "keys", false, "")
	fs.StringVar(&o.SetKey, "set-key", "", "")
	fs.BoolVar(&o.Clear, "clear", false, "")
	fs.StringVar(&o.Columns, "columns", "", "")
	fs.StringVar(&o.Columns, "cols", "", "")

	fs.BoolVar(&o.Silent, "silent", false, "")
	fs.BoolVar(&o.Silent, "s", false, "")
	fs.BoolVar(&o.Verbose, "verbose", false, "")
	fs.BoolVar(&o.Verbose, "v", false, "")
	fs.BoolVar(&o.Version, "version", false, "")

	// Help is printed by Usage; the flag package itself stays quiet so a
	// parse error is reported once, as an [ERR] line.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	if err := fs.Parse(joinColumnArgs(args)); err != nil {
		return nil, err
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "list", "stats", "library", "check", "update", "up", "version", "keys", "set-key":
			o.Action = true
		}
	})
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0)) // "(see -h)" is added once, by the caller
	}
	// -cols -h / -cols -help: show the column list, like -cols list.
	switch strings.ToLower(o.Columns) {
	case "-h", "-help", "--help":
		o.Columns = "list"
	}
	if strings.HasPrefix(o.Columns, "-") {
		return nil, fmt.Errorf("-cols needs column names, for example -cols version,date (-cols list shows them all)")
	}
	if o.JSON && o.Text {
		return nil, fmt.Errorf("-json and -text cannot be used together")
	}
	if o.Clear && o.SetKey == "" {
		return nil, fmt.Errorf("-clear can only be used with -set-key")
	}
	if o.Full && !o.Update {
		return nil, fmt.Errorf("-full can only be used with -update")
	}
	if o.Timeout < 1 {
		return nil, fmt.Errorf("-timeout must be at least 1 second")
	}
	return o, nil
}

// joinColumnArgs rejoins a -cols list that the shell split at spaces:
//
//	-cols library, version, date   ->  -cols library,version,date
//	-cols library ,version         ->  -cols library,version
//
// Joining continues while the list so far ends with "," or the next
// argument starts with ","; it stops at the next switch (anything starting
// with "-"). A list without a dangling comma is left alone, so a genuine
// stray argument is still reported as an error.
func joinColumnArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, inline := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || (name != "cols" && name != "columns") {
			out = append(out, a)
			continue
		}
		if !inline { // value is the next argument: -cols x
			if i+1 >= len(args) {
				out = append(out, a)
				continue
			}
			i++
			val = args[i]
		}
		for i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") &&
			(strings.HasSuffix(val, ",") || strings.HasPrefix(args[i+1], ",")) {
			i++
			val += args[i]
		}
		out = append(out, "-"+name, strings.ReplaceAll(val, " ", ""))
	}
	return out
}

func helpGroups() []flagGroup {
	indent := strings.Repeat(" ", 28)
	return []flagGroup{
		{"INPUT", []flagDoc{
			{"-library string", wrap("library: "+libraryKeywords()+" (comma-separated allowed) (default \"all\")", indent, 75)},
			{"-data string", "data file (default \"jsrelease.json\" in the current directory, next to the\n" + indent + "executable, or in your user data folder; the bundled data until the first -update)"},
			{"-list", "list every recorded release"},
			{"-stats", "per-library summary: releases, latest version, advisories (from the local files)"},
		}},
		{"VULNERABILITIES", []flagDoc{
			{"-check string", "version to check (needs one -library): shows the latest version and every CVE\n" + indent + "affecting any version from the given one up to the latest"},
		}},
		{"UPDATE", []flagDoc{
			{"-up, -update", "check releases.jquery.com for new releases and refresh advisories from GitHub"},
			{"-full", "with -update, re-download every release file instead of only new ones"},
			{"-timeout int", "HTTP timeout in seconds (default 30)"},
		}},
		{"OUTPUT", []flagDoc{
			{"-o, -output string", "file to write results to"},
			{"-json", "write results as JSON"},
			{"-text", "write plain aligned columns instead of Markdown tables"},
			{"-cols, -columns string", "columns to show, in order (comma-separated); -cols list shows the names"},
		}},
		{"CONFIG", []flagDoc{
			{"-keys", "show whether the GitHub token and NVD API key are set, and how to set them"},
			{"-set-key string", "store a key in the config file: github or nvd (input is hidden; -clear removes it)"},
			{"-config string", "config file to use (default: config.yaml in your user config folder)"},
		}},
		{"DEBUG", []flagDoc{
			{"-s, -silent", "show only results (no heading or informational messages)"},
			{"-v, -verbose", "show verbose output"},
			{"-nc, -no-color", "no colours in messages (also when NO_COLOR is set, or output is not a terminal)"},
			{"-version", "show jsrelease version"},
		}},
	}
}

var helpExamples = [][2]string{
	{"jsrelease -library core,migrate -cols library,version,support,cves -o jquery.md", "jQuery and Migrate releases with their support status and CVEs, saved as Markdown"},
	{"jsrelease -library bootstrap -check 4.6.2 -cols version,support,latest,advisory,cvss", "check a version, choosing columns from both tables"},
	{"jsrelease -library moment -check 2.29.1 -json -s -o moment.json", "a version check as JSON, with no other output, for scripts"},
	{"jsrelease -library ui -cols version,date,support,notes -text", "plain columns with support status and release-notes links"},
	{"jsrelease -keys", "check or set up the GitHub token and NVD API key"},
	{"jsrelease -up -v", "update, showing each step"},
}

// libraryKeywords lists the -library keywords from the catalog:
// "core, migrate, ui, mobile (jQuery), bootstrap, ... or all".
func libraryKeywords() string {
	var jq, other []string
	for _, d := range catalog.Libraries {
		if d.Source == catalog.FromJQuerySite {
			jq = append(jq, string(d.ID))
		} else {
			other = append(other, string(d.ID))
		}
	}
	var parts []string
	if len(jq) > 0 {
		parts = append(parts, strings.Join(jq, ", ")+" (jQuery)")
	}
	parts = append(parts, other...)
	return strings.Join(parts, ", ") + " or all"
}

// libraryNames lists the libraries for the help text:
// "jQuery (Core, Migrate, UI, Mobile), Bootstrap, ... and Sizzle".
func libraryNames() string {
	var jq, all []string
	for _, d := range catalog.Libraries {
		if d.Source == catalog.FromJQuerySite {
			n := strings.TrimPrefix(d.Name, "jQuery ")
			if n == "jQuery" {
				n = "Core"
			}
			jq = append(jq, n)
		} else {
			all = append(all, d.Name)
		}
	}
	if len(jq) > 0 {
		all = append([]string{"jQuery (" + strings.Join(jq, ", ") + ")"}, all...)
	}
	if len(all) < 2 {
		return strings.Join(all, "")
	}
	return strings.Join(all[:len(all)-1], ", ") + " and " + all[len(all)-1]
}

// wrap breaks text into lines of at most width characters; continuation
// lines start with indent.
func wrap(text, indent string, width int) string {
	var lines []string
	line := ""
	for _, w := range strings.Fields(text) {
		if line != "" && len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = w
			continue
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	lines = append(lines, line)
	return strings.Join(lines, "\n"+indent)
}

// Usage writes the help text: shown by -h and when jsrelease is run with no
// arguments.
func Usage(w io.Writer) {
	var b strings.Builder
	b.WriteString(wrap("jsrelease lists the releases of "+libraryNames()+", with their release dates, support status and CVEs.", "", 80) + "\n\n")
	b.WriteString("Usage:\n  jsrelease [flags]\n\nFlags:\n")
	for _, g := range helpGroups() {
		b.WriteString(g.title + ":\n")
		for _, f := range g.flags {
			fmt.Fprintf(&b, "   %-24s %s\n", f.names, f.usage)
		}
	}
	b.WriteString("\nEXAMPLES:\n")
	for _, e := range helpExamples {
		fmt.Fprintf(&b, "   %s\n                          %s\n", e[0], e[1])
	}
	io.WriteString(w, b.String())
}
