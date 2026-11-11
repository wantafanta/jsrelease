# jsrelease guide

`jsrelease` lists every release of **jQuery** (Core, Migrate, UI and Mobile), **Bootstrap**, **Prototype**, **Moment.js**, **Underscore.js** and **Sizzle** with its release date, whether it is still supported, and the known vulnerabilities (CVEs) of each version. It is written in Go in the style of the ProjectDiscovery tools (single-dash flags, `-silent`, `-json`, `-o`), with [mapcidr](https://github.com/projectdiscovery/mapcidr) as the main reference for simplicity.

Shown here with `-text` (plain columns); by default the same table is printed in Markdown:

```text
Library         Version          Release Date  Support
jQuery          4.0.0            18/01/2026    Supported
jQuery          3.7.1            28/08/2023    Security only
jQuery UI       1.13.3           26/04/2024    Unsupported†
Bootstrap       5.3.8            26/08/2025*   Supported
Bootstrap       4.6.2            19/07/2022*   Unsupported
Prototype       1.7              16/11/2010‡   Unsupported†
Moment.js       2.31.0           14/09/2026‡   Security only
Underscore.js   1.13.8           19/02/2026‡   Supported†
Sizzle          2.3.10           14/02/2023    Unsupported†

* date of the release's git tag (the release files carry no date)
‡ date stated in the project's CHANGELOG (the release files carry no date)
† support status inferred: the project states no support policy for it
```

It keeps two JSON files in the current directory:

- **`jsrelease.json`:** every release with its date, and the advisories from the GitHub Advisory Database (plus NVD for Prototype) with CVSS scores and GitHub release-notes links.

Both ship populated, so the tool works offline straight away. `-update` keeps them current with **about 13 requests** when nothing is new, and most of those are answered "unchanged" (see [How `-update` keeps network use minimal](#how--update-keeps-network-use-minimal)).

It can also check a version you use against the latest release:

```text
$ jsrelease -library core -check 3.4.1
| Library | Version | Release Date | Support       | Latest | Latest Release Date |
|---------|---------|--------------|---------------|--------|---------------------|
| jQuery  | 3.4.1   | 01/05/2019   | Security only | 4.0.0  | 18/01/2026          |

| CVE / Advisory                       | Severity | CVSS | Summary                               |
|--------------------------------------|----------|------|---------------------------------------|
| CVE-2020-11022                       | Medium   | 6.9  | Potential XSS vulnerability in jQuery |
| CVE-2020-11023 (also CVE-2020-23064) | Medium   | 6.9  | Potential XSS vulnerability in jQuery |
```

Results are Markdown tables by default; `-text` gives plain aligned columns and `-json` gives JSON.

## Installation

```bash
go install github.com/wantafanta/jsrelease@latest
```

This needs Go 1.22 or later, and puts `jsrelease` in Go's bin folder (`$(go env GOPATH)/bin`, usually `~/go/bin`). If the command isn't found afterwards, add that folder to your PATH:

```bash
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc && source ~/.bashrc
```

To build from source instead:

```bash
git clone https://github.com/wantafanta/jsrelease.git
cd jsrelease
go build -o jsrelease .      # or: go install .
```

On Windows the same commands produce `jsrelease.exe`.

### Where the data lives

All the data is in one file, `jsrelease.json`. It has two sections: the releases, and the advisories with release notes. jsrelease uses the first of these that exists:

1. `jsrelease.json` in the current folder;
2. `jsrelease.json` next to the executable;
3. `jsrelease.json` in your user data folder:

   | System | Folder |
   |---|---|
   | Linux | `~/.local/share/jsrelease/` (or `$XDG_DATA_HOME/jsrelease/`) |
   | macOS | `~/Library/Application Support/jsrelease/` |
   | Windows | `%LocalAppData%\jsrelease\` |

If none exists, it reads the copy of the data bundled into the binary, so a fresh install works straight away and offline. Reading never writes anything. The first `-update` saves the file to your user data folder, and that copy is used from then on. `-data path` uses a specific file instead.

## Usage

Running `jsrelease` with no arguments, or with only switches that change how output looks (such as `-v`, `-s`, `-text`, `-json`, `-cols` or `-o`), shows this help (the same as `-h`). Anything that produces results, such as `-list`, `-library`, `-cve`, `-check` or `-update`, runs normally:

```text
jsrelease lists the releases of jQuery (Core, Migrate, UI, Mobile), Bootstrap,
Prototype, Moment.js, Underscore.js and Sizzle, with their release dates,
support status and CVEs.

Usage:
  jsrelease [flags]

Flags:
INPUT:
   -library string          library: core, migrate, ui, mobile (jQuery), bootstrap, prototype, moment,
                            underscore, sizzle or all (comma-separated allowed) (default "all")
   -data string             data file (default "jsrelease.json" in the current directory, next to the
                            executable, or in your user data folder; the bundled data until the first -update)
   -list                    list every recorded release
   -stats                   per-library summary: releases, latest version, advisories (from the local files)
VULNERABILITIES:
   -check string            version to check (needs one -library): shows the latest version and every CVE
                            affecting any version from the given one up to the latest
UPDATE:
   -up, -update             check releases.jquery.com for new releases and refresh advisories from GitHub
   -full                    with -update, re-download every release file instead of only new ones
   -timeout int             HTTP timeout in seconds (default 30)
OUTPUT:
   -o, -output string       file to write results to
   -json                    write results as JSON
   -text                    write plain aligned columns instead of Markdown tables
   -cols, -columns string   columns to show, in order (comma-separated); -cols list shows the names
CONFIG:
   -keys                    show whether the GitHub token and NVD API key are set, and how to set them
   -set-key string          store a key in the config file: github or nvd (input is hidden; -clear removes it)
   -config string           config file to use (default: config.yaml in your user config folder)
DEBUG:
   -s, -silent              show only results (no heading or informational messages)
   -v, -verbose             show verbose output
   -nc, -no-color           no colours in messages (also when NO_COLOR is set, or output is not a terminal)
   -version                 show jsrelease version

EXAMPLES:
   jsrelease -library core,migrate -cols library,version,support,cves -o jquery.md
                          jQuery and Migrate releases with their support status and CVEs, saved as Markdown
   jsrelease -library bootstrap -check 4.6.2 -cols version,support,latest,advisory,cvss
                          check a version, choosing columns from both tables
   jsrelease -library moment -check 2.29.1 -json -s -o moment.json
                          a version check as JSON, with no other output, for scripts
   jsrelease -library ui -cols version,date,support,notes -text
                          plain columns with support status and release-notes links
   jsrelease -keys
                          check or set up the GitHub token and NVD API key
   jsrelease -up -v
                          update, showing each step
```

Any switch that asks for results runs normally. For example, `-library core` and `-check` produce output. Use `-list` to list every release with no other options.


### Examples

```bash
./jsrelease                           # show the help, with examples
./jsrelease -list                     # all releases, sorted by library then newest version first
./jsrelease -silent                   # results only: no heading or log messages
./jsrelease -update                   # check for new releases (3 requests if nothing is new)
./jsrelease -update -full             # re-download and re-verify every release file
./jsrelease -update -full -v          # same, showing the raw header date found in every file
./jsrelease -json                     # JSON array
./jsrelease -library core
./jsrelease -library migrate
./jsrelease -library ui
./jsrelease -library mobile
./jsrelease -library core,migrate
./jsrelease -library all
./jsrelease -output releases.txt      # print and also write to a file
./jsrelease -json -s -o list.json
./jsrelease -version
./jsrelease -list -cols library,version,support,cves    # add a CVE column
./jsrelease -list -json -s            # releases with advisories and release-notes links
./jsrelease -library core -check 3.4.1          # version check
./jsrelease -library ui -check 1.13.0 -json -s  # version check as JSON
./jsrelease -list -s -o releases.md             # save the Markdown table
./jsrelease -list -text                         # plain columns
./jsrelease -library core -cols library,version,cves -s -o core.md
./jsrelease -library core -check 3.4.1 -s -o check.md
./jsrelease -json -s | jq -r '.[] | select(.library=="core") | "\(.version) \(.release_date)"'
```

### Output and logging

- **Results** (the table or JSON) go to **stdout**. **Log messages** (`[INF]`, `[WRN]`, `[ERR]`, `[DBG]`) go to **stderr**, so piping stays clean.
- **Log and results are separated** by a blank line after the last `[INF]` line, for example:

  ```text
  [INF] Loaded 577 releases from jsrelease.json (updated 09/11/2026 16:52:06)

  Library         Version          Release Date
  ```

  Like the log lines, the blank line goes to stderr, so piped or saved results (`> file`, `-o`) don't include it. With `-s` there's neither.
- **"updated" times** are shown as `dd/mm/yyyy hh:mm:ss` in your computer's local time zone. The files store them in UTC (`2026-11-09T16:52:06Z`).
- **`-update`:** see [How `-update` keeps network use minimal](#how--update-keeps-network-use-minimal) for its output.
- **Severity** is shown with a capital first letter (`Medium`). `-json` output and the data file keep GitHub's lowercase values (`medium`), so scripts can compare them with GitHub's data directly.
- **`-silent`** removes the table heading and all informational and warning messages. Errors are still shown.
- **`-output`** writes exactly what is printed to stdout, including the heading unless `-silent` is also given.
- **`-update`** on its own only updates the databases. Add `-list`, `-json`, `-text`, `-check` or `-output` to print results afterwards.
- **Markdown is the default.** Tables are aligned Markdown pipe tables that render as tables on GitHub, GitLab, Confluence, Obsidian and most wikis, and read well in a terminal:

  ```text
  | Library        | Version | Release Date | Support        |
  |----------------|---------|--------------|----------------|
  | jQuery Migrate | 4.0.2   | 21/01/2026   | Supported†     |
  ```

  - **`-silent`:** the heading row and the `|---|` line are always written, because without them the rows aren't a Markdown table. `-silent` still removes the log messages, the footnotes and the "No known advisories" sentence from `-check`.
  - **Footnotes:** on a terminal they're plain text. In a file (`-o`), or when the output is piped or redirected, they're escaped Markdown, `\*` at the start and a trailing `\`, so they render correctly as separate lines rather than becoming a list or being run together. A pager (`| less`) counts as a pipe; add `-text` for plain output anywhere.
  - **Pipes in values:** a `|` inside a value is written as `\|` so it stays in its cell, for example in CVE-2015-9251's range `< 1.12.2 \| >= 1.12.3, < 3.0.0`.
  - **`-check`:** writes two tables separated by a blank line: your version and the latest, then the advisories.
- **`-text`** gives plain aligned columns instead, with no pipes.
- **`-json`** and **`-text`** cannot be combined.
- **Colours.** On a terminal, the message tags are coloured: `[INF]` blue, `[WRN]` red, `[ERR]` bold bright red, `[DBG]` grey. Only the tag is coloured, not the message. Colour is off when the output goes to a pipe or file, when `NO_COLOR` is set, or with `-nc` / `-no-color`. On Windows, colour works in current terminals and is switched on in older consoles.
- **Exit codes:** `0` success, `1` runtime error (for example a failed update or a missing database), `2` invalid flags.

**Old data.** When the data you're reading is more than 30 days old, jsrelease suggests an update: `[INF] Data is 47 days old; run 'jsrelease -up' to refresh`. This matters most for advisories, because new CVEs appear all the time. `-s` hides it, as it does all messages.

### Choosing columns: `-cols`

`-cols` (or `-columns`) takes a comma-separated list of column names, shown in the order you give. `-cols list` (or `-cols -h`) prints the available names:

| Table | Columns (defaults in **bold**) |
|---|---|
| Release list | **library**, **version**, **date**, **support**, cves, notes |
| `-check` summary table | **library**, **version**, **date**, **support**, **latest**, **latest-date** |
| `-check` advisory table | **advisory**, **severity**, **cvss**, **summary**, range, fixed, ghsa, link, published |

- **`link`** is the GitHub advisory page, for example `https://github.com/advisories/GHSA-gxr4-xjj5-5px2`. Every advisory has one. Markdown viewers such as GitHub make it clickable.
- **`notes`** is the GitHub release-notes URL, or `-` for versions without one.
- **`published`** is the date GitHub published the advisory, as DD/MM/YYYY.
- **`-check` has two tables, and one `-cols` list covers both.** Names for either table can be mixed. Each table shows the columns named for it, in the order given, and a table with no names keeps its defaults. For example, `-cols version,support,latest,advisory,cvss` gives a three-column summary and a two-column advisory table. `date` means the release date in both the release list and the `-check` summary.
- **`cve`, `cves` and `advisory` are interchangeable.** Each names the CVE column of whichever table it's used with: the list of CVEs per release, or one advisory per row in `-check`.
- **`cves` and `notes` load the advisory data automatically** when selected.

```bash
./jsrelease -library core -check 3.4.1 -cols version,support,latest,advisory,cvss
./jsrelease -library core -check 3.4.1 -cols advisory,cvss,link
./jsrelease -library ui -check 1.13.1 -cols published,advisory,summary,link
./jsrelease -library migrate -cols version,date,notes
```

```text
| Version | Support       | Latest |
|---------|---------------|--------|
| 3.4.1   | Security only | 4.0.0  |

| CVE / Advisory                       | CVSS |
|--------------------------------------|------|
| CVE-2020-11022                       | 6.9  |
| CVE-2020-11023 (also CVE-2020-23064) | 6.9  |
```

Without `-cols`, the output is exactly as before. Names aren't case-sensitive.

Spaces after the commas are fine: `-cols library, version, date` works the same as `-cols library,version,date`. The shell splits that command into separate words at each space, so jsrelease joins them back together while the list ends with a comma, or the next word starts with one. It stops at the next switch, so `-cols library, version -text` still gives plain columns. Names separated only by spaces, as in `-cols library version`, are reported as an error, because without a comma the second word can't be told apart from a stray argument. Quoting also works: `-cols "library, version"`. A switch given where the names should be, such as `-cols -s`, is an error explaining what `-cols` needs; `-cols -h` shows the column list. An unknown or repeated name is an error (exit code 2) that lists the valid names. `-cols` applies to text and Markdown output; `-json` always includes every field, and a warning says so.

## Where the data comes from

Each library is published differently, so the dates come from different places. **Every displayed date shows where it came from:**

| Library | Versions from | Dates from | Marker | CVEs from |
|---|---|---|---|---|
| jQuery Core, Migrate, UI, Mobile | releases.jquery.com | the official uncompressed file's header; its git tag where the header has none | none / `*` | GitHub Advisory Database (npm) |
| Bootstrap | git tags of `twbs/bootstrap` | the git tag (its files carry no date) | `*` | GitHub Advisory Database (npm) |
| Prototype | its CHANGELOG and git tags (`prototypejs/prototype`) | the CHANGELOG; the git tag after the CHANGELOG stopped (1.7.1–1.7.3) | `‡` / `*` | NVD's affected-product data (it isn't on npm) |
| Moment.js | its CHANGELOG and git tags (`moment/moment`) | the CHANGELOG; the git tag where it states no date | `‡` / `*` | GitHub Advisory Database (npm) |
| Underscore.js | its change log and git tags (`jashkenas/underscore`) | the change log; the git tag where it states no date | `‡` / `*` | GitHub Advisory Database (npm) |
| Sizzle | git tags of `jquery/sizzle` | its release file's `Date:` line; the git tag where the file has none | none / `*` | GitHub Advisory Database (npm) |

- **No marker:** the date in the official release file.
- **`*`:** the date of the release's git tag, which is the commit date of the tagged release commit, in UTC.
- **`‡`:** the release date stated in the project's own CHANGELOG.

Tables show a footnote for each marker they contain; `-s` leaves the footnotes out. `-json` gives each source as a separate field (`release_date`, `changelog_date`, `tag_date`) without markers.

### jQuery: releases.jquery.com

jQuery's data comes from the official site, https://releases.jquery.com/:

| Library | Release page |
|---|---|
| jQuery Core | https://releases.jquery.com/jquery/ |
| jQuery Migrate | https://releases.jquery.com/jquery/ (listed on the Core page; there is no `/migrate/` page) |
| jQuery UI | https://releases.jquery.com/ui/ |
| jQuery Mobile | https://releases.jquery.com/mobile/ |

For each release, `-update` follows the link labelled **uncompressed** (for example `https://code.jquery.com/jquery-3.7.1.js`, never `.min.js`, `.slim.js`, `.pack.js` or `.module.js`), downloads that file and reads the release date from its header. No jQuery `release_date` is taken from npm, Wikipedia, GitHub release notes or any built-in list. Releases whose file has no date get a separately stored, clearly marked git tag date instead (see [Releases whose official file has no date](#releases-whose-official-file-has-no-date)). The one exception is the shipped database: it was produced from the copies of these files in the repository that code.jquery.com is published from (see [The shipped databases](#the-shipped-databases)).

### How `-update` keeps network use minimal

A routine update, with nothing new published, makes about 13 requests:

| Requests | What | Notes |
|---|---|---|
| 3 | jQuery release pages | Needed to see new jQuery releases |
| 5 | Tag lists of Bootstrap, Prototype, Moment.js, Underscore.js, Sizzle | Needed to see their new releases |
| 3 | CHANGELOGs of Prototype, Moment.js, Underscore.js | Prototype's hasn't changed since 2010, so it's always "unchanged" |
| 1 | GitHub advisories for all eight npm packages | One batched request, not one per package |
| 1 | NVD search for Prototype's CVEs | One search for the vendor, covering both its product names |

A routine update skips:

- **Release-notes lists:** a repository's GitHub releases are read only when its library has a new version.
- **NVD scores:** a CVSS score already obtained from NVD is stored and reused.
- **Tag dates:** a commit date is fetched only for a tag that has none recorded. Published tags don't change, so not even `-full` looks them up again.
- **jQuery files:** a jQuery file is downloaded only for a new release.

**"Unchanged" answers.** Each data file stores the version tag (ETag) of every response it was built from (`http_cache`). The next update asks each server "has this changed?" (`If-None-Match`). If not, the server answers `304 Not Modified` without resending the data, and the stored data is reused. The summary shows how many came back unchanged:

```text
$ ./jsrelease -up
| Library        | Releases | New | Latest | Advisories | Affects Latest |
|----------------|----------|-----|--------|------------|----------------|
| jQuery         | 87       | 0   | 4.0.0  | 8          | 0              |
| jQuery Migrate | 22       | 0   | 4.0.2  | 0          | 0              |
| jQuery UI      | 66       | 0   | 1.14.2 | 7          | 0              |
| jQuery Mobile  | 42       | 0   | 1.4.5  | 1          | 1              |
| Bootstrap      | 95       | 0   | 5.3.8  | 9          | 0              |
| Prototype      | 28       | 0   | 1.7.3  | 4          | 1              |
| Moment.js      | 96       | 0   | 2.31.0 | 5          | 0              |
| Underscore.js  | 83       | 0   | 1.13.8 | 2          | 0              |
| Sizzle         | 58       | 0   | 2.3.10 | 0          | 0              |

[INF] Releases: 577, 0 new, 11 requests (8 unchanged), saved to jsrelease.json
[INF] Advisories: 36 (35 with a CVSS score), 417 releases affected, 122 with release notes, 2 requests (2 unchanged), saved to jsrelease.json
```

The table is the update's result: one row per library, so it stays readable however many libraries are added.

| Column | Meaning |
|---|---|
| Releases | releases recorded |
| New | releases added by this update |
| Latest | the newest stable release |
| Advisories | advisories recorded for the library |
| Affects Latest | how many of them affect the latest release; usually 0, but 1 for jQuery Mobile and Prototype, whose latest release is still affected |

The table follows the output switches like any other result:

- **Format:** Markdown by default; `-text` gives plain columns and `-json` gives JSON.
- **`-s`:** shows only the table, without the summary lines.
- **Saving:** `-o file` saves it, and `./jsrelease -up > report.md` captures just the table, because the summary lines go to the message stream.
- **`-library`:** limits the rows to the libraries you name.
- **With `-list` or `-check`:** `-up -list` and `-up -check …` show those results instead of the table.

**`-stats`** prints the same table at any time from the local files, without updating or using the network. For example, `jsrelease -stats -library bootstrap,moment` shows just those two libraries.

In that example the jQuery pages weren't counted as unchanged; whether they are depends on the jQuery site sending ETags. Other things to know:

- **GitHub's rate limit:** GitHub doesn't count `304` answers against it **when the request is authenticated**, so with a GitHub token set (see [GitHub token and NVD API key](#github-token-and-nvd-api-key)), a routine update costs almost nothing. Without a token, a 304 may still count.
- **Stored ETags are tied to the jsrelease version that wrote the file** (`generated_by`). After an upgrade, the first update re-reads everything once, so any change in how the data is processed takes effect.
- **`-full` ignores the stored ETags** and re-checks everything except published tag dates.
- **ETags are only kept from steps that succeed.** If a step fails part-way, for example a commit-date lookup is rate-limited after a tag list was fetched, its ETags aren't saved. The next update then asks again in full, instead of being told "unchanged" and missing the new release.

Anything new gets its own line before the summary, with its date and where the date came from:

```text
[INF] New: jQuery 4.0.1 (12/12/2026)
[INF] New: Bootstrap 5.3.9 (03/02/2027*, from its git tag)
[INF] New advisory: CVE-2027-12345 (High, CVSS 7.5) affecting jQuery < 4.0.1
```

`New advisory:` lines compare against the previous data, so they don't appear on a first update. Warnings and errors are always shown. `-v` adds the step-by-step detail: each page or list checked or found unchanged, files downloaded, NVD scores reused, and Moment.js CHANGELOG/tag disagreements. `-s` prints only the table, plus any errors.

To re-download and re-verify every jQuery file, for example after upgrading `jsrelease`, run `-update -full`. That's about 225 requests (about 50 MB), and it also re-checks NVD scores and release notes.

### How the release pages are parsed

The release pages are generated from the [`jquery/codeorigin.jquery.com`](https://github.com/jquery/codeorigin.jquery.com) repository, and each release is rendered as a line such as:

```html
jQuery Core 3.7.1: <a class='open-sri-modal' href='https://code.jquery.com/jquery-3.7.1.js' ...>uncompressed</a>, <a ...>minified</a>, ...
jQuery Mobile 1.4.5 - <a ... href='https://code.jquery.com/mobile/1.4.5/jquery.mobile-1.4.5.js'>uncompressed</a>, ...
```

The parser ties each version label to its own "uncompressed" link and then checks that:

- the link points to `code.jquery.com`;
- the file name has the uncompressed-file pattern of that library;
- the version in the file name agrees with the version shown on the page;
- every uncompressed-file link on the page belongs to a recognised release line;
- each library has at least a minimum number of releases (Core 40, Migrate 10, UI 30, Mobile 20; the pages currently list 87, 22, 66 and 42).

If any check fails, the update stops with an "unexpected HTML structure" error instead of writing incomplete data.

Some details of the official pages that the parser handles:

- **Versions are stored exactly as the page shows them.** The site normalises some old version numbers, so `jquery-1.2.js` is listed as **1.2.0** and `jquery.mobile-1.0a4.1.js` as **1.0.0-a4.1**. The `source_url` field keeps the original file name.
- **`jquery-1.7.js` and `jquery-1.7.0.js` are both listed as 1.7.0.** They are the same file, so one record is kept, using `jquery-1.7.0.js`.
- **jQuery 4.x has two "uncompressed" links**: one for the script build and one for the ES module build. The script build (`jquery-4.0.0.js`) is used.
- **The Core and Migrate page lists stable releases only.** The UI and Mobile pages also list alpha, beta and release-candidate builds.

### How the date is read

The header is the first licence or copyright comment near the top of the file. In a few old Core builds it follows a short guard comment or line of code. Later comments are ignored, because some files bundle other components (for example a jQuery UI Widget header inside early jQuery Mobile builds), and a date in one of those would belong to a different product.

The date is taken from the header's `Date:` field. If there is none, it comes from the banner line used by Migrate and newer UI builds:

| Library and versions | Example header text |
|---|---|
| Core 1.10+, 2.x, 3.x, 4.x | `Date: 2023-08-28T13:37Z` |
| Core 1.0–1.2 (`$Date$`) | `$Date: 2008-05-24 14:22:17 -0400 (Sat, 24 May 2008) $` |
| Core 1.3 | `Date: 2009-01-13 12:50:31 -0500 (Tue, 13 Jan 2009)` |
| Core 1.4–1.7 | `Date: Wed Mar 21 12:46:34 2012 -0700` |
| Core 1.8 | `Date: Thu Aug 09 2012 16:24:48 GMT-0400 (Eastern Daylight Time)` |
| Core 1.9, 2.0.0 | `Date: 2013-2-4` |
| Mobile 1.0rc3, 1.2.0–1.3.0 | `... <> Date: Mon Nov 14 16:39:50 2011 -0500` |
| Mobile 1.3.1+ | `... <> Date: Fri Oct 31 2014 17:33:30 UTC` |
| Migrate (all versions) | `jQuery Migrate - v3.4.1 - 2023-02-23T15:31Z` |
| UI 1.8.19+ | `jQuery UI - v1.13.2 - 2022-07-14` |

Dates are stored as `DD/MM/YYYY`, using the **calendar date exactly as written in the header**, without converting time zones. For example, jQuery 4.0.0's header says `2026-01-18T00:20Z`, so it is recorded as `18/01/2026`.

### Releases whose official file has no date

Some genuine releases carry **no date anywhere in their header**:

- jQuery UI 1.7.0–1.7.3 and 1.8.0–1.8.18 (23 releases);
- jQuery Mobile 1.0a1 through 1.1.2, except 1.0rc3 (18 releases).

For these, `release_date` stays empty with a `date_note`, and the date of the release's **git tag** is recorded separately instead:

- **Source:** the commit date, in UTC, of the tag in jQuery's own repositories: `jquery/jquery-ui`, and `jquery-archive/jquery-mobile`.
- **Reliability:** the tag date was checked against every release that does have an official date. It matches on the same day for 41 of 43 jQuery UI releases (the other two are one day apart) and for 24 of 24 jQuery Mobile releases.
- **Display:** tag dates are shown with a star, `20/02/2012*`, in the release list and in the `-check` summary. A footnote follows the table, `* date of the release's git tag (the official file has no date)`; it's left out with `-s`.
- **Stored separately:** they're kept in the `tag_date` and `tag_url` fields, never in `release_date`, which always comes only from the official file. `-json` output has them as separate fields, without the star.
- **Coverage:** 38 of the 41 undated releases have a tag. jQuery UI 1.7.1, 1.7.2 and 1.7.3 were never tagged, so they show `N/A`.

**Lookups.** Tags are only looked up for undated releases that haven't been searched before, so a routine update makes no tag requests. `tag_checked` records the search, so the three untagged releases aren't searched again. A first update of an empty database, or `-update -full`, makes about 40 extra GitHub requests (2 tag lists and 38 commit dates); with GitHub's limit of 60 per hour, set a GitHub token for those (`jsrelease -keys`). If the tag lookup fails, a warning is shown, the tag dates already recorded are kept, and the release update itself still succeeds.

### Bootstrap, Prototype, Moment.js, Underscore.js and Sizzle: GitHub

These five are published through GitHub. Except for Sizzle's, none of their release files carries a date: Bootstrap's headers have only a copyright year, and Prototype's and Moment.js's have none. So:

- **Bootstrap:** 95 versions, v1.0.0 (2011) to v5.3.8 and the 6.0.0 pre-releases, from the git tags of `twbs/bootstrap`, dated by their tags. GitHub Release dates were considered and rejected: the releases for v1.0.0 to v2.x were all created in one batch in July 2013, up to two years after those versions shipped. npm lacks the 1.x, 2.x and 3.0.0 versions, and some of its dates are months late.
- **Prototype:** 28 versions. Its CHANGELOG gives 24 dated releases, 1.5.0_pre0 (January 2006) to 1.7 (November 2010); it stopped being updated after that, so 1.6.1_rc2 and 1.7.1–1.7.3 come from git tags. Where both cover a version (8 of them), they agree on the same day every time. Versions before 1.5 (2005–2006) appear in neither source, so they aren't listed.
- **Moment.js:** 96 versions, 0.1.0 (2011) to 2.31.0 (September 2026). The CHANGELOG's "_Released …_" line is used where it has one (85 versions), otherwise the git tag. Where both exist, they agree on the same day for 53 versions and within a day for 24; for 8 they're further apart, for example 2.14.0, which the CHANGELOG dates 20/07/2016 but which was tagged on 04/07/2016. The CHANGELOG is the project's own statement, so it is used; `-update -v` lists those 8 differences. 6 early or untagged versions (0.1.0, 0.2.0, 0.2.1, 1.0.0, 2.10.0, 2.10.1) have neither a CHANGELOG date nor a tag, so they show `N/A`.
- **Underscore.js:** 83 versions, 0.1.0 (2009) to 1.13.8 (2026). The project's change log (the source of underscorejs.org, `index.html` in `jashkenas/underscore`) dates 81 of them; 0.5.3 and 1.3.2 are only tagged. The change log is used first, as for Moment.js. It agrees with the tag on the same day for 68 versions and within a day for 11. The two exceptions are both security fixes, dated in the change log before they were tagged: 1.12.1 (15/03/2021 against 29/03/2021) and 1.13.8 (19/02/2026 against 03/03/2026). `-update -v` lists them.
- **Sizzle** (jQuery's selector engine): 58 versions, 1.0.0 (2009) to 2.3.10 (2023), from the git tags of `jquery/sizzle`; the tag `2.1.1-jquery.2.1.2`, a build made for jQuery, isn't a Sizzle release and is left out. Like jQuery's, Sizzle's own release file (`dist/sizzle.js`, or `sizzle.js` in older releases) carries a `Date:` line, so 39 releases are dated from it, with no marker. The 19 oldest (1.0.0 to 1.7.x) have no date in the file and use their git tag date (`*`). The file and tag agree within a day except for 1.9.2 (16/04/2013 against 18/04/2013), which `-update -v` lists.

**Network.** A routine update reads each repository's tag list and the two CHANGELOGs (usually "unchanged"), and fetches a commit date only for a new tag. The shipped database already has every date. Only a first update of an empty database looks up all of them, about 380, plus Sizzle's release files. That's more than GitHub's 60 unauthenticated requests per hour, so set a GitHub token for that (`jsrelease -keys`).

If GitHub fails, these five libraries keep their previously recorded releases (with a warning), and the jQuery update is unaffected.

### What makes an update fail

Any of the following stops the update, lists each problem on stderr and **leaves the existing database unchanged**:

- a release page cannot be fetched, or returns an HTTP error;
- a release page no longer matches the expected structure;
- any file cannot be downloaded, or returns HTML instead of JavaScript;
- a header contains a date that cannot be understood;
- a release already in the database is no longer listed on the pages. Releases are never removed from the official site, so this means the pages were not read correctly. The error names the missing releases.

HTTP 5xx, HTTP 429 and network errors are retried twice, with a growing pause. Other HTTP errors are not retried.

The releases and the advisories are updated **independently**, each in its own section of `jsrelease.json`. If GitHub is unreachable, new releases are still recorded; if releases.jquery.com is unreachable, advisories are still refreshed. Each failure is reported, the exit code is 1, and the file whose update failed is left unchanged.

## Vulnerabilities and release notes

### Sources

- **Advisories:** the [GitHub Advisory Database](https://github.com/advisories), reviewed advisories for the npm packages `jquery`, `jquery-migrate`, `jquery-ui` and `jquery-mobile`. Each one gives the CVE ID (when assigned), severity, vulnerable version ranges and first fixed version.
- **Release notes:** GitHub Releases of `jquery/jquery`, `jquery/jquery-migrate`, `jquery/jquery-ui` and `jquery-archive/jquery-mobile` (jQuery Mobile's repository moved to the `jquery-archive` organisation).

- **CVSS scores:** GitHub's score for each advisory. Where GitHub has none, the score comes from the [NVD](https://nvd.nist.gov/) CVE API, using NVD's own (Primary) score.

GitHub is queried with one batched advisory request per update, plus a repository's release list when its library has a new version. NVD is queried once for Prototype, and for scores only for advisories that have a CVE ID but no GitHub score and no stored NVD score. Unauthenticated use allows 60 requests per hour per IP address; on shared networks, set a token to raise the limit:

```bash
jsrelease -keys               # shows whether keys are set, and how to set them
jsrelease -set-key github     # stores a token; what you type is hidden
```

The token is only sent to GitHub, and only as an `Authorization` header; it is never sent to NVD. See [GitHub token and NVD API key](#github-token-and-nvd-api-key).

NVD allows 5 requests per 30 seconds without a key. jsrelease pauses between NVD requests when it needs more than 5, and you can set a free NVD API key to raise the limit; it is sent only to NVD, as the `apiKey` header:

```bash
jsrelease -set-key nvd
```

A score obtained from NVD is stored and reused on later updates, so NVD is only contacted for an advisory with no stored score, for example a newly published one, or when you run `-update -full`.

NVD is a supplementary source, so a failed NVD lookup doesn't fail the update. It produces a warning, and if an earlier update obtained a score from NVD, that score is kept.

### What the data contains

At the time of writing the advisory data covers:

| Library | Active advisories | Notes |
|---|---|---|
| jQuery Core | 8 | CVE-2011-4969 to CVE-2020-11023, plus 2 duplicate CVE IDs as aliases; nothing affects 3.5.0 or later |
| jQuery Migrate | 0 | |
| jQuery UI | 7 | CVE-2010-5312 to CVE-2022-31160; nothing affects 1.13.2 or later |
| jQuery Mobile | 1 | GHSA-fj93-7wm4-8x2g: no CVE ID and no fix, affects every version |
| Bootstrap | 9 | CVE-2016-10735 to CVE-2025-1647; CVE-2024-6485 affects every version up to 3.4.1 with no fix in the 3.x line; nothing affects 5.x |
| Prototype | 4 | from NVD (see [Prototype's CVEs](#prototypes-cves-come-from-nvd)); CVE-2020-27511 affects the last release, 1.7.3 |
| Moment.js | 5 | CVE-2016-4055 to CVE-2026-17495; nothing affects 2.31.0 |
| Underscore.js | 2 | CVE-2021-23358 (Critical, CVSS 9.8, >= 1.3.2 < 1.12.1) and CVE-2026-27601 (High, <= 1.13.7); nothing affects 1.13.8 |
| Sizzle | 0 | none known |

Of the 577 releases, 417 are affected by at least one advisory.

GitHub release notes exist only for some versions: jQuery Core 3.5.0 onwards, Migrate 3.5.0 onwards, UI 1.13.0 onwards, every Bootstrap release, 2 Moment.js releases and 5 Sizzle releases. That's 122 of the 577 releases. jQuery Mobile, Prototype and Underscore.js have git tags but no GitHub Releases. Older jQuery release notes are on blog.jquery.com and jqueryui.com, whose URLs don't follow a reliable pattern, so they aren't guessed; `release_notes_url` is `null` for those versions.

### CVSS scores

The `-check` table has a `CVSS` column next to `Severity`:

- **GitHub's score is used when it has one.** It is usually CVSS 3.1 or 3.0; 13 of the 16 advisories have one, ranging from 6.1 to 7.5. GitHub's score can differ from NVD's. For CVE-2020-11022, GitHub gives 6.9 and NVD 6.1. GitHub is the primary source here, so its score is kept.
- **CVSS v3 is preferred** when an advisory has scores in several versions. For example, CVE-2020-7656 has v3.1 6.1 and v4.0 5.3; both are stored, and 6.1 is shown.
- **Scores from NVD:** when GitHub has no score, NVD's is used. GitHub reports a missing score as `0.0` with no vector string. That isn't a real score, so it's never shown as 0.0.
- **Other CVSS versions are labelled**, because their scales differ from v3. CVE-2011-4969 and CVE-2012-6662 only have CVSS v2 scores at NVD, shown as `4.3 (v2.0)`, which is not comparable with a v3 6.1. A v4-only score would show as, for example, `5.3 (v4.0)`.
- **`-`** means there is no score anywhere. That applies to the jQuery Mobile advisory, which has no CVE ID, so NVD can't be asked.

The data file and `-json` output include the full details: version, score, vector string and source (`GitHub` or `NVD`).

### How versions are matched

- **npm only:** an advisory can also list NuGet, Composer, Maven and RubyGems packages; only the npm entry for the exact package name is used.
- **Withdrawn duplicates become aliases.** When GitHub withdraws an advisory as a duplicate of another, its text names the advisory it duplicates. The withdrawn advisory's CVE ID is then recorded as an alias of that advisory instead of being lost, because scanners and NVD-based reports still use those IDs. Today this covers:
  - **CVE-2020-23064**, shown as `CVE-2020-11023 (also CVE-2020-23064)`;
  - **CVE-2019-5428**, shown as `CVE-2019-11358 (also CVE-2019-5428)`.

  It is still one vulnerability with one range, so nothing is counted twice. Other withdrawn advisories (for example a jQuery UI one withdrawn as an "accidental duplicate publish", with no CVE ID) are ignored; `-v` logs them.
- **Every range counts.** Some advisories have more than one vulnerable range. CVE-2015-9251 covers `< 1.12.2` and `>= 1.12.3, < 3.0.0`, so 1.12.2 itself is not affected.
- **Pre-releases are compared exactly.** `3.0.0-rc1` is treated as equal to `3.0.0-rc.1` and as earlier than `3.0.0`, so it matches both `= 3.0.0-rc.1` and `< 3.5.0`.
- **Advisories without a CVE** are shown by their GHSA ID.
- **Ranges are GitHub's assessment.** Every match records the advisory ID and the exact range, so you can see why a version was flagged.

### Prototype's CVEs come from NVD

Prototype isn't published on npm, so GitHub's advisories for it are unreviewed, with no affected versions. Its CVEs therefore come from NVD's affected-product (CPE) data for `prototypejs:prototype` and `prototypejs:prototype_framework`, found with one NVD search for the `prototypejs` vendor per update. They're used **exactly as NVD publishes them**, and shown with `(NVD)` after the range:

| CVE | NVD says affects | Note |
|---|---|---|
| CVE-2020-27511 | = 1.7.3 | The last release, so there's no fixed version |
| CVE-2008-7220 | < 1.6.0.2 | A clean range; fixed in 1.6.0.2 |
| CVE-2007-2383 | = 1.5.1_rc3 | Contradicts its own description, which says "before 1.5.1 RC3" |
| CVE-2020-7993 | = 1.6.0.1 | Describes "ticket creation", which looks like a different product |

NVD's data doesn't say whether a fix exists unless it gives an upper bound, so "fixed in" shows `unknown` rather than `none`, and these advisories don't trigger the "no fixed version" warning. If NVD can't be reached, the Prototype advisories from the previous update are kept, with a warning.

### Checking a version: `-check`

```bash
./jsrelease -library core -check 3.4.1
```

- **Version:** the release you give, matched semantically (`1.2` finds `1.2.0`; a leading `v` is accepted). A version that isn't in the database is an error, not a guess.
- **Latest:** the newest **stable** release of that library, ignoring alpha, beta and release-candidate builds.
- **CVEs:** every advisory affecting **any** version from yours up to the latest. The versions considered are yours plus every stable release after it, up to the latest. So an advisory introduced after your version is listed too, as it matters if you upgrade to an intermediate release. For example, `-check 1.12.2` lists CVE-2015-9251 even though 1.12.2 itself isn't affected, because 1.12.3 to 2.2.4 are.
- **Warnings:** an advisory that also affects the latest release produces a warning, saying whether it has a fixed version. If your version is a pre-release newer than the latest stable release, you're told that too.
- **`-library` is required**, with a single library, because the same version number exists in more than one library. It works the same way for every library, for example `-library bootstrap -check 3.4.1` or `-library moment -check 2.29.1`.

## Support status

Every release shows whether its release line is still supported:

- **`Supported`:** the line receives fixes.
- **`Security only`:** the line receives security fixes only.
- **`Unsupported`:** the line receives no fixes.

An older patch release has the same status as its line. jQuery 3.6.0 is `Security only` like 3.7.1, but only the newest release in the line, 3.7.1, actually contains the fixes, and `-check` says so. Pre-releases (alpha, beta, rc) are always `Unsupported`, because they aren't meant for production use.

| Library | Status | Basis |
|---|---|---|
| jQuery Core | latest major (4.x) supported; previous major (3.x) security only; older unsupported | **Official**: [jquery.com/support](https://jquery.com/support/), "only the two latest releases are supported" |
| jQuery Migrate | follows the jQuery line it's used with (Migrate 4 is for jQuery 4, Migrate 3 for jQuery 3); 1.x unsupported | *Inferred* from its [compatibility table](https://github.com/jquery/jquery-migrate#version-compatibility); no stated policy |
| jQuery UI | latest line (1.14) supported; older lines unsupported, each since the next line's first release | *Inferred*: no stated policy; only its latest line receives releases |
| jQuery Mobile | all unsupported since 07/10/2021 | **Official**: [deprecated](https://blog.jquerymobile.com/2021/10/07/jquery-maintainers-continue-modernization-initiative-with-deprecation-of-jquery-mobile/), repository archived |
| Bootstrap | latest major (5) supported; 4 since 01/01/2023, 3 since 24/07/2019, 2 since 19/08/2013 unsupported | **Official**: [Bootstrap's release policy](https://github.com/twbs/release); 1.x *inferred* |
| Moment.js | 2.x security only ("a legacy project in maintenance mode"); 1.x and 0.x unsupported | **Official** for 2.x ([project status](https://momentjs.com/docs/#/-project-status/)); older majors *inferred* |
| Prototype | all unsupported | *Inferred*: no release since 2015, and the project has made no statement |
| Underscore.js | latest line (1.13) supported; older lines unsupported, each since the next line's first release | *Inferred*: no stated policy; only its latest line receives releases |
| Sizzle | all unsupported | *Inferred*: no release since 2023, and the project has made no statement |

**How inferred statuses are shown.** Statuses not based on a project's statement are marked `†`, with the footnote `† support status inferred: the project states no support policy for it`.

**Rules, not a fixed list.** The statuses are worked out from the release data, so they follow new releases without a tool update:
- When jQuery 5.0.0 appears, 4.x becomes `Security only` and 3.x `Unsupported`.
- When Bootstrap 6 appears, 5.x becomes `Security only†` until Bootstrap publishes an end date, at which point the date is added to the tool.

**Where it appears:**
- **The default table:** a `Support` column, also selectable with `-cols support`.
- **The `-check` summary:** a `Support` column, plus a warning for anything not `Supported`:

  ```text
  [WRN] jQuery 3.4.1 is Security only: its line receives security fixes only; the newest release in its line is 3.7.1, the latest is 4.0.0
  [WRN] Bootstrap 3.4.1 is Unsupported since 24/07/2019; the latest is 5.3.8
  ```

- **JSON:** a `support` object, for example `{"status": "security-only", "basis": "official", "since": "18/01/2026", "source": "https://jquery.com/support/", "note": "…"}`.

## GitHub token and NVD API key

Both are optional, and jsrelease only reads public data:

- **A GitHub token** raises GitHub's API limit from 60 requests per hour. A fine-grained token with **no permissions** is enough; create one at <https://github.com/settings/personal-access-tokens/new>. GitHub doesn't count "unchanged" answers against the limit for requests made with a token.
- **An NVD API key** raises NVD's rate limit; request one at <https://nvd.nist.gov/developers/request-an-api-key>.

`jsrelease -keys` shows whether each key is set and where it comes from. It never shows a key. It also prints copy-and-paste instructions for your system:

```text
$ jsrelease -keys
GitHub token: not set
NVD API key:  not set
…
  jsrelease -set-key github
  jsrelease -set-key nvd
…
  read -rs GITHUB_TOKEN && export GITHUB_TOKEN
```

**Storing a key: `-set-key github` or `-set-key nvd`.** You're asked for the key, and what you type isn't shown, so the key never appears on screen, in your shell history or in the list of running processes. It's saved in the config file:

| System | Config file |
|---|---|
| Linux | `~/.config/jsrelease/config.yaml` (or under `$XDG_CONFIG_HOME`) |
| macOS | `~/Library/Application Support/jsrelease/config.yaml` |
| Windows | `%AppData%\jsrelease\config.yaml` |

- **File permissions:** the folder is created readable only by you (`700`) and the file likewise (`600`). jsrelease warns if the file becomes readable by others.
- **Removing a key:** `-set-key github -clear` removes a stored key.
- **Piped input:** a key can also be piped in, for example from a password manager: `pass show github | jsrelease -set-key github`.

**Environment variables** `GITHUB_TOKEN` and `NVD_API_KEY` take priority over the config file; `-keys` shows the commands. **`-config path`** uses another config file, for example one in the tool's own folder. jsrelease only reads a config file there when you point to it with `-config`. `.gitignore` and the release archives exclude `config.yaml` and `jsrelease.yaml`, so a key file kept beside the tool isn't committed or packaged by mistake.

The file format is plain `key: value` lines:

```yaml
github_token: "github_pat_..."
nvd_api_key: ""
```

Rate-limit warnings during `-update` end with `run jsrelease -keys to set a GitHub token`. With `-v`, jsrelease logs where each key came from, without showing it.

## Data file format

`jsrelease.json` has two sections, each saved on its own:

```json
{
  "releases": { "updated_at": "…", "source": "…", "releases": [ … ], "http_cache": { … }, "generated_by": "…" },
  "vulnerabilities": { "updated_at": "…", "sources": [ … ], "advisories": [ … ], "releases": [ … ], "http_cache": { … }, "generated_by": "…" }
}
```

### The releases section

```json
{
  "updated_at": "2026-11-09T12:00:00Z",
  "source": "https://releases.jquery.com/",
  "releases": [
    {
      "library": "core",
      "name": "jQuery",
      "version": "3.7.1",
      "release_date": "28/08/2023",
      "source_url": "https://code.jquery.com/jquery-3.7.1.js"
    },
    {
      "library": "ui",
      "name": "jQuery UI",
      "version": "1.8.18",
      "release_date": "",
      "source_url": "https://code.jquery.com/ui/1.8.18/jquery-ui.js",
      "date_note": "no release date in the header of the official uncompressed file",
      "tag_date": "20/02/2012",
      "tag_url": "https://github.com/jquery/jquery-ui/tree/1.8.18",
      "tag_checked": true
    }
  ]
}
```

- Records are unique per library and version, and the same version number may appear under different libraries.
- Every `release_date` is either a valid `DD/MM/YYYY` date or empty, in which case `date_note` explains why.
- `tag_date` (DD/MM/YYYY) and `tag_url` appear only on releases with an empty `release_date`. `tag_checked` means the git tags were searched; it's also set when no tag was found.
- `changelog_date` and `changelog_url` hold the date stated in a project's CHANGELOG (Prototype, Moment.js, Underscore.js), also only when `release_date` is empty.
- `http_cache` maps each checked URL to the ETag of its last response, and `generated_by` names the jsrelease version that wrote the file (see [How `-update` keeps network use minimal](#how--update-keeps-network-use-minimal)). The vulnerability file has both fields too.
- The support status isn't stored: it's worked out when the data is shown. `-json` output includes it as a `support` object.
- The file is checked when it is loaded and before it is written.
- Writes are atomic: the file is written to a temporary file in the same directory, flushed to disk and renamed over the old one, so an interrupted or failed update cannot leave a half-written database.

The `-json` output is an array of these release objects.

### The vulnerabilities section

```json
{
  "updated_at": "2026-11-09T14:58:12Z",
  "sources": ["https://github.com/advisories (GitHub Advisory Database, reviewed npm advisories)", "..."],
  "advisories": [
    {
      "id": "GHSA-gxr4-xjj5-5px2",
      "cve": "CVE-2020-11022",
      "library": "core",
      "package": "jquery",
      "severity": "medium",
      "cvss": [
        { "version": "3.1", "score": 6.9, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N", "source": "GitHub" }
      ],
      "summary": "Potential XSS vulnerability in jQuery",
      "published": "2020-04-29",
      "url": "https://github.com/advisories/GHSA-gxr4-xjj5-5px2",
      "ranges": [{ "vulnerable_range": ">= 1.12.0, < 3.5.0", "patched": "3.5.0" }]
    }
  ],
  "releases": [
    { "library": "core", "version": "3.7.1", "release_notes_url": "https://github.com/jquery/jquery/releases/tag/3.7.1", "advisories": [] },
    { "library": "core", "version": "3.4.1", "release_notes_url": null, "advisories": ["GHSA-gxr4-xjj5-5px2", "GHSA-jpcq-cgw6-v4j6"] }
  ]
}
```

- **`advisories`** is the source of truth. `patched` is omitted when there is no fix, and `cve` when none is assigned. `cvss` lists every score found, and is omitted when there is none. `aliases` lists duplicate CVE IDs (for example `"aliases": ["CVE-2020-23064"]` on CVE-2020-11023) and is omitted when there are none. `-cve -json` output includes it too.
- **`releases`** is a convenience snapshot that maps each release to its advisory IDs, recalculated on every successful update. At run time, the `cves` column and `-check` match versions against `advisories` directly, so a release added since the last GitHub refresh is still checked.
- **Validation and saving:** the file is validated on load and before saving, and saved atomically.
