# jsrelease

Lists every release of popular JavaScript libraries, with release dates, support status and known CVEs, and checks a version you use against the latest one.

Libraries: **jQuery** (Core, Migrate, UI, Mobile), **Bootstrap**, **Prototype**, **Moment.js**, **Underscore.js** and **Sizzle**.

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

## Install

```bash
go install github.com/wantafanta/jsrelease@latest
```

Requires Go 1.22 or later. The release data is bundled, so it works offline straight away.

## Usage

```bash
jsrelease -list                                   # every release
jsrelease -library bootstrap                      # one library (comma-separated for several)
jsrelease -library core -check 3.4.1              # a version against the latest, with its CVEs
jsrelease -stats                                  # per-library summary
jsrelease -up                                     # fetch new releases and advisories
jsrelease -list -cols version,date,support,cves   # choose columns (-cols list shows them all)
jsrelease -list -text                             # plain columns instead of Markdown
jsrelease -list -json -s -o list.json             # JSON, for scripts
```

Run `jsrelease -h` for every option.

## Where the data comes from

Release dates come from each project's own release files, CHANGELOG or git tags. A marker shows which:

| Marker | Date from |
|---|---|
| none | the official release file |
| `‡` | the project's CHANGELOG |
| `*` | the release's git tag |

Support status follows each project's stated policy. Where a project states none, the status is inferred and marked `†`.

CVEs come from the GitHub Advisory Database, plus NVD for Prototype. CVSS scores come from GitHub, or from NVD where GitHub has none.

## GitHub token (optional)

Updating uses the GitHub API, which allows 60 requests per hour without a token. To set one (input is hidden):

```bash
jsrelease -keys             # status and instructions
jsrelease -set-key github   # a token with no permissions is enough
```

## More

The full guide covers per-library sources, date and support rules, every switch and the data file: [docs/GUIDE.md](docs/GUIDE.md).

## Licence

MIT
