# Advisory test fixtures

- `adv-<package>.json`: real responses of the GitHub REST API
  `/advisories?ecosystem=npm&affects=<package>&per_page=100` (9 November 2026).
- `rel-<repo>.json`: real responses of `/repos/<owner>/<repo>/releases?per_page=100`.
  `rel-jquery-mobile.json` is from `jquery-archive/jquery-mobile` (the repository
  moved there) and is genuinely empty: it has git tags but no GitHub Releases.
- `nvd-<CVE>.json`: real NVD CVE records for the two advisories that GitHub
  gives no CVSS score, wrapped in the NVD CVE API 2.0 response envelope
  (`{"vulnerabilities":[{"cve": ...}]}`). NVD itself was not reachable from the
  development environment; the records come from the fkie-cad/nvd-json-data-feeds
  mirror on GitHub, which republishes the NVD API's CVE objects unchanged.
- `tags-<repo>.json` and `commits-<repo>.json`: the git tags of `jquery/jquery-ui`
  and `jquery-archive/jquery-mobile` in the shape of the GitHub API's
  `/repos/<owner>/<repo>/tags` response, and each tagged commit's committer
  date (UTC, as `/repos/<owner>/<repo>/commits/<sha>` returns it). Both were
  generated from clones of the real repositories on 9 November 2026.
- `adv-bootstrap.json`, `adv-moment.json`, `rel-bootstrap.json`, `rel-moment.json`,
  `rel-prototype.json`: real GitHub API responses for the libraries added later.
  The fake server answers a batched request (`affects=a,b,c`) with the union of
  the per-package responses; a live check confirmed GitHub returns the same set.
- `tags-<repo>.json` / `commits-<repo>.json` for bootstrap, moment and prototype:
  from clones of `twbs/bootstrap`, `moment/moment` and `prototypejs/prototype`.
- `changelog-moment.md`, `changelog-prototype.txt`: the projects' CHANGELOG files.
- `nvd-cpe-prototypejs.json`: the real NVD records of Prototype's four CVEs, in the
  NVD API response envelope, as returned for `virtualMatchString=cpe:2.3:a:prototypejs`.
