# Test fixtures

All fixtures come from https://github.com/jquery/codeorigin.jquery.com, the
repository from which code.jquery.com and releases.jquery.com are published
(commit 9aa323d1dec3661e8b1ef10664fa4fcd6f9da925, 2026-09-27).

- `releases-jquery.html`, `releases-ui.html`, `releases-mobile.html`:
  output of that repository's own page generator (`Gruntfile.js` task
  `build-index` with `templates/*.hbs`) run over its real `cdn/` file list,
  wrapped in a minimal page shell with unrelated navigation links. SRI hashes
  are placeholders. They are not captures of the live pages.
- `headers/<library>_<file version>.js`: the first 4 KB of each real
  uncompressed file listed on the release pages (217 files).
- `expected-entries.txt`: expected parse result, derived independently (in
  Python) from the repository file tree using the generator's rules.
- `expected-dates.txt`: expected date for each header, computed
  independently in Python. `NONE` marks the 41 official files whose header
  contains no release date.
