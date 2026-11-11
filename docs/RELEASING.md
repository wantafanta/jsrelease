# Publishing a release

Releases are published from the GitHub web interface. A workflow
(`.github/workflows/release.yml`) then builds the binaries and attaches them.

## 1. Refresh the bundled data (on your machine)

The data in `jsrelease.json` is built into the binary, so refresh it first:

```bash
make data
git commit -am "Refresh data"
git push
```

`make data` needs a GitHub token (`jsrelease -set-key github`).

## 2. Publish the release (on GitHub)

1. Open the repository, then **Releases → Draft a new release**.
2. **Choose a tag:** type the new version, for example `v1.0.1`, and select
   **Create new tag on publish**. Use the next version number: `v1.0.1` for
   fixes and data refreshes, `v1.1.0` for new features.
3. Add a title and notes. **Generate release notes** fills them in from the
   commits since the last release.
4. Click **Publish release**.

## 3. Wait for the binaries

The workflow starts automatically (see the **Actions** tab). It runs the tests,
then builds and attaches these, after a minute or two:

| File | For |
|---|---|
| `jsrelease_<version>_linux_amd64.tar.gz` | Linux, Intel/AMD |
| `jsrelease_<version>_linux_arm64.tar.gz` | Linux, ARM |
| `jsrelease_<version>_darwin_amd64.tar.gz` | macOS, Intel |
| `jsrelease_<version>_darwin_arm64.tar.gz` | macOS, Apple silicon |
| `jsrelease_<version>_windows_amd64.zip` | Windows, Intel/AMD |
| `jsrelease_<version>_windows_arm64.zip` | Windows, ARM |
| `checksums.txt` | SHA-256 checksums of the files above |

If the tests fail, nothing is attached: fix the problem, delete the release
and its tag, and publish again.

The new version is also available straight away through
`go install github.com/wantafanta/jsrelease@latest`.

## Notes

- macOS may block a downloaded binary the first time it runs, because it is
  not signed. `xattr -d com.apple.quarantine jsrelease` allows it.
- To try the build locally without publishing anything:
  `goreleaser release --snapshot --clean` (builds into `dist/`).
