## What changes

<!-- One or two sentences. -->

## Checks

- [ ] `npm test`, `npm run check` and `npm run example` pass
- [ ] A change to a check, its MASVS category, a permission list, the usage description map or a reader is described in docs/method.md, and has a test with the files written inline
- [ ] Text from the input goes through `safeText`, and no signing setting or other build file value reaches a report; the tool still runs no Gradle, Xcode or `plutil`, fetches nothing, opens no connection and reads no file other than the ones named on the command line
- [ ] Paths are opened with `path.resolve`, file names are read with either separator, and resource names are compared exactly, so the result is the same on Linux, macOS and Windows
- [ ] No real manifest, plist, entitlements or build file and no real key, token or signing identity in fixtures or examples
- [ ] The commit messages of this pull request follow Conventional Commits
