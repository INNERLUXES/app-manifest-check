# Contributing

Every change goes through a pull request and is reviewed before it is merged. The pipeline runs the tests on Linux, Windows and macOS, the repository checks, CodeQL, and a secure development check of the repository itself.

Commit messages in this repository follow Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `ci:`, with `!` for a breaking change.

## Changing a check

1. Describe the change in docs/method.md first: what the check reports, its severity, its MASVS category, and why it matters for a release, with the part of OWASP MASVS, the OWASP MASTG, the Apple App Store Review Guidelines or the Google Play target API level requirements it follows. Where the tool makes its own choice (which permissions count as broad, which capability needs which usage description, the default lowest target SDK), say so and say why.
2. Add a test with the manifest, plist, network config or build file written inline, small enough that the result can be worked out by hand. Use made-up package ids, bundle ids and host names (`com.example.orders`, `example.test`).
3. Text from the input goes through `safeText` before it reaches a finding or a note, so control characters are removed. Never put a signing setting, a key or another value from a build file into a finding.
4. A finding id and its MASVS category, once released, keep their meaning: pipelines, SARIF viewers and other tools read them from the JSON, CSV and SARIF reports.

## Changing the readers

1. For the XML and plist readers, add a test for every form you add and one that must be refused. Keep refusing DOCTYPE and ENTITY declarations and every entity except the five XML predefines; the plist DOCTYPE line stays an exact match. A form that cannot be read with certainty is refused, never guessed.
2. For the Gradle patterns, add a test in both the Groovy and the Kotlin DSL. Keep every pattern anchored and free of nested repetition, and never evaluate anything from the file.
3. Paths given on the command line are opened with `path.resolve`, never `path.join`, so an absolute path works on every system. A file name taken from a path is read with either separator, and resource names are compared exactly, letter case included, on every system; say so in docs/method.md when you add a comparison.
4. Keep the size, depth and element limits.

## Rules for the code

- No runtime dependencies. Node 22 or newer and nothing else.
- The tool reads the files it is given and writes only to the screen. It opens no network connection, runs no program (no Gradle, no Xcode, no `plutil`, no shell), and never follows a URL, a resource name or a build setting from an input.
- Source files stay ASCII; write any other character in a pattern as a `\u` escape.
- Never commit a real manifest, plist, entitlements file or build file, even as a fixture. Write small made-up files, and never put a real key, token, keystore password or signing identity into one, even an expired one.

## Before you open the pull request

```
npm test
npm run check
npm run example
```
