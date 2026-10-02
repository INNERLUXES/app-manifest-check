# Changes

## 1.0.0

First release.

- Checks the settings files of a mobile app before a store release for risky configuration, by the OWASP MASVS categories. Reads files only; never runs Gradle, Xcode, `plutil` or a build and never fetches anything.
- Reads the source `AndroidManifest.xml` (with any prefix bound to the Android namespace), the network security config (base config, nested domain configs with inheritance, trust anchors, debug overrides) and the module build file in the Groovy or Kotlin DSL, by documented patterns, for the SDK levels, the namespace and the release build type.
- Reads `Info.plist` and `.entitlements` files in the XML property list format; binary plists are refused with the `plutil` command that converts them, and compiled binary manifests with a request for the source manifest.
- A small XML reader that refuses DOCTYPE and ENTITY declarations and every entity except the five XML predefines, skips only the exact public plist DOCTYPE line, and stops at the line of anything that is not well-formed.
- Eleven Android checks: `debuggable`, `allow-backup`, `cleartext-traffic`, `user-certs-trusted`, `exported-without-permission`, `missing-exported`, `dangerous-permissions`, `broad-permissions`, `target-sdk`, `minify-off` and `task-hijacking`.
- Seven iOS checks: `ats-arbitrary-loads`, `ats-insecure-exception`, `missing-usage-description`, `file-sharing`, `background-modes`, `url-schemes` and `debug-entitlement`.
- Every finding has an id, a severity, a MASVS category, the file and line, the subject, a message and a fix.
- A JSON config for the lowest target SDK, hosts allowed to use plain HTTP, components meant to be exported, and ignore rules by check and subject; every key is checked.
- Reports as text, Markdown, JSON, CSV and SARIF 2.1.0; `--fail-on` for a pipeline gate.
- Safe input: only the named files are read; files over 10 MB, XML nested more than 64 deep and more than 200,000 elements are refused; control characters are removed from every text shown.
- Release packages come with a CycloneDX SBOM, SHA-256 checksums and a build provenance attestation.
