# 1. Read the settings files, not the built app

## Context

The tool needs to know, for an Android and an iOS app, whether the settings that decide debugging, backups, transport security, exported components, permissions, the target SDK and entitlements are safe for a store release. There are richer ways to get that: build the app and read the merged manifest and the built `Info.plist`, unpack the APK, AAB or IPA and decode its binary manifest and plist, run the Android Gradle plugin's lint, or run a full mobile scanner on the binary. Each of them needs the Android SDK or Xcode, a macOS machine for iOS, signing credentials or at least a working build, and often network access to download plugins and dependencies. Running a Gradle build is running the code in its build files and plugins. And the people who need the answer most often need it before a build exists: on a pull request that changes the manifest, in a pipeline on Linux, or in a review of files sent by someone else.

## Decision

The tool reads the source settings files as data, and nothing else: `AndroidManifest.xml`, the network security config and the module build file for Android, and `Info.plist` and the entitlements file for iOS. It never runs Gradle, Xcode, `plutil` or any other program, never evaluates the build file, never expands a build setting, never decodes a binary file and never fetches anything. XML is read by a small reader inside the tool that refuses DOCTYPE and entity declarations; the one public DOCTYPE line Xcode writes into plists is matched exactly and skipped. Every finding is a fact written in those files, and the rules that turn these facts into findings and MASVS categories are written down in docs/method.md.

## Consequences

The check runs in a second, on Windows, Linux or macOS, with only Node, no SDK, no Xcode, no network access and no credentials, and no input can make it run code or reach out to a host. The same files always give the same report, so it can run on every pull request and gate a release branch. The cost is that it sees only what the source files say: what libraries add to the merged manifest, what Gradle computes from variables and flavors, what Xcode fills in from build settings, and everything the code of the app does are outside it. The README and docs/limits.md say so, and point to running it on the merged manifest of the release build too, and to the OWASP MASTG tests on the built app as the next step.
