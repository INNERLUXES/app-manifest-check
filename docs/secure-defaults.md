# Secure defaults

The default run is the safe run. Nothing below needs a flag, and none of it can be switched off.

## How the tool behaves by default

- **No network.** The tool reads the files it is given and sends nothing anywhere. It does not resolve the domains in a network security config or an `NSExceptionDomains` entry, does not download Apple's plist DTD, does not look up a permission, a plugin or a library, does not follow an address from any file, and does not check for updates. A file argument that looks like an address is refused. It can run in a locked-down job with no outbound access at all.
- **No Gradle, no Xcode, no commands.** The tool never runs Gradle, the Android SDK, Xcode, `plutil`, a shell or any other program. The build file is read as text and searched with a few anchored patterns; plugins, tasks, `providers.exec` calls and anything else in it are never run. No name, path or value from the input is ever put on a command line. A project from an unknown source can be checked without running any of its code, which is not true of syncing it in an IDE or building it.
- **No dependencies.** Node 22 or newer and nothing else, so a security check of an app does not add a supply chain of its own. There is no `node_modules` to install before it runs.
- **Safe XML.** Every XML file is read by a small reader that refuses a DOCTYPE or an ENTITY declaration before reading anything in it, and refuses every entity except `&lt;`, `&gt;`, `&amp;`, `&quot;` and `&apos;`. The one exception is the public DOCTYPE line Xcode writes at the top of every plist, which is compared character for character (with or without the older "Apple Computer" name) and skipped as text: it has no internal subset, and the DTD it names is never opened. A plist DOCTYPE with anything added to it is refused like any other. No entity is ever expanded beyond the five, no external file or address named in an entity is ever opened, and a "billion laughs" file is refused at its first line. Nesting deeper than 64 levels and more than 200,000 elements in one file are refused too.
- **No binary parsers.** Binary property lists and compiled binary manifests are recognised by their first bytes and refused, with the `plutil` command or the source file to give instead. There is no code that decodes a binary format, so a crafted binary file has nothing to attack.
- **Strict parsing.** A file that is not well-formed XML (a tag that is not closed, a second root element, an attribute given twice, a stray `<` or `&`), a plist with a key given twice or a value of an unknown type, a manifest whose root is not `<manifest>` and a network config whose root is not `<network-security-config>` are refused with the file and line, and the run stops with exit code 2. A report that skipped the part it did not understand is never written.
- **Reads only what is named.** The tool opens exactly the files given on the command line. It does not follow `@xml/...` resource names, `$(...)` build settings, paths in the build file or any other reference to another file, and it does not look at the folders around the files.
- **Regular files only, bounded.** Each file is opened once, its type and size are taken from the open file, and anything that is not a regular file or is over 10 MB is refused before it is read. A folder, a device or a pipe given by mistake cannot make the run hang.
- **Clean output.** Text from the input has control characters, line separators and direction controls removed and its length capped before it reaches a report or an error message, so a hostile component name cannot rewrite the terminal or reorder what a reader sees. Markdown cells escape pipes, backslashes, line breaks and `<`, `>` and `&`, so a name cannot break a table and a tag in a message is shown, not swallowed as HTML. CSV cells are quoted as RFC 4180 says, and a cell that a spreadsheet would read as a formula gets a leading `'`. No report renders a name as a link.
- **No prototype tricks.** Attributes and dict keys are stored in objects without a prototype, so an attribute or key named `__proto__` or `constructor` is just data.
- **The config cannot be wrong quietly.** Every key of the config file is checked. An unknown key, a misspelled check in an ignore rule, a domain entry that is not a host name, and a target SDK outside 1 to 99 stop the run with exit code 2. Ignore rules are counted in the report, so a reviewer sees that findings were left out.
- **The gate is on.** Without any option, an error makes the run exit with `1`. A pipeline that adds the tool notices a debuggable manifest or a switched-off App Transport Security from the first run.
- **Writes nothing to disk.** The report goes to the screen. Redirect it to a file, the job summary or a SARIF upload only when you need to keep it.

## Running it safely on an app you do not know

1. Run the check before anything else touches the project: before opening it in Android Studio or Xcode, before a Gradle sync, before `pod install` or a package resolve, and before a build. Each of those runs code from the project or its dependencies; the check does not.
2. Run it as a user with read access to the project and nothing else. It needs no SDK, no Xcode, no signing certificates, no keystore, no store credentials and no network.
3. Give the files the release build uses: the manifest in `src/main` (and in `src/release` if there is one), the network security config the manifest names, the module build file of the app (not the root one), the `Info.plist` of the app target and the entitlements file of its release configuration.
4. Keep the files you were given unchanged while you check them; the tool reads them and writes nothing, so the check does not change what a later review sees.
5. Read the notes at the end of the report. They say which values come from build settings or expressions the tool did not work out, when the network config given is not the one the manifest names, when no target SDK was found, and how many findings were left out by the config. Each one is something the report did not see.
6. Treat a refused file as a question. A manifest or plist refused for a DOCTYPE, an entity or broken XML may be damaged, may come from an unusual tool, or may be built to attack whoever opens it.

## Running it in a pipeline safely

1. Run the check as its own step, with read access to the repository and nothing else: no signing keys, no keystore passwords, no store credentials, no cloud credentials. It needs none.
2. Use the tool from a pinned commit. `npx --yes github:INNERLUXES/app-manifest-check#<commit>` runs exactly the code that was reviewed, not whatever the default branch holds on the day.
3. Run it on every pull request that touches a manifest, a network config, a build file, a plist or an entitlements file, and on the release branch before the build that goes to the store.
4. Keep the default `--fail-on error` on pull requests, so a debuggable flag, blanket plain HTTP, a component without `android:exported`, switched-off App Transport Security, a missing usage description or `get-task-allow` stops the change.
5. Use `--fail-on warning` on the release branch, so every warning is either fixed or written down in the config with a reason before the store build.
6. Upload the SARIF log, so findings appear on the pull request next to the line that caused them, and write the Markdown report to the job summary for the reviewer. Keep the exit code as the gate.
7. After the release build, run the check again on the merged manifest from the build output. A library can add permissions and components that the source manifest does not show.
8. Keep a code scanner, a dependency scanner and the OWASP MASTG tests on the built app in the pipeline next to it. This check looks at the settings; those look at the code, the libraries and the running app. None of them replaces the others.

## Using the config without hiding a real problem

- **`minTargetSdk`.** Set it to the level that the Google Play target API level requirements give for your app type, and raise it when the requirement moves. Lowering it below that level only hides the warning; Google Play still applies its own requirement.
- **`allowCleartextDomains`.** Put only hosts that cannot carry real user data: `localhost`, the emulator's `10.0.2.2`, a test server on a private network. Never add a production API, a CDN or a partner host, and avoid wide wildcards; `*.example.test` covers every subdomain, including ones that do not exist yet. A blanket `cleartextTrafficPermitted` on `<base-config>`, `usesCleartextTraffic` and `NSAllowsArbitraryLoads` are reported whatever the list holds.
- **`allowExported`.** Name a component only when other apps are meant to reach it (a share target, an authenticator, an app widget receiver) and it checks every input it gets. Prefer a signature permission for components used only by your own apps; then no entry is needed.
- **`ignore`.** Give every rule a `subject` when you can, so it covers one component, permission, domain or key and not the whole check, and write the reason in `reason`. Review ignore rules with every release; a rule written for a test build has a way of outliving it.

## Making the settings safe

The tool tells you which line is risky; these are the usual fixes, in the order they tend to pay off.

1. **Remove debug settings from release files.** Delete `android:debuggable` from the manifest; the build system sets it for debug builds. Remove `isDebuggable` from the release build type. Remove `get-task-allow` from the release entitlements; Xcode adds it to development builds.
2. **Keep backups away from secrets.** Set `android:allowBackup="false"`, or write `dataExtractionRules` (and `fullBackupContent` for older Android versions) that leave out tokens, keys, databases with personal data and caches. On iOS, keep such files out of Documents and mark them as excluded from backup.
3. **Use HTTPS everywhere.** Remove `usesCleartextTraffic` and `NSAllowsArbitraryLoads`. When one host truly cannot move yet, allow only that host, in a `<domain-config>` or under `NSExceptionDomains`, and plan the end of the exception.
4. **Trust only system certificates in release.** Keep `<certificates src="user"/>` inside `<debug-overrides>`, so a proxy can be used while testing a debug build but not against the store build. Consider certificate pinning for the app's own API, with a backup pin and a plan for rotation.
5. **Close what does not need to be open.** Set `android:exported="false"` on every component other apps do not need, and set `android:exported` on every component with an intent filter. For components that must be open, add a permission (a signature permission for your own apps) and treat every intent as untrusted input.
6. **Ask for less.** Remove permissions the app does not use, replace broad ones with narrower APIs (the photo picker instead of storage permissions, package queries for named apps instead of `QUERY_ALL_PACKAGES`), and request runtime permissions when the feature is used, not at start-up.
7. **Say why.** Give every usage description a plain sentence that tells the user what the access is for, and add the key for every capability the app declares.
8. **Keep the target level current.** Raise `targetSdk` each year, read the behaviour changes of the new level, and test them; newer levels turn on protections the app gets for free.
9. **Shrink and obfuscate the release build.** Turn on `isMinifyEnabled` and `isShrinkResources` in the release build type, with keep rules for code reached by reflection, and keep the mapping file to read crash reports.
10. **Check deep links and URL schemes.** Validate the host, path and every parameter of a URL that opens the app, never accept tokens through a custom scheme, and prefer verified app links and universal links for sign-in callbacks.
11. **Share only what users choose to share.** Turn `UIFileSharingEnabled` on only when users need to exchange files with the app, and keep everything else in Application Support or the keychain.
12. **Set `taskAffinity=""`** on activities that do not need a shared task, and use the default launch mode where possible.

## Sharing a report safely

1. A report shows the package or bundle id, component class names, permission names, domain names from the network config and ATS exceptions, URL schemes, background modes and entitlement names, with file paths as they were given. For a published app most of that is public anyway. For an app that is not released yet it shows its structure, its internal hosts and its plans: share it with the people who can see the code.
2. Values that are not settings are never shown: the tool does not print signing settings, keystore paths, API keys or other values from the build file, and it shows plist values only where they are the subject of a finding (a domain, a scheme, a mode).
3. A Markdown report in a job summary, and SARIF results on a pull request, are visible to everyone who can see the pipeline runs or the pull requests of the repository. Use the text or JSON report when the audience should be smaller.
