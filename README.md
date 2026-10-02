# app-manifest-check

Checks the settings files of a mobile app before a store release for risky configuration. For Android it reads the source `AndroidManifest.xml`, the network security config and the module build file (`build.gradle` or `build.gradle.kts`); for iOS it reads `Info.plist` and the `.entitlements` file. It reports debuggable builds, app data in backups, plain HTTP and switched-off App Transport Security, user certificates trusted in release, components other apps can start, broad and runtime permissions, an old target SDK, release builds without code shrinking, missing or empty usage descriptions, shared document folders, background modes, custom URL schemes and debug entitlements. Every finding carries the category of the [OWASP Mobile Application Security Verification Standard (MASVS)](https://mas.owasp.org/MASVS/) it belongs to.

Most store-release security slips are one setting in a manifest or a plist. A `debuggable="true"` left from a test session, `usesCleartextTraffic` added to reach a staging server, `NSAllowsArbitraryLoads` switched on to make one image load, a service marked `exported="true"` so a partner app could call it, an entitlements file that still holds `get-task-allow`. None of them breaks a build or a test, and each one is a line in a file that nobody reads again before the release. This tool reads those files and lists every such line, with the file, the line number and what to do, in a second, so the check can run on every pull request and before every release.

- Every finding has an id, a severity (error, warning, info), a MASVS category, the file and the line, a plain message and a fix.
- It reads XML with a small, strict reader of its own that refuses a DOCTYPE or an entity declaration, so a manifest cannot make it expand entities or read another file. The one public DOCTYPE line Xcode writes into every plist is skipped as text and never fetched.
- Binary property lists and compiled binary manifests are refused with a message that says what to give instead.
- Reports as text, Markdown, JSON, CSV and SARIF, so findings can show up in GitHub code scanning.
- It reads files only. It never runs Gradle, Xcode, `plutil` or a build, builds nothing, fetches nothing and opens no network connection.
- Plain JavaScript, no dependencies; the same files always give the same report.

```
npm test
```

```
ℹ tests 54
ℹ pass 54
ℹ fail 0
```

## Quick start

Requires Node 22 or newer. There is nothing to install.

```
git clone https://github.com/INNERLUXES/app-manifest-check.git
cd app-manifest-check
node bin/app-manifest-check.js --android examples/android/AndroidManifest.xml --ios examples/ios/Info.plist
```

Or without a clone, in the folder of your app:

```
npx --yes github:INNERLUXES/app-manifest-check --android app/src/main/AndroidManifest.xml --ios ios/Orders/Info.plist
```

`examples/` holds the settings files of a made-up "orders" app (`com.example.orders`). The Android side is risky on purpose: the manifest is debuggable, allows plain HTTP, exports a sync service with no permission and asks for `REQUEST_INSTALL_PACKAGES`; the network security config allows plain HTTP to one domain and trusts user certificates; the build file targets an old SDK and turns code shrinking off. The iOS side switches App Transport Security off, requires a camera without a camera usage description, and its entitlements file holds `get-task-allow`. `examples/android/clean/` and `examples/ios/clean/` hold the same app with those settings fixed. All names are made up.

## Usage

```
node bin/app-manifest-check.js \
  --android examples/android/AndroidManifest.xml \
  --network-config examples/android/network_security_config.xml \
  --gradle examples/android/build.gradle.kts \
  --ios examples/ios/Info.plist \
  --entitlements examples/ios/Orders.entitlements
```

```
app-manifest-check: android, ios
android: examples/android/AndroidManifest.xml, examples/android/network_security_config.xml, examples/android/build.gradle.kts
  package com.example.orders; minSdk 24; targetSdk 33; compileSdk 35; 5 components (2 exported); 5 permissions
  findings: 2 error, 6 warning, 4 info
ios: examples/ios/Info.plist, examples/ios/Orders.entitlements
  bundle id $(PRODUCT_BUNDLE_IDENTIFIER); 1 usage description; 1 URL scheme; 1 background mode; 3 entitlements
  findings: 3 error, 1 warning, 3 info
findings: 5 error, 7 warning, 7 info

ERROR    debuggable (MASVS-RESILIENCE)  examples/android/AndroidManifest.xml:13
         android:debuggable="true" on <application>: any app on the device, and anyone with a USB cable, can attach a debugger and read its memory
         fix: Remove android:debuggable from the manifest; the build system sets it for debug builds only

ERROR    cleartext-traffic (MASVS-NETWORK)  examples/android/AndroidManifest.xml:13
         android:usesCleartextTraffic="true" on <application>: the app may send and receive plain HTTP, which anyone on the network path can read and change
         fix: Remove android:usesCleartextTraffic and use HTTPS; if one host must stay on HTTP, allow only that domain in the network security config

ERROR    ats-arbitrary-loads (MASVS-NETWORK)  examples/ios/Info.plist:18
         NSAllowsArbitraryLoads is true: App Transport Security is off, so the app may load anything over plain HTTP or weak TLS, and App Review asks for a reason
         fix: Remove NSAllowsArbitraryLoads; if one host cannot use HTTPS yet, add an exception for that domain only under NSExceptionDomains

ERROR    missing-usage-description (MASVS-PRIVACY)  examples/ios/Info.plist:31
         the required device capability still-camera needs NSCameraUsageDescription in Info.plist, and it is missing: the app is stopped the moment it asks for access, and App Review rejects it
         fix: Add NSCameraUsageDescription with a sentence that says what the app uses the access for

ERROR    debug-entitlement (MASVS-RESILIENCE)  examples/ios/Orders.entitlements:12
         get-task-allow is true: a build signed with this file lets a debugger attach to the app; App Store builds must not have it
         fix: Remove get-task-allow from the entitlements file; Xcode adds it to development builds by itself

WARNING  allow-backup (MASVS-STORAGE)  examples/android/AndroidManifest.xml:13
         android:allowBackup="true", with no dataExtractionRules or fullBackupContent: the whole app data folder, tokens and databases included, goes into device backups and device-to-device transfers
         fix: Set android:allowBackup="false", or add android:dataExtractionRules (and android:fullBackupContent for older versions) that leave out secrets and personal data

WARNING  cleartext-traffic (MASVS-NETWORK)  examples/android/network_security_config.xml:10
         plain HTTP is allowed for legacy-api.example.test
         fix: Move these hosts to HTTPS; if a host must stay on HTTP (a local test server), add it to allowCleartextDomains in the config so the choice is written down

WARNING  user-certs-trusted (MASVS-NETWORK)  examples/android/network_security_config.xml:4
         <certificates src="user"/> in <base-config>: certificates the user installs are trusted for release builds, so a proxy with its own certificate can read the traffic
         fix: Keep src="user" only inside <debug-overrides>, which applies to debug builds alone

WARNING  exported-without-permission (MASVS-PLATFORM)  examples/android/AndroidManifest.xml:38
         <service> com.example.orders.sync.OrderSyncService is exported without android:permission: any app on the device can start or bind to it
         fix: Set android:exported="false" when only this app uses it; otherwise protect it with android:permission (a signature permission for your own apps), and add it to allowExported in the config when it is meant to be open

WARNING  broad-permissions (MASVS-PRIVACY)  examples/android/AndroidManifest.xml:11
         android.permission.REQUEST_INSTALL_PACKAGES reaches far beyond the app, and Google Play allows it only for apps whose core feature needs it
         fix: Remove it, or use the narrower API (the photo picker, a package query for named apps, the storage access framework) and declare the use in the Play Console

WARNING  target-sdk (MASVS-CODE)  examples/android/build.gradle.kts:14
         targetSdk is 33, below 35: the app runs with the older behaviour of the platform, without newer protections, and Google Play sets a lowest target level for new apps and updates
         fix: Raise targetSdk to 35 or higher and test the behaviour changes of each level

WARNING  ats-insecure-exception (MASVS-NETWORK)  examples/ios/Info.plist:26
         NSExceptionAllowsInsecureHTTPLoads is true for legacy-api.example.test: plain HTTP is allowed to this host
         fix: Serve this host over HTTPS and remove the exception; if it must stay (a local test server), add it to allowCleartextDomains in the config so the choice is written down

INFO     exported-without-permission (MASVS-PLATFORM)  examples/android/AndroidManifest.xml:23
         <activity> com.example.orders.MainActivity is the launcher activity and is exported, as it must be
         fix: Make sure it reads the intent that starts it as input from any app

INFO     dangerous-permissions (MASVS-PRIVACY)  examples/android/AndroidManifest.xml:8
         3 runtime permissions: CAMERA, ACCESS_FINE_LOCATION, POST_NOTIFICATIONS
         fix: Check that each one is needed, asked for when the feature is used, and described in the privacy policy and the Data safety form

INFO     minify-off (MASVS-RESILIENCE)  examples/android/build.gradle.kts:28
         the release build type sets isMinifyEnabled to false: the release build keeps every class and method name, which makes it easier to read and change
         fix: Set isMinifyEnabled = true (minifyEnabled true in Groovy) and isShrinkResources = true in the release build type, with keep rules for code reached by reflection

INFO     task-hijacking (MASVS-PLATFORM)  examples/android/AndroidManifest.xml:32
         <activity> com.example.orders.OrderDetailActivity has launchMode singleTask and taskAffinity com.example.orders.detail: another app can claim the same task and show its own screen in its place (task hijacking)
         fix: Use the default launchMode where possible, and set android:taskAffinity="" on the activity or the application

INFO     file-sharing (MASVS-STORAGE)  examples/ios/Info.plist:53
         UIFileSharingEnabled is true: the files in the app's Documents folder can be seen and copied through the Files app or a computer
         fix: Keep tokens, databases and caches out of Documents (use Application Support or the keychain), or turn the key off

INFO     background-modes (MASVS-PRIVACY)  examples/ios/Info.plist:38
         background modes: remote-notification
         fix: Keep only the modes the app uses; App Review checks each one, and a mode such as location keeps the app collecting data when it is not on screen

INFO     url-schemes (MASVS-PLATFORM)  examples/ios/Info.plist:42
         custom URL schemes: orders; any app can register the same scheme and any web page can open it
         fix: Treat every URL that opens the app as untrusted input: check the host, path and parameters, and never put tokens in it; prefer universal links for sign-in callbacks

note: examples/ios/Info.plist and examples/ios/Orders.entitlements: 1 value uses Xcode build settings such as $(PRODUCT_BUNDLE_IDENTIFIER), which are not expanded

GATE: FAIL - 5 errors
```

The exit code is `1`: five findings are errors, and errors fail the run by default. Each one is a setting that should not reach a store build. The warnings are risky choices to make on purpose or to undo, and the info findings are facts a reviewer should see before the release: which runtime permissions the app asks for, which URL schemes it opens, which background modes it declares.

The fixed app passes, also with `--fail-on warning`; only the launcher activity is listed, as info, because it has to be exported:

```
node bin/app-manifest-check.js --android examples/android/clean/AndroidManifest.xml --ios examples/ios/clean/Info.plist --fail-on warning
```

```
app-manifest-check: android, ios
android: examples/android/clean/AndroidManifest.xml
  package com.example.orders; minSdk 26; targetSdk 35; compileSdk -; 3 components (1 exported); 1 permission
  findings: 0 error, 0 warning, 1 info
ios: examples/ios/clean/Info.plist
  bundle id com.example.orders; 2 usage descriptions; 0 URL schemes; 0 background modes
  findings: 0 error, 0 warning, 0 info
findings: 0 error, 0 warning, 1 info

INFO     exported-without-permission (MASVS-PLATFORM)  examples/android/clean/AndroidManifest.xml:17
         <activity> com.example.orders.MainActivity is the launcher activity and is exported, as it must be
         fix: Make sure it reads the intent that starts it as input from any app

GATE: PASS (--fail-on warning)
```

```
app-manifest-check [--android <AndroidManifest.xml>] [--ios <Info.plist>] [options]
```

```
--android <file>         the source AndroidManifest.xml (src/main/AndroidManifest.xml)
--network-config <file>  the network security config (res/xml/network_security_config.xml)
--gradle <file>          the module build file (build.gradle or build.gradle.kts), read as text
--ios <file>             the Info.plist, in XML format
--entitlements <file>    the .entitlements file used for the release build
--config <file>          ignore rules, allowed cleartext domains, allowed exported components and the
                         lowest target SDK (JSON)
--min-target-sdk <n>     the lowest targetSdk that passes (default: 35, or minTargetSdk from the config)
--format <name>          text, markdown, json, csv or sarif (default: text)
--fail-on <level>        exit with 1 when a finding is at this level or above: error or warning
                         (default: error)
--help                   show the usage
--version                show the version
```

Give `--android`, `--ios` or both. `--network-config` and `--gradle` go with `--android`, and `--entitlements` with `--ios`. Paths in the report are shown as they were given.

An Info.plist kept in the binary format is refused with exit code `2` and the command that converts it: `plutil -convert xml1 -o converted.plist Info.plist`. A compiled manifest taken from an APK is refused too; give the source manifest from `src/main`.

## Checks

| Id | Platform | Severity | MASVS | What it reports |
| --- | --- | --- | --- | --- |
| `debuggable` | Android | error | MASVS-RESILIENCE | `android:debuggable="true"` in the manifest, or a release build type that sets `isDebuggable` / `debuggable` to true |
| `allow-backup` | Android | warning | MASVS-STORAGE | `android:allowBackup` is true or not set, with no `dataExtractionRules` or `fullBackupContent` rules |
| `cleartext-traffic` | Android | error / warning | MASVS-NETWORK | `usesCleartextTraffic="true"` or a `base-config` with `cleartextTrafficPermitted="true"` (error); a `domain-config` that allows plain HTTP for listed domains (warning) |
| `user-certs-trusted` | Android | warning | MASVS-NETWORK | `<certificates src="user"/>` in `base-config` or a `domain-config`, outside `debug-overrides` |
| `exported-without-permission` | Android | warning / info | MASVS-PLATFORM | An activity, service, receiver or provider exported (by `exported="true"` or by an intent filter) with no `android:permission`; info for the launcher activity |
| `missing-exported` | Android | error | MASVS-PLATFORM | An activity, service or receiver with an intent filter and no `android:exported`, which Android 12 and later require |
| `dangerous-permissions` | Android | info | MASVS-PRIVACY | The runtime (dangerous) permissions the app asks for, listed once |
| `broad-permissions` | Android | warning | MASVS-PRIVACY | `MANAGE_EXTERNAL_STORAGE`, `QUERY_ALL_PACKAGES`, `REQUEST_INSTALL_PACKAGES`, `SYSTEM_ALERT_WINDOW`, `READ_SMS`, `ACCESS_BACKGROUND_LOCATION` and a few more, one finding each |
| `target-sdk` | Android | warning | MASVS-CODE | `targetSdk` below the lowest level set with `--min-target-sdk` or the config (default 35) |
| `minify-off` | Android | info | MASVS-RESILIENCE | With `--gradle`: the release build type does not turn on code shrinking |
| `task-hijacking` | Android | info | MASVS-PLATFORM | An activity with `launchMode="singleTask"` and a `taskAffinity` |
| `ats-arbitrary-loads` | iOS | error / warning | MASVS-NETWORK | `NSAllowsArbitraryLoads` is true (error); `NSAllowsArbitraryLoadsInWebContent` or `NSAllowsArbitraryLoadsForMedia` is true (warning) |
| `ats-insecure-exception` | iOS | warning | MASVS-NETWORK | An exception domain with `NSExceptionAllowsInsecureHTTPLoads`, or a minimum TLS version below 1.2 |
| `missing-usage-description` | iOS | error / warning | MASVS-PRIVACY | A capability, background mode or entitlement that needs an `NS...UsageDescription` that is missing (error), or a usage description that is empty (warning) |
| `file-sharing` | iOS | info | MASVS-STORAGE | `UIFileSharingEnabled` or `LSSupportsOpeningDocumentsInPlace` is true |
| `background-modes` | iOS | info | MASVS-PRIVACY | The background modes in `UIBackgroundModes` |
| `url-schemes` | iOS | info | MASVS-PLATFORM | The custom URL schemes in `CFBundleURLTypes`, with a reminder to check their input |
| `debug-entitlement` | iOS | error | MASVS-RESILIENCE | `get-task-allow` is true in the entitlements file |

[docs/method.md](docs/method.md) gives each check, its MASVS category, the exact rule, and why it matters, with the permission lists and the map of capabilities to usage descriptions.

## Config file

```json
{
  "minTargetSdk": 35,
  "allowCleartextDomains": ["localhost", "10.0.2.2", "*.dev.example.test"],
  "allowExported": ["com.example.orders.ShareActivity"],
  "ignore": [
    { "check": "dangerous-permissions", "reason": "reviewed with the privacy policy" },
    { "check": "url-schemes", "subject": "orders*", "reason": "the handler checks every parameter" }
  ]
}
```

- `minTargetSdk`: the lowest `targetSdk` that passes `target-sdk`. `--min-target-sdk` wins over it.
- `allowCleartextDomains`: hosts that may use plain HTTP, such as a local test server. They are left out of `cleartext-traffic` warnings for a `domain-config` and of the insecure-HTTP part of `ats-insecure-exception`. Names are compared ignoring case; `*.dev.example.test` covers every subdomain of `dev.example.test`, but not `dev.example.test` itself. A blanket `cleartextTrafficPermitted` or `NSAllowsArbitraryLoads` is still reported.
- `allowExported`: components that are meant to be open to other apps, by full class name or as written in the manifest. They are left out of `exported-without-permission`.
- `ignore`: findings to leave out, by `check`, and optionally by `subject` (the component, permission, domain or key a finding names, with `*` for any text). `reason` is for the reader and is not used. The report says how many findings were left out.

Every key is checked. An unknown key, or an ignore rule for a check that does not exist, stops the run with exit code `2`, so a typo cannot quietly turn a check off.

## Formats

- `text`: for a terminal: a summary per platform, then the findings, errors first, each with its category, file and line, message and fix.
- `markdown`: the same for a pull request comment or the job summary. Pipes, line breaks and angle brackets from the input are escaped, so a component name cannot break a table and `<application>` is shown, not swallowed as HTML.
- `json`: the whole report: each platform with its files and facts, every finding with id, severity, category, platform, file, line, subject, message and fix, the notes and the gate.
- `csv`: one row per finding, quoted as RFC 4180 says. A cell that starts with `=`, `+`, `-` or `@` gets a leading `'`, so a spreadsheet does not run it as a formula.
- `sarif`: a SARIF 2.1.0 log. Each result points at the file and line of the setting, with the MASVS category in its properties and in the tags of its rule.

To see the findings in GitHub code scanning, write the SARIF log and upload it:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  - uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0
    with:
      node-version: 22
  - name: Check the app settings
    run: npx --yes github:INNERLUXES/app-manifest-check --android app/src/main/AndroidManifest.xml --network-config app/src/main/res/xml/network_security_config.xml --gradle app/build.gradle.kts --ios ios/Orders/Info.plist --entitlements ios/Orders/Orders.entitlements --format sarif > app-manifest-check.sarif
  - uses: github/codeql-action/upload-sarif@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2 # v4.38.2
    if: always()
    with:
      sarif_file: app-manifest-check.sarif
      category: app-manifest-check
```

The step fails the job on an error; `if: always()` still uploads the log so the findings appear on the pull request. It needs no Android SDK, no Xcode, no macOS runner and no secrets.

## Exit codes

`0` no finding at the `--fail-on` level, `1` at least one such finding (by default: an error), `2` a usage or input error (a missing option or file, a file that is not well-formed XML or holds a DOCTYPE, a binary plist or compiled manifest, a file over 10 MB, a config with an unknown key or a bad value).

## Limits

The tool reads the settings as they are written in the source files. The manifest of a built app is merged from the app manifest, the manifests of every library, build types and flavors, so a library can add a permission or an exported component that the source manifest does not show; check the merged manifest of the release build too. Xcode build settings such as `$(PRODUCT_BUNDLE_IDENTIFIER)` are not expanded, and a note says how many values use them. The Gradle file is read by simple patterns, not evaluated. Nothing in the code of the app is looked at, so this is a check of the settings, not a security test of the app: pair it with the tests of the [OWASP MASTG](https://mas.owasp.org/MASTG/). [docs/limits.md](docs/limits.md) lists these, with the size limits.

## Background

- How mobile apps are built and kept safe to release, with checks like this one in the pipeline: [mobile application development](https://innerluxes.dev/application/mobile/development).

## License

MIT
