# Method

The tool answers one question: before a mobile app goes to the store, is there a setting in its manifest, its plist, its network config, its build file or its entitlements that weakens the security of the release build? It reads those files as data, turns each risky setting into a finding with a severity and a category, and applies the config and the gate. It never runs Gradle, Xcode, `plutil` or a build, and it never fetches anything.

The categories come from the [OWASP Mobile Application Security Verification Standard (MASVS)](https://mas.owasp.org/MASVS/), which groups the security requirements of a mobile app into eight areas: MASVS-STORAGE, MASVS-CRYPTO, MASVS-AUTH, MASVS-NETWORK, MASVS-PLATFORM, MASVS-CODE, MASVS-RESILIENCE and MASVS-PRIVACY. The tests that check each requirement on a running app are in the [OWASP Mobile Application Security Testing Guide (MASTG)](https://mas.owasp.org/MASTG/); many of them start by reading exactly these settings. Where a setting also decides whether the app is accepted in a store, the rule follows the [Apple App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/) or the [Google Play target API level requirements](https://support.google.com/googleplay/android-developer/answer/11926878).

## Why the settings files

A large part of what MASVS asks for is decided by configuration, not by code: whether the app can be debugged, whether its data goes into backups, whether it may talk plain HTTP, which certificates it trusts, which of its components other apps can reach, which permissions it holds, and how the release build is made. On Android those decisions live in `AndroidManifest.xml`, `res/xml/network_security_config.xml` and the module build file; on iOS in `Info.plist` and the `.entitlements` file. They are small files, changed rarely, often for a quick test, and almost never reviewed again before a release. A setting that was right for a debug session (a debuggable flag, a plain-HTTP staging host, trusted user certificates for a proxy) survives into the store build because nothing fails.

Each check below names one such setting. A finding is an **error** when the setting should never reach a store build: it switches off a protection for the whole app (debugging, all plain HTTP, all of App Transport Security), it makes the app fail at install or at its first permission prompt, or it is a debug entitlement. It is a **warning** when the setting is risky but may be chosen on purpose for part of the app, so a person should decide and, where the config allows, write the choice down. It is **info** when the fact belongs in a release review but is not wrong in itself, such as the list of runtime permissions or URL schemes.

## How the files are read

**The XML reader.** Every file except the Gradle file is read by a small XML reader written for this tool. It reads elements, attributes (with prefixes such as `android:`), text, CDATA sections, comments, processing instructions, the five predefined entities and character references. A DOCTYPE or an ENTITY declaration is refused before anything in it is read: a manifest never needs one, and a DOCTYPE is how a file would define entities that expand into large text or point at other files. An entity other than the five predefined ones is refused for the same reason. A file that is not well-formed (a tag that is not closed, a second root element, an attribute given twice) is refused with its line, and the run stops with exit code 2.

**Plists.** `Info.plist` and `.entitlements` files are property lists in XML. Xcode writes one DOCTYPE line at the top of each: the public identifier `-//Apple//DTD PLIST 1.0//EN` with the address of Apple's DTD (older files say `Apple Computer`). That exact line, with no internal subset, is skipped as text; the DTD it names is never opened, and any other DOCTYPE, or that line with anything added, is refused. The reader keeps `dict`, `array`, `string`, `integer`, `real`, `date`, `data`, `true` and `false`, and the line of every key. A key given twice in one dict is refused. A plist in the binary format (it starts with `bplist`) is refused with the command that converts it: `plutil -convert xml1 -o converted.plist Info.plist`.

**Manifests.** The prefix bound to the Android namespace (the `xmlns:` URI that ends in `/apk/res/android`) is taken from the root element, so a manifest that binds it to another prefix is read the same way. Attribute and element names are compared exactly, letter case included, as Android does. Component names that start with `.`, or have no `.` at all, are completed with the package (from the `package` attribute, or the `namespace` or `applicationId` of the build file). A compiled binary manifest, as found inside an APK, is refused with a message that asks for the source manifest.

**The network security config.** `<base-config>`, every `<domain-config>` (nested ones inherit `cleartextTrafficPermitted` and trust anchors from the one around them, as Android applies them), their `<domain>` entries and their `<trust-anchors>` are read. `<debug-overrides>` applies to debug builds only and is not checked. When the manifest names the config as `@xml/<name>`, the file given with `--network-config` should be `<name>.xml`; the names are compared exactly, letter case included, as the Android resource compiler does, on every system, and the file name is taken from the path with either separator. A difference is a note.

**The Gradle file.** `build.gradle` and `build.gradle.kts` are read as text. Comments are blanked first (`//` to the end of the line and `/* ... */`, but not inside quoted strings). Then these patterns are looked for, each at the start of a line, with `=`, a space or `(` between name and value:

- `minSdk`, `minSdkVersion`, `targetSdk`, `targetSdkVersion`, `compileSdk`, `compileSdkVersion` followed by a number of up to three digits. Any other value (a variable, a version catalog entry, a function call) is not worked out and is named in a note; when a name is set more than once (for product flavors), the first is used and a note says so.
- `namespace` and `applicationId` followed by a quoted string.
- Inside the `buildTypes { }` block only, the `release { }` block (also written `getByName("release")`, `named("release")` or `create("release")`), and inside it `isMinifyEnabled` / `minifyEnabled` and `isDebuggable` / `debuggable` set to `true` or `false`.

Blocks are found by matching braces, skipping quoted strings, so a `release` block under `signingConfigs` is not taken for the build type. A value in `targetSdk` of the build file wins over `<uses-sdk>` in the manifest, as it does in a build; a difference is a note.

## The Android checks

| Id | Severity | MASVS | Rule and why it matters |
| --- | --- | --- | --- |
| `debuggable` | error | MASVS-RESILIENCE | `android:debuggable="true"` on `<application>`, or a release build type that sets `isDebuggable` / `debuggable` to true. A debuggable app accepts a debugger from anyone with the device and a cable, and through `run-as` its private files can be read. The build system already sets the flag for debug builds, so it should never be written in the manifest. MASTG tests for debugging start from this flag |
| `allow-backup` | warning | MASVS-STORAGE | `android:allowBackup` is `true` or not set (it defaults to true), and neither `android:dataExtractionRules` nor `android:fullBackupContent` limits what is backed up. The whole private data folder, tokens and databases included, then goes into cloud backups and device-to-device transfers, out of the app's control. MASVS-STORAGE asks that sensitive data is kept out of backups |
| `cleartext-traffic` | error / warning | MASVS-NETWORK | An error for `android:usesCleartextTraffic="true"` on `<application>` or `<base-config cleartextTrafficPermitted="true">`: plain HTTP is allowed to every host. A warning for a `<domain-config>` that allows plain HTTP for listed domains, unless every domain is in `allowCleartextDomains`. MASVS-NETWORK asks for secure transport for all traffic |
| `user-certs-trusted` | warning | MASVS-NETWORK | `<certificates src="user"/>` in the trust anchors of `<base-config>` or a `<domain-config>`. Certificates a user (or anyone with the unlocked device, or a device policy) installs are then trusted by the release build, so a proxy with its own certificate can read and change the traffic. Kept inside `<debug-overrides>`, it applies to debug builds only and is not reported |
| `exported-without-permission` | warning / info | MASVS-PLATFORM | An `<activity>`, `<activity-alias>`, `<service>`, `<receiver>` or `<provider>` that other apps can reach: `android:exported="true"`, or no `android:exported` and an intent filter (exported by default before Android 12; providers are never counted as exported by an intent filter). It is reported when the component has no `android:permission` (for a provider: no `android:permission` and not both `readPermission` and `writePermission`) and is not in `allowExported`. The launcher activity has to be exported and is info. MASVS-PLATFORM asks that the app's IPC is protected; an open service, receiver or provider is the usual way another app on the device reaches into one |
| `missing-exported` | error | MASVS-PLATFORM | An activity, activity alias, service or receiver with an intent filter and no `android:exported`. Apps that target Android 12 (API level 31) or higher must set it, or they cannot be installed; on older targets the component is exported without anyone having said so |
| `dangerous-permissions` | info | MASVS-PRIVACY | The runtime permissions the app asks for (listed below), in one finding. Each one needs a prompt, a reason in the privacy policy and an entry in Play's Data safety form; MASVS-PRIVACY asks that the app collects only what it needs |
| `broad-permissions` | warning | MASVS-PRIVACY | One finding for each permission from the broad list below. They reach far beyond the app (all files, all installed apps, installing other apps, drawing over other apps, SMS and call logs, location in the background), and Google Play allows most of them only for apps whose core feature needs them, after a declaration |
| `target-sdk` | warning | MASVS-CODE | `targetSdk` (from the build file, or `<uses-sdk>`) is below the lowest level set with `--min-target-sdk` or `minTargetSdk` in the config. Without either, the lowest level is 35. An app that targets an old level runs with the old behaviour of the platform and misses protections that newer levels turn on; the Google Play target API level requirements page sets the level that new apps and updates must reach, and it changes over time, so set the option to the level that applies to your app. When no `targetSdk` is found, a note says so |
| `minify-off` | info | MASVS-RESILIENCE | With `--gradle`: the release build type sets `isMinifyEnabled` to false, does not set it (it is false by default), or there is no release build type. The release build then keeps every class, method and field name, which makes it easier to read and to change. Shrinking is not a security boundary, which is why it is info; MASVS-RESILIENCE lists obfuscation as one of the layers that make reverse engineering slower |
| `task-hijacking` | info | MASVS-PLATFORM | An `<activity>` with `android:launchMode="singleTask"` and a non-empty `android:taskAffinity` (its own, or the application's). Another app that declares the same affinity can take over the task and show its own screen in place of the app's, a pattern the MASTG describes as task hijacking. `taskAffinity=""` is the usual fix and is not reported |

**Runtime (dangerous) permissions the tool knows**, all in `android.permission.` unless written in full: `READ_CALENDAR`, `WRITE_CALENDAR`, `CAMERA`, `READ_CONTACTS`, `WRITE_CONTACTS`, `GET_ACCOUNTS`, `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION`, `ACCESS_BACKGROUND_LOCATION`, `ACCESS_MEDIA_LOCATION`, `RECORD_AUDIO`, `READ_PHONE_STATE`, `READ_PHONE_NUMBERS`, `CALL_PHONE`, `ANSWER_PHONE_CALLS`, `READ_CALL_LOG`, `WRITE_CALL_LOG`, `USE_SIP`, `ACCEPT_HANDOVER`, `BODY_SENSORS`, `BODY_SENSORS_BACKGROUND`, `ACTIVITY_RECOGNITION`, `SEND_SMS`, `RECEIVE_SMS`, `READ_SMS`, `RECEIVE_WAP_PUSH`, `RECEIVE_MMS`, `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`, `READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO`, `READ_MEDIA_AUDIO`, `READ_MEDIA_VISUAL_USER_SELECTED`, `BLUETOOTH_SCAN`, `BLUETOOTH_CONNECT`, `BLUETOOTH_ADVERTISE`, `NEARBY_WIFI_DEVICES`, `UWB_RANGING`, `POST_NOTIFICATIONS`, and `com.android.voicemail.permission.ADD_VOICEMAIL`. A permission that is also on the broad list is reported there, not here.

**Broad permissions**, all in `android.permission.`: `MANAGE_EXTERNAL_STORAGE`, `QUERY_ALL_PACKAGES`, `REQUEST_INSTALL_PACKAGES`, `SYSTEM_ALERT_WINDOW`, `READ_SMS`, `SEND_SMS`, `RECEIVE_SMS`, `READ_CALL_LOG`, `WRITE_CALL_LOG`, `ACCESS_BACKGROUND_LOCATION`, `WRITE_SETTINGS` and `PACKAGE_USAGE_STATS`.

Both lists are the tool's own choice, kept small on purpose: they name the permissions a reviewer should see, not every permission the platform defines. A permission the lists do not know is not reported.

## The iOS checks

| Id | Severity | MASVS | Rule and why it matters |
| --- | --- | --- | --- |
| `ats-arbitrary-loads` | error / warning | MASVS-NETWORK | An error when `NSAppTransportSecurity` has `NSAllowsArbitraryLoads` set to true: App Transport Security is off for the whole app, so connections may use plain HTTP or weak TLS. A warning when `NSAllowsArbitraryLoadsInWebContent` or `NSAllowsArbitraryLoadsForMedia` is true, which turns it off for web views or for media only. The App Store Review Guidelines expect a reason for turning it off |
| `ats-insecure-exception` | warning | MASVS-NETWORK | A domain under `NSExceptionDomains` with `NSExceptionAllowsInsecureHTTPLoads` or `NSThirdPartyExceptionAllowsInsecureHTTPLoads` set to true (unless the domain is in `allowCleartextDomains`), or with `NSExceptionMinimumTLSVersion` or `NSThirdPartyExceptionMinimumTLSVersion` set to `TLSv1.0` or `TLSv1.1`. An exception for one host is the right way to deal with a host that cannot move yet, which is why it is a warning; it should still have an end |
| `missing-usage-description` | error / warning | MASVS-PRIVACY | An error when the app declares something that needs a usage description and the key is missing from `Info.plist` (the map is below): iOS stops the app the moment it asks for access, and the App Store Review Guidelines ask that every request for personal data says why. A warning when any key ending in `UsageDescription` holds an empty string, which gives the user a prompt with no reason |
| `file-sharing` | info | MASVS-STORAGE | `UIFileSharingEnabled` or `LSSupportsOpeningDocumentsInPlace` is true. The files in the app's Documents folder can then be seen and copied through the Files app or a computer, so tokens, databases and caches must live elsewhere |
| `background-modes` | info | MASVS-PRIVACY | The modes in `UIBackgroundModes`. A mode such as `location` keeps the app collecting data when it is not on screen; App Review checks that each declared mode is used |
| `url-schemes` | info | MASVS-PLATFORM | The schemes in `CFBundleURLTypes` / `CFBundleURLSchemes`. Any app can register the same scheme, and any web page can open it, so every URL that opens the app is untrusted input. MASVS-PLATFORM asks that the app checks the data it receives this way |
| `debug-entitlement` | error | MASVS-RESILIENCE | `get-task-allow` is true in the entitlements file given with `--entitlements`. A build signed with it lets a debugger attach; Xcode adds it to development builds by itself, so it has no place in a file used for the release |

**The map of capabilities to usage descriptions.** It is kept small and covers what a settings file declares outright:

| Declared in | Value | Needs |
| --- | --- | --- |
| `UIRequiredDeviceCapabilities` | `still-camera`, `video-camera`, `auto-focus-camera`, `front-facing-camera`, `camera-flash` | `NSCameraUsageDescription` |
| `UIRequiredDeviceCapabilities` | `microphone` | `NSMicrophoneUsageDescription` |
| `UIRequiredDeviceCapabilities` | `location-services`, `gps` | `NSLocationWhenInUseUsageDescription` |
| `UIRequiredDeviceCapabilities` | `healthkit` | `NSHealthShareUsageDescription` |
| `UIRequiredDeviceCapabilities` | `nfc` | `NFCReaderUsageDescription` |
| `UIBackgroundModes` | `location` | `NSLocationWhenInUseUsageDescription` and `NSLocationAlwaysAndWhenInUseUsageDescription` |
| `UIBackgroundModes` | `bluetooth-central`, `bluetooth-peripheral` | `NSBluetoothAlwaysUsageDescription` |
| entitlements | `com.apple.developer.healthkit` | `NSHealthShareUsageDescription` |
| entitlements | `com.apple.developer.homekit` | `NSHomeKitUsageDescription` |
| entitlements | `com.apple.developer.nfc.readersession.formats` | `NFCReaderUsageDescription` |
| entitlements | `com.apple.developer.siri` | `NSSiriUsageDescription` |

`UIRequiredDeviceCapabilities` may be an array of names or a dict of names set to true or false; both are read, and a name set to false does not count. Each missing key is reported once, at the first place that needs it. Most uses of the camera, the photo library, contacts or the microphone are decided in code, not in a settings file; the tool cannot see those, and docs/limits.md says so.

## Categories without a check

MASVS-CRYPTO and MASVS-AUTH have no check here. Which algorithms and keys an app uses, and how it signs users in, are decided in code and on the server, not in the files this tool reads. The MASTG tests for those categories need the app itself.

## The config and the gate

The config file can raise or lower the lowest target SDK, allow plain HTTP for named hosts, allow named components to be exported, and leave out findings by check and subject. docs/secure-defaults.md says how to use each without hiding a real problem. Every key is checked, and an unknown key or an ignore rule for a check that does not exist stops the run, so a typo cannot turn a check off. The report says how many findings were left out.

`--fail-on error`, the default, makes the run exit with `1` when any error is found. `--fail-on warning` also fails on any warning, which suits a release branch. Info never fails a run.

## The report

Each report shows, for each platform, the files read and the facts found in them (package or bundle id, SDK levels, components, permissions, usage descriptions, URL schemes, background modes, entitlements) with the number of findings by severity; then the findings ordered by severity, platform, check, file and line; then the notes; then the gate. Every finding has its id, severity, MASVS category, file and line, the subject it is about, a message and a fix. Every text taken from the input has control characters removed before it reaches any format.

The method has no randomness and no network access: the same files always give the same report, and any change in the report comes from a change in the files.
