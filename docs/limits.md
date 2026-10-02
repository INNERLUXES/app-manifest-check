# Limits

## Source files, not the built app

- **The source manifest is not the merged manifest.** An Android build merges the app's `AndroidManifest.xml` with the manifests of every library it uses, of each build type and flavor, and with values from the build file (such as `minSdk`, `targetSdk` and `applicationId`). A library can add a permission, an exported service or a receiver that the source manifest does not show, and a flavor can change a setting. The tool reads the file it is given. Run it on the merged manifest of the release build as well (`app/build/intermediates/merged_manifests/release/.../AndroidManifest.xml` after a build, or the manifest view of the IDE), and read the permission list of the store listing before a release.
- **Plist variables are not expanded.** `Info.plist` files hold Xcode build settings such as `$(PRODUCT_BUNDLE_IDENTIFIER)` or `$(MARKETING_VERSION)`, which Xcode fills in at build time. They are shown as written, and a note says how many values use them. A key whose whole value comes from a build setting is read as a non-empty string. Keys that Xcode writes into the built `Info.plist` from the project file (`INFOPLIST_KEY_...` build settings) are not seen; check the `Info.plist` inside the built app when the project uses them.
- **Entitlements are those of the file.** The entitlements that end up in a signed app also come from the provisioning profile and the signing settings. The tool checks the file given with `--entitlements`; pass the file the release configuration uses.
- **No binary analysis.** Nothing in the code of the app is read: not Kotlin, Java, Swift or Objective-C, not native libraries, not an APK, AAB or IPA. The tool cannot see whether the app stores secrets in plain files, pins certificates, checks the input of an exported component or a URL scheme, logs personal data, or asks for a permission at the right time. A clean report means the settings files hold none of the listed risks, not that the app is secure. Pair it with the tests of the OWASP MASTG on the built app, and with static and dynamic analysis of the code.

## Gradle is read by pattern, not evaluated

- The build file is text to the tool. Values set from variables, `gradle.properties`, version catalogs, `ext` blocks, functions or other files are not worked out; they are named in a note.
- Settings must start a line: `targetSdk = 35` is found, `defaultConfig { targetSdk = 35 }` written on one line is not.
- Only the `release` build type is read. Custom release-like build types (`staging`, `production`) and flavors are not checked for `debuggable` or `minify-off`; settings in convention plugins, `buildSrc` or a shared `build-logic` module are not seen.
- When a setting appears more than once (for flavors), the first one is used, and a note says so.
- The legacy `proguard` and the R8 options other than `isMinifyEnabled` are not read; `isShrinkResources` is mentioned in the fix but not checked.

## Android

- Only the settings listed in docs/method.md are checked. Intent filters are counted, not judged: the tool does not decide whether a deep link is verified (`android:autoVerify`) or whether the data an activity accepts is checked.
- `android:exported`, `android:debuggable` and other attributes set from a resource (`@bool/...`) are not resolved; an `android:exported` value from a resource is named in a note, and the component is treated as not exported.
- The default of `android:exported` changed over Android versions. The tool treats a component with an intent filter and no `android:exported` as exported, as older versions do, and reports `missing-exported`; providers are judged only by their own `android:exported`.
- The runtime and broad permission lists are the tool's own, listed in docs/method.md. A permission the lists do not know, a custom permission and its protection level, and `<permission>` declarations are not checked.
- The network security config is checked only when it is given with `--network-config`. Pinning (`<pin-set>`), certificate files in `res/raw` and the `overridePins` attribute are not checked.
- `target-sdk` compares a number. The lowest level Google Play requires changes over time and differs for new apps, updates, Wear OS, TV and Automotive; the default of 35 is a starting point, not a statement of the current rule. Set `--min-target-sdk` or `minTargetSdk` to the level that applies to your app.

## iOS

- Only XML property lists are read. A binary plist is refused with the `plutil` command that converts it. JSON plists and the old OpenStep format are not read.
- The map of capabilities to usage descriptions is small (docs/method.md lists it). Most access to the camera, the photo library, contacts, the microphone, Bluetooth or tracking is decided in code; a missing usage description for such access is not found here, and App Review or the first run on a device finds it instead.
- App Transport Security is checked as written. Exceptions that iOS ignores in some combinations (for example `NSAllowsArbitraryLoads` next to `NSAllowsArbitraryLoadsInWebContent` on recent versions) are still reported as written, because the older versions the app supports may honour them.
- Privacy manifests (`PrivacyInfo.xcprivacy`), tracking domains and required reason APIs are not read.

## Size

- A file over 10 MB is not read, and the run stops with exit code 2.
- A file with XML elements nested more than 64 deep, or with more than 200,000 elements, is refused.
- Text shown in a report is cut to a fixed length: 300 characters for a name, a subject or a path, 1,200 for a message or a fix, 600 for a note.

Every limit is reported, as an error, a note or a stopped run, so a cut is never silent.
