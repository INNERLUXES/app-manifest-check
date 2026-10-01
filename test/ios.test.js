import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FINDINGS, ENTITLEMENT_USAGE, CAPABILITY_USAGE, BACKGROUND_USAGE } from '../src/index.js';
import { check, plist, ids, find } from './helpers.js';

const I = 'Info.plist';
const E = 'Release.entitlements';
const ios = (info, entitlements = null, options) => check(entitlements === null ? { [I]: plist(info) } : { [I]: plist(info), [E]: plist(entitlements) }, entitlements === null ? { ios: I } : { ios: I, entitlements: E }, options);

test('a plain Info.plist has no findings', async () => {
  const r = await ios('<key>CFBundleIdentifier</key>\n<string>com.example.orders</string>');
  assert.deepEqual(ids(r), []);
  assert.equal(r.platforms[0].bundleId, 'com.example.orders');
  assert.equal(r.gate.pass, true);
});

test('ats-arbitrary-loads: NSAllowsArbitraryLoads is an error; web content and media are warnings', async () => {
  const r = await ios([
    '<key>NSAppTransportSecurity</key>',
    '<dict>',
    '<key>NSAllowsArbitraryLoads</key><true/>',
    '<key>NSAllowsArbitraryLoadsInWebContent</key><true/>',
    '<key>NSAllowsArbitraryLoadsForMedia</key><true/>',
    '<key>NSAllowsLocalNetworking</key><true/>',
    '</dict>'
  ].join('\n'));
  assert.deepEqual(find(r, 'ats-arbitrary-loads').map((f) => [f.severity, f.category, f.line, f.subject]), [
    ['error', 'MASVS-NETWORK', 7, 'NSAllowsArbitraryLoads'],
    ['warning', 'MASVS-NETWORK', 8, 'NSAllowsArbitraryLoadsInWebContent'],
    ['warning', 'MASVS-NETWORK', 9, 'NSAllowsArbitraryLoadsForMedia']
  ]);
  const off = await ios('<key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><false/></dict>');
  assert.deepEqual(ids(off), []);
});

test('ats-insecure-exception: insecure HTTP and old TLS for a domain are warnings; allowed domains skip the HTTP part', async () => {
  const info = [
    '<key>NSAppTransportSecurity</key><dict><key>NSExceptionDomains</key><dict>',
    '<key>legacy.example.test</key><dict><key>NSExceptionAllowsInsecureHTTPLoads</key><true/></dict>',
    '<key>partner.example.test</key><dict><key>NSThirdPartyExceptionMinimumTLSVersion</key><string>TLSv1.0</string></dict>',
    '<key>modern.example.test</key><dict><key>NSExceptionMinimumTLSVersion</key><string>TLSv1.2</string></dict>',
    '<key>localhost</key><dict><key>NSExceptionAllowsInsecureHTTPLoads</key><true/></dict>',
    '</dict></dict>'
  ].join('\n');
  const r = await ios(info, null, { config: { allowCleartextDomains: ['localhost'] } });
  assert.deepEqual(find(r, 'ats-insecure-exception').map((f) => [f.severity, f.category, f.subject, f.line]), [
    ['warning', 'MASVS-NETWORK', 'legacy.example.test', 6],
    ['warning', 'MASVS-NETWORK', 'partner.example.test', 7]
  ]);
  assert.match(find(r, 'ats-insecure-exception')[1].message, /TLS versions older than 1\.2/);
});

test('missing-usage-description: a required camera without NSCameraUsageDescription is an error', async () => {
  const r = await ios('<key>UIRequiredDeviceCapabilities</key>\n<array><string>arm64</string><string>still-camera</string><string>video-camera</string></array>');
  assert.deepEqual(find(r, 'missing-usage-description').map((f) => [f.severity, f.category, f.subject, f.line]), [['error', 'MASVS-PRIVACY', 'NSCameraUsageDescription', 5]]);
  const ok = await ios('<key>UIRequiredDeviceCapabilities</key><dict><key>still-camera</key><true/><key>microphone</key><false/></dict><key>NSCameraUsageDescription</key><string>Scans parcel labels.</string>');
  assert.deepEqual(ids(ok), [], 'the dict form of capabilities is read, and false entries do not count');
});

test('missing-usage-description: entitlements and background modes need their usage descriptions', async () => {
  const r = await ios(
    '<key>UIBackgroundModes</key><array><string>location</string><string>bluetooth-central</string></array>\n<key>NSLocationWhenInUseUsageDescription</key><string>Shows the nearest pickup point.</string>',
    '<key>com.apple.developer.healthkit</key><true/>\n<key>com.apple.developer.healthkit.access</key><array/>'
  );
  assert.deepEqual(find(r, 'missing-usage-description').map((f) => [f.file, f.subject]), [
    [I, 'NSBluetoothAlwaysUsageDescription'],
    [I, 'NSLocationAlwaysAndWhenInUseUsageDescription'],
    [E, 'NSHealthShareUsageDescription']
  ]);
  assert.deepEqual(ENTITLEMENT_USAGE['com.apple.developer.healthkit'], ['NSHealthShareUsageDescription']);
  assert.deepEqual(CAPABILITY_USAGE['still-camera'], ['NSCameraUsageDescription']);
  assert.equal(BACKGROUND_USAGE.location.length, 2);
});

test('missing-usage-description: an empty usage string is a warning', async () => {
  const r = await ios('<key>NSMicrophoneUsageDescription</key>\n<string>   </string>\n<key>NSContactsUsageDescription</key>\n<string>Finds friends who also order.</string>');
  assert.deepEqual(find(r, 'missing-usage-description').map((f) => [f.severity, f.subject, f.line]), [['warning', 'NSMicrophoneUsageDescription', 5]]);
});

test('file-sharing, background-modes and url-schemes are info findings', async () => {
  const r = await ios([
    '<key>UIFileSharingEnabled</key><true/>',
    '<key>LSSupportsOpeningDocumentsInPlace</key><true/>',
    '<key>UIBackgroundModes</key><array><string>remote-notification</string><string>fetch</string></array>',
    '<key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>orders</string><string>orders-pay</string></array></dict></array>'
  ].join('\n'));
  assert.deepEqual(r.findings.map((f) => [f.id, f.severity, f.category, f.subject]), [
    ['file-sharing', 'info', 'MASVS-STORAGE', 'UIFileSharingEnabled'],
    ['file-sharing', 'info', 'MASVS-STORAGE', 'LSSupportsOpeningDocumentsInPlace'],
    ['background-modes', 'info', 'MASVS-PRIVACY', 'remote-notification, fetch'],
    ['url-schemes', 'info', 'MASVS-PLATFORM', 'orders, orders-pay']
  ]);
  assert.equal(r.platforms[0].urlSchemes, 2);
});

test('debug-entitlement: get-task-allow true is an error; false is fine', async () => {
  const r = await ios('<key>CFBundleIdentifier</key><string>com.example.orders</string>', '<key>aps-environment</key><string>production</string>\n<key>get-task-allow</key><true/>');
  assert.deepEqual(r.findings.map((f) => [f.id, f.severity, f.category, f.file, f.line]), [['debug-entitlement', 'error', 'MASVS-RESILIENCE', E, 6]]);
  assert.equal(r.platforms[0].entitlements, 2);
  const off = await ios('', '<key>get-task-allow</key><false/>');
  assert.deepEqual(ids(off), []);
});

test('Xcode build settings are not expanded, and a note says so; a top value that is not a dict stops the run', async () => {
  const r = await ios('<key>CFBundleIdentifier</key><string>$(PRODUCT_BUNDLE_IDENTIFIER)</string>\n<key>CFBundleName</key><string>${PRODUCT_NAME}</string>');
  assert.equal(r.platforms[0].bundleId, '$(PRODUCT_BUNDLE_IDENTIFIER)');
  assert.ok(r.notes.some((n) => /2 values use Xcode build settings/.test(n)));
  await assert.rejects(check({ [I]: '<plist><array/></plist>' }, { ios: I }), /top value of Info\.plist is <array>, not <dict>/);
});

test('every iOS finding carries the platform and the category of its check', async () => {
  const r = await ios('<key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict><key>UIFileSharingEnabled</key><true/><key>UIRequiredDeviceCapabilities</key><array><string>microphone</string></array>', '<key>get-task-allow</key><true/>');
  assert.equal(r.findings.length, 4);
  for (const f of r.findings) {
    assert.equal(f.platform, 'ios');
    assert.equal(f.category, FINDINGS.find((x) => x.id === f.id).category);
  }
});
