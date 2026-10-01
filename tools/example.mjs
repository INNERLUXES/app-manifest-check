// Runs the README examples and checks that they report what the README shows.

import { main } from '../src/index.js';

async function run(argv) {
  let out = '';
  const code = await main(argv, { out: (t) => { out += t; }, err: (t) => process.stderr.write(t) });
  process.stdout.write(out);
  return { code, out };
}

const problems = [];
function expect(name, result, code, expected, unwanted) {
  const missing = expected.filter((e) => !result.out.includes(e));
  const wrong = unwanted.filter((e) => result.out.includes(e));
  if (result.code !== code || missing.length || wrong.length) {
    problems.push(`${name}: unexpected report (exit code ${result.code}, expected ${code}; missing: ${missing.join(' / ') || 'none'}; should not appear: ${wrong.join(' / ') || 'none'})`);
  }
}

const RISKY = [
  '--android', 'examples/android/AndroidManifest.xml',
  '--network-config', 'examples/android/network_security_config.xml',
  '--gradle', 'examples/android/build.gradle.kts',
  '--ios', 'examples/ios/Info.plist',
  '--entitlements', 'examples/ios/Orders.entitlements'
];

const risky = await run(RISKY);
expect('risky orders app', risky, 1, [
  'app-manifest-check: android, ios',
  'android: examples/android/AndroidManifest.xml, examples/android/network_security_config.xml, examples/android/build.gradle.kts',
  '  package com.example.orders; minSdk 24; targetSdk 33; compileSdk 35; 5 components (2 exported); 5 permissions',
  '  findings: 2 error, 6 warning, 4 info',
  'ios: examples/ios/Info.plist, examples/ios/Orders.entitlements',
  '  bundle id $(PRODUCT_BUNDLE_IDENTIFIER); 1 usage description; 1 URL scheme; 1 background mode; 3 entitlements',
  '  findings: 3 error, 1 warning, 3 info',
  'findings: 5 error, 7 warning, 7 info',
  'ERROR    debuggable (MASVS-RESILIENCE)  examples/android/AndroidManifest.xml:13',
  'ERROR    cleartext-traffic (MASVS-NETWORK)  examples/android/AndroidManifest.xml:13',
  'ERROR    ats-arbitrary-loads (MASVS-NETWORK)  examples/ios/Info.plist:18',
  'ERROR    missing-usage-description (MASVS-PRIVACY)  examples/ios/Info.plist:31',
  '         the required device capability still-camera needs NSCameraUsageDescription in Info.plist',
  'ERROR    debug-entitlement (MASVS-RESILIENCE)  examples/ios/Orders.entitlements:12',
  'WARNING  allow-backup (MASVS-STORAGE)  examples/android/AndroidManifest.xml:13',
  'WARNING  cleartext-traffic (MASVS-NETWORK)  examples/android/network_security_config.xml:10',
  '         plain HTTP is allowed for legacy-api.example.test',
  'WARNING  user-certs-trusted (MASVS-NETWORK)  examples/android/network_security_config.xml:4',
  'WARNING  exported-without-permission (MASVS-PLATFORM)  examples/android/AndroidManifest.xml:38',
  '         <service> com.example.orders.sync.OrderSyncService is exported without android:permission',
  'WARNING  broad-permissions (MASVS-PRIVACY)  examples/android/AndroidManifest.xml:11',
  'WARNING  target-sdk (MASVS-CODE)  examples/android/build.gradle.kts:14',
  'WARNING  ats-insecure-exception (MASVS-NETWORK)  examples/ios/Info.plist:26',
  'INFO     exported-without-permission (MASVS-PLATFORM)  examples/android/AndroidManifest.xml:23',
  'INFO     dangerous-permissions (MASVS-PRIVACY)  examples/android/AndroidManifest.xml:8',
  '         3 runtime permissions: CAMERA, ACCESS_FINE_LOCATION, POST_NOTIFICATIONS',
  'INFO     minify-off (MASVS-RESILIENCE)  examples/android/build.gradle.kts:28',
  'INFO     task-hijacking (MASVS-PLATFORM)  examples/android/AndroidManifest.xml:32',
  'INFO     file-sharing (MASVS-STORAGE)  examples/ios/Info.plist:53',
  'INFO     background-modes (MASVS-PRIVACY)  examples/ios/Info.plist:38',
  'INFO     url-schemes (MASVS-PLATFORM)  examples/ios/Info.plist:42',
  'note: examples/ios/Info.plist and examples/ios/Orders.entitlements: 1 value uses Xcode build settings such as $(PRODUCT_BUNDLE_IDENTIFIER), which are not expanded',
  'GATE: FAIL - 5 errors'
], ['missing-exported', 'GATE: PASS']);

process.stdout.write('\n');
const clean = await run(['--android', 'examples/android/clean/AndroidManifest.xml', '--ios', 'examples/ios/clean/Info.plist', '--fail-on', 'warning']);
expect('clean orders app with --fail-on warning', clean, 0, [
  '  package com.example.orders; minSdk 26; targetSdk 35; compileSdk -; 3 components (1 exported); 1 permission',
  '  bundle id com.example.orders; 2 usage descriptions; 0 URL schemes; 0 background modes',
  'findings: 0 error, 0 warning, 1 info',
  'INFO     exported-without-permission (MASVS-PLATFORM)  examples/android/clean/AndroidManifest.xml:17',
  'GATE: PASS (--fail-on warning)'
], ['ERROR', 'WARNING', 'note:']);

let sarif = '';
const sarifCode = await main([...RISKY, '--format', 'sarif'], { out: (t) => { sarif += t; }, err: (t) => process.stderr.write(t) });
const log = JSON.parse(sarif);
const results = log.runs[0].results;
const first = results[0];
if (sarifCode !== 1 || log.version !== '2.1.0' || results.length !== 19) problems.push(`sarif: unexpected log (exit code ${sarifCode}, ${results.length} results)`);
if (first.ruleId !== 'debuggable' || first.locations[0].physicalLocation.artifactLocation.uri !== 'examples/android/AndroidManifest.xml' || first.locations[0].physicalLocation.region.startLine !== 13 || first.properties.category !== 'MASVS-RESILIENCE') problems.push('sarif: unexpected first result');

if (problems.length) {
  for (const p of problems) console.error(`example: ${p}`);
  process.exit(1);
}
