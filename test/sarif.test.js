import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SARIF_VERSION, SARIF_SCHEMA, sarifUri, toSarif, FINDINGS } from '../src/index.js';
import { check, manifest, plist } from './helpers.js';

test('SARIF log: version 2.1.0, one rule per check with its MASVS tag, results that point at the file and line', async () => {
  const r = await check({
    'app/AndroidManifest.xml': manifest({ app: 'android:allowBackup="false" android:debuggable="true"', perms: ['CAMERA'] }),
    'ios/Info.plist': plist('<key>UIFileSharingEnabled</key>\n<true/>')
  }, { android: 'app/AndroidManifest.xml', ios: 'ios/Info.plist' });
  const log = JSON.parse(toSarif(r));
  assert.equal(log.version, SARIF_VERSION);
  assert.equal(log.version, '2.1.0');
  assert.equal(log.$schema, SARIF_SCHEMA);
  assert.equal(log.runs.length, 1);
  const driver = log.runs[0].tool.driver;
  assert.equal(driver.name, 'app-manifest-check');
  assert.equal(driver.version, '1.0.0');
  assert.deepEqual(driver.rules.map((x) => x.id), FINDINGS.map((f) => f.id));
  assert.equal(driver.rules.find((x) => x.id === 'cleartext-traffic').defaultConfiguration.level, 'error');
  assert.equal(driver.rules.find((x) => x.id === 'url-schemes').defaultConfiguration.level, 'note');
  assert.equal(driver.rules.find((x) => x.id === 'exported-without-permission').name, 'ExportedWithoutPermission');
  assert.ok(driver.rules.find((x) => x.id === 'debuggable').properties.tags.includes('MASVS-RESILIENCE'));
  const results = log.runs[0].results;
  assert.deepEqual(results.map((x) => [x.ruleId, x.level, x.locations[0].physicalLocation.artifactLocation.uri, x.locations[0].physicalLocation.region.startLine, x.properties.category]), [
    ['debuggable', 'error', 'app/AndroidManifest.xml', 4, 'MASVS-RESILIENCE'],
    ['dangerous-permissions', 'note', 'app/AndroidManifest.xml', 3, 'MASVS-PRIVACY'],
    ['file-sharing', 'note', 'ios/Info.plist', 5, 'MASVS-STORAGE']
  ]);
  for (const x of results) {
    assert.equal(driver.rules[x.ruleIndex].id, x.ruleId);
    assert.match(x.message.text, /\. Fix: /);
    assert.ok(x.partialFingerprints.appManifestCheck.startsWith(x.ruleId));
  }
});

test('sarifUri: relative paths stay relative with forward slashes, absolute paths become file URIs', () => {
  assert.equal(sarifUri('./app/src/main/AndroidManifest.xml'), 'app/src/main/AndroidManifest.xml');
  assert.equal(sarifUri('app\\src\\main\\AndroidManifest.xml'), 'app/src/main/AndroidManifest.xml');
  assert.equal(sarifUri('My App/Info.plist'), 'My%20App/Info.plist');
  assert.equal(sarifUri('C:\\work\\ios\\Info.plist'), 'file:///C:/work/ios/Info.plist');
  assert.equal(sarifUri('/srv/app/Info.plist'), 'file:///srv/app/Info.plist');
  assert.equal(sarifUri(null), 'AndroidManifest.xml');
});

test('an app without findings gives an empty result list', async () => {
  const r = await check({ 'Info.plist': plist('<key>CFBundleIdentifier</key><string>com.example.orders</string>') }, { ios: 'Info.plist' });
  assert.deepEqual(JSON.parse(toSarif(r)).runs[0].results, []);
});
