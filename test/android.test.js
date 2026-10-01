import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseManifest, parseNetworkConfig, fullName, domainAllowed, isBinaryManifest, DANGEROUS_PERMISSIONS, BROAD_PERMISSIONS, FINDINGS } from '../src/index.js';
import { check, manifest, LAUNCHER, ids, find } from './helpers.js';

const M = 'AndroidManifest.xml';
const android = (files, extra = {}, options) => check(files, { android: M, ...extra }, options);

test('parseManifest reads the package, permissions, application attributes and components', () => {
  const m = parseManifest(manifest({
    app: 'android:allowBackup="false" android:usesCleartextTraffic="true"',
    perms: ['CAMERA', 'com.example.orders.permission.SYNC'],
    top: '<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34" />',
    body: `${LAUNCHER}<service android:name="sync.Sync" android:permission="com.example.orders.permission.SYNC" android:exported="true"/>`
  }));
  assert.equal(m.package, 'com.example.orders');
  assert.deepEqual([m.minSdk.value, m.targetSdk.value], [24, 34]);
  assert.deepEqual(m.permissions.map((p) => p.name), ['android.permission.CAMERA', 'com.example.orders.permission.SYNC']);
  assert.equal(m.application.usesCleartextTraffic, 'true');
  assert.deepEqual(m.components.map((c) => [c.kind, c.name, c.exported, c.launcher]), [['activity', '.MainActivity', 'true', true], ['service', 'sync.Sync', 'true', false]]);
  assert.equal(fullName('.MainActivity', 'com.example.orders'), 'com.example.orders.MainActivity');
  assert.equal(fullName('Main', 'com.example.orders'), 'com.example.orders.Main');
  assert.equal(fullName('com.example.other.Main', 'com.example.orders'), 'com.example.other.Main');
});

test('parseManifest follows the prefix bound to the android namespace, and refuses compiled manifests', () => {
  const text = '<manifest xmlns:a="http://schemas.android.com/apk/res/android" package="com.example.orders"><application a:debuggable="true"/></manifest>';
  assert.equal(parseManifest(text).application.debuggable, 'true');
  const compiled = Buffer.from([0x03, 0x00, 0x08, 0x00, 0x10, 0x00]);
  assert.equal(isBinaryManifest(compiled), true);
  assert.throws(() => parseManifest(compiled, M), /compiled binary manifest, as found inside an APK; give the source manifest/);
  assert.throws(() => parseManifest('<application/>', M), /not <manifest>/);
  assert.throws(() => parseManifest('<!DOCTYPE manifest><manifest/>', M), /DOCTYPE declaration is refused/);
});

test('debuggable: android:debuggable="true" is an error; false or missing is not reported', async () => {
  const r = await android({ [M]: manifest({ app: 'android:allowBackup="false" android:debuggable="true"' }) });
  assert.deepEqual(find(r, 'debuggable').map((f) => [f.severity, f.category, f.line]), [['error', 'MASVS-RESILIENCE', 3]]);
  const off = await android({ [M]: manifest({ app: 'android:allowBackup="false" android:debuggable="false"' }) });
  assert.deepEqual(ids(off), []);
});

test('allow-backup: true or missing without rules is a warning; false or rules are fine', async () => {
  const missing = await android({ [M]: manifest({ app: '' }) });
  assert.deepEqual(find(missing, 'allow-backup').map((f) => [f.severity, f.category]), [['warning', 'MASVS-STORAGE']]);
  assert.match(find(missing, 'allow-backup')[0].message, /not set, so it defaults to true/);
  const on = await android({ [M]: manifest({ app: 'android:allowBackup="true"' }) });
  assert.match(find(on, 'allow-backup')[0].message, /android:allowBackup="true"/);
  const rules = await android({ [M]: manifest({ app: 'android:allowBackup="true" android:dataExtractionRules="@xml/rules"' }) });
  assert.equal(find(rules, 'allow-backup').length, 0);
  const legacy = await android({ [M]: manifest({ app: 'android:fullBackupContent="@xml/backup"' }) });
  assert.equal(find(legacy, 'allow-backup').length, 0);
});

test('cleartext-traffic: usesCleartextTraffic and a base-config are errors; listed domains are a warning', async () => {
  const net = `<network-security-config>
  <base-config cleartextTrafficPermitted="true" />
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="true">Legacy.Example.test</domain>
    <domain-config cleartextTrafficPermitted="false"><domain>secure.legacy.example.test</domain></domain-config>
    <domain-config><domain>inherits.example.test</domain></domain-config>
  </domain-config>
</network-security-config>`;
  const r = await android({ [M]: manifest({ app: 'android:allowBackup="false" android:usesCleartextTraffic="true" android:networkSecurityConfig="@xml/network_security_config"' }), 'res/xml/network_security_config.xml': net }, { networkConfig: 'res/xml/network_security_config.xml' });
  const found = find(r, 'cleartext-traffic').map((f) => [f.severity, f.file, f.line, f.subject]);
  assert.deepEqual(found, [
    ['error', M, 3, 'android:usesCleartextTraffic'],
    ['error', 'res/xml/network_security_config.xml', 2, 'base-config'],
    ['warning', 'res/xml/network_security_config.xml', 3, 'legacy.example.test'],
    ['warning', 'res/xml/network_security_config.xml', 6, 'inherits.example.test']
  ]);
  assert.ok(find(r, 'cleartext-traffic').every((f) => f.category === 'MASVS-NETWORK'));
  const parsed = parseNetworkConfig(net);
  assert.deepEqual(parsed.domains.map((d) => [d.domains[0].name, d.cleartext]), [['legacy.example.test', true], ['secure.legacy.example.test', false], ['inherits.example.test', true]]);
});

test('cleartext-traffic: allowCleartextDomains in the config leaves allowed domains out', async () => {
  const net = '<network-security-config><domain-config cleartextTrafficPermitted="true"><domain>localhost</domain><domain>10.0.2.2</domain><domain>api.dev.example.test</domain><domain>other.example.test</domain></domain-config></network-security-config>';
  const files = { [M]: manifest({ app: 'android:allowBackup="false" android:networkSecurityConfig="@xml/network_security_config"' }), 'network_security_config.xml': net };
  const r = await android(files, { networkConfig: 'network_security_config.xml' }, { config: { allowCleartextDomains: ['localhost', '10.0.2.2', '*.dev.example.test'] } });
  assert.deepEqual(find(r, 'cleartext-traffic').map((f) => f.subject), ['other.example.test']);
  assert.equal(domainAllowed('API.DEV.example.test', ['*.dev.example.test']), true);
  assert.equal(domainAllowed('dev.example.test', ['*.dev.example.test']), false, 'a wildcard covers subdomains only');
  assert.equal(domainAllowed('evil-dev.example.test', ['*.dev.example.test']), false);
  const all = await android(files, { networkConfig: 'network_security_config.xml' }, { config: { allowCleartextDomains: ['localhost', '10.0.2.2', '*.example.test'] } });
  assert.equal(find(all, 'cleartext-traffic').length, 0);
});

test('network config notes: a config the manifest does not use, a name that differs, and a config that was not given', async () => {
  const net = '<network-security-config><base-config/></network-security-config>';
  const unused = await android({ [M]: manifest(), 'net.xml': net }, { networkConfig: 'net.xml' });
  assert.ok(unused.notes.some((n) => /has no android:networkSecurityConfig, so Android does not apply/.test(n)));
  const other = await android({ [M]: manifest({ app: 'android:allowBackup="false" android:networkSecurityConfig="@xml/network_security_config"' }), 'xml\\Network_Security_Config.xml': net }, { networkConfig: 'xml\\Network_Security_Config.xml' });
  assert.ok(other.notes.some((n) => /names @xml\/network_security_config, but the network config given is Network_Security_Config\.xml/.test(n)), 'resource names keep their letter case');
  const missing = await android({ [M]: manifest({ app: 'android:allowBackup="false" android:networkSecurityConfig="@xml/net"' }) });
  assert.ok(missing.notes.some((n) => /names @xml\/net; give that file with --network-config/.test(n)));
});

test('user-certs-trusted: user certificates in base-config or a domain-config are a warning; debug-overrides are fine', async () => {
  const net = `<network-security-config>
  <base-config><trust-anchors><certificates src="system"/><certificates src="user"/></trust-anchors></base-config>
  <domain-config><domain>api.example.test</domain><trust-anchors><certificates src="user"/></trust-anchors></domain-config>
  <debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides>
</network-security-config>`;
  const r = await android({ [M]: manifest({ app: 'android:allowBackup="false" android:networkSecurityConfig="@xml/net"' }), 'net.xml': net }, { networkConfig: 'net.xml' });
  assert.deepEqual(find(r, 'user-certs-trusted').map((f) => [f.severity, f.category, f.line, f.subject]), [
    ['warning', 'MASVS-NETWORK', 2, 'base-config'],
    ['warning', 'MASVS-NETWORK', 3, 'api.example.test']
  ]);
  const debugOnly = await android({ [M]: manifest({ app: 'android:allowBackup="false" android:networkSecurityConfig="@xml/net"' }), 'net.xml': '<network-security-config><debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides></network-security-config>' }, { networkConfig: 'net.xml' });
  assert.equal(find(debugOnly, 'user-certs-trusted').length, 0);
});

test('exported-without-permission: exported components without a permission, the launcher as info', async () => {
  const body = [
    LAUNCHER,
    '<activity android:name=".Share" android:exported="true" />',
    '<service android:name=".Sync" android:exported="true" />',
    '<service android:name=".Guarded" android:exported="true" android:permission="com.example.orders.permission.SYNC" />',
    '<receiver android:name=".Push" android:exported="false"><intent-filter><action android:name="com.example.orders.PUSH"/></intent-filter></receiver>',
    '<provider android:name=".Data" android:authorities="com.example.orders.data" android:exported="true" />',
    '<provider android:name=".Locked" android:authorities="com.example.orders.locked" android:exported="true" android:readPermission="com.example.orders.R" android:writePermission="com.example.orders.W" />',
    '<provider android:name=".Hidden" android:authorities="com.example.orders.hidden" />'
  ].join('\n');
  const r = await android({ [M]: manifest({ body }) });
  assert.deepEqual(find(r, 'exported-without-permission').map((f) => [f.severity, f.subject]), [
    ['warning', 'com.example.orders.Share'],
    ['warning', 'com.example.orders.Sync'],
    ['warning', 'com.example.orders.Data'],
    ['info', 'com.example.orders.MainActivity']
  ]);
  assert.ok(find(r, 'exported-without-permission').every((f) => f.category === 'MASVS-PLATFORM'));
  assert.match(find(r, 'exported-without-permission')[1].message, /can start or bind to it/);
});

test('intent-filter export rules: a filter without android:exported is missing-exported and counts as exported', async () => {
  const body = [
    '<activity android:name=".Deep"><intent-filter><action android:name="android.intent.action.VIEW"/></intent-filter></activity>',
    '<receiver android:name=".Boot"><intent-filter><action android:name="android.intent.action.BOOT_COMPLETED"/></intent-filter></receiver>',
    '<service android:name=".Plain" />',
    '<activity-alias android:name=".Alias" android:targetActivity=".Deep" android:permission="com.example.orders.permission.OPEN"><intent-filter><action android:name="android.intent.action.SEND"/></intent-filter></activity-alias>'
  ].join('\n');
  const r = await android({ [M]: manifest({ body }) });
  assert.deepEqual(find(r, 'missing-exported').map((f) => [f.severity, f.category, f.subject]), [
    ['error', 'MASVS-PLATFORM', 'com.example.orders.Deep'],
    ['error', 'MASVS-PLATFORM', 'com.example.orders.Boot'],
    ['error', 'MASVS-PLATFORM', 'com.example.orders.Alias']
  ]);
  assert.deepEqual(find(r, 'exported-without-permission').map((f) => f.subject), ['com.example.orders.Deep', 'com.example.orders.Boot']);
  assert.match(find(r, 'exported-without-permission')[0].message, /exported through its intent filter/);
});

test('allowExported in the config leaves named components out, by full or written name', async () => {
  const body = '<activity android:name=".Share" android:exported="true" /><service android:name=".Sync" android:exported="true" />';
  const r = await android({ [M]: manifest({ body }) }, {}, { config: { allowExported: ['com.example.orders.Share', '.Sync'] } });
  assert.equal(find(r, 'exported-without-permission').length, 0);
});

test('permissions: broad ones are warnings, one each; dangerous ones are listed once as info', async () => {
  const r = await android({ [M]: manifest({ perms: ['INTERNET', 'CAMERA', 'READ_CONTACTS', 'READ_SMS', 'QUERY_ALL_PACKAGES', 'CAMERA'] }) });
  assert.deepEqual(find(r, 'broad-permissions').map((f) => [f.severity, f.category, f.subject]), [
    ['warning', 'MASVS-PRIVACY', 'android.permission.READ_SMS'],
    ['warning', 'MASVS-PRIVACY', 'android.permission.QUERY_ALL_PACKAGES']
  ]);
  assert.deepEqual(find(r, 'dangerous-permissions').map((f) => [f.severity, f.category, f.subject, f.line]), [['info', 'MASVS-PRIVACY', 'CAMERA, READ_CONTACTS', 4]]);
  assert.ok(DANGEROUS_PERMISSIONS.includes('android.permission.POST_NOTIFICATIONS'));
  assert.ok(BROAD_PERMISSIONS.includes('android.permission.MANAGE_EXTERNAL_STORAGE'));
  assert.ok(!DANGEROUS_PERMISSIONS.includes('android.permission.INTERNET'));
});

test('target-sdk: below the default, the config value or --min-target-sdk is a warning; a missing value is a note', async () => {
  const files = { [M]: manifest({ top: '<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34" />' }) };
  const r = await android(files);
  assert.deepEqual(find(r, 'target-sdk').map((f) => [f.severity, f.category, f.subject]), [['warning', 'MASVS-CODE', 'targetSdk 34']]);
  assert.equal(r.minTargetSdk, 35);
  assert.equal(find(await android(files, {}, { config: { minTargetSdk: 34 } }), 'target-sdk').length, 0);
  assert.equal(find(await android(files, {}, { config: { minTargetSdk: 30 }, minTargetSdk: 36 }), 'target-sdk').length, 1, 'the option wins over the config');
  const none = await android({ [M]: manifest() });
  assert.equal(find(none, 'target-sdk').length, 0);
  assert.ok(none.notes.some((n) => /no targetSdk found; give the module build file with --gradle/.test(n)));
});

test('task-hijacking: singleTask with a taskAffinity, also from the application; an empty affinity is fine', async () => {
  const body = [
    '<activity android:name=".A" android:launchMode="singleTask" android:taskAffinity="com.example.orders.a" />',
    '<activity android:name=".B" android:launchMode="singleTask" android:taskAffinity="" />',
    '<activity android:name=".C" android:launchMode="singleTop" android:taskAffinity="com.example.orders.c" />'
  ].join('\n');
  const r = await android({ [M]: manifest({ body }) });
  assert.deepEqual(find(r, 'task-hijacking').map((f) => [f.severity, f.category, f.subject]), [['info', 'MASVS-PLATFORM', 'com.example.orders.A']]);
  const app = await android({ [M]: manifest({ app: 'android:allowBackup="false" android:taskAffinity="com.example.shared"', body: '<activity android:name=".D" android:launchMode="singleTask" />' }) });
  assert.equal(find(app, 'task-hijacking').length, 1);
});

test('every Android finding carries the platform and the category of its check', async () => {
  const r = await android({ [M]: manifest({ app: 'android:debuggable="true" android:usesCleartextTraffic="true"', perms: ['CAMERA', 'SYSTEM_ALERT_WINDOW'], body: '<service android:name=".S"><intent-filter><action android:name="x.y"/></intent-filter></service>' }) });
  assert.ok(r.findings.length >= 6);
  for (const f of r.findings) {
    const spec = FINDINGS.find((x) => x.id === f.id);
    assert.equal(f.category, spec.category);
    assert.equal(f.platform, 'android');
    assert.match(f.category, /^MASVS-[A-Z]+$/);
  }
});
