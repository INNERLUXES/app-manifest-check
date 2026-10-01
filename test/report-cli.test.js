import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { parseArgs, toText, toMarkdown, toJson, toCsv, csvCell, mdCell, platformLine, readBounded, USAGE, VERSION, LIMITS } from '../src/index.js';
import { check, manifest, plist, run, withFiles } from './helpers.js';

const root = resolve(fileURLToPath(import.meta.url), '..', '..');
const ex = (p) => resolve(root, 'examples', p);
const risky = ['--android', ex('android/AndroidManifest.xml'), '--network-config', ex('android/network_security_config.xml'), '--gradle', ex('android/build.gradle.kts'), '--ios', ex('ios/Info.plist'), '--entitlements', ex('ios/Orders.entitlements')];
const clean = ['--android', ex('android/clean/AndroidManifest.xml'), '--ios', ex('ios/clean/Info.plist')];

// A report with names that try to break each format.
function hostile() {
  return check({
    'AndroidManifest.xml': manifest({ body: '<service android:name="=cmd.x|calc" android:exported="true" />\n<activity android:name="Evil&#10;Line&#x1b;[2J" android:exported="true" />' })
  }, { android: 'AndroidManifest.xml' });
}

test('parseArgs reads options and refuses bad input', () => {
  const o = parseArgs(['--android', 'm.xml', '--network-config', 'n.xml', '--gradle', 'build.gradle', '--ios', 'Info.plist', '--entitlements', 'a.entitlements', '--config', 'c.json', '--min-target-sdk', '34', '--format', 'sarif', '--fail-on', 'warning']);
  assert.deepEqual([o.android, o.networkConfig, o.gradle, o.ios, o.entitlements, o.config, o.minTargetSdk, o.format, o.failOn], ['m.xml', 'n.xml', 'build.gradle', 'Info.plist', 'a.entitlements', 'c.json', 34, 'sarif', 'warning']);
  const d = parseArgs(['--ios', 'Info.plist']);
  assert.deepEqual([d.format, d.failOn, d.minTargetSdk, d.android], ['text', 'error', null, null]);
  assert.equal(parseArgs(['--help']).help, true);
  assert.throws(() => parseArgs([]), /give an Android manifest with --android, an Info.plist with --ios, or both/);
  assert.throws(() => parseArgs(['--gradle', 'b.gradle', '--ios', 'I.plist']), /--network-config and --gradle need --android/);
  assert.throws(() => parseArgs(['--android', 'm.xml', '--entitlements', 'a']), /--entitlements needs --ios/);
  assert.throws(() => parseArgs(['--android', 'a', '--android', 'b']), /give --android once/);
  assert.throws(() => parseArgs(['--android', 'a', '--format', 'html']), /unknown format html/);
  assert.throws(() => parseArgs(['--android', 'a', '--format', 'toString']), /unknown format/);
  assert.throws(() => parseArgs(['--android', 'a', '--fail-on', 'info']), /error or warning/);
  assert.throws(() => parseArgs(['--android', 'a', '--min-target-sdk', '0']), /from 1 to 99/);
  assert.throws(() => parseArgs(['--android', 'a', '--min-target-sdk', '100']), /from 1 to 99/);
  assert.throws(() => parseArgs(['--android']), /needs a value/);
  assert.throws(() => parseArgs(['m.xml']), /give each file with its option/);
  assert.throws(() => parseArgs(['--android', 'a', '--fix']), /unknown argument --fix/);
  assert.throws(() => parseArgs(['-']), /standard input/);
  assert.throws(() => parseArgs(['--ios', 'https://example.test/Info.plist']), /never fetches a URL/);
});

test('exit codes: 0 on a clean app, 1 on errors or with --fail-on warning, 2 on usage or input errors', async () => {
  assert.equal((await run(clean)).code, 0);
  assert.equal((await run([...clean, '--fail-on', 'warning'])).code, 0, 'info never fails a run');
  const bad = await run(risky);
  assert.equal(bad.code, 1);
  assert.ok(bad.out.endsWith('GATE: FAIL - 5 errors\n'));
  const warn = await run(['--android', ex('android/clean/AndroidManifest.xml'), '--min-target-sdk', '36', '--fail-on', 'warning']);
  assert.deepEqual([warn.code, warn.out.endsWith('GATE: FAIL - 1 warning\n')], [1, true]);
  assert.equal((await run(['--nope'])).code, 2);
  const help = await run(['--help']);
  assert.deepEqual([help.code, help.out], [0, USAGE]);
  const v = await run(['--version']);
  assert.equal(v.out.trim(), VERSION);
  assert.equal(VERSION, '1.0.0');
  const missing = await run(['--android', ex('android/None.xml')]);
  assert.deepEqual([missing.code, /None\.xml: no such file/.test(missing.err)], [2, true]);
  const folder = await run(['--android', ex('android')]);
  assert.equal(folder.code, 2);
  const usage = await run(['--format', 'json']);
  assert.deepEqual([usage.code, usage.err.includes(USAGE)], [2, true]);
  const broken = await withFiles({ 'AndroidManifest.xml': '<manifest>\n<application>\n</manifest>' }, (dir) => run(['--android', resolve(dir, 'AndroidManifest.xml')]));
  assert.equal(broken.code, 2);
  assert.match(broken.err, /AndroidManifest\.xml: line 3: <\/manifest> does not close <application> from line 2/);
});

test('size limits: a file over the limit is refused before it is read', async () => {
  await withFiles({ 'AndroidManifest.xml': manifest({ body: `<!-- ${'x'.repeat(600)} -->` }), 'Info.plist': plist('') }, async (dir) => {
    const small = { ...LIMITS, maxFileBytes: 500 };
    const r = await run(['--android', resolve(dir, 'AndroidManifest.xml')], small);
    assert.equal(r.code, 2);
    assert.match(r.err, /AndroidManifest\.xml: \d+ bytes is over the .* MB limit/);
    assert.equal((await run(['--ios', resolve(dir, 'Info.plist')], small)).code, 0);
    await assert.rejects(readBounded(resolve(dir, 'AndroidManifest.xml'), small), /over the/);
    assert.equal(LIMITS.maxFileBytes, 10 * 1024 * 1024);
  });
});

test('text report: per-platform summary, findings with category, file and line, fix and gate', async () => {
  const r = await run(risky.map((a) => (a.startsWith(root) ? a.slice(root.length + 1).split('\\').join('/') : a)));
  assert.ok(r.out.startsWith('app-manifest-check: android, ios\n'));
  assert.match(r.out, /^ {2}package com\.example\.orders; minSdk 24; targetSdk 33; compileSdk 35; 5 components \(2 exported\); 5 permissions$/m);
  assert.match(r.out, /^ {2}bundle id \$\(PRODUCT_BUNDLE_IDENTIFIER\); 1 usage description; 1 URL scheme; 1 background mode; 3 entitlements$/m);
  assert.match(r.out, /^findings: 5 error, 7 warning, 7 info$/m);
  assert.match(r.out, /^ERROR {4}debuggable \(MASVS-RESILIENCE\) {2}examples\/android\/AndroidManifest\.xml:13$/m);
  assert.match(r.out, /^ {9}fix: Remove android:debuggable from the manifest/m);
  const empty = toText({ platforms: [], counts: { error: 0, warning: 0, info: 0 }, findings: [], notes: [], gate: { pass: true, failOn: 'error' } });
  assert.match(empty, /no findings/);
});

test('markdown escapes pipes, line breaks and angle brackets; text and JSON strip control characters', async () => {
  const r = await hostile();
  const text = toText(r);
  assert.ok(!/[\u0000-\u0008\u000b-\u001f]/.test(text), 'no control characters reach the terminal');
  assert.ok(text.includes('Evil Line [2J'));
  const md = toMarkdown(r);
  assert.ok(md.includes('=cmd.x\\|calc'));
  assert.ok(md.includes('&lt;service&gt;'));
  assert.ok(!md.split('\n').some((l) => l.startsWith('| warning') && l.split(/(?<!\\)\|/).length !== 8), 'every finding row keeps its seven cells');
  assert.equal(mdCell('a|b\nc\\d<e>'), 'a\\|b c\\\\d&lt;e&gt;');
  const json = JSON.parse(toJson(r));
  assert.equal(json.findings.find((f) => f.subject.startsWith('com.example.orders.Evil')).subject, 'com.example.orders.Evil Line [2J');
  assert.equal(platformLine(json.platforms[0]), 'package com.example.orders; minSdk -; targetSdk -; compileSdk -; 2 components (2 exported); 0 permissions');
});

test('csv: RFC 4180 quoting and a leading quote on formula-like cells', async () => {
  assert.equal(csvCell('=SUM(A1)'), "'=SUM(A1)");
  assert.equal(csvCell('+1'), "'+1");
  assert.equal(csvCell('-x'), "'-x");
  assert.equal(csvCell('@x'), "'@x");
  assert.equal(csvCell('a "b", c'), '"a ""b"", c"');
  assert.equal(csvCell(null), '');
  const csv = toCsv(await hostile());
  const lines = csv.split('\r\n');
  assert.equal(lines[0], 'platform,severity,id,category,file,line,subject,message,fix');
  assert.ok(csv.endsWith('\r\n'));
  assert.ok(lines.some((l) => l.includes(",'=cmd.x|calc,")));
});

test('formats: every format runs on the examples, and JSON holds the whole report', async () => {
  for (const format of ['text', 'markdown', 'json', 'csv', 'sarif']) {
    const r = await run([...risky, '--format', format]);
    assert.equal(r.code, 1, format);
    assert.ok(r.out.length > 200, format);
  }
  const j = JSON.parse((await run([...risky, '--format', 'json'])).out);
  assert.equal(j.tool, 'app-manifest-check');
  assert.deepEqual(j.counts, { error: 5, warning: 7, info: 7 });
  assert.deepEqual(j.platforms.map((p) => [p.platform, p.counts.error, p.counts.warning, p.counts.info]), [['android', 2, 6, 4], ['ios', 3, 1, 3]]);
  for (const f of j.findings) for (const k of ['id', 'severity', 'category', 'platform', 'file', 'line', 'subject', 'message', 'fix']) assert.ok(k in f, k);
});
