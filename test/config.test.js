import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { parseConfig, matchesPattern, isFindingId, meetsThreshold, safeText, CATEGORIES, FINDINGS, SEVERITIES } from '../src/index.js';
import { check, manifest, run, withFiles, find } from './helpers.js';

test('parseConfig fills in the defaults and keeps valid values', () => {
  assert.deepEqual(parseConfig(null), { minTargetSdk: null, allowCleartextDomains: [], allowExported: [], ignore: [] });
  const c = parseConfig({
    minTargetSdk: 34,
    allowCleartextDomains: ['localhost', '*.dev.example.test', '10.0.2.2'],
    allowExported: ['com.example.orders.ShareActivity', '.Sync'],
    ignore: [{ check: 'dangerous-permissions', reason: 'reviewed' }, { check: 'url-schemes', subject: 'orders*' }]
  });
  assert.equal(c.minTargetSdk, 34);
  assert.deepEqual(c.ignore, [{ check: 'dangerous-permissions', subject: null }, { check: 'url-schemes', subject: 'orders*' }]);
});

test('parseConfig refuses unknown keys, unknown checks and bad values', () => {
  assert.throws(() => parseConfig({ allowCleartext: [] }), /unknown key allowCleartext/);
  assert.throws(() => parseConfig([]), /JSON object/);
  assert.throws(() => parseConfig({ ignore: [{ check: 'debugable' }] }), /ignore\[0\]\.check must name a check/);
  assert.throws(() => parseConfig({ ignore: [{ check: 'debuggable', file: 'x' }] }), /unknown key file/);
  assert.throws(() => parseConfig({ ignore: {} }), /ignore must be a list/);
  assert.throws(() => parseConfig({ minTargetSdk: 340 }), /from 1 to 99/);
  assert.throws(() => parseConfig({ minTargetSdk: '35' }), /from 1 to 99/);
  assert.throws(() => parseConfig({ allowCleartextDomains: ['http://example.test'] }), /allowCleartextDomains\[0\] is not a valid entry/);
  assert.throws(() => parseConfig({ allowExported: ['a b'] }), /allowExported\[0\] is not a valid entry/);
  assert.throws(() => parseConfig({ toString: 1 }), /unknown key toString/);
});

test('ignore rules leave findings out by check and subject pattern, and the report counts them', async () => {
  const files = { 'AndroidManifest.xml': manifest({ perms: ['CAMERA', 'QUERY_ALL_PACKAGES', 'READ_SMS'] }) };
  const r = await check(files, { android: 'AndroidManifest.xml' }, { config: { ignore: [{ check: 'dangerous-permissions' }, { check: 'broad-permissions', subject: '*QUERY_ALL_*' }] } });
  assert.equal(find(r, 'dangerous-permissions').length, 0);
  assert.deepEqual(find(r, 'broad-permissions').map((f) => f.subject), ['android.permission.READ_SMS']);
  assert.equal(r.ignored, 2);
  assert.ok(r.notes.includes('2 findings were left out by ignore rules in the config'));
  assert.equal(matchesPattern('orders*', 'orders-pay'), true);
  assert.equal(matchesPattern('*.Sync', 'com.example.Sync'), true);
  assert.equal(matchesPattern('a*b*c', 'abc'), true);
  assert.equal(matchesPattern('a*b*c', 'acb'), false);
  assert.equal(matchesPattern('ab*ab', 'ab'), false);
  assert.equal(matchesPattern('exact', 'exact'), true);
});

test('a config file is read from disk; broken JSON or an unknown key stops the run with exit code 2', async () => {
  await withFiles({
    'AndroidManifest.xml': manifest({ top: '<uses-sdk android:targetSdkVersion="33" />' }),
    'good.json': '\uFEFF{ "minTargetSdk": 33 }',
    'bad.json': '{ "minTargetSdk": ',
    'typo.json': '{ "ignores": [] }'
  }, async (dir) => {
    const m = resolve(dir, 'AndroidManifest.xml');
    const good = await run(['--android', m, '--config', resolve(dir, 'good.json'), '--format', 'json']);
    assert.equal(good.code, 0);
    assert.equal(JSON.parse(good.out).minTargetSdk, 33);
    const bad = await run(['--android', m, '--config', resolve(dir, 'bad.json')]);
    assert.deepEqual([bad.code, /bad\.json: not valid JSON/.test(bad.err)], [2, true]);
    const typo = await run(['--android', m, '--config', resolve(dir, 'typo.json')]);
    assert.deepEqual([typo.code, /config: unknown key ignores/.test(typo.err)], [2, true]);
  });
});

test('the catalog: every check has a known severity and one MASVS category; safeText and thresholds', () => {
  for (const f of FINDINGS) {
    assert.ok(isFindingId(f.id));
    assert.ok(CATEGORIES.includes(f.category), f.id);
    for (const s of f.severity.split(' / ')) assert.ok(SEVERITIES.includes(s), f.id);
    assert.ok(['android', 'ios'].includes(f.platform));
  }
  assert.equal(new Set(FINDINGS.map((f) => f.id)).size, FINDINGS.length);
  assert.equal(isFindingId('constructor'), false);
  assert.equal(safeText('a\u001b[31mb\u202Ec\nd'), 'a [31mb c d');
  assert.equal(safeText('x'.repeat(400)).length, 300);
  assert.equal(meetsThreshold('warning', 'error'), false);
  assert.equal(meetsThreshold('warning', 'warning'), true);
  assert.equal(meetsThreshold('info', 'warning'), false);
});
