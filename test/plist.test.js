import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePlist, isBinaryPlist, plistGet, plistTrue, plistStrings, lineOf, PLIST_DOCTYPE } from '../src/index.js';
import { plist, run, withFiles } from './helpers.js';
import { resolve } from 'node:path';

test('parsePlist reads dicts, arrays, scalars and booleans with the line of each key', () => {
  const top = parsePlist(plist([
    '<key>CFBundleIdentifier</key><string>com.example.orders</string>',
    '<key>Count</key><integer>3</integer>',
    '<key>On</key><true/>',
    '<key>Off</key><false/>',
    '<key>Modes</key>',
    '<array><string>audio</string><integer>1</integer><string>fetch</string></array>',
    '<key>Inner</key><dict><key>Deep</key><string> spaced </string></dict>'
  ].join('\n')), 'Info.plist');
  assert.equal(top.type, 'dict');
  assert.equal(plistGet(top, 'CFBundleIdentifier').value, 'com.example.orders');
  assert.equal(plistGet(top, 'Count').value, '3');
  assert.equal(plistTrue(plistGet(top, 'On')), true);
  assert.equal(plistTrue(plistGet(top, 'Off')), false);
  assert.deepEqual(plistStrings(plistGet(top, 'Modes')), ['audio', 'fetch']);
  assert.equal(plistGet(plistGet(top, 'Inner'), 'Deep').value, ' spaced ', 'strings keep their spaces');
  assert.equal(lineOf(plistGet(top, 'On')), 7);
  assert.equal(plistGet(top, 'Missing'), null);
  assert.equal(plistGet(top, 'toString'), null, 'keys are looked up without a prototype');
});

test('parsePlist accepts the Apple DOCTYPE line, and refuses any other DOCTYPE or an entity', () => {
  assert.equal(parsePlist(plist('')).type, 'dict');
  const old = plist('').replace('//Apple//', '//Apple Computer//');
  assert.equal(parsePlist(old).type, 'dict');
  const inner = plist('').replace(PLIST_DOCTYPE, '<!DOCTYPE plist [<!ENTITY x SYSTEM "file:///etc/hostname">]>');
  assert.throws(() => parsePlist(inner, 'Info.plist'), /Info\.plist: line 2: a DOCTYPE declaration is refused/);
  assert.throws(() => parsePlist(plist('<key>A</key><string>&x;</string>')), /the entity &x; is not one of/);
});

test('parsePlist refuses a binary plist with the plutil command, and structures that are not a plist', () => {
  const binary = Buffer.concat([Buffer.from('bplist00', 'latin1'), Buffer.from([0xd1, 0x01, 0x02])]);
  assert.equal(isBinaryPlist(binary), true);
  assert.equal(isBinaryPlist(Buffer.from('<?xml')), false);
  assert.throws(() => parsePlist(binary, 'Info.plist'), /Info\.plist: a binary property list; convert it to XML first, for example with: plutil -convert xml1/);
  assert.throws(() => parsePlist('<root/>'), /not <plist>/);
  assert.throws(() => parsePlist('<plist><dict/><dict/></plist>'), /exactly one value/);
  assert.throws(() => parsePlist(plist('<key>A</key>')), /needs a value after every <key>/);
  assert.throws(() => parsePlist(plist('<key>A</key><string/><key>A</key><string/>')), /the key "A" appears twice/);
  assert.throws(() => parsePlist(plist('<key>A</key><bogus/>')), /not a property list value/);
  assert.throws(() => parsePlist(plist('<key>A</key><true>x</true>')), /must be empty/);
});

test('a binary Info.plist given on the command line stops the run with exit code 2', async () => {
  await withFiles({ 'Info.plist': Buffer.from('bplist00\u0000\u0001', 'latin1') }, async (dir) => {
    const r = await run(['--ios', resolve(dir, 'Info.plist')]);
    assert.equal(r.code, 2);
    assert.match(r.err, /binary property list; convert it to XML first/);
  });
});
