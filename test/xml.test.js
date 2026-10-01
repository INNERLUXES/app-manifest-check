import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseXml, decodeEntities, localName, prefixFor, childElements, attr, textOf, XML_LIMITS } from '../src/index.js';

test('parseXml reads elements, attributes with prefixes, text and lines', () => {
  const root = parseXml('<?xml version="1.0"?>\n<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.orders">\n  <application android:debuggable=\'true\'>\n    <activity android:name=".Main"/>\n  </application>\n</manifest>\n');
  assert.equal(root.name, 'manifest');
  assert.equal(root.line, 2);
  assert.equal(attr(root, 'package'), 'com.example.orders');
  assert.equal(prefixFor(root, 'http://schemas.android.com/apk/res/android'), 'android');
  assert.equal(prefixFor(root, 'http://example.test/other'), null);
  const app = childElements(root, 'application')[0];
  assert.equal(attr(app, 'android:debuggable'), 'true');
  assert.equal(attr(app, 'android:Debuggable'), null, 'attribute names are compared exactly');
  assert.equal(childElements(app, 'activity')[0].line, 4);
  assert.equal(localName('android:exported'), 'exported');
  assert.equal(localName('exported'), 'exported');
});

test('parseXml handles comments, CDATA, entities and character references', () => {
  const root = parseXml('<a><!-- <b>not an element</b> --><t>x &amp; y &lt; &#65;&#x42; <![CDATA[<raw> & more]]></t></a>');
  assert.equal(root.children.length, 1);
  assert.equal(textOf(root.children[0]), 'x & y < AB <raw> & more');
  assert.equal(decodeEntities('&quot;&apos;&gt;'), '"\'>');
  assert.throws(() => decodeEntities('a & b'), /bare "&"/);
  assert.throws(() => decodeEntities('&#0;'), /not a valid character/);
});

test('parseXml refuses a DOCTYPE, an ENTITY declaration and undefined entities', () => {
  const bomb = '<?xml version="1.0"?>\n<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>\n<lolz>&lol2;</lolz>';
  assert.throws(() => parseXml(bomb, 'bomb.xml'), /bomb\.xml: line 2: a DOCTYPE declaration is refused/);
  assert.throws(() => parseXml('<a><!ENTITY x "y"></a>'), /an ENTITY declaration is refused/);
  assert.throws(() => parseXml('<a>&xxe;</a>'), /the entity &xxe; is not one of lt, gt, amp, quot, apos/);
  assert.throws(() => parseXml('<!DOCTYPE a SYSTEM "file:///etc/hostname"><a/>'), /DOCTYPE declaration is refused/);
});

test('parseXml skips only a DOCTYPE line the caller names exactly', () => {
  const line = '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">';
  assert.equal(parseXml(`${line}\n<plist/>`, 'x', { doctype: [line] }).name, 'plist');
  assert.throws(() => parseXml(`${line.replace('>', ' [<!ENTITY a "b">]>')}<plist/>`, 'x', { doctype: [line] }), /DOCTYPE declaration is refused/);
  assert.throws(() => parseXml(`<plist/>${line}`, 'x', { doctype: [line] }), /DOCTYPE declaration is refused/, 'not after the root element');
});

test('parseXml refuses what is not well-formed, with the line', () => {
  assert.throws(() => parseXml('<a>\n<b></a>', 'm.xml'), /m\.xml: line 2: <\/a> does not close <b> from line 2/);
  assert.throws(() => parseXml('<a/><b/>'), /a second root element/);
  assert.throws(() => parseXml('<a x="1" x="2"/>'), /appears twice/);
  assert.throws(() => parseXml('<a x=1/>'), /not in quotes/);
  assert.throws(() => parseXml('<a>'), /<a> from line 1 is not closed/);
  assert.throws(() => parseXml('text'), /text outside the root element/);
  assert.throws(() => parseXml(''), /no root element/);
  assert.throws(() => parseXml('<a><!-- open</a>'), /comment is not closed/);
});

test('parseXml keeps limits on depth and element count, and attributes cannot reach a prototype', () => {
  const deep = '<a>'.repeat(XML_LIMITS.maxDepth + 1) + '</a>'.repeat(XML_LIMITS.maxDepth + 1);
  assert.throws(() => parseXml(deep), /nested more than 64 deep/);
  assert.throws(() => parseXml(`<r>${'<e/>'.repeat(20)}</r>`, 'x', { limits: { maxDepth: 64, maxElements: 10 } }), /more than 10 elements/);
  const root = parseXml('<a __proto__="x" constructor="y"/>');
  assert.equal(Object.getPrototypeOf(root.attrs), null);
  assert.equal(attr(root, '__proto__'), 'x');
  assert.equal({}.polluted, undefined);
});
