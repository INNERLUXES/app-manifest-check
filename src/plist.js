// Reads a property list in the XML format (Info.plist, .entitlements) into plain values that keep the line
// of each key. Binary property lists are refused with the command that converts them. The DOCTYPE line that
// Xcode writes is skipped as text; it is never fetched, and any other DOCTYPE is refused by the XML reader.

import { parseXml, textOf } from './xml.js';

export const PLIST_DOCTYPE = '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">';
// Older files name the publisher "Apple Computer"; both lines are the same public identifier.
const DOCTYPES = [PLIST_DOCTYPE, PLIST_DOCTYPE.replace('//Apple//', '//Apple Computer//')];
const SCALARS = new Set(['string', 'integer', 'real', 'date', 'data']);

// True when the bytes are a binary property list ("bplist" magic).
export function isBinaryPlist(bytes) {
  return bytes.length >= 6 && Buffer.from(bytes.subarray(0, 6)).toString('latin1') === 'bplist';
}

// A value node: { type, value, line }. A dict has value: an object without a prototype that maps each key to
// its node, and each node of a dict carries keyLine, the line of its <key>.
function readValue(el, label) {
  const type = el.name;
  if (type === 'dict') {
    const value = Object.create(null);
    const kids = el.children;
    if (kids.length % 2 !== 0) throw new Error(`${label}: line ${el.line}: a <dict> needs a value after every <key>`);
    for (let k = 0; k < kids.length; k += 2) {
      const key = kids[k];
      if (key.name !== 'key') throw new Error(`${label}: line ${key.line}: <${key.name}> where a <key> was expected`);
      const name = key.text;
      if (Object.hasOwn(value, name)) throw new Error(`${label}: line ${key.line}: the key ${JSON.stringify(name.slice(0, 80))} appears twice`);
      const node = readValue(kids[k + 1], label);
      node.keyLine = key.line;
      value[name] = node;
    }
    return { type, value, line: el.line };
  }
  if (type === 'array') return { type, value: el.children.map((c) => readValue(c, label)), line: el.line };
  if (type === 'true' || type === 'false') {
    if (el.children.length || textOf(el)) throw new Error(`${label}: line ${el.line}: <${type}/> must be empty`);
    return { type: 'boolean', value: type === 'true', line: el.line };
  }
  if (SCALARS.has(type)) {
    if (el.children.length) throw new Error(`${label}: line ${el.line}: <${type}> holds elements`);
    return { type, value: type === 'string' ? el.text : textOf(el), line: el.line };
  }
  throw new Error(`${label}: line ${el.line}: <${String(type).slice(0, 40)}> is not a property list value`);
}

// Reads the text of an XML property list and returns its top value node.
export function parsePlist(input, label = 'input') {
  if (typeof input !== 'string' && isBinaryPlist(input)) {
    throw new Error(`${label}: a binary property list; convert it to XML first, for example with: plutil -convert xml1 -o converted.plist <file>`);
  }
  const text = typeof input === 'string' ? input : Buffer.from(input).toString('utf8');
  if (text.startsWith('bplist')) throw new Error(`${label}: a binary property list; convert it to XML first, for example with: plutil -convert xml1 -o converted.plist <file>`);
  const root = parseXml(text, label, { doctype: DOCTYPES });
  if (root.name !== 'plist') throw new Error(`${label}: line ${root.line}: the root element is <${root.name.slice(0, 40)}>, not <plist>`);
  if (root.children.length !== 1) throw new Error(`${label}: line ${root.line}: <plist> must hold exactly one value`);
  return readValue(root.children[0], label);
}

// The node under a key of a dict node, or null.
export function plistGet(node, key) {
  if (!node || node.type !== 'dict') return null;
  return Object.hasOwn(node.value, key) ? node.value[key] : null;
}

// True only for a <true/> value.
export function plistTrue(node) {
  return Boolean(node && node.type === 'boolean' && node.value === true);
}

// The strings of an array node (other values are left out), or [].
export function plistStrings(node) {
  if (!node || node.type !== 'array') return [];
  return node.value.filter((v) => v.type === 'string').map((v) => v.value);
}

// The line to point at for a node: its key when it has one.
export function lineOf(node, fallback = 1) {
  return node?.keyLine ?? node?.line ?? fallback;
}
