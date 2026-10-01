// Runs the iOS checks on an Info.plist and, when one is given, a .entitlements file, both read with
// parsePlist. docs/method.md gives the reason behind every check and the small map of capabilities to
// the usage description each one needs.

import { plistGet, plistTrue, plistStrings, lineOf } from './plist.js';
import { domainAllowed } from './android.js';

const LOCATION = ['NSLocationWhenInUseUsageDescription', 'NSLocationAlwaysAndWhenInUseUsageDescription'];

// Entitlements that need a usage description in Info.plist.
export const ENTITLEMENT_USAGE = {
  'com.apple.developer.healthkit': ['NSHealthShareUsageDescription'],
  'com.apple.developer.homekit': ['NSHomeKitUsageDescription'],
  'com.apple.developer.nfc.readersession.formats': ['NFCReaderUsageDescription'],
  'com.apple.developer.siri': ['NSSiriUsageDescription']
};

// Background modes that need a usage description.
export const BACKGROUND_USAGE = {
  location: LOCATION,
  'bluetooth-central': ['NSBluetoothAlwaysUsageDescription'],
  'bluetooth-peripheral': ['NSBluetoothAlwaysUsageDescription']
};

// Required device capabilities (UIRequiredDeviceCapabilities) that imply the app uses a protected resource.
export const CAPABILITY_USAGE = {
  'still-camera': ['NSCameraUsageDescription'],
  'video-camera': ['NSCameraUsageDescription'],
  'auto-focus-camera': ['NSCameraUsageDescription'],
  'front-facing-camera': ['NSCameraUsageDescription'],
  'camera-flash': ['NSCameraUsageDescription'],
  microphone: ['NSMicrophoneUsageDescription'],
  'location-services': [LOCATION[0]],
  gps: [LOCATION[0]],
  healthkit: ['NSHealthShareUsageDescription'],
  nfc: ['NFCReaderUsageDescription']
};

const OLD_TLS = ['TLSv1.0', 'TLSv1.1'];

// The strings of an array, or the keys set to true in a dict (UIRequiredDeviceCapabilities allows both).
function namesOf(node) {
  if (node?.type === 'dict') return Object.keys(node.value).filter((k) => plistTrue(node.value[k]));
  return plistStrings(node);
}

// How many string values hold an Xcode build setting such as $(PRODUCT_BUNDLE_IDENTIFIER).
function variables(node) {
  let count = 0;
  const stack = [node];
  while (stack.length) {
    const n = stack.pop();
    if (!n) continue;
    if (n.type === 'string' && /\$\([A-Za-z0-9_:]+\)|\$\{[A-Za-z0-9_:]+\}/.test(n.value)) count += 1;
    else if (n.type === 'array') stack.push(...n.value);
    else if (n.type === 'dict') stack.push(...Object.values(n.value));
  }
  return count;
}

// input: { info: { file, data }, entitlements: { file, data } | null }.
export function checkIos(input, { add, note, config }) {
  const info = input.info.data;
  const file = input.info.file;
  if (info.type !== 'dict') throw new Error(`${file}: line ${info.line}: the top value of Info.plist is <${info.type}>, not <dict>`);
  const ent = input.entitlements?.data ?? null;
  const entFile = input.entitlements?.file ?? null;
  if (ent && ent.type !== 'dict') throw new Error(`${entFile}: line ${ent.line}: the top value of an entitlements file is <${ent.type}>, not <dict>`);

  const ats = plistGet(info, 'NSAppTransportSecurity');
  if (plistTrue(plistGet(ats, 'NSAllowsArbitraryLoads'))) {
    add('ats-arbitrary-loads', file, lineOf(plistGet(ats, 'NSAllowsArbitraryLoads')), 'NSAllowsArbitraryLoads', 'NSAllowsArbitraryLoads is true: App Transport Security is off, so the app may load anything over plain HTTP or weak TLS, and App Review asks for a reason', 'Remove NSAllowsArbitraryLoads; if one host cannot use HTTPS yet, add an exception for that domain only under NSExceptionDomains');
  }
  for (const key of ['NSAllowsArbitraryLoadsInWebContent', 'NSAllowsArbitraryLoadsForMedia']) {
    const node = plistGet(ats, key);
    if (plistTrue(node)) {
      add('ats-arbitrary-loads', file, lineOf(node), key, `${key} is true: App Transport Security is off for ${key.endsWith('Media') ? 'media loaded with AVFoundation' : 'pages shown in web views'}`, 'Remove it once the content is served over HTTPS; keep it only for content the app cannot control, and say why in the App Review notes', 'warning');
    }
  }
  const exceptions = plistGet(ats, 'NSExceptionDomains');
  if (exceptions?.type === 'dict') {
    for (const [domain, node] of Object.entries(exceptions.value)) {
      const insecure = ['NSExceptionAllowsInsecureHTTPLoads', 'NSThirdPartyExceptionAllowsInsecureHTTPLoads'].find((k) => plistTrue(plistGet(node, k)));
      if (insecure && !domainAllowed(domain, config.allowCleartextDomains)) {
        add('ats-insecure-exception', file, lineOf(plistGet(node, insecure)), domain, `${insecure} is true for ${domain}: plain HTTP is allowed to this host`, 'Serve this host over HTTPS and remove the exception; if it must stay (a local test server), add it to allowCleartextDomains in the config so the choice is written down');
      }
      for (const k of ['NSExceptionMinimumTLSVersion', 'NSThirdPartyExceptionMinimumTLSVersion']) {
        const v = plistGet(node, k);
        if (v?.type === 'string' && OLD_TLS.includes(v.value.trim())) {
          add('ats-insecure-exception', file, lineOf(v), domain, `${k} is ${v.value.trim()} for ${domain}: TLS versions older than 1.2 are allowed to this host`, 'Remove the exception, so the default of TLS 1.2 or later applies');
        }
      }
    }
  }

  const has = (key) => {
    const node = plistGet(info, key);
    return node !== null && node.type === 'string';
  };
  const needs = [];
  if (ent) {
    for (const [key, usage] of Object.entries(ENTITLEMENT_USAGE)) {
      const node = plistGet(ent, key);
      if (node && !(node.type === 'boolean' && node.value === false)) needs.push({ source: `the entitlement ${key}`, file: entFile, line: lineOf(node), usage });
    }
  }
  const modesNode = plistGet(info, 'UIBackgroundModes');
  const modes = plistStrings(modesNode);
  for (const mode of modes) if (Object.hasOwn(BACKGROUND_USAGE, mode)) needs.push({ source: `the background mode ${mode}`, file, line: lineOf(modesNode), usage: BACKGROUND_USAGE[mode] });
  const capsNode = plistGet(info, 'UIRequiredDeviceCapabilities');
  for (const cap of namesOf(capsNode)) if (Object.hasOwn(CAPABILITY_USAGE, cap)) needs.push({ source: `the required device capability ${cap}`, file, line: lineOf(capsNode), usage: CAPABILITY_USAGE[cap] });
  const reported = new Set();
  for (const n of needs) {
    for (const key of n.usage) {
      if (has(key) || reported.has(key)) continue;
      reported.add(key);
      add('missing-usage-description', n.file, n.line, key, `${n.source} needs ${key} in Info.plist, and it is missing: the app is stopped the moment it asks for access, and App Review rejects it`, `Add ${key} with a sentence that says what the app uses the access for`);
    }
  }
  for (const [key, node] of Object.entries(info.value)) {
    if (!/UsageDescription$/.test(key) || node.type !== 'string') continue;
    if (!node.value.trim()) {
      add('missing-usage-description', file, lineOf(node), key, `${key} is empty: the permission prompt gives the user no reason, and App Review rejects a usage description that does not say what the access is for`, 'Write one plain sentence that says what the app uses the access for', 'warning');
    }
  }

  for (const key of ['UIFileSharingEnabled', 'LSSupportsOpeningDocumentsInPlace']) {
    const node = plistGet(info, key);
    if (plistTrue(node)) {
      add('file-sharing', file, lineOf(node), key, `${key} is true: the files in the app's Documents folder can be seen and copied through the Files app or a computer`, 'Keep tokens, databases and caches out of Documents (use Application Support or the keychain), or turn the key off');
    }
  }

  if (modes.length) {
    add('background-modes', file, lineOf(modesNode), modes.join(', '), `background modes: ${modes.join(', ')}`, 'Keep only the modes the app uses; App Review checks each one, and a mode such as location keeps the app collecting data when it is not on screen');
  }

  const schemes = [];
  const types = plistGet(info, 'CFBundleURLTypes');
  if (types?.type === 'array') for (const t of types.value) schemes.push(...plistStrings(plistGet(t, 'CFBundleURLSchemes')));
  if (schemes.length) {
    add('url-schemes', file, lineOf(types), schemes.join(', '), `custom URL schemes: ${schemes.join(', ')}; any app can register the same scheme and any web page can open it`, 'Treat every URL that opens the app as untrusted input: check the host, path and parameters, and never put tokens in it; prefer universal links for sign-in callbacks');
  }

  if (ent) {
    const node = plistGet(ent, 'get-task-allow');
    if (plistTrue(node)) {
      add('debug-entitlement', entFile, lineOf(node), 'get-task-allow', 'get-task-allow is true: a build signed with this file lets a debugger attach to the app; App Store builds must not have it', 'Remove get-task-allow from the entitlements file; Xcode adds it to development builds by itself');
    }
  }

  const vars = variables(info) + (ent ? variables(ent) : 0);
  if (vars) note(`${file}${ent ? ` and ${entFile}` : ''}: ${vars} value${vars === 1 ? ' uses' : 's use'} Xcode build settings such as $(PRODUCT_BUNDLE_IDENTIFIER), which are not expanded`);

  const bundle = plistGet(info, 'CFBundleIdentifier');
  return {
    platform: 'ios',
    files: [file, entFile].filter(Boolean),
    bundleId: bundle?.type === 'string' ? bundle.value : null,
    minimumOs: plistGet(info, 'MinimumOSVersion')?.value ?? null,
    usageDescriptions: Object.keys(info.value).filter((k) => /UsageDescription$/.test(k)).length,
    urlSchemes: schemes.length,
    backgroundModes: modes.length,
    entitlements: ent ? Object.keys(ent.value).length : null
  };
}
