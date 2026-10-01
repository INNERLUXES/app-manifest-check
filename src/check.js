// Reads the settings files of an app, runs the Android and iOS checks, applies the config and the gate, and
// returns one report. docs/method.md gives the reason behind every check.

import { open } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseManifest, parseNetworkConfig, checkAndroid, DEFAULT_MIN_TARGET_SDK } from './android.js';
import { parseGradle } from './gradle.js';
import { parsePlist } from './plist.js';
import { checkIos } from './ios.js';

export const SEVERITIES = ['error', 'warning', 'info'];
export const RANK = { error: 0, warning: 1, info: 2 };
export const LIMITS = { maxFileBytes: 10 * 1024 * 1024 };
export const CATEGORIES = ['MASVS-STORAGE', 'MASVS-CRYPTO', 'MASVS-AUTH', 'MASVS-NETWORK', 'MASVS-PLATFORM', 'MASVS-CODE', 'MASVS-RESILIENCE', 'MASVS-PRIVACY'];

// Every check, in report order within a severity. severity is the usual one; "error / warning" means the
// finding says which, as docs/method.md explains.
export const FINDINGS = [
  { id: 'debuggable', platform: 'android', severity: 'error', category: 'MASVS-RESILIENCE', what: 'The app, or its release build type, is marked debuggable' },
  { id: 'allow-backup', platform: 'android', severity: 'warning', category: 'MASVS-STORAGE', what: 'App data goes into device backups: allowBackup is true or not set, with no backup rules' },
  { id: 'cleartext-traffic', platform: 'android', severity: 'error / warning', category: 'MASVS-NETWORK', what: 'Plain HTTP is allowed for every host (error) or for listed domains (warning)' },
  { id: 'user-certs-trusted', platform: 'android', severity: 'warning', category: 'MASVS-NETWORK', what: 'The network security config trusts user-installed certificates outside debug-overrides' },
  { id: 'exported-without-permission', platform: 'android', severity: 'warning / info', category: 'MASVS-PLATFORM', what: 'A component other apps can start, bind or call, with no android:permission (info for the launcher activity)' },
  { id: 'missing-exported', platform: 'android', severity: 'error', category: 'MASVS-PLATFORM', what: 'A component with an intent filter and no android:exported, which Android 12 and later require' },
  { id: 'dangerous-permissions', platform: 'android', severity: 'info', category: 'MASVS-PRIVACY', what: 'Runtime (dangerous) permissions the app asks for' },
  { id: 'broad-permissions', platform: 'android', severity: 'warning', category: 'MASVS-PRIVACY', what: 'A permission that reaches far beyond the app and that Google Play restricts' },
  { id: 'target-sdk', platform: 'android', severity: 'warning', category: 'MASVS-CODE', what: 'targetSdk is below the configured lowest level' },
  { id: 'minify-off', platform: 'android', severity: 'info', category: 'MASVS-RESILIENCE', what: 'The release build does not shrink and obfuscate code' },
  { id: 'task-hijacking', platform: 'android', severity: 'info', category: 'MASVS-PLATFORM', what: 'An activity with launchMode singleTask and a taskAffinity' },
  { id: 'ats-arbitrary-loads', platform: 'ios', severity: 'error / warning', category: 'MASVS-NETWORK', what: 'App Transport Security is turned off for everything (error) or for web content or media (warning)' },
  { id: 'ats-insecure-exception', platform: 'ios', severity: 'warning', category: 'MASVS-NETWORK', what: 'An exception domain allows plain HTTP or TLS older than 1.2' },
  { id: 'missing-usage-description', platform: 'ios', severity: 'error / warning', category: 'MASVS-PRIVACY', what: 'A capability that needs a usage description has none (error), or a usage description is empty (warning)' },
  { id: 'file-sharing', platform: 'ios', severity: 'info', category: 'MASVS-STORAGE', what: 'The Documents folder is shared through the Files app or a computer' },
  { id: 'background-modes', platform: 'ios', severity: 'info', category: 'MASVS-PRIVACY', what: 'The background modes the app declares' },
  { id: 'url-schemes', platform: 'ios', severity: 'info', category: 'MASVS-PLATFORM', what: 'Custom URL schemes the app registers; their input must be checked' },
  { id: 'debug-entitlement', platform: 'ios', severity: 'error', category: 'MASVS-RESILIENCE', what: 'get-task-allow is true in the entitlements file' }
];

const ORDER = Object.fromEntries(FINDINGS.map((f, i) => [f.id, i]));
const BY_ID = Object.fromEntries(FINDINGS.map((f) => [f.id, f]));
const CONFIG_KEYS = ['minTargetSdk', 'allowCleartextDomains', 'allowExported', 'ignore'];
const RULE_KEYS = ['check', 'subject', 'reason'];

export function isFindingId(id) {
  return Object.hasOwn(ORDER, id);
}

// Text from the input: control, line separator and direction characters replaced by a space, length capped.
export function safeText(value, max = 300) {
  const s = String(value).replace(/[\u0000-\u001f\u007f-\u009f\u200E\u200F\u2028\u2029\u202A-\u202E\u2066-\u2069]/g, ' ');
  return s.length > max ? `${s.slice(0, max - 3)}...` : s;
}

export function meetsThreshold(severity, failOn) {
  return RANK[severity] <= RANK[failOn];
}

// A name matched against a pattern where * stands for any text; no regular expression is built from input.
export function matchesPattern(pattern, value) {
  const parts = String(pattern).split('*');
  const v = String(value);
  if (parts.length === 1) return v === parts[0];
  if (!v.startsWith(parts[0])) return false;
  let at = parts[0].length;
  for (let k = 1; k < parts.length - 1; k += 1) {
    const found = v.indexOf(parts[k], at);
    if (found < 0) return false;
    at = found + parts[k].length;
  }
  const last = parts[parts.length - 1];
  return v.length - last.length >= at && v.endsWith(last);
}

function list(value, key, check) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 10_000) throw new Error(`config: ${key} must be a list`);
  return value.map((v, i) => {
    if (typeof v !== 'string' || !v || v.length > 300 || !check(v)) throw new Error(`config: ${key}[${i}] is not a valid entry`);
    return v;
  });
}

// Checks a parsed JSON config and fills in the defaults. An unknown key, or an ignore rule for a check that
// does not exist, is an error, so a typo cannot quietly turn a check off.
export function parseConfig(raw) {
  const c = raw ?? {};
  if (typeof c !== 'object' || Array.isArray(c)) throw new Error('config: the file must hold a JSON object');
  for (const k of Object.keys(c)) if (!CONFIG_KEYS.includes(k)) throw new Error(`config: unknown key ${safeText(k, 60)} (${CONFIG_KEYS.join(', ')})`);
  let minTargetSdk = null;
  if (c.minTargetSdk !== undefined) {
    if (!Number.isInteger(c.minTargetSdk) || c.minTargetSdk < 1 || c.minTargetSdk > 99) throw new Error('config: minTargetSdk must be a whole number from 1 to 99');
    minTargetSdk = c.minTargetSdk;
  }
  const ignore = (c.ignore === undefined ? [] : c.ignore);
  if (!Array.isArray(ignore)) throw new Error('config: ignore must be a list');
  const rules = ignore.map((r, i) => {
    if (!r || typeof r !== 'object' || Array.isArray(r)) throw new Error(`config: ignore[${i}] must be an object`);
    for (const k of Object.keys(r)) if (!RULE_KEYS.includes(k)) throw new Error(`config: ignore[${i}] has an unknown key ${safeText(k, 60)} (${RULE_KEYS.join(', ')})`);
    if (typeof r.check !== 'string' || !isFindingId(r.check)) throw new Error(`config: ignore[${i}].check must name a check (${FINDINGS.map((f) => f.id).join(', ')})`);
    if (r.subject !== undefined && (typeof r.subject !== 'string' || !r.subject)) throw new Error(`config: ignore[${i}].subject must be a text`);
    return { check: r.check, subject: r.subject ?? null };
  });
  return {
    minTargetSdk,
    allowCleartextDomains: list(c.allowCleartextDomains, 'allowCleartextDomains', (v) => /^(?:\*\.)?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*$/.test(v)),
    allowExported: list(c.allowExported, 'allowExported', (v) => /^[A-Za-z0-9_.$]+$/.test(v)),
    ignore: rules
  };
}

// Reads a whole file, refusing anything that is not a regular file or is over the size limit. The size is
// taken from the open file, so it cannot change between the check and the read.
export async function readBounded(path, limits = LIMITS) {
  let handle;
  try {
    handle = await open(resolve(path), 'r');
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error(`${path}: no such file`);
    if (error.code === 'EISDIR') throw new Error(`${path}: a folder, not a file`);
    throw new Error(`${path}: cannot be read (${error.code ?? error.message})`);
  }
  try {
    const info = await handle.stat();
    if (!info.isFile()) throw new Error(`${path}: not a regular file`);
    if (info.size > limits.maxFileBytes) throw new Error(`${path}: ${info.size.toLocaleString('en-US')} bytes is over the ${(limits.maxFileBytes / 1024 / 1024).toLocaleString('en-US')} MB limit`);
    const buffer = Buffer.alloc(info.size);
    let read = 0;
    while (read < info.size) {
      const { bytesRead } = await handle.read(buffer, read, info.size - read, read);
      if (bytesRead === 0) break;
      read += bytesRead;
    }
    return buffer.subarray(0, read);
  } finally {
    await handle.close();
  }
}

// Reads and parses the files named in sources: { android, networkConfig, gradle, ios, entitlements }, each a
// path or null. Any file that cannot be read or parsed stops the run with its reason.
export async function loadApp(sources, limits = LIMITS) {
  const read = async (path, parse) => (path === null || path === undefined ? null : { file: path, data: parse(await readBounded(path, limits), path) });
  return {
    android: sources.android
      ? {
          manifest: await read(sources.android, parseManifest),
          network: await read(sources.networkConfig, parseNetworkConfig),
          gradle: await read(sources.gradle, (bytes, label) => parseGradle(bytes.toString('utf8'), label))
        }
      : null,
    ios: sources.ios
      ? {
          info: await read(sources.ios, parsePlist),
          entitlements: await read(sources.entitlements, parsePlist)
        }
      : null
  };
}

function findingOrder(a, b) {
  return RANK[a.severity] - RANK[b.severity]
    || (a.platform === b.platform ? 0 : a.platform === 'android' ? -1 : 1)
    || ORDER[a.id] - ORDER[b.id]
    || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0)
    || a.line - b.line
    || (a.subject < b.subject ? -1 : a.subject > b.subject ? 1 : 0);
}

// Runs the checks on loaded inputs. options: { config (from parseConfig), minTargetSdk, failOn, version }.
export function checkApp(inputs, { config = parseConfig(null), minTargetSdk = null, failOn = 'error', version = '1.0.0' } = {}) {
  const all = [];
  const notes = [];
  const note = (text) => notes.push(safeText(text, 600));
  const minTarget = minTargetSdk ?? config.minTargetSdk ?? DEFAULT_MIN_TARGET_SDK;
  const adder = (platform) => (id, file, line, subject, message, fix, severity) => {
    const f = BY_ID[id];
    if (!f || f.platform !== platform) throw new Error(`unknown check ${id}`);
    all.push({
      id,
      severity: severity ?? f.severity.split(' / ')[0],
      category: f.category,
      platform,
      file: safeText(file),
      line: Math.max(1, Number(line) || 1),
      subject: safeText(subject),
      message: safeText(message, 1200),
      fix: safeText(fix, 1200)
    });
  };
  const platforms = [];
  if (inputs.android) platforms.push(checkAndroid(inputs.android, { add: adder('android'), note, config, minTargetSdk: minTarget }));
  if (inputs.ios) platforms.push(checkIos(inputs.ios, { add: adder('ios'), note, config }));

  const findings = [];
  let ignored = 0;
  for (const f of all) {
    if (config.ignore.some((r) => r.check === f.id && (r.subject === null || matchesPattern(r.subject, f.subject)))) ignored += 1;
    else findings.push(f);
  }
  findings.sort(findingOrder);
  const counts = { error: 0, warning: 0, info: 0 };
  for (const f of findings) counts[f.severity] += 1;
  for (const p of platforms) {
    p.files = p.files.map((x) => safeText(x));
    for (const k of Object.keys(p)) if (typeof p[k] === 'string') p[k] = safeText(p[k]);
    p.counts = { error: 0, warning: 0, info: 0 };
    for (const f of findings) if (f.platform === p.platform) p.counts[f.severity] += 1;
  }
  if (ignored) notes.push(`${ignored} finding${ignored === 1 ? ' was' : 's were'} left out by ignore rules in the config`);
  const failing = findings.filter((f) => meetsThreshold(f.severity, failOn));
  const reason = failOn === 'error'
    ? `${counts.error} error${counts.error === 1 ? '' : 's'}`
    : [counts.error ? `${counts.error} error${counts.error === 1 ? '' : 's'}` : '', counts.warning ? `${counts.warning} warning${counts.warning === 1 ? '' : 's'}` : ''].filter(Boolean).join(', ');
  return {
    tool: 'app-manifest-check',
    version,
    minTargetSdk: minTarget,
    platforms,
    counts,
    findings,
    ignored,
    notes,
    gate: { failOn, pass: failing.length === 0, reason: failing.length ? reason : null }
  };
}
