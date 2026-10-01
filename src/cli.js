// Command line: app-manifest-check [--android <AndroidManifest.xml>] [--ios <Info.plist>] [options]

import { readFileSync } from 'node:fs';
import { checkApp, loadApp, parseConfig, readBounded, LIMITS, FINDINGS } from './check.js';
import { DEFAULT_MIN_TARGET_SDK } from './android.js';
import { toText, toMarkdown, toJson, toCsv } from './report.js';
import { toSarif } from './sarif.js';

export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

const FORMATS = { text: toText, markdown: toMarkdown, json: toJson, csv: toCsv, sarif: toSarif };
const THRESHOLDS = ['error', 'warning'];
const FILE_OPTIONS = { '--android': 'android', '--network-config': 'networkConfig', '--gradle': 'gradle', '--ios': 'ios', '--entitlements': 'entitlements', '--config': 'config' };

export const USAGE = `Usage: app-manifest-check [--android <AndroidManifest.xml>] [--ios <Info.plist>] [options]

Checks the settings files of a mobile app before a store release for risky configuration, by the OWASP
MASVS categories: debuggable builds, backups, plain HTTP, App Transport Security, exported components,
permissions, usage descriptions and entitlements. It reads files only; it never runs Gradle, Xcode or a
build, and opens no connection.

Options:
  --android <file>         the source AndroidManifest.xml (src/main/AndroidManifest.xml)
  --network-config <file>  the network security config (res/xml/network_security_config.xml)
  --gradle <file>          the module build file (build.gradle or build.gradle.kts), read as text
  --ios <file>             the Info.plist, in XML format
  --entitlements <file>    the .entitlements file used for the release build
  --config <file>          ignore rules, allowed cleartext domains, allowed exported components and the
                           lowest target SDK (JSON)
  --min-target-sdk <n>     the lowest targetSdk that passes (default: ${DEFAULT_MIN_TARGET_SDK}, or minTargetSdk from the config)
  --format <name>          text, markdown, json, csv or sarif (default: text)
  --fail-on <level>        exit with 1 when a finding is at this level or above: error or warning
                           (default: error)
  --help                   show this text
  --version                show the version

Checks: ${FINDINGS.map((f) => f.id).join(', ')}

Exit codes: 0 no finding at the --fail-on level, 1 such a finding, 2 usage or input error.
`;

export function parseArgs(argv) {
  const o = { android: null, networkConfig: null, gradle: null, ios: null, entitlements: null, config: null, minTargetSdk: null, format: 'text', failOn: 'error', help: false, version: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const next = () => {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) throw new Error(`${a} needs a value`);
      i += 1;
      return v;
    };
    if (a === '--help' || a === '-h') o.help = true;
    else if (a === '--version' || a === '-v') o.version = true;
    else if (Object.hasOwn(FILE_OPTIONS, a)) {
      const key = FILE_OPTIONS[a];
      if (o[key] !== null) throw new Error(`give ${a} once`);
      o[key] = next();
    } else if (a === '--min-target-sdk') {
      const v = next();
      if (!/^\d{1,2}$/.test(v) || Number(v) < 1) throw new Error(`--min-target-sdk takes a whole number from 1 to 99, not ${v}`);
      o.minTargetSdk = Number(v);
    } else if (a === '--format') o.format = next();
    else if (a === '--fail-on') o.failOn = next();
    else if (a === '-') throw new Error('reading from standard input is not supported; give the files with --android and --ios');
    else if (a.startsWith('-')) throw new Error(`unknown argument ${a}`);
    else throw new Error(`give each file with its option (--android, --ios, ...), not ${a}`);
  }
  if (!o.help && !o.version) {
    if (o.android === null && o.ios === null) throw new Error('give an Android manifest with --android, an Info.plist with --ios, or both');
    if (o.android === null && (o.networkConfig !== null || o.gradle !== null)) throw new Error('--network-config and --gradle need --android');
    if (o.ios === null && o.entitlements !== null) throw new Error('--entitlements needs --ios');
    if (!Object.hasOwn(FORMATS, o.format)) throw new Error(`unknown format ${o.format} (text, markdown, json, csv or sarif)`);
    if (!THRESHOLDS.includes(o.failOn)) throw new Error(`--fail-on takes error or warning, not ${o.failOn}`);
    for (const key of Object.values(FILE_OPTIONS)) {
      if (o[key] !== null && /^[a-z][a-z0-9+.-]*:\/\//i.test(o[key])) throw new Error('give local files; the tool never fetches a URL');
    }
  }
  return o;
}

function parseJsonConfig(bytes, label) {
  try {
    return JSON.parse(bytes.toString('utf8').replace(/^\uFEFF/, ''));
  } catch (error) {
    throw new Error(`${label}: not valid JSON (${error.message})`);
  }
}

// Exit code: 0 no finding at the --fail-on level, 1 such a finding, 2 usage or input error.
export async function main(argv, io = { out: (t) => process.stdout.write(t), err: (t) => process.stderr.write(t) }, limits = LIMITS) {
  let o;
  try {
    o = parseArgs(argv);
  } catch (error) {
    io.err(`app-manifest-check: ${error.message}\n\n${USAGE}`);
    return 2;
  }
  if (o.help) {
    io.out(USAGE);
    return 0;
  }
  if (o.version) {
    io.out(`${VERSION}\n`);
    return 0;
  }
  let report;
  try {
    const config = o.config === null ? parseConfig(null) : parseConfig(parseJsonConfig(await readBounded(o.config, limits), o.config));
    const inputs = await loadApp(o, limits);
    report = checkApp(inputs, { config, minTargetSdk: o.minTargetSdk, failOn: o.failOn, version: VERSION });
  } catch (error) {
    io.err(`app-manifest-check: ${String(error.message).replace(/[\u0000-\u001f\u007f-\u009f\u200E\u200F\u2028\u2029\u202A-\u202E\u2066-\u2069]/g, ' ')}\n`);
    return 2;
  }
  io.out(FORMATS[o.format](report));
  return report.gate.pass ? 0 : 1;
}
