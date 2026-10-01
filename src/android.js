// Reads a source AndroidManifest.xml and a network security config, and runs the Android checks on them
// (with the settings found in the module build file, when one is given). docs/method.md gives the reason
// behind every check.

import { parseXml, prefixFor, childElements, attr, textOf } from './xml.js';

export const ANDROID_NS = 'http://schemas.android.com/apk/res/android';
export const COMPONENTS = ['activity', 'activity-alias', 'service', 'receiver', 'provider'];
// The default lowest target API level for target-sdk; --min-target-sdk or the config changes it.
export const DEFAULT_MIN_TARGET_SDK = 35;

const P = 'android.permission.';
// Runtime ("dangerous") permissions that the tool knows. docs/method.md lists them.
export const DANGEROUS_PERMISSIONS = [
  'READ_CALENDAR', 'WRITE_CALENDAR', 'CAMERA', 'READ_CONTACTS', 'WRITE_CONTACTS', 'GET_ACCOUNTS',
  'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'ACCESS_MEDIA_LOCATION',
  'RECORD_AUDIO', 'READ_PHONE_STATE', 'READ_PHONE_NUMBERS', 'CALL_PHONE', 'ANSWER_PHONE_CALLS',
  'READ_CALL_LOG', 'WRITE_CALL_LOG', 'USE_SIP', 'ACCEPT_HANDOVER', 'BODY_SENSORS', 'BODY_SENSORS_BACKGROUND',
  'ACTIVITY_RECOGNITION', 'SEND_SMS', 'RECEIVE_SMS', 'READ_SMS', 'RECEIVE_WAP_PUSH', 'RECEIVE_MMS',
  'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'READ_MEDIA_IMAGES', 'READ_MEDIA_VIDEO', 'READ_MEDIA_AUDIO',
  'READ_MEDIA_VISUAL_USER_SELECTED', 'BLUETOOTH_SCAN', 'BLUETOOTH_CONNECT', 'BLUETOOTH_ADVERTISE',
  'NEARBY_WIFI_DEVICES', 'UWB_RANGING', 'POST_NOTIFICATIONS'
].map((p) => P + p).concat(['com.android.voicemail.permission.ADD_VOICEMAIL']);

// Permissions that reach far beyond the app, and that Google Play reviews or restricts. They are reported as
// broad-permissions, and not again as dangerous-permissions.
export const BROAD_PERMISSIONS = [
  'MANAGE_EXTERNAL_STORAGE', 'QUERY_ALL_PACKAGES', 'REQUEST_INSTALL_PACKAGES', 'SYSTEM_ALERT_WINDOW',
  'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'READ_CALL_LOG', 'WRITE_CALL_LOG', 'ACCESS_BACKGROUND_LOCATION',
  'WRITE_SETTINGS', 'PACKAGE_USAGE_STATS'
].map((p) => P + p);

// True when the bytes are a compiled (binary) manifest from an APK rather than the XML source.
export function isBinaryManifest(bytes) {
  return bytes.length >= 4 && bytes[0] === 0x03 && bytes[1] === 0x00 && bytes[2] === 0x08 && bytes[3] === 0x00;
}

// The full class name of a component: ".Foo" and "Foo" are relative to the package.
export function fullName(name, pkg) {
  if (!name) return '(no name)';
  if (!pkg) return name;
  if (name.startsWith('.')) return pkg + name;
  return name.includes('.') ? name : `${pkg}.${name}`;
}

function textBytes(input) {
  return typeof input === 'string' ? input : Buffer.from(input).toString('utf8');
}

// Reads the text (or bytes) of a source manifest. Returns the package, uses-sdk values, the application
// attributes, permissions and components, each with its line.
export function parseManifest(input, label = 'AndroidManifest.xml') {
  if (typeof input !== 'string' && isBinaryManifest(input)) {
    throw new Error(`${label}: a compiled binary manifest, as found inside an APK; give the source manifest (src/main/AndroidManifest.xml)`);
  }
  const root = parseXml(textBytes(input), label);
  if (root.name !== 'manifest') throw new Error(`${label}: line ${root.line}: the root element is <${root.name.slice(0, 40)}>, not <manifest>`);
  const ns = prefixFor(root, ANDROID_NS) ?? 'android';
  const a = (el, name) => attr(el, `${ns}:${name}`);
  const pkg = attr(root, 'package');
  const usesSdk = childElements(root, 'uses-sdk')[0] ?? null;
  const sdk = (name) => {
    const v = usesSdk ? a(usesSdk, name) : null;
    return v === null ? null : { value: /^\d{1,3}$/.test(v) ? Number(v) : null, raw: v, line: usesSdk.line };
  };
  const permissions = [...childElements(root, 'uses-permission'), ...childElements(root, 'uses-permission-sdk-23')]
    .map((el) => ({ name: a(el, 'name') ?? '', line: el.line }))
    .filter((p) => p.name)
    .sort((x, y) => x.line - y.line);
  const app = childElements(root, 'application')[0] ?? null;
  const application = app
    ? Object.fromEntries(['name', 'debuggable', 'allowBackup', 'dataExtractionRules', 'fullBackupContent', 'usesCleartextTraffic', 'networkSecurityConfig', 'taskAffinity'].map((k) => [k, a(app, k)]))
    : null;
  const components = [];
  if (app) {
    for (const el of app.children) {
      if (!COMPONENTS.includes(el.name)) continue;
      const filters = childElements(el, 'intent-filter').map((f) => ({
        actions: childElements(f, 'action').map((x) => a(x, 'name')),
        categories: childElements(f, 'category').map((x) => a(x, 'name'))
      }));
      components.push({
        kind: el.name,
        name: a(el, 'name'),
        line: el.line,
        exported: a(el, 'exported'),
        permission: a(el, 'permission'),
        readPermission: a(el, 'readPermission'),
        writePermission: a(el, 'writePermission'),
        launchMode: a(el, 'launchMode'),
        taskAffinity: a(el, 'taskAffinity'),
        intentFilters: filters.length,
        launcher: filters.some((f) => f.actions.includes('android.intent.action.MAIN') && f.categories.includes('android.intent.category.LAUNCHER'))
      });
    }
  }
  return {
    package: pkg,
    minSdk: sdk('minSdkVersion'),
    targetSdk: sdk('targetSdkVersion'),
    application,
    applicationLine: app ? app.line : root.line,
    permissions,
    components
  };
}

// Reads res/xml/network_security_config.xml. Returns the base config, the domain configs (nested ones
// inherit cleartext and trust anchors from their parent, as Android applies them) and whether there are
// debug overrides.
export function parseNetworkConfig(input, label = 'network_security_config.xml') {
  const root = parseXml(textBytes(input), label);
  if (root.name !== 'network-security-config') throw new Error(`${label}: line ${root.line}: the root element is <${root.name.slice(0, 40)}>, not <network-security-config>`);
  const anchors = (el) => {
    const t = childElements(el, 'trust-anchors')[0];
    if (!t) return null;
    return childElements(t, 'certificates').map((c) => ({ src: attr(c, 'src') ?? '', line: c.line }));
  };
  const cleartext = (el) => {
    const v = attr(el, 'cleartextTrafficPermitted');
    return v === null ? null : v === 'true';
  };
  const baseEl = childElements(root, 'base-config')[0] ?? null;
  const base = baseEl ? { line: baseEl.line, cleartext: cleartext(baseEl), anchors: anchors(baseEl) } : null;
  const domains = [];
  const stack = childElements(root, 'domain-config').map((el) => ({ el, parent: null })).reverse();
  while (stack.length) {
    const { el, parent } = stack.pop();
    const own = cleartext(el);
    const entry = {
      line: el.line,
      domains: childElements(el, 'domain').map((d) => ({ name: textOf(d).toLowerCase(), subdomains: attr(d, 'includeSubdomains') === 'true', line: d.line })),
      cleartext: own === null ? (parent ? parent.cleartext : null) : own,
      anchors: anchors(el) ?? (parent ? parent.anchors : null)
    };
    domains.push(entry);
    const nested = childElements(el, 'domain-config');
    for (let k = nested.length - 1; k >= 0; k -= 1) stack.push({ el: nested[k], parent: entry });
  }
  return { base, domains, debugOverrides: childElements(root, 'debug-overrides').length > 0 };
}

// True when a domain is allowed by the config: entries are compared ignoring case; "*.example.test" allows
// every subdomain of example.test, but not example.test itself.
export function domainAllowed(domain, allowed) {
  const d = String(domain).toLowerCase();
  return allowed.some((entry) => {
    const e = String(entry).toLowerCase();
    return e.startsWith('*.') ? d.endsWith(e.slice(1)) && d.length > e.length - 1 : d === e;
  });
}

// Runs the Android checks. input: { manifest: { file, data }, network: { file, data } | null,
// gradle: { file, data } | null }. add(id, file, line, subject, message, fix) records a finding.
export function checkAndroid(input, { add, note, config, minTargetSdk }) {
  const m = input.manifest.data;
  const file = input.manifest.file;
  const app = m.application ?? {};
  const appLine = m.applicationLine;
  const gradle = input.gradle?.data ?? null;
  const pkg = m.package ?? gradle?.namespace ?? gradle?.applicationId ?? null;

  if (app.debuggable === 'true') {
    add('debuggable', file, appLine, 'android:debuggable', 'android:debuggable="true" on <application>: any app on the device, and anyone with a USB cable, can attach a debugger and read its memory', 'Remove android:debuggable from the manifest; the build system sets it for debug builds only');
  }
  if (gradle?.release?.debuggable?.value === true) {
    add('debuggable', input.gradle.file, gradle.release.debuggable.line, 'release build type', 'the release build type sets debuggable to true, so the store build can be attached by a debugger', 'Remove isDebuggable / debuggable from the release build type');
  }

  const backup = app.allowBackup;
  if (backup !== 'false' && !app.dataExtractionRules && !app.fullBackupContent) {
    const how = backup === null ? 'android:allowBackup is not set, so it defaults to true' : `android:allowBackup="${backup}"`;
    add('allow-backup', file, appLine, 'android:allowBackup', `${how}, with no dataExtractionRules or fullBackupContent: the whole app data folder, tokens and databases included, goes into device backups and device-to-device transfers`, 'Set android:allowBackup="false", or add android:dataExtractionRules (and android:fullBackupContent for older versions) that leave out secrets and personal data');
  }

  const allowedDomains = config.allowCleartextDomains;
  if (app.usesCleartextTraffic === 'true') {
    add('cleartext-traffic', file, appLine, 'android:usesCleartextTraffic', 'android:usesCleartextTraffic="true" on <application>: the app may send and receive plain HTTP, which anyone on the network path can read and change', 'Remove android:usesCleartextTraffic and use HTTPS; if one host must stay on HTTP, allow only that domain in the network security config');
  }
  const net = input.network?.data ?? null;
  const netFile = input.network?.file ?? null;
  if (app.networkSecurityConfig && !net) {
    note(`${file}: the manifest names ${app.networkSecurityConfig}; give that file with --network-config to check it`);
  }
  if (net && app.networkSecurityConfig) {
    // Resource names are compared exactly, letter case included, as the Android resource compiler does,
    // on every system. The file name is read with either separator.
    const want = /^@xml\/(.+)$/.exec(app.networkSecurityConfig)?.[1] ?? null;
    const given = String(netFile).split(/[\\/]/).pop().replace(/\.xml$/, '');
    if (want && want !== given) note(`${file}: the manifest names @xml/${want}, but the network config given is ${given}.xml`);
  }
  if (net && !app.networkSecurityConfig) {
    note(`${file}: <application> has no android:networkSecurityConfig, so Android does not apply ${netFile}`);
  }
  if (net) {
    if (net.base?.cleartext === true) {
      add('cleartext-traffic', netFile, net.base.line, 'base-config', '<base-config cleartextTrafficPermitted="true">: plain HTTP is allowed to every host', 'Set cleartextTrafficPermitted="false" in <base-config> (or remove it) and allow plain HTTP only for the domains that need it, in a <domain-config>');
    }
    for (const d of net.domains) {
      if (d.cleartext !== true) continue;
      const names = d.domains.map((x) => x.name).filter((x) => !domainAllowed(x, allowedDomains));
      if (!names.length) continue;
      add('cleartext-traffic', netFile, d.line, names.join(', '), `plain HTTP is allowed for ${names.join(', ')}`, 'Move these hosts to HTTPS; if a host must stay on HTTP (a local test server), add it to allowCleartextDomains in the config so the choice is written down', 'warning');
    }
    const userCerts = [];
    if (net.base?.anchors?.some((c) => c.src === 'user')) userCerts.push({ where: 'base-config', line: net.base.line });
    for (const d of net.domains) if (d.anchors?.some((c) => c.src === 'user')) userCerts.push({ where: d.domains.map((x) => x.name).join(', ') || 'domain-config', line: d.line });
    for (const u of userCerts) {
      add('user-certs-trusted', netFile, u.line, u.where, `<certificates src="user"/> in ${u.where === 'base-config' ? '<base-config>' : `the domain config for ${u.where}`}: certificates the user installs are trusted for release builds, so a proxy with its own certificate can read the traffic`, 'Keep src="user" only inside <debug-overrides>, which applies to debug builds alone');
    }
  }

  for (const c of m.components) {
    const name = fullName(c.name, pkg);
    const allowed = config.allowExported.includes(name) || (c.name !== null && config.allowExported.includes(c.name));
    if (c.exported === null && c.intentFilters > 0 && c.kind !== 'provider') {
      add('missing-exported', file, c.line, name, `<${c.kind}> ${name} has an intent filter but no android:exported; apps that target Android 12 (API level 31) or higher must set it, or they cannot be installed, and on older versions it is exported without saying so`, 'Set android:exported="false", or "true" when other apps must start it, and protect it with android:permission');
    }
    const exported = c.exported === 'true' || (c.exported === null && c.intentFilters > 0 && c.kind !== 'provider');
    if (c.exported !== null && c.exported !== 'true' && c.exported !== 'false') {
      note(`${file}: line ${c.line}: android:exported of ${name} is ${c.exported}, which is not read`);
    }
    const protectedBy = c.permission || (c.kind === 'provider' && c.readPermission && c.writePermission);
    if (exported && !protectedBy && !allowed) {
      if (c.launcher) {
        add('exported-without-permission', file, c.line, name, `<${c.kind}> ${name} is the launcher activity and is exported, as it must be`, 'Make sure it reads the intent that starts it as input from any app', 'info');
      } else {
        add('exported-without-permission', file, c.line, name, `<${c.kind}> ${name} is exported${c.exported === 'true' ? '' : ' through its intent filter'} without android:permission: any app on the device can ${c.kind === 'service' ? 'start or bind to it' : c.kind === 'receiver' ? 'send it broadcasts' : c.kind === 'provider' ? 'read and write its data' : 'start it'}`, 'Set android:exported="false" when only this app uses it; otherwise protect it with android:permission (a signature permission for your own apps), and add it to allowExported in the config when it is meant to be open');
      }
    }
    const affinity = c.taskAffinity ?? app.taskAffinity ?? null;
    if (c.kind === 'activity' && c.launchMode === 'singleTask' && affinity) {
      add('task-hijacking', file, c.line, name, `<activity> ${name} has launchMode singleTask and taskAffinity ${affinity}: another app can claim the same task and show its own screen in its place (task hijacking)`, 'Use the default launchMode where possible, and set android:taskAffinity="" on the activity or the application');
    }
  }

  const broad = m.permissions.filter((p) => BROAD_PERMISSIONS.includes(p.name));
  for (const p of broad) {
    add('broad-permissions', file, p.line, p.name, `${p.name} reaches far beyond the app, and Google Play allows it only for apps whose core feature needs it`, 'Remove it, or use the narrower API (the photo picker, a package query for named apps, the storage access framework) and declare the use in the Play Console');
  }
  const dangerous = m.permissions.filter((p) => DANGEROUS_PERMISSIONS.includes(p.name) && !BROAD_PERMISSIONS.includes(p.name));
  if (dangerous.length) {
    const names = [...new Set(dangerous.map((p) => p.name.replace(/^android\.permission\./, '')))];
    add('dangerous-permissions', file, dangerous[0].line, names.join(', '), `${names.length} runtime permission${names.length === 1 ? '' : 's'}: ${names.join(', ')}`, 'Check that each one is needed, asked for when the feature is used, and described in the privacy policy and the Data safety form');
  }

  const target = gradle?.targetSdk ?? m.targetSdk;
  const targetFile = gradle?.targetSdk ? input.gradle.file : file;
  if (!target) {
    note(`${file}: no targetSdk found${input.gradle ? ` in ${input.gradle.file} or the manifest` : '; give the module build file with --gradle'}, so target-sdk was not checked`);
  } else if (target.value !== null && target.value < minTargetSdk) {
    add('target-sdk', targetFile, target.line, `targetSdk ${target.value}`, `targetSdk is ${target.value}, below ${minTargetSdk}: the app runs with the older behaviour of the platform, without newer protections, and Google Play sets a lowest target level for new apps and updates`, `Raise targetSdk to ${minTargetSdk} or higher and test the behaviour changes of each level`);
  }
  if (gradle?.targetSdk && m.targetSdk && gradle.targetSdk.value !== m.targetSdk.value) {
    note(`${file}: <uses-sdk> sets targetSdkVersion ${m.targetSdk.raw}, but ${input.gradle.file} sets ${gradle.targetSdk.raw}; the build file wins`);
  }

  if (gradle) {
    const r = gradle.release;
    if (!r || !r.minify || r.minify.value === false) {
      const why = !r ? 'there is no release build type, so code shrinking is off' : !r.minify ? 'the release build type does not set isMinifyEnabled, which is false by default' : 'the release build type sets isMinifyEnabled to false';
      add('minify-off', input.gradle.file, r?.minify?.line ?? r?.line ?? 1, 'release build type', `${why}: the release build keeps every class and method name, which makes it easier to read and change`, 'Set isMinifyEnabled = true (minifyEnabled true in Groovy) and isShrinkResources = true in the release build type, with keep rules for code reached by reflection');
    }
    for (const n of gradle.notes) note(n);
  }

  return {
    platform: 'android',
    files: [file, netFile, input.gradle?.file ?? null].filter(Boolean),
    package: pkg,
    minSdk: (gradle?.minSdk ?? m.minSdk)?.raw ?? null,
    targetSdk: target?.raw ?? null,
    compileSdk: gradle?.compileSdk?.raw ?? null,
    components: m.components.length,
    exported: m.components.filter((c) => c.exported === 'true' || (c.exported === null && c.intentFilters > 0 && c.kind !== 'provider')).length,
    permissions: m.permissions.length
  };
}
