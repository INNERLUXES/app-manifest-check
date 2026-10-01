// Shared test helpers: manifests, plists and build files written inline into a temporary folder that is
// removed after the test.

import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { loadApp, checkApp, parseConfig, main, PLIST_DOCTYPE } from '../src/index.js';

export async function withFiles(files, fn) {
  const dir = await mkdtemp(resolve(tmpdir(), 'app-manifest-check-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      await mkdir(dirname(resolve(dir, rel)), { recursive: true });
      await writeFile(resolve(dir, rel), content);
    }
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

// A source manifest with the android namespace. app holds attributes of <application>.
export function manifest({ pkg = 'com.example.orders', app = 'android:allowBackup="false"', body = '', perms = [], top = '' } = {}) {
  return [
    '<?xml version="1.0" encoding="utf-8"?>',
    `<manifest xmlns:android="http://schemas.android.com/apk/res/android"${pkg ? ` package="${pkg}"` : ''}>`,
    top,
    ...perms.map((p) => `  <uses-permission android:name="${p.includes('.') ? p : `android.permission.${p}`}" />`),
    `  <application ${app}>`,
    body,
    '  </application>',
    '</manifest>',
    ''
  ].filter((l) => l !== '').join('\n');
}

// A launcher activity, as Android Studio writes it.
export const LAUNCHER = '<activity android:name=".MainActivity" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN" /><category android:name="android.intent.category.LAUNCHER" /></intent-filter></activity>';

// An XML property list holding one dict with the given inner text.
export function plist(inner) {
  return `<?xml version="1.0" encoding="UTF-8"?>\n${PLIST_DOCTYPE}\n<plist version="1.0">\n<dict>\n${inner}\n</dict>\n</plist>\n`;
}

// Writes the files and runs the checks. sources maps an option (android, networkConfig, gradle, ios,
// entitlements) to a file name inside files.
export async function check(files, sources, { config = null, ...options } = {}) {
  return withFiles(files, async (dir) => {
    const paths = {};
    for (const [k, v] of Object.entries(sources)) paths[k] = resolve(dir, v);
    const report = checkApp(await loadApp(paths), { config: parseConfig(config), ...options });
    for (const f of report.findings) f.file = f.file.slice(dir.length + 1).split('\\').join('/');
    return report;
  });
}

// Runs the command line and keeps what it writes.
export async function run(argv, limits) {
  let out = '';
  let err = '';
  const code = await main(argv, { out: (t) => { out += t; }, err: (t) => { err += t; } }, limits);
  return { code, out, err };
}

export const ids = (report) => report.findings.map((f) => f.id);
export const find = (report, id) => report.findings.filter((f) => f.id === id);
