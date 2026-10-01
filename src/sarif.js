// A minimal SARIF 2.1.0 log, so GitHub code scanning (or any SARIF viewer) can show the findings. Each
// result points at the file and line of the setting, and carries its MASVS category as a tag.

import { FINDINGS } from './check.js';

export const SARIF_VERSION = '2.1.0';
export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const INFO_URI = 'https://github.com/INNERLUXES/app-manifest-check';
const LEVEL = { error: 'error', warning: 'warning', info: 'note' };

// A path as a URI with forward slashes: relative paths stay relative (as code scanning expects, from the
// repository root), absolute ones become file:// URIs. Both separators are read, on every system, and
// characters outside the URI set are percent-encoded.
export function sarifUri(path) {
  const p = String(path || 'AndroidManifest.xml').replace(/\\/g, '/').replace(/^(?:\.\/)+/, '');
  const drive = /^([A-Za-z]):\//.exec(p);
  const encode = (s) => s.split('/').map((part) => encodeURIComponent(part)).join('/');
  if (drive) return `file:///${drive[1]}:/${encode(p.slice(3))}`;
  if (p.startsWith('/')) return `file://${encode(p)}`;
  return encode(p);
}

function ruleLevel(severity) {
  return LEVEL[severity.split(' / ')[0]];
}

export function toSarif(r) {
  const rules = FINDINGS.map((f) => ({
    id: f.id,
    name: f.id.replace(/(^|-)([a-z])/g, (all, dash, c) => c.toUpperCase()),
    shortDescription: { text: f.what },
    helpUri: `${INFO_URI}/blob/main/docs/method.md`,
    defaultConfiguration: { level: ruleLevel(f.severity) },
    properties: { tags: ['security', f.category, f.platform] }
  }));
  const index = Object.fromEntries(rules.map((rule, i) => [rule.id, i]));
  const results = r.findings.map((f) => ({
    ruleId: f.id,
    ruleIndex: index[f.id],
    level: LEVEL[f.severity],
    message: { text: `${f.message}. Fix: ${f.fix}` },
    locations: [{ physicalLocation: { artifactLocation: { uri: sarifUri(f.file) }, region: { startLine: Math.max(1, f.line || 1) } } }],
    partialFingerprints: { appManifestCheck: `${f.id}:${f.file}:${f.subject}` },
    properties: { category: f.category, platform: f.platform }
  }));
  const log = {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [{
      tool: { driver: { name: 'app-manifest-check', version: r.version, informationUri: INFO_URI, rules } },
      results
    }]
  };
  return JSON.stringify(log, null, 2) + '\n';
}
