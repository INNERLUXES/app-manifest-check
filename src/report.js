// Report formats: text for a terminal, Markdown for a pull request or job summary, JSON for other tools,
// CSV for a spreadsheet. SARIF is in sarif.js.

function plural(count, one, many = `${one}s`) {
  return `${count.toLocaleString('en-US')} ${count === 1 ? one : many}`;
}

function countsLine(c) {
  return `${c.error} error, ${c.warning} warning, ${c.info} info`;
}

// The facts line of a platform summary.
export function platformLine(p) {
  if (p.platform === 'android') {
    return [
      `package ${p.package ?? '(not set)'}`,
      `minSdk ${p.minSdk ?? '-'}`,
      `targetSdk ${p.targetSdk ?? '-'}`,
      `compileSdk ${p.compileSdk ?? '-'}`,
      `${plural(p.components, 'component')} (${p.exported} exported)`,
      plural(p.permissions, 'permission')
    ].join('; ');
  }
  const parts = [
    `bundle id ${p.bundleId ?? '(not set)'}`,
    plural(p.usageDescriptions, 'usage description'),
    plural(p.urlSchemes, 'URL scheme'),
    plural(p.backgroundModes, 'background mode')
  ];
  if (p.entitlements !== null) parts.push(plural(p.entitlements, 'entitlement'));
  return parts.join('; ');
}

function where(f) {
  return `${f.file}:${f.line}`;
}

function gateLine(r) {
  return r.gate.pass ? `GATE: PASS (--fail-on ${r.gate.failOn})` : `GATE: FAIL - ${r.gate.reason}`;
}

export function toText(r) {
  const lines = [`app-manifest-check: ${r.platforms.map((p) => p.platform).join(', ')}`];
  for (const p of r.platforms) {
    lines.push(`${p.platform}: ${p.files.join(', ')}`, `  ${platformLine(p)}`, `  findings: ${countsLine(p.counts)}`);
  }
  lines.push(`findings: ${countsLine(r.counts)}`);
  if (!r.findings.length) lines.push('', 'no findings');
  for (const f of r.findings) {
    lines.push('', `${f.severity.toUpperCase().padEnd(7)}  ${f.id} (${f.category})  ${where(f)}`, `         ${f.message}`, `         fix: ${f.fix}`);
  }
  if (r.notes.length) lines.push('');
  for (const note of r.notes) lines.push(`note: ${note}`);
  lines.push('', gateLine(r));
  return lines.join('\n') + '\n';
}

// A Markdown table cell: backslashes and pipes escaped, line breaks flattened, and <, > and & written as
// entities, so text from an input file cannot break the table or be read as HTML (<application> would
// otherwise vanish from a rendered report).
export function mdCell(t) {
  return String(t)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n|\r/g, ' ');
}

export function toMarkdown(r) {
  const lines = [`## app-manifest-check: ${countsLine(r.counts)}`, '', '| Platform | Files | Settings | Findings |', '| --- | --- | --- | --- |'];
  for (const p of r.platforms) lines.push(`| ${p.platform} | ${mdCell(p.files.join(', '))} | ${mdCell(platformLine(p))} | ${countsLine(p.counts)} |`);
  if (!r.findings.length) lines.push('', 'No findings.');
  else {
    lines.push('', '| Severity | Check | MASVS | Where | Message | Fix |', '| --- | --- | --- | --- | --- | --- |');
    for (const f of r.findings) lines.push(`| ${f.severity} | ${mdCell(f.id)} | ${f.category} | ${mdCell(where(f))} | ${mdCell(f.message)} | ${mdCell(f.fix)} |`);
  }
  if (r.notes.length) lines.push('');
  for (const note of r.notes) lines.push(`- ${mdCell(note)}`);
  lines.push('', r.gate.pass ? `**Gate passed** (--fail-on ${r.gate.failOn}).` : `**Gate failed:** ${mdCell(r.gate.reason)}.`);
  return lines.join('\n') + '\n';
}

export function toJson(r) {
  return JSON.stringify(r, null, 2) + '\n';
}

// RFC 4180 quoting, and a leading quote on cells a spreadsheet would read as a formula.
export function csvCell(value) {
  let s = value === null || value === undefined ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

// One row per finding.
export function toCsv(r) {
  const rows = [['platform', 'severity', 'id', 'category', 'file', 'line', 'subject', 'message', 'fix']];
  for (const f of r.findings) rows.push([f.platform, f.severity, f.id, f.category, f.file, String(f.line), f.subject, f.message, f.fix]);
  return rows.map((row) => row.map(csvCell).join(',')).join('\r\n') + '\r\n';
}
