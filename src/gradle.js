// Reads an Android module build file (build.gradle in Groovy, or build.gradle.kts in Kotlin) as text, to find
// a few settings by simple patterns. Nothing is evaluated: a value written as an expression, a variable or a
// version catalog entry is not worked out, and a note says so. docs/method.md lists the patterns.

const SDK_KEYS = {
  minSdk: ['minSdk', 'minSdkVersion'],
  targetSdk: ['targetSdk', 'targetSdkVersion'],
  compileSdk: ['compileSdk', 'compileSdkVersion']
};

// Comments are replaced by spaces (line breaks kept), so offsets and lines stay the same. Text inside "..."
// and '...' strings is left as it is.
export function blankComments(text) {
  const s = String(text);
  let out = '';
  let i = 0;
  let quote = null;
  while (i < s.length) {
    const c = s[i];
    if (quote) {
      out += c;
      if (c === '\\' && i + 1 < s.length) {
        out += s[i + 1];
        i += 2;
        continue;
      }
      if (c === quote || c === '\n') quote = null;
      i += 1;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      out += c;
      i += 1;
      continue;
    }
    if (c === '/' && s[i + 1] === '/') {
      while (i < s.length && s[i] !== '\n') {
        out += ' ';
        i += 1;
      }
      continue;
    }
    if (c === '/' && s[i + 1] === '*') {
      const end = s.indexOf('*/', i + 2);
      const stop = end < 0 ? s.length : end + 2;
      out += s.slice(i, stop).replace(/[^\n]/g, ' ');
      i = stop;
      continue;
    }
    out += c;
    i += 1;
  }
  return out;
}

function lineAt(s, pos) {
  let line = 1;
  for (let k = 0; k < pos && k < s.length; k += 1) if (s.charCodeAt(k) === 10) line += 1;
  return line;
}

// The index just after the "}" that closes the "{" at open, skipping strings; s.length when it is not closed.
function closeOf(s, open) {
  let depth = 0;
  let quote = null;
  for (let k = open; k < s.length; k += 1) {
    const c = s[k];
    if (quote) {
      if (c === '\\') k += 1;
      else if (c === quote || c === '\n') quote = null;
      continue;
    }
    if (c === '"' || c === "'") quote = c;
    else if (c === '{') depth += 1;
    else if (c === '}') {
      depth -= 1;
      if (depth === 0) return k + 1;
    }
  }
  return s.length;
}

// The first block "<header> {" in s between from and to, as { start, end, line } (start is just after "{").
function block(s, header, from = 0, to = s.length) {
  const re = new RegExp(`(?:^|[^A-Za-z0-9_.])(?:${header})[ \\t]*\\{`, 'g');
  re.lastIndex = from;
  const m = re.exec(s);
  if (!m || m.index >= to) return null;
  const open = m.index + m[0].length - 1;
  return { start: open + 1, end: Math.min(closeOf(s, open), to), line: lineAt(s, open) };
}

// name = value, name value, or name(value), at the start of a line.
function setting(s, names, from = 0, to = s.length) {
  const re = new RegExp(`^[ \\t]*(${names.join('|')})(?:[ \\t]*=[ \\t]*|[ \\t]*\\([ \\t]*|[ \\t]+)([^\\s)]+)`, 'gm');
  re.lastIndex = from;
  const found = [];
  for (let m = re.exec(s); m && m.index < to; m = re.exec(s)) found.push({ name: m[1], raw: m[2], line: lineAt(s, m.index + m[0].indexOf(m[1])) });
  return found;
}

function unquote(raw) {
  const m = /^(["'])(.*)\1$/.exec(raw);
  return m ? m[2] : null;
}

// Reads the text of a module build file. Returns
//   { kotlin, minSdk, targetSdk, compileSdk, namespace, applicationId, release, notes }
// where each SDK value is { value (a number or null), raw, line } or null, and release is
//   { line, minify: { value, line } | null, debuggable: { value, line } | null } or null.
export function parseGradle(text, label = 'build.gradle') {
  const s = blankComments(String(text).replace(/^\uFEFF/, ''));
  const kotlin = /\.kts$/i.test(label);
  const notes = [];
  const out = { kotlin, minSdk: null, targetSdk: null, compileSdk: null, namespace: null, applicationId: null, release: null, notes };
  for (const [key, names] of Object.entries(SDK_KEYS)) {
    const found = setting(s, names);
    if (!found.length) continue;
    const first = found[0];
    const value = /^\d{1,3}$/.test(first.raw) ? Number(first.raw) : null;
    out[key] = { value, raw: first.raw, line: first.line };
    if (value === null) notes.push(`${label}: line ${first.line}: ${first.name} is set from an expression (${first.raw.slice(0, 60)}), which is not worked out`);
    if (found.length > 1) notes.push(`${label}: ${first.name} is set ${found.length} times (product flavors or build types); the first, on line ${first.line}, is used`);
  }
  for (const key of ['namespace', 'applicationId']) {
    const found = setting(s, [key]);
    if (found.length) out[key] = unquote(found[0].raw);
  }
  const types = block(s, 'buildTypes');
  if (types) {
    const release = block(s, 'release|getByName\\([ \\t]*"release"[ \\t]*\\)|named\\([ \\t]*"release"[ \\t]*\\)|create\\([ \\t]*"release"[ \\t]*\\)', types.start, types.end);
    if (release) {
      const bool = (names) => {
        const re = new RegExp(`(?:^|[^A-Za-z0-9_.])(${names})(?:[ \\t]*=[ \\t]*|[ \\t]*\\([ \\t]*|[ \\t]+)(true|false)\\b`, 'g');
        re.lastIndex = release.start;
        const m = re.exec(s);
        if (!m || m.index >= release.end) return null;
        return { value: m[2] === 'true', line: lineAt(s, m.index + m[0].indexOf(m[1])) };
      };
      out.release = {
        line: release.line,
        minify: bool('isMinifyEnabled|minifyEnabled'),
        debuggable: bool('isDebuggable|debuggable')
      };
    }
  }
  return out;
}
