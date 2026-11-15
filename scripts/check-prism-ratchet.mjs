// Only Prism is implemented: the shrink-only ratchet of UOR-Foundation/template's audit-prism.
//
// Stitch's behavior belongs in its Prism model (app/src/*.lex.tex). Every other language that
// executes, hand-written JavaScript, Rust, Python, shell, CSS or HTML, may only shrink. The
// ceiling is the commit's first parent, measured rather than recorded: a pull request's merge
// commit has the base branch as first parent and main has the previous main, so a removal lowers
// it as it merges. Refused: a non-Prism file the parent lacks, and net growth in non-Prism lines
// (non-blank, outside comments, so explaining a decision is free). A shallow clone that hides
// the parent fails. The ratchet starts at the commit that installs it.
//
//   node scripts/check-prism-ratchet.mjs
import { execFileSync } from 'node:child_process';
import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const SELF = 'scripts/check-prism-ratchet.mjs';

// The model check (`scripts/check-model.mjs`, in `npm test`) refuses this file unless it is
// exactly what the Prism model generates, so it is Prism output.
export const PRISM_OUTPUTS = new Set(['src/layer1-uor/generated-model.js']);

const C = ['//', '/*', '*/'], HASH = ['#'], HTML = [null, '<!--', '-->'], LEAN = ['--', '/-', '-/'];
const LANGUAGES = {
  js: C, mjs: C, cjs: C, jsx: C, ts: C, tsx: C, mts: C, cts: C, rs: C, css: C, scss: C, c: C, h: C, cpp: C,
  html: HTML, py: HASH, sh: HASH, bash: HASH, awk: HASH, lean: LEAN,
};

export function language(path) {
  const name = path.split('/').pop();
  const dot = name.lastIndexOf('.');
  const extension = name.slice(dot + 1);
  return dot > 0 && Object.hasOwn(LANGUAGES, extension) ? LANGUAGES[extension] : undefined;
}

/** Non-blank lines outside comments. */
export function countLines(text, [line, open, close]) {
  let inBlock = false, count = 0;
  for (const raw of text.split('\n')) {
    let rest = raw.trim();
    if (inBlock) {
      const end = rest.indexOf(close);
      if (end < 0) continue;
      inBlock = false;
      rest = rest.slice(end + close.length).trim();
    }
    while (open && rest.startsWith(open)) {
      const end = rest.indexOf(close, open.length);
      if (end < 0) { inBlock = true; rest = ''; break; }
      rest = rest.slice(end + close.length).trim();
    }
    if (!rest || (line && rest.startsWith(line))) continue;
    count++;
  }
  return count;
}

export function measure(entries) {
  const files = new Map();
  for (const [path, text] of entries) {
    const syntax = language(path);
    if (syntax && !PRISM_OUTPUTS.has(path)) files.set(path, countLines(text, syntax));
  }
  return files;
}

const total = (files) => [...files.values()].reduce((a, b) => a + b, 0);

export function refusals(ceiling, current) {
  const out = [];
  const added = [...current.keys()].filter((path) => !ceiling.has(path));
  if (added.length) {
    out.push(`${added.length} new non-Prism file(s): ${added.slice(0, 20).join(', ')}${added.length > 20 ? ', ...' : ''}. Author the behavior in the Prism model (app/src/*.lex.tex).`);
  }
  const now = total(current), before = total(ceiling);
  if (now > before) {
    const grown = [...current].map(([path, n]) => [path, n - (ceiling.get(path) ?? 0)]).filter(([, d]) => d > 0)
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 10).map(([p, d]) => `${p} +${d}`);
    out.push(`non-Prism implementation grew by ${now - before} lines (${before} to ${now}); grown: ${grown.join(', ')}. It may only shrink: move the logic into the Prism model, or delete as much as you add.`);
  }
  return out;
}

const git = (...args) => execFileSync('git', args, { cwd: root, maxBuffer: 1 << 30 });

function worktree() {
  const entries = [];
  for (const path of git('ls-files', '-z', '--cached').toString().split('\0')) {
    if (!path || !language(path)) continue;
    const full = root + path;
    if (!existsSync(full) || lstatSync(full).isSymbolicLink() || !lstatSync(full).isFile()) continue;
    entries.push([path, readFileSync(full, 'utf8')]);
  }
  return measure(entries);
}

function commit(id) {
  const entries = [];
  for (const entry of git('ls-tree', '-r', '-z', id).toString().split('\0')) {
    const tab = entry.indexOf('\t');
    if (tab < 0) continue;
    const [mode, type, oid] = entry.slice(0, tab).split(' '), path = entry.slice(tab + 1);
    if (mode === '120000' || type !== 'blob' || !language(path)) continue;
    entries.push([path, git('cat-file', 'blob', oid).toString('utf8')]);
  }
  return measure(entries);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const current = worktree();
  let parent;
  try { parent = git('rev-parse', '--verify', '-q', 'HEAD^1^{commit}').toString().trim(); } catch { parent = null; }
  if (!parent) {
    if (git('rev-parse', '--is-shallow-repository').toString().startsWith('true')) {
      console.error('prism-ratchet: the clone is shallow, so the parent commit, the ratchet\'s ceiling, cannot be read; fetch at least depth 2');
      process.exit(1);
    }
    console.log(`prism-ratchet: a root commit; non-Prism implementation is ${total(current)} lines in ${current.size} files`);
  } else if (!git('ls-tree', '--name-only', parent, SELF).toString().trim()) {
    console.log(`prism-ratchet: installed here; the parent ran no ratchet, so this commit sets the ceiling: ${total(current)} lines in ${current.size} files`);
  } else {
    const ceiling = commit(parent);
    const refused = refusals(ceiling, current);
    if (refused.length) {
      console.error(`prism-ratchet: only Prism may be implemented here, measured against ${parent.slice(0, 12)}:\n  - ${refused.join('\n  - ')}`);
      process.exit(1);
    }
    console.log(`prism-ratchet: non-Prism implementation is ${total(current)} lines in ${current.size} files (${total(ceiling)} lines, ${ceiling.size} files in the parent); it only shrinks`);
  }
}
