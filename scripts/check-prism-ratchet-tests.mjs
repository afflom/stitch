// The ratchet's planted defects: each must be refused, and what Prism or comments add must not.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { countLines, language, measure, refusals } from './check-prism-ratchet.mjs';

test('counts code, not comments or blank lines', () => {
  assert.equal(countLines('// why\n/* a\n b */\nconst a = 1;\n\n/* x */ let b;\n', language('a.js')), 2);
  assert.equal(countLines('#!/bin/sh\n# why\necho hi\n', language('a.sh')), 1);
  assert.equal(countLines('<!--\n x -->\n<p>a</p>\n', language('a.html')), 1);
});

test('Prism, data and the generated model are not counted', () => {
  const m = measure([['app/src/Stitch.lex.tex', 'def a := 1\n'], ['product/facets.json', '{}\n'], ['src/layer1-uor/generated-model.js', 'x()\n'], ['src/a.js', 'a()\n'], ['src/a.constructor', 'x\n']]);
  assert.deepEqual([...m.keys()], ['src/a.js']);
});

test('refuses a new non-Prism file', () => {
  const refused = refusals(measure([['src/a.js', 'a()\nb()\n']]), measure([['src/a.js', 'a()\n'], ['src/b.js', 'b()\n']]));
  assert.equal(refused.length, 1);
  assert.match(refused[0], /src\/b\.js/);
});

test('refuses net growth and names what grew', () => {
  const refused = refusals(measure([['src/a.js', 'a()\nb()\n'], ['src/c.js', 'c()\n']]), measure([['src/a.js', 'a()\n'], ['src/c.js', 'c()\nd()\ne()\nf()\n']]));
  assert.equal(refused.length, 1);
  assert.match(refused[0], /grew by 2 lines \(3 to 5\); grown: src\/c\.js \+3\./);
});

test('admits shrinking, growth paid for by deletion, and comments', () => {
  const before = measure([['src/a.js', 'a()\nb()\n'], ['src/c.js', 'c()\n']]);
  assert.deepEqual(refusals(before, measure([['src/a.js', 'a()\nb()\nd()\n']])), []);
  assert.deepEqual(refusals(before, measure([['src/a.js', '// why\n\na()\nb()\n'], ['src/c.js', 'c()\n']])), []);
});
