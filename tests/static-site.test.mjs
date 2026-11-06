import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, mkdir, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Script } from 'node:vm';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { buildStatic, PUBLIC_FILES } from '../scripts/build-static.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'cyber-radar-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'combiner'));
  for (const file of PUBLIC_FILES) await writeFile(join(root, file), await readFile(join(ROOT, file)));
  return root;
}

test('build publishes exactly five original assets and excludes source/audit files', async t => {
  const root = await fixture(t);
  await writeFile(join(root, 'private.txt'), 'must not be published');
  await mkdir(join(root, 'public'));
  await writeFile(join(root, 'public', 'old.txt'), 'stale asset');
  const { output, files } = await buildStatic(root);
  assert.equal(files, 5);
  assert.deepEqual((await readdir(output)).sort(), ['combiner', 'data.json', 'index.html']);
  assert.deepEqual((await readdir(join(output, 'combiner'))).sort(), ['catalog.json', 'index.html', 'playbooks.json']);
  for (const file of PUBLIC_FILES) assert.deepEqual(await readFile(join(output, file)), await readFile(join(root, file)));
});

test('bad combiner reference rejects build before replacing previous output', async t => {
  const root = await fixture(t);
  await mkdir(join(root, 'public'));
  await writeFile(join(root, 'public', 'sentinel'), 'previous build');
  const playbooks = JSON.parse(await readFile(join(root, 'combiner/playbooks.json')));
  playbooks.playbooks[0].steps[0].slug = 'unknown-skill';
  await writeFile(join(root, 'combiner/playbooks.json'), JSON.stringify(playbooks));
  await assert.rejects(buildStatic(root), /unknown skill/);
  assert.equal(await readFile(join(root, 'public', 'sentinel'), 'utf8'), 'previous build');
});

test('both HTML pages contain syntactically valid inline JavaScript', async () => {
  let checked = 0;
  for (const file of ['index.html', 'combiner/index.html']) {
    const html = await readFile(join(ROOT, file), 'utf8');
    for (const [, attributes, source] of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
      if (!/\bsrc\s*=/.test(attributes) && source.trim()) { new Script(source, { filename: file }); checked++; }
    }
  }
  assert.ok(checked >= 4);
});

test('static HTTP delivery resolves both pages and their relative JSON paths', async t => {
  const root = await fixture(t);
  const { output } = await buildStatic(root);
  const server = createServer(async (request, response) => {
    const pathname = new URL(request.url, 'http://localhost').pathname;
    const file = pathname.endsWith('/') ? `${pathname}index.html`.slice(1) : pathname.slice(1);
    if (!PUBLIC_FILES.includes(file)) { response.writeHead(404); response.end(); return; }
    try {
      response.writeHead(200, { 'Content-Type': file.endsWith('.json') ? 'application/json' : 'text/html; charset=utf-8' });
      response.end(await readFile(join(output, file)));
    } catch { response.writeHead(500); response.end(); }
  });
  t.after(() => new Promise(resolveClose => { server.closeAllConnections(); server.close(resolveClose); }));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}/`;
  for (const file of ['', 'combiner/', 'data.json?t=test', 'combiner/catalog.json', 'combiner/playbooks.json']) {
    const response = await fetch(new URL(file, base));
    assert.equal(response.status, 200, file);
    if (file.includes('.json')) assert.ok(await response.json());
  }
  for (const page of ['', 'combiner/']) {
    const url = new URL(page, base);
    const html = await (await fetch(url)).text();
    for (const [, relative] of html.matchAll(/fetch\(['"]([^'"]+)/g)) {
      assert.equal((await fetch(new URL(relative, url))).status, 200, `${page}: ${relative}`);
    }
  }
  for (const file of ['package.json', 'scripts/fetch.mjs', 'security-audit/gmail_audit.py', '.github/workflows/refresh.yml']) {
    assert.equal((await fetch(new URL(file, base))).status, 404, file);
  }
});
