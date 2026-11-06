import test from 'node:test';
import assert from 'node:assert/strict';
import { publishData, blobSha } from '../scripts/publish-data.mjs';
import { SOURCE_KEYS, validateData } from '../scripts/validate-data.mjs';

const now = Date.parse('2026-11-06T05:00:00Z');
const head = 'a'.repeat(40), next = 'b'.repeat(40);
function snapshot() {
  return {
    generatedAt: new Date(now).toISOString(),
    sources: Object.fromEntries(SOURCE_KEYS.map(key => [key, [{ title: `Item ${key}`, url: `https://example.com/${key}` }]])),
    status: Object.fromEntries(SOURCE_KEYS.map(key => [key, true])),
    kpis: { crit: 0, kev: 1, adv: 1, feed: 4 }, okCount: 8,
  };
}
const signature = { isValid: true, state: 'VALID', wasSignedByGitHub: true };
function api(replies) {
  const calls = [];
  return {
    calls,
    fetchImpl: async (url, init) => {
      calls.push({ url, ...init, body: JSON.parse(init.body) });
      const reply = replies.shift();
      if (reply instanceof Error) throw reply;
      assert.ok(reply, 'unexpected extra API call');
      return { ok: true, status: 200, json: async () => reply };
    },
  };
}
const read = (oid = head, blob = 'c'.repeat(40)) => ({ data: { repository: { ref: { target: { oid } }, object: { oid: blob } } } });
const created = (sig = signature) => ({ data: { createCommitOnBranch: { commit: { oid: next, signature: sig } } } });
const options = () => ({ content: JSON.stringify(snapshot()), repository: 'bpthevenot-hub/cyber-radar', expectedHeadOid: head, token: 'test-secret', now });

test('publishes only data.json atomically and verifies the resulting signature', async () => {
  const mock = api([read(), created()]);
  const result = await publishData({ ...options(), fetchImpl: mock.fetchImpl });
  assert.deepEqual(result, { published: true, sha: next });
  assert.equal(mock.calls.length, 2);
  const input = mock.calls[1].body.variables.input;
  assert.equal(input.expectedHeadOid, head);
  assert.deepEqual(input.branch, { repositoryNameWithOwner: 'bpthevenot-hub/cyber-radar', refName: 'main' });
  assert.deepEqual(input.fileChanges.additions.map(file => file.path), ['data.json']);
  assert.equal(Buffer.from(input.fileChanges.additions[0].contents, 'base64').toString(), options().content);
  assert.ok(mock.calls.every(call => call.url === 'https://api.github.com/graphql' && call.redirect === 'error'));
});

test('identical content produces no mutation', async () => {
  const mock = api([read(head, blobSha(options().content))]);
  assert.deepEqual(await publishData({ ...options(), fetchImpl: mock.fetchImpl }), { published: false, sha: head });
  assert.equal(mock.calls.length, 1);
});

test('concurrent update detected before publication produces no mutation', async () => {
  const mock = api([read(next)]);
  await assert.rejects(publishData({ ...options(), fetchImpl: mock.fetchImpl }), /main changed/);
  assert.equal(mock.calls.length, 1);
});

test('concurrent update during publication is rejected without force or retry', async () => {
  const mock = api([read(), { errors: [{ message: 'expectedHeadOid mismatch' }] }]);
  await assert.rejects(publishData({ ...options(), fetchImpl: mock.fetchImpl }), /publish refused/);
  assert.equal(mock.calls.length, 2);
});

test('unverified commit is never reported as successfully verified', async () => {
  const mock = api([read(), created(null)]);
  await assert.rejects(publishData({ ...options(), fetchImpl: mock.fetchImpl }), /Commit may exist/);
});

test('ambiguous mutation timeout is not retried and never prints the token', async () => {
  const mock = api([read(), new Error('test-secret')]);
  await assert.rejects(publishData({ ...options(), fetchImpl: mock.fetchImpl }), error => {
    assert.match(error.message, /inspect main before retrying/);
    assert.ok(!error.message.includes('test-secret'));
    return true;
  });
  assert.equal(mock.calls.length, 2);
});

test('API permission failure stops publication', async () => {
  let calls = 0;
  await assert.rejects(publishData({ ...options(), fetchImpl: async () => {
    calls++;
    return { ok: false, status: 403 };
  } }), /HTTP 403/);
  assert.equal(calls, 1);
});

test('all failed sources preserve the old published snapshot with zero API calls', async () => {
  const data = snapshot();
  data.sources = Object.fromEntries(SOURCE_KEYS.map(key => [key, []]));
  data.status = Object.fromEntries(SOURCE_KEYS.map(key => [key, false]));
  data.okCount = 0;
  data.kpis = { crit: 0, kev: 0, adv: 0, feed: 0 };
  const mock = api([]);
  await assert.rejects(publishData({ ...options(), content: JSON.stringify(data), fetchImpl: mock.fetchImpl }), /all sources failed/);
  assert.equal(mock.calls.length, 0);
});

test('partial source failure remains explicit and valid', () => {
  const data = snapshot();
  data.sources.reddit = []; data.status.reddit = false; data.okCount = 7; data.kpis.feed = 3;
  assert.equal(validateData(data, { now }).okCount, 7);
});

for (const [name, change, expected] of [
  ['unsafe link', d => { d.sources.thn[0].url = 'javascript:alert(1)'; }, /unsafe URL/],
  ['credential-bearing link', d => { d.sources.thn[0].url = 'https://user:secret@example.com/'; }, /unsafe URL/],
  ['invalid title', d => { d.sources.thn[0].title = 123; }, /title/],
  ['bad CVSS', d => { d.sources.cve[0].score = 11; }, /score/],
  ['lying status', d => { d.status.thn = false; }, /inconsistent status/],
  ['wrong total', d => { d.okCount = 7; }, /okCount/],
  ['wrong KPI', d => { d.kpis.feed = 200; }, /kpis.feed mismatch/],
  ['missing source', d => { delete d.sources.thn; }, /sources keys/],
  ['future date', d => { d.generatedAt = new Date(now + 600_000).toISOString(); }, /future/],
  ['stale snapshot', d => { d.generatedAt = new Date(now - 3_600_001).toISOString(); }, /too old/],
]) {
  test(`rejects ${name} before any API call`, async () => {
    const data = snapshot(); change(data);
    const mock = api([]);
    await assert.rejects(publishData({ ...options(), content: JSON.stringify(data), fetchImpl: mock.fetchImpl }), expected);
    assert.equal(mock.calls.length, 0);
  });
}

test('malformed JSON is not published', async () => {
  const mock = api([]);
  await assert.rejects(publishData({ ...options(), content: '{', fetchImpl: mock.fetchImpl }), SyntaxError);
  assert.equal(mock.calls.length, 0);
});
