import { appendFile, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateData } from './validate-data.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SHA = /^[a-f0-9]{40}$/;
export function blobSha(content) {
  return createHash('sha1').update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest('hex');
}

export async function publishData({ content, repository, expectedHeadOid, token, fetchImpl = fetch, now = Date.now() }) {
  if (typeof content !== 'string' || Buffer.byteLength(content) > 1_000_000) throw new Error('Invalid data.json size');
  const data = validateData(JSON.parse(content), { now, maxAgeMs: 60 * 60_000 });
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository || '')) throw new Error('Invalid GITHUB_REPOSITORY');
  if (!SHA.test(expectedHeadOid || '')) throw new Error('Invalid expected branch head');
  if (typeof token !== 'string' || !token) throw new Error('Missing GitHub token');
  const [owner, name] = repository.split('/');

  async function graphql(query, variables, operation) {
    let response;
    try {
      response = await fetchImpl('https://api.github.com/graphql', {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(20_000),
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'User-Agent': 'cyber-radar-publisher' },
        body: JSON.stringify({ query, variables }),
      });
    } catch {
      // A timed-out mutation may already have succeeded. Never blindly retry it.
      throw new Error(`GitHub ${operation} transport failed; inspect main before retrying`);
    }
    if (!response.ok) throw new Error(`GitHub ${operation} HTTP ${response.status}; no automatic retry`);
    let result;
    try { result = await response.json(); } catch { throw new Error(`GitHub ${operation} returned invalid JSON`); }
    if (result.errors?.length || !result.data) {
      const detail = Array.isArray(result.errors) ? result.errors.slice(0, 2)
        .map(error => String(error.message || 'GraphQL error').replaceAll(token, '[redacted]').replace(/[\r\n]/g, ' ').slice(0, 300)).join('; ')
        : 'No response data';
      throw new Error(`GitHub ${operation} refused: ${detail}`);
    }
    return result.data;
  }

  const before = await graphql(`query Snapshot($owner: String!, $name: String!, $expression: String!) {
    repository(owner: $owner, name: $name) {
      ref(qualifiedName: "refs/heads/main") { id target { oid } }
      object(expression: $expression) { ... on Blob { oid } }
    }
  }`, { owner, name, expression: `${expectedHeadOid}:data.json` }, 'read');
  if (before.repository?.ref?.target?.oid !== expectedHeadOid) {
    throw new Error('main changed since checkout; discard this run and collect again from the new head');
  }
  const branchId = before.repository.ref.id;
  if (typeof branchId !== 'string' || !branchId) throw new Error('GitHub did not return the main branch ID');
  if (before.repository.object?.oid === blobSha(content)) return { published: false, sha: expectedHeadOid };

  // GitHub signs this API's commits. expectedHeadOid provides an atomic compare-and-swap.
  // Only data.json can be changed; no rebase, force push, custom author, or persistent key.
  const created = await graphql(`mutation Publish($input: CreateCommitOnBranchInput!) {
    createCommitOnBranch(input: $input) {
      commit { oid url signature { isValid state wasSignedByGitHub } }
    }
  }`, {
    input: {
      branch: { id: branchId },
      expectedHeadOid,
      message: { headline: `Refresh cyber feeds — ${data.generatedAt}` },
      fileChanges: { additions: [{ path: 'data.json', contents: Buffer.from(content).toString('base64') }] },
    },
  }, 'publish');
  const commit = created.createCommitOnBranch?.commit;
  if (!SHA.test(commit?.oid || '') || commit.signature?.isValid !== true
      || commit.signature?.state !== 'VALID' || commit.signature?.wasSignedByGitHub !== true) {
    throw new Error('Commit may exist but its GitHub signature was not verified; inspect main before deploying');
  }
  return { published: true, sha: commit.oid };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.env.GITHUB_REF !== 'refs/heads/main') throw new Error('Publication is restricted to main');
    const result = await publishData({
      content: await readFile(join(ROOT, 'data.json'), 'utf8'),
      repository: process.env.GITHUB_REPOSITORY,
      expectedHeadOid: process.env.EXPECTED_HEAD_SHA,
      token: process.env.GH_TOKEN || process.env.GITHUB_TOKEN,
    });
    if (process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, `published=${result.published}\nsha=${result.sha}\n`);
    console.log(result.published ? `Published verified commit ${result.sha}` : `No change: ${result.sha}`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
