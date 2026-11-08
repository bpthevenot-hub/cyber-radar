import test from 'node:test';
import assert from 'node:assert/strict';
import { newestKev } from '../scripts/kev.mjs';

test('CISA KEV feed displays most recently added records irrespective of source order', () => {
  const input = [
    { cveID: 'CVE-2020-0001', dateAdded: '2021-11-03' },
    { cveID: 'CVE-2025-0001', dateAdded: '2025-08-11' },
    { cveID: 'CVE-2026-0002', dateAdded: '2026-11-07' },
    { cveID: 'CVE-2026-0001', dateAdded: '2026-11-07' },
  ];
  assert.deepEqual(newestKev(input).map(x => x.cveID), [
    'CVE-2026-0001', 'CVE-2026-0002', 'CVE-2025-0001', 'CVE-2020-0001',
  ]);
  assert.equal(input[0].cveID, 'CVE-2020-0001', 'caller array is not mutated');
});

test('undated or invalid records are handled explicitly and never outrank dated entries', () => {
  const records = [
    { cveID: 'CVE-2025-0001' },
    { cveID: 'CVE-2026-0001', dateAdded: '2026-11-07' },
    { cveID: 'CVE-2024-0001', dateAdded: 'not-a-date' },
    { cveID: 'NOCVE', dateAdded: '2026-11-08' },
    null,
  ];
  assert.deepEqual(newestKev(records, 2).map(x => x.cveID), [
    'CVE-2026-0001', 'CVE-2024-0001',
  ]);
  assert.deepEqual(newestKev(undefined), []);
});
