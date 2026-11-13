/**
 * Return CISA KEV records ordered by dateAdded (most recently added first).
 * Never infer order from the provider's array order; keep unknown dates last.
 * This module deliberately performs no I/O, making it safe to unit-test.
 */
export function newestKev(records, limit = 14) {
  if (!Array.isArray(records)) return [];
  const stamp = (record) => {
    const time = Date.parse(record?.dateAdded || '');
    return Number.isFinite(time) ? time : Number.NEGATIVE_INFINITY;
  };
  return records
    .filter((record) => record && typeof record.cveID === 'string' && record.cveID.startsWith('CVE-'))
    .slice()
    .sort((a, b) => {
      const timeDiff = stamp(b) - stamp(a);
      if (!Number.isNaN(timeDiff) && timeDiff !== 0) return timeDiff;
      // Includes equal dates and unknown/unknown dates.
      return a.cveID.localeCompare(b.cveID);
    })
    .slice(0, limit);
}
