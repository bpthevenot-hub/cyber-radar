export const SOURCE_KEYS = ['cve', 'kev', 'adv', 'thn', 'bleep', 'tools', 'hn', 'reddit'];

const requireValue = (condition, message) => {
  if (!condition) throw new Error(`Invalid data.json: ${message}`);
};
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);

// Publication requires fresh data; a rebuild may serve an older, known-good snapshot.
export function validateData(data, { now = Date.now(), maxAgeMs = Infinity } = {}) {
  requireValue(record(data), 'expected an object');
  const generated = Date.parse(data.generatedAt);
  requireValue(typeof data.generatedAt === 'string' && Number.isFinite(generated), 'generatedAt');
  requireValue(generated <= now + 5 * 60_000, 'generatedAt is in the future');
  requireValue(now - generated <= maxAgeMs, 'snapshot is too old to publish');
  requireValue(record(data.sources) && record(data.status), 'sources/status');
  for (const field of ['sources', 'status']) {
    requireValue(Object.keys(data[field]).sort().join(',') === [...SOURCE_KEYS].sort().join(','), `${field} keys`);
  }

  for (const key of SOURCE_KEYS) {
    const items = data.sources[key];
    requireValue(Array.isArray(items), `${key}: expected an array`);
    requireValue(typeof data.status[key] === 'boolean' && data.status[key] === (items.length > 0), `${key}: inconsistent status`);
    for (const item of items) {
      requireValue(record(item) && typeof item.title === 'string' && item.title.trim().length > 0, `${key}: title`);
      let url;
      try { url = new URL(item.url); } catch { /* rejected below */ }
      requireValue(typeof item.url === 'string' && url && ['http:', 'https:'].includes(url.protocol)
        && !url.username && !url.password, `${key}: unsafe URL`);
      if (item.score != null) requireValue(Number.isFinite(item.score) && item.score >= 0 && item.score <= 10, `${key}: score`);
      for (const metric of ['stars', 'points', 'comments']) {
        if (item[metric] != null) requireValue(Number.isInteger(item[metric]) && item[metric] >= 0, `${key}: ${metric}`);
      }
    }
  }
  const okCount = SOURCE_KEYS.filter(key => data.status[key]).length;
  requireValue(data.okCount === okCount, 'okCount');
  requireValue(okCount > 0, 'all sources failed; preserve the published snapshot');
  requireValue(record(data.kpis), 'kpis');
  for (const key of ['crit', 'kev', 'adv', 'feed']) {
    requireValue(Number.isInteger(data.kpis[key]) && data.kpis[key] >= 0, `kpis.${key}`);
  }
  requireValue(data.kpis.crit === data.sources.cve.filter(item => item.score != null && item.score >= 9).length, 'kpis.crit mismatch');
  requireValue(data.kpis.kev >= data.sources.kev.length, 'kpis.kev mismatch');
  requireValue(data.kpis.adv === data.sources.adv.length, 'kpis.adv mismatch');
  requireValue(data.kpis.feed === ['thn', 'bleep', 'hn', 'reddit'].reduce((n, key) => n + data.sources[key].length, 0), 'kpis.feed mismatch');
  return data;
}
