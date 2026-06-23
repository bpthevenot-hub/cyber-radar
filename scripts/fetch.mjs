#!/usr/bin/env node
/* CYBER RADAR — agrégateur côté serveur (GitHub Actions / local).
   Fetch toutes les sources cyber (pas de CORS côté serveur), normalise,
   classe, et écrit data.json (lu en même-origine par index.html). */
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const UA = 'cyber-radar/1.0 (+https://github.com/bpthevenot-hub/cyber-radar)';
const GH = process.env.GH_TOKEN || process.env.GITHUB_TOKEN || '';

const ghHeaders = { 'User-Agent': UA, 'Accept': 'application/vnd.github+json',
  ...(GH ? { Authorization: 'Bearer ' + GH } : {}) };

async function get(url, { headers = {}, json = true } = {}) {
  const r = await fetch(url, { headers: { 'User-Agent': UA, ...headers },
    signal: AbortSignal.timeout(20000) });
  if (!r.ok) throw new Error(`HTTP ${r.status} ${url}`);
  return json ? r.json() : r.text();
}
const clip = (s, n = 150) => (s || '').replace(/\s+/g, ' ').trim().slice(0, n);

function parseRSS(xml, n = 12) {
  const items = [];
  const blocks = xml.split(/<item[ >]/i).slice(1);
  for (const b of blocks.slice(0, n)) {
    const pick = (tag) => {
      const m = b.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, 'i'));
      if (!m) return '';
      return m[1].replace(/<!\[CDATA\[|\]\]>/g, '').replace(/<[^>]+>/g, '').trim();
    };
    const title = pick('title');
    let link = pick('link') || (b.match(/<link[^>]*>([\s\S]*?)<\/link>/i) || [])[1] || '';
    link = link.trim();
    const date = pick('pubDate') || pick('dc:date');
    if (title && link) items.push({ title: clip(title, 160), url: link, date: date || null });
  }
  return items;
}

function parseAtom(xml, n = 12) {
  const items = [];
  const blocks = xml.split(/<entry[ >]/i).slice(1);
  for (const b of blocks.slice(0, n)) {
    const tm = b.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    const title = tm ? tm[1].replace(/<!\[CDATA\[|\]\]>/g, '').replace(/<[^>]+>/g, '').trim() : '';
    const lm = b.match(/<link[^>]*href=["']([^"']+)["']/i);
    const url = lm ? lm[1] : '';
    const dm = b.match(/<(updated|published)[^>]*>([\s\S]*?)<\/\1>/i);
    if (title && url) items.push({ title: clip(title, 160), url, date: dm ? dm[2].trim() : null });
  }
  return items;
}

const SOURCES = {
  // 1) CVE récentes (CIRCL — format OSV : CVE dans aliases, sévérité via vecteur CVSS)
  async cve() {
    const data = await get('https://cve.circl.lu/api/last/60');
    const arr = Array.isArray(data) ? data : (data.results || data.cves || []);
    const sevMap = { CRITICAL: 9.5, HIGH: 7.5, MODERATE: 5, MEDIUM: 5, LOW: 2 };
    const out = arr.map((c) => {
      const cveId = (c.aliases || []).find((a) => /^CVE-/.test(a)) || (/^CVE-/.test(c.id || '') ? c.id : c.id);
      if (!cveId) return null;
      // score : vecteur CVSS (OSV) -> baseScore approximé, sinon sévérité textuelle
      let score = null;
      const sevArr = c.severity || c?.database_specific?.severity;
      try {
        if (Array.isArray(sevArr)) {
          for (const s of sevArr) {
            const m = String(s.score || '').match(/baseScore['":\s]+([\d.]+)/i);
            if (m) { score = Number(m[1]); break; }
          }
        }
        if (score == null) {
          const txt = String(c?.database_specific?.severity || '').toUpperCase();
          if (sevMap[txt] != null) score = sevMap[txt];
        }
      } catch {}
      const summary = c.summary || c.details || cveId;
      const date = c.published || c.modified || null;
      const linkId = /^CVE-/.test(cveId) ? cveId : cveId;
      return { title: `${cveId} — ${clip(summary, 140)}`,
        url: /^CVE-/.test(cveId) ? `https://www.cve.org/CVERecord?id=${cveId}` : `https://github.com/advisories/${cveId}`,
        score: score == null ? null : Number(score), date };
    }).filter(Boolean);
    // tri : score d'abord, puis date récente
    out.sort((a, b) => (b.score || 0) - (a.score || 0) || (new Date(b.date || 0) - new Date(a.date || 0)));
    return out.slice(0, 14);
  },
  // 2) CISA KEV
  async kev() {
    const data = await get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
    const v = (data.vulnerabilities || []).slice().reverse();
    SOURCES._kevCount = data.count || v.length;
    return v.slice(0, 14).map((x) => ({
      title: `${x.cveID} — ${clip(x.vulnerabilityName, 130)}`,
      url: `https://www.cve.org/CVERecord?id=${x.cveID}`,
      badge: 'EXPLOITÉE', badgeClass: 'b-crit', vendor: x.vendorProject || '', date: x.dateAdded || null,
    }));
  },
  // 3) GitHub Security Advisories
  async adv() {
    const data = await get('https://api.github.com/advisories?per_page=20&sort=published', { headers: ghHeaders });
    const sev = { critical: 9.5, high: 7.5, moderate: 5, low: 2 };
    return data.slice(0, 12).map((a) => ({
      title: clip(a.summary, 150), url: a.html_url || a.url,
      score: a?.cvss?.score ?? sev[a.severity] ?? null, ghsa: a.ghsa_id || '', date: a.published_at || null,
    }));
  },
  // 4) The Hacker News (RSS)
  async thn() {
    const xml = await get('https://feeds.feedburner.com/TheHackersNews', { json: false });
    return parseRSS(xml).slice(0, 12).map((i) => ({ ...i, badge: 'THREAT', badgeClass: 'b-high' }));
  },
  // 5) BleepingComputer (RSS) — grand public
  async bleep() {
    const xml = await get('https://www.bleepingcomputer.com/feed/', { json: false });
    return parseRSS(xml).slice(0, 12).map((i) => ({ ...i, badge: 'CONSO', badgeClass: 'b-low' }));
  },
  // 6) Outils sécu qui montent (GitHub stars)
  async tools() {
    const since = new Date(Date.now() - 45 * 864e5).toISOString().slice(0, 10);
    const q = encodeURIComponent(`topic:security created:>${since}`);
    const data = await get(`https://api.github.com/search/repositories?q=${q}&sort=stars&order=desc&per_page=20`, { headers: ghHeaders });
    return (data.items || []).slice(0, 12).map((r) => ({
      title: `${r.full_name} — ${clip(r.description, 110)}`, url: r.html_url,
      stars: r.stargazers_count, lang: r.language || '—',
    }));
  },
  // 7) Hacker News (Algolia — tri popularité)
  async hn() {
    const data = await get('https://hn.algolia.com/api/v1/search?query=security&tags=story&hitsPerPage=40');
    return (data.hits || []).filter((h) => h.title && h.url && (h.points || 0) >= 10).slice(0, 12).map((h) => ({
      title: clip(h.title, 150), url: h.url, points: h.points, comments: h.num_comments || 0,
      date: h.created_at || null,
    }));
  },
  // 8) Reddit r/netsec (flux Atom .rss — passe là où .json est bloqué)
  async reddit() {
    const xml = await get('https://www.reddit.com/r/netsec/.rss', { json: false,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; cyber-radar/1.0)', Accept: 'application/atom+xml' } });
    return parseAtom(xml, 14).slice(0, 12).map((i) => ({ ...i, badge: 'r/netsec', badgeClass: 'b-med' }));
  },
};

const out = { generatedAt: new Date().toISOString(), sources: {}, status: {}, kpis: {} };
const keys = ['cve', 'kev', 'adv', 'thn', 'bleep', 'tools', 'hn', 'reddit'];

const results = await Promise.allSettled(keys.map((k) => SOURCES[k]()));
keys.forEach((k, i) => {
  if (results[i].status === 'fulfilled') { out.sources[k] = results[i].value; out.status[k] = true; }
  else { out.sources[k] = []; out.status[k] = false; console.error(`[${k}]`, results[i].reason?.message || results[i].reason); }
});

out.kpis = {
  crit: (out.sources.cve || []).filter((x) => x.score != null && x.score >= 9).length,
  kev: SOURCES._kevCount || (out.sources.kev || []).length,
  adv: (out.sources.adv || []).length,
  feed: ['thn', 'bleep', 'hn', 'reddit'].reduce((n, k) => n + (out.sources[k] || []).length, 0),
};
out.okCount = Object.values(out.status).filter(Boolean).length;

writeFileSync(join(ROOT, 'data.json'), JSON.stringify(out, null, 1));
console.log(`data.json écrit — ${out.okCount}/${keys.length} sources OK, généré ${out.generatedAt}`);
