#!/usr/bin/env python3
"""Parse les 817 SKILL.md -> catalog.json (index structuré) + graphe de combinaison.
La 'meilleure combinaison' = skills reliées par techniques MITRE ATT&CK / contrôles NIST CSF partagés."""
import os, re, json, glob
from collections import defaultdict, Counter

SRC = os.path.expanduser('~/cyber-skills-catalog/skills')
OUT = os.path.dirname(os.path.abspath(__file__))

def parse_frontmatter(txt):
    m = re.search(r'^---\s*\n(.*?)\n---', txt, re.S)
    if not m: return {}
    fm, cur = {}, None
    for line in m.group(1).split('\n'):
        if re.match(r'^[a-zA-Z_]+:', line):
            key = line.split(':', 1)[0].strip()
            rest = line.split(':', 1)[1].strip()
            cur = key
            fm[key] = rest if rest and rest != '' else []
        elif re.match(r'^\s*-\s+', line) and cur:
            if not isinstance(fm.get(cur), list): fm[cur] = []
            fm[cur].append(re.sub(r'^\s*-\s+', '', line).strip())
    return fm

skills = []
for path in sorted(glob.glob(os.path.join(SRC, '*', 'SKILL.md'))):
    slug = os.path.basename(os.path.dirname(path))
    fm = parse_frontmatter(open(path, encoding='utf-8', errors='ignore').read())
    def lst(k):
        v = fm.get(k, [])
        return v if isinstance(v, list) else ([v] if v else [])
    desc = fm.get('description', '')
    if isinstance(desc, list): desc = ' '.join(desc)
    skills.append({
        'slug': slug,
        'name': fm.get('name', slug) if not isinstance(fm.get('name'), list) else slug,
        'verb': slug.split('-')[0],                       # analyzing / abusing / achieving...
        'domain': fm.get('domain', '') if not isinstance(fm.get('domain'), list) else '',
        'subdomain': fm.get('subdomain', '') if not isinstance(fm.get('subdomain'), list) else '',
        'tags': lst('tags'),
        'nist_csf': lst('nist_csf'),
        'mitre_attack': [t.split('.')[0] for t in lst('mitre_attack')],  # technique racine
        'attack_full': lst('mitre_attack'),
        'desc': re.sub(r'\s+', ' ', desc)[:240],
    })

# ----- graphe de combinaison : arête si >=2 techniques ATT&CK OU >=2 contrôles NIST partagés -----
edges = []
for i in range(len(skills)):
    for j in range(i + 1, len(skills)):
        a, b = skills[i], skills[j]
        sh_att = set(a['mitre_attack']) & set(b['mitre_attack'])
        sh_nist = set(a['nist_csf']) & set(b['nist_csf'])
        w = len(sh_att) * 2 + len(sh_nist)
        if len(sh_att) >= 2 or len(sh_nist) >= 2:
            edges.append({'a': a['slug'], 'b': b['slug'], 'w': w,
                          'attack': sorted(sh_att), 'nist': sorted(sh_nist)})

catalog = {'count': len(skills), 'skills': skills}
json.dump(catalog, open(os.path.join(OUT, 'catalog.json'), 'w'), ensure_ascii=False)
json.dump({'count': len(edges), 'edges': edges}, open(os.path.join(OUT, 'graph.json'), 'w'), ensure_ascii=False)

# ----- stats -----
sub = Counter(s['subdomain'] for s in skills if s['subdomain'])
verb = Counter(s['verb'] for s in skills)
att = Counter(t for s in skills for t in s['mitre_attack'])
with_att = sum(1 for s in skills if s['mitre_attack'])
with_nist = sum(1 for s in skills if s['nist_csf'])

print(f"skills parsées : {len(skills)}")
print(f"  avec mapping ATT&CK : {with_att} | avec NIST CSF : {with_nist}")
print(f"  arêtes de combinaison : {len(edges)}")
print(f"\nTop 12 sous-domaines :")
for k, v in sub.most_common(12): print(f"  {v:3d}  {k}")
print(f"\nTop 8 verbes d'action :")
for k, v in verb.most_common(8): print(f"  {v:3d}  {k}")
print(f"\nTop 10 techniques ATT&CK couvertes :")
for k, v in att.most_common(10): print(f"  {v:3d} skills  {k}")
