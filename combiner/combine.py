#!/usr/bin/env python3
"""Moteur de combinaison de skills cyber.
Entrée : un scénario (défini par ses techniques MITRE ATT&CK + domaines).
Sortie : la combinaison optimale de skills — sélection pondérée par rareté (idf),
diversité de domaine, et ordonnée par rôle (détecter→investiguer→chasser→répondre→durcir)."""
import json, os, math
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
cat = json.load(open(os.path.join(HERE, 'catalog.json')))['skills']
N = len(cat)

# idf des techniques : rare = discriminant
df = Counter(t for s in cat for t in set(s['mitre_attack']))
def idf(t): return math.log((N + 1) / (df.get(t, 0) + 1)) + 1

# rôle d'une skill, déduit du verbe d'action (proxy de phase)
VERB_ROLE = {
    'analyzing': 'investiguer', 'detecting': 'détecter', 'hunting': 'chasser',
    'performing': 'répondre', 'responding': 'répondre', 'implementing': 'durcir',
    'building': 'durcir', 'achieving': 'durcir', 'configuring': 'durcir', 'hardening': 'durcir',
    'exploiting': 'accès', 'abusing': 'escalader', 'testing': 'tester', 'attacking': 'accès',
    'reconnaissance': 'recon', 'enumerating': 'recon', 'scanning': 'recon',
}
ROLE_ORDER_DEF = ['recon', 'détecter', 'investiguer', 'chasser', 'répondre', 'durcir', 'tester', 'accès', 'escalader']
ROLE_ORDER_OFF = ['recon', 'accès', 'escalader', 'tester', 'investiguer', 'chasser', 'répondre', 'détecter', 'durcir']

def role(s): return VERB_ROLE.get(s['verb'], 'investiguer')

# ---- scénarios : signature = techniques ATT&CK clés + domaines préférés ----
SCENARIOS = [
    {'id':'ransomware', 'title':'Réponse à incident — Ransomware', 'type':'defense',
     'icon':'🔒', 'desc':"De l'accès initial au chiffrement : contenir, investiguer, éradiquer, restaurer.",
     'attack':['T1486','T1490','T1566','T1059','T1078','T1003','T1071','T1567','T1048','T1547','T1055'],
     'subs':['digital-forensics','malware-analysis','threat-hunting','soc-operations','incident-response','threat-intelligence']},
    {'id':'ad-compromise', 'title':'Compromission Active Directory', 'type':'defense',
     'icon':'🏛️', 'desc':"Vol d'identifiants, élévation et mouvement latéral dans un domaine Windows.",
     'attack':['T1078','T1003','T1558','T1550','T1207','T1484','T1098','T1021','T1555','T1110'],
     'subs':['identity-access-management','threat-hunting','digital-forensics','soc-operations']},
    {'id':'cloud-breach', 'title':'Intrusion Cloud (AWS / Azure / GCP)', 'type':'cloud',
     'icon':'☁️', 'desc':"Accès via identités cloud, exfiltration de stockage, persistance serverless.",
     'attack':['T1078','T1190','T1530','T1538','T1526','T1580','T1098','T1496','T1619'],
     'subs':['cloud-security','container-security','identity-access-management','soc-operations']},
    {'id':'web-pentest', 'title':'Audit offensif — Application web', 'type':'offense',
     'icon':'🕸️', 'desc':"Reconnaissance, exploitation OWASP, post-exploitation d'une appli exposée.",
     'attack':['T1190','T1059','T1505','T1071','T1083','T1212','T1552','T1133'],
     'subs':['web-application-security','red-teaming','network-security']},
    {'id':'threat-hunt', 'title':'Threat hunting proactif', 'type':'defense',
     'icon':'🎯', 'desc':"Chasser un adversaire furtif : C2, persistance, exfil, sans alerte préalable.",
     'attack':['T1071','T1055','T1547','T1053','T1543','T1567','T1090','T1027','T1070'],
     'subs':['threat-hunting','threat-intelligence','soc-operations','digital-forensics']},
    {'id':'phishing', 'title':'Campagne de phishing — détection & réponse', 'type':'defense',
     'icon':'🎣', 'desc':"De l'email piégé à la charge utile : analyser, détecter, durcir.",
     'attack':['T1566','T1204','T1059','T1547','T1071','T1114','T1598'],
     'subs':['threat-intelligence','soc-operations','malware-analysis','digital-forensics']},
    {'id':'compliance', 'title':'Conformité — NIST CSF / CMMC', 'type':'compliance',
     'icon':'📋', 'desc':"Mettre en place et prouver des contrôles défensifs alignés aux référentiels.",
     'attack':['T1078','T1190','T1110','T1486'],
     'subs':['governance-risk-compliance','security-operations','identity-access-management','cloud-security']},
    {'id':'malware-analysis', 'title':'Analyse de malware (poste à poste)', 'type':'defense',
     'icon':'🦠', 'desc':"Triage, sandbox, rétro-ingénierie et extraction d'IOC d'un échantillon.",
     'attack':['T1055','T1027','T1059','T1071','T1547','T1564','T1497','T1620'],
     'subs':['malware-analysis','digital-forensics','threat-intelligence']},
]

def build(scn, size=8):
    tset = set(scn['attack']); subs = set(scn['subs'])
    scored = []
    for s in cat:
        att = set(s['mitre_attack']) & tset
        score = sum(idf(t) for t in att)
        if s['subdomain'] in subs: score += 2.5
        if not att and s['subdomain'] not in subs: continue
        scored.append((score, s, sorted(att)))
    scored.sort(key=lambda x: -x[0])
    # sélection avec diversité de domaine (max 2 par sous-domaine) + diversité de rôle
    chosen, sub_count = [], Counter()
    for score, s, att in scored:
        if sub_count[s['subdomain']] >= 2: continue
        chosen.append((score, s, att)); sub_count[s['subdomain']] += 1
        if len(chosen) >= size: break
    order = ROLE_ORDER_OFF if scn['type'] == 'offense' else ROLE_ORDER_DEF
    chosen.sort(key=lambda x: (order.index(role(x[1])) if role(x[1]) in order else 99, -x[0]))
    steps = []
    for score, s, att in chosen:
        why = (f"couvre {', '.join(att)}" if att else f"domaine {s['subdomain']}")
        steps.append({'slug': s['slug'], 'name': s['name'], 'role': role(s),
                      'subdomain': s['subdomain'], 'verb': s['verb'],
                      'attack': s['mitre_attack'][:5], 'covers': att,
                      'why': why, 'score': round(score, 2),
                      'url': f"https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/{s['slug']}"})
    covered = set()
    for st in steps: covered |= set(st['covers'])
    return {'id': scn['id'], 'title': scn['title'], 'type': scn['type'], 'icon': scn['icon'],
            'desc': scn['desc'], 'targetAttack': scn['attack'],
            'coverage': sorted(covered), 'steps': steps}

playbooks = [build(s) for s in SCENARIOS]
json.dump({'count': len(playbooks), 'playbooks': playbooks},
          open(os.path.join(HERE, 'playbooks.json'), 'w'), ensure_ascii=False)

# aperçu
for p in playbooks[:2]:
    print(f"\n=== {p['icon']} {p['title']}  (couvre {len(p['coverage'])} techniques) ===")
    for i, st in enumerate(playbooks[0]['steps'] if False else p['steps'], 1):
        print(f" {i}. [{st['role']:11s}] {st['slug']}")
        print(f"      {st['why']}")
print(f"\n{len(playbooks)} playbooks écrits -> playbooks.json")
