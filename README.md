# ⬡ CYBER RADAR — veille cybersécurité live & classements

Agrégateur de veille cybersécurité **temps réel**, en un seul fichier statique, qui pull
des sources publiques et **classe** la menace du jour. Pour les équipes sécurité (SOC) comme
pour les particuliers.

**Live :** https://bpthevenot-hub.github.io/cyber-radar/

## Sources agrégées (fetch live, côté client)

| Bloc | Source | Public |
|---|---|---|
| CVE récentes par gravité | CIRCL CVE Search | Pros |
| Vulnérabilités activement exploitées | CISA KEV | Pros |
| Security Advisories | GitHub Advisories API | Pros |
| Menaces du jour | The Hacker News (RSS) | Tous |
| Grand public & arnaques | BleepingComputer (RSS) | Particuliers |
| Outils sécu qui montent | GitHub Search (stars) | Pros |
| Discussions sécurité | Hacker News (Algolia) | Tous |
| r/netsec top semaine | Reddit | Pros |

## Fonctionnement

- **Rafraîchissement automatique toutes les heures** (`setInterval`) + à chaque ouverture + bouton manuel.
- Chaque source = fetch **indépendant** avec timeout, et états *loading / vide / erreur* (lien direct en repli).
- Classements calculés côté client : CVSS, votes, stars, fraîcheur.
- Filtres par public : **Tout / Pros-SOC / Particuliers**.
- Aucune donnée personnelle collectée. 100 % open-data.

## Au-delà du catalogue statique

S'inspire et complète [`mukul975/Anthropic-Cybersecurity-Skills`](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)
(817 skills figées, un dossier par skill, mappées MITRE ATT&CK / NIST / D3FEND).
Là où le catalogue dit *« comment »*, CYBER RADAR dit *« quoi, maintenant »* — le flux vivant qui alimente les skills.

## Déploiement

Fichier unique `index.html`, zéro build. Servi par GitHub Pages.
Scripts de déploiement alternatifs (`deploy*.py`, non versionnés) pour Vercel / Netlify.
