# 🛡️ security-audit — boîte à outils d'audit défensif de comptes (read-only)

Outillage **défensif**, **en lecture seule par défaut**, pour auditer *ses propres* comptes
e-mail et repérer les signes classiques de compromission : règles de transfert cachées,
filtres qui masquent les alertes de sécurité, applications OAuth abusives, délégations,
accès POP/IMAP, sessions et appareils inconnus.

> ⚠️ **Usage strictement personnel et autorisé.** N'exécute ces scripts que sur des comptes
> qui t'appartiennent ou pour lesquels tu disposes d'une autorisation explicite. Aucun script
> ici ne contourne d'authentification, ne force de mot de passe, ni ne modifie de compte :
> ils **lisent** des paramètres via les API officielles (OAuth) et produisent un rapport.

## Contenu

| Fichier | Rôle |
|---|---|
| `gmail_audit.py` | Audit read-only d'un compte Google/Gmail (transferts, filtres, délégués, sendAs, POP/IMAP, vacation) + scoring de filtres suspects |
| `graph_audit.py` | Audit read-only d'un compte Microsoft 365 / Outlook via Graph (règles de boîte, transfert, OAuth grants, appareils) |
| `redact.py` | Masquage des données sensibles (codes OTP, jetons, e-mails) dans les sorties |
| `oauth_review.md` | Procédure de revue + révocation des applications OAuth Google/Microsoft |
| `checklist.md` | Checklist manuelle par compte (Google / Microsoft / macOS / iPhone) |
| `voicemail-diagnostic.md` | Arbre de décision + protocole de test pour une messagerie vocale qui ne remonte plus |
| `requirements.txt` | Dépendances Python épinglées |

## Modèle de sécurité

- **Lecture seule** : les scripts n'appellent que des endpoints `GET`/`list`/`get`. Ils
  n'écrivent, ne suppriment et ne modifient jamais rien.
- **Aucun secret en dur** : les identifiants OAuth sont fournis via variables d'environnement
  ou fichier `credentials.json` local (jamais committé — voir `.gitignore`).
- **Masquage automatique** : tout code de vérification, jeton ou clé détecté est masqué dans
  les sorties CSV/JSON (`redact.py`).
- **Traces** : chaque exécution produit un rapport horodaté dans `./out/` (non committé).

### Note sur les scopes Google

Google ne propose pas de scope « paramètres en lecture seule ». Pour **lire** les filtres,
transferts et sendAs, il faut le scope `gmail.settings.basic`, qui autorise techniquement
l'écriture. **Ces scripts n'écrivent jamais** — ils n'appellent que les méthodes `.get()` /
`.list()`. Tu peux le vérifier : aucune méthode `create`, `update`, `delete`, `patch`.

## Prérequis

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Google (Gmail)
1. Crée un projet sur https://console.cloud.google.com/ → « APIs & Services ».
2. Active **Gmail API**.
3. Crée des identifiants **OAuth 2.0 Client ID** de type *Desktop app*.
4. Télécharge le `credentials.json` dans ce dossier.
5. Lance : `python gmail_audit.py --account bp.thevenot@gmail.com`
   Un navigateur s'ouvre pour le consentement (compte que TU contrôles).

### Microsoft (Outlook / 365)
1. Enregistre une application sur https://entra.microsoft.com/ → « App registrations ».
2. Type *Public client* ; ajoute les **delegated permissions** read-only listées dans
   `graph_audit.py` ; autorise le *device code flow*.
3. Lance : `MS_CLIENT_ID=xxxx MS_TENANT=common python graph_audit.py`
   Le script affiche un code de périphérique à saisir sur https://microsoft.com/devicelogin.

## Ce que les scripts NE peuvent pas faire seuls

- Les **journaux de connexion** détaillés Google/Microsoft et la révocation de sessions se
  font dans les consoles web (voir `checklist.md`).
- Sur un **tenant TBS / entreprise**, certaines lectures exigent un rôle admin : le script le
  signale proprement au lieu d'échouer.
- La **messagerie vocale / SIM / opérateur** ne sont pas des objets d'API e-mail :
  voir `voicemail-diagnostic.md`.
