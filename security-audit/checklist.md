# ✅ Checklist d'audit manuel par compte

Vérifications 100 % lecture seule, réalisables sans aucun outil, depuis les consoles
officielles. Coche au fur et à mesure. Reporte les anomalies dans le tableau final.

## A. Google — pour CHAQUE compte Gmail

| # | Vérification | URL | Anomalie si… |
|---|---|---|---|
| A1 | Appareils & sessions actives | myaccount.google.com/device-activity | Appareil/lieu/navigateur inconnu, connexion simultanée incohérente |
| A2 | Événements de sécurité récents | myaccount.google.com/notifications | Connexion inhabituelle, changement non initié |
| A3 | Applications tierces OAuth | myaccount.google.com/connections | App inconnue, accès Gmail/Drive complet — voir `oauth_review.md` |
| A4 | **Transfert automatique** | Gmail → Paramètres → Transfert et POP/IMAP | Adresse de transfert inconnue |
| A5 | **Filtres** | Gmail → Paramètres → Filtres et adresses bloquées | Filtre qui supprime/archive/marque-lu ou redirige des mails *security/code/facture* |
| A6 | Délégation de compte | Gmail → Paramètres → Comptes → « Accorder l'accès » | Délégué inconnu |
| A7 | « Envoyer en tant que » | Gmail → Paramètres → Comptes | Alias/identité inconnue |
| A8 | POP / IMAP | Gmail → Paramètres → Transfert et POP/IMAP | POP/IMAP activé sans raison |
| A9 | Validation en 2 étapes + méthodes | myaccount.google.com/signinoptions/two-step-verification | 2SV désactivée ; clé d'accès/2FA inconnue |
| A10 | E-mail & téléphone de récupération | myaccount.google.com/signinoptions/rescue | Adresse/numéro de secours inconnu |
| A11 | Mots de passe d'application | même page 2SV | App password inconnu |
| A12 | Bilan global | myaccount.google.com/security-checkup | Tout point rouge/jaune |

> Les scripts `gmail_audit.py` couvrent A3–A8 automatiquement. A1–A2, A9–A12 restent manuels
> (pas d'API grand public fiable pour les journaux de connexion).

## B. Microsoft / Outlook (perso + TBS)

| # | Vérification | URL / chemin | Anomalie si… |
|---|---|---|---|
| B1 | Activité de connexion & appareils | account.microsoft.com/security | Connexion/lieu inconnu |
| B2 | Règles de boîte | Outlook → Paramètres → Courrier → Règles | Règle de transfert/redirection/suppression inconnue |
| B3 | Transfert de boîte | Outlook → Paramètres → Courrier → Transfert | Transfert vers adresse externe |
| B4 | Méthodes de sécurité (MFA) | account.microsoft.com/security | Méthode/téléphone inconnu |
| B5 | Alias & récupération | account.live.com | Alias/e-mail de secours inconnu |
| B6 | Apps consenties | myapps.microsoft.com | App inconnue à privilèges mail |
| B7 | (TBS) accès délégués / boîtes partagées | dépend de l'admin | Délégué inconnu |

> `graph_audit.py` couvre B2, B3, B6 (selon scopes). Pour TBS, certaines lectures exigent
> l'admin : prépare une demande précise au support informatique de l'école.

## C. macOS (à faire sur le Mac lui-même)

- [ ] Extensions Chrome (`chrome://extensions`) : retire celles inconnues avec accès à
      `mail.google.com` / « lire et modifier vos données sur tous les sites ».
- [ ] Profils Chrome : `chrome://settings/people` — aucun profil géré/inconnu.
- [ ] Éléments d'ouverture de session : Réglages → Général → Éléments d'ouverture.
- [ ] Profils de configuration : Réglages → Confidentialité → Profils (aucun inattendu).
- [ ] Accès sensibles : Réglages → Confidentialité → **Accès complet au disque**,
      **Accessibilité**, **Enregistrement de l'écran** — retire tout logiciel inconnu.
- [ ] Apps d'accès distant / prise en main (TeamViewer, AnyDesk, VNC…) non installées par toi.
- [ ] LaunchAgents / LaunchDaemons : `ls -la ~/Library/LaunchAgents /Library/LaunchAgents
      /Library/LaunchDaemons` — rien d'inconnu.
- [ ] DNS / Proxy / VPN : Réglages → Réseau — pas de DNS/proxy imposé inconnu.
- [ ] Téléchargements liés à des mails suspects : `~/Downloads` — pas d'exécutable/archive douteux.

## Tableau récapitulatif — État par compte

| Compte | Niveau de risque | Incident confirmé (O/N) | Corrigé (O/N) | Action restante |
|---|---|---|---|---|
| ___ |  |  |  |  |
| ___ |  |  |  |  |
| ___ |  |  |  |  |

## Classement des constats (rappel §13)

`CONFIRMÉ` / `PROBABLE` / `POSSIBLE` / `NON PROUVÉ` / `FAUX POSITIF` /
`NON VÉRIFIABLE AVEC LES ACCÈS ACTUELS` — gravité `CRITIQUE`→`INFORMATION`.
Un spam reçu **n'est pas** une compromission.
