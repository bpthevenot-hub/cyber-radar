#!/usr/bin/env python3
"""Audit read-only d'un compte Microsoft 365 / Outlook via Microsoft Graph.

Ne modifie jamais rien : uniquement des appels GET. Signale proprement les objets
inaccessibles (scopes admin manquants) au lieu d'échouer — utile pour un compte
institutionnel (ex. TBS) où certaines lectures dépendent de l'administrateur.

Objets audités
--------------
- Règles de boîte de réception (/mailFolders/inbox/messageRules) + scoring
- Réglage de transfert de la boîte (mailboxSettings)
- Applications OAuth consenties par l'utilisateur (/oauth2PermissionGrants)
- Appareils enregistrés (/me/registeredDevices)
- Profil (/me)

Auth : device code flow (public client), scopes DELEGATED read-only.

Usage
-----
    pip install -r requirements.txt
    export MS_CLIENT_ID=<app-registration-client-id>
    export MS_TENANT=common          # ou l'ID de tenant TBS
    python graph_audit.py --account baptiste@tbs-education.fr
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import msal
    import requests
except ImportError:
    sys.exit("Dépendances manquantes. Lance:  pip install -r requirements.txt")

from redact import redact, mask_email

GRAPH = "https://graph.microsoft.com/v1.0"
# Scopes délégués en lecture seule. MailboxSettings.Read permet de lire règles + transfert.
SCOPES = [
    "User.Read",
    "MailboxSettings.Read",
    "Mail.Read",
    "Directory.Read.All",  # OAuth grants / devices ; peut nécessiter consentement admin
]

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"

SUSPECT_KEYWORDS = [
    "password", "mot de passe", "security", "sécurité", "code", "verification",
    "vérification", "2fa", "otp", "invoice", "facture", "payment", "paiement",
    "recovery", "récupération", "alert", "alerte", "sign-in", "connexion",
]


def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] {msg}")


def get_token() -> str:
    client_id = os.environ.get("MS_CLIENT_ID")
    tenant = os.environ.get("MS_TENANT", "common")
    if not client_id:
        sys.exit("Définis MS_CLIENT_ID (App registration). Voir README.")
    app = msal.PublicClientApplication(client_id, authority=f"https://login.microsoftonline.com/{tenant}")
    accounts = app.get_accounts()
    result = None
    if accounts:
        result = app.acquire_token_silent(SCOPES, account=accounts[0])
    if not result:
        flow = app.initiate_device_flow(scopes=SCOPES)
        if "user_code" not in flow:
            sys.exit(f"Échec device flow: {json.dumps(flow, indent=2)}")
        print("\n" + flow["message"] + "\n")  # « Rends-toi sur ... et saisis le code ... »
        result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        sys.exit(f"Auth échouée: {result.get('error_description', result)}")
    return result["access_token"]


def gget(token: str, path: str):
    """GET Graph. Renvoie (data | None, note). Gère 403/404 sans planter."""
    url = path if path.startswith("http") else f"{GRAPH}{path}"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=30)
    if r.status_code == 200:
        return r.json(), None
    if r.status_code in (401, 403):
        return None, f"NON VÉRIFIABLE (accès refusé {r.status_code} — scope/rôle admin requis)"
    if r.status_code == 404:
        return None, "absent (404)"
    return None, f"erreur HTTP {r.status_code}"


def score_rule(rule: dict) -> tuple[int, list[str]]:
    score, reasons = 0, []
    actions = rule.get("actions", {})
    conds = rule.get("conditions", {})

    if actions.get("forwardTo"):
        score += 40
        dests = [mask_email(x.get("emailAddress", {}).get("address", "")) for x in actions["forwardTo"]]
        reasons.append("transfère vers " + ", ".join(dests))
    if actions.get("redirectTo"):
        score += 45
        dests = [mask_email(x.get("emailAddress", {}).get("address", "")) for x in actions["redirectTo"]]
        reasons.append("redirige vers " + ", ".join(dests))
    if actions.get("delete"):
        score += 40
        reasons.append("supprime le message")
    if actions.get("markAsRead"):
        score += 20
        reasons.append("marque comme lu")
    if actions.get("moveToFolder"):
        score += 15
        reasons.append("déplace vers un dossier (potentiellement masqué)")

    text = json.dumps(conds, ensure_ascii=False).lower()
    hit = [kw for kw in SUSPECT_KEYWORDS if kw in text]
    if hit:
        score += 25
        reasons.append("cible des mots sensibles: " + ", ".join(sorted(set(hit))[:6]))
    if not rule.get("isEnabled", True):
        reasons.append("(règle désactivée)")
    return min(score, 100), reasons


def audit(account: str) -> dict:
    token = get_token()
    report = {"account": account, "generated_at": datetime.now(timezone.utc).isoformat(),
              "findings": [], "notes": {}}

    def add(kind, severity, score, detail, evidence):
        report["findings"].append({"kind": kind, "severity": severity, "score": score,
                                   "detail": detail, "evidence": evidence})

    # Profil
    me, note = gget(token, "/me")
    if me:
        report["profile"] = {k: me.get(k) for k in ("displayName", "userPrincipalName", "mail", "id")}
        log(f"Profil: {mask_email(me.get('userPrincipalName',''))}")
    else:
        report["notes"]["me"] = note

    # Réglages de boîte (transfert automatique)
    ms, note = gget(token, "/me/mailboxSettings")
    if ms:
        report["mailboxSettings"] = ms
        af = ms.get("automaticRepliesSetting", {})
        if af.get("status") not in (None, "disabled"):
            add("auto_reply", "FAIBLE", 15, "Réponse automatique active (vérifier le contenu)", af)
    else:
        report["notes"]["mailboxSettings"] = note

    # Règles de boîte de réception
    rules, note = gget(token, "/me/mailFolders/inbox/messageRules")
    if rules is not None:
        items = rules.get("value", [])
        report["inboxRules_count"] = len(items)
        report["inboxRules"] = items
        log(f"Règles de boîte: {len(items)}")
        for rule in items:
            s, reasons = score_rule(rule)
            if s > 0:
                sev = "CRITIQUE" if s >= 60 else "ÉLEVÉE" if s >= 40 else "MOYENNE" if s >= 25 else "FAIBLE"
                add("inbox_rule", sev, s,
                    f"Règle « {rule.get('displayName','?')} »: " + "; ".join(reasons), rule)
    else:
        report["notes"]["inboxRules"] = note

    # Applications OAuth consenties par l'utilisateur
    grants, note = gget(token, "/me/oauth2PermissionGrants")
    if grants is not None:
        items = grants.get("value", [])
        report["oauthGrants"] = items
        for g in items:
            scope = g.get("scope", "")
            risky = any(x in scope.lower() for x in ("mail", "read", "write", "full", "offline"))
            add("oauth_grant", "ÉLEVÉE" if risky else "INFORMATION", 40 if risky else 10,
                f"Application OAuth consentie (clientId {g.get('clientId','?')[:8]}…) scopes: {scope[:120]}", g)
    else:
        report["notes"]["oauthGrants"] = note

    # Appareils enregistrés
    devs, note = gget(token, "/me/registeredDevices")
    if devs is not None:
        items = devs.get("value", [])
        report["registeredDevices"] = items
        log(f"Appareils enregistrés: {len(items)}")
    else:
        report["notes"]["registeredDevices"] = note

    return report


def write_outputs(report: dict, account: str) -> None:
    OUT.mkdir(exist_ok=True)
    try:
        os.chmod(OUT, 0o700)
    except OSError:
        pass
    safe = redact(report)
    (OUT / f"{account}-graph-audit.json").write_text(json.dumps(safe, ensure_ascii=False, indent=2))

    with (OUT / f"{account}-graph-findings.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["account", "kind", "severity", "score", "detail"])
        for f in sorted(report["findings"], key=lambda x: -x["score"]):
            w.writerow([account, f["kind"], f["severity"], f["score"], redact(f["detail"])])

    log(f"Rapport: {OUT / f'{account}-graph-audit.json'}")
    if report.get("notes"):
        for k, v in report["notes"].items():
            log(f"  note[{k}]: {v}")
    for f in sorted(report["findings"], key=lambda x: -x["score"])[:10]:
        log(f"  [{f['severity']:>11}] ({f['score']:>3}) {redact(f['detail'])}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Audit read-only Microsoft Graph.")
    ap.add_argument("--account", required=True, help="UPN du compte (que tu contrôles).")
    args = ap.parse_args()
    log(f"Audit read-only de {mask_email(args.account)}")
    report = audit(args.account)
    write_outputs(report, args.account)


if __name__ == "__main__":
    main()
