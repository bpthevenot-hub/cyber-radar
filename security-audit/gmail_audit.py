#!/usr/bin/env python3
"""Audit read-only d'un compte Google / Gmail.

Détecte les signes classiques de compromission de boîte mail SANS jamais rien
modifier : le script n'appelle que des méthodes .get() et .list().

Objets audités
--------------
- Transfert automatique (forwardingAddresses) + réglage POP/IMAP
- Filtres (settings.filters) + scoring des filtres suspects
- Délégués (settings.delegates)
- Identités « Envoyer en tant que » (sendAs)
- Réponse automatique (vacation)
- Profil (adresse, total messages/threads)

Sorties
-------
- out/<compte>-gmail-audit.json  (rapport complet, données masquées)
- out/<compte>-gmail-findings.csv (constats scorés)

Usage
-----
    pip install -r requirements.txt
    # credentials.json OAuth "Desktop app" présent dans ce dossier
    python gmail_audit.py --account bp.thevenot@gmail.com

Scopes : gmail.settings.basic + gmail.readonly. Voir README (note sur les scopes).
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
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    sys.exit("Dépendances manquantes. Lance:  pip install -r requirements.txt")

from redact import redact, mask_email

# Lecture seule : settings.basic est requis pour LIRE filtres/transferts (Google
# n'expose pas de scope settings read-only). Le script n'écrit jamais.
SCOPES = [
    "https://www.googleapis.com/auth/gmail.settings.basic",
    "https://www.googleapis.com/auth/gmail.readonly",
]

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"

# Mots-clés dont le filtrage/masquage est un signal fort de dissimulation d'alertes.
SUSPECT_KEYWORDS = [
    "password", "mot de passe", "security", "sécurité", "securite",
    "code", "verification", "vérification", "verify", "2fa", "otp",
    "invoice", "facture", "payment", "paiement", "sign-in", "connexion",
    "recovery", "récupération", "alert", "alerte", "suspicious", "suspect",
]


def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] {msg}")


def get_service(account: str):
    """Authentifie (OAuth desktop flow) et renvoie un client Gmail."""
    creds = None
    token_path = HERE / f".token-{account}.json"  # jamais committé (.gitignore)
    cred_path = Path(os.environ.get("GOOGLE_CREDENTIALS", HERE / "credentials.json"))

    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not cred_path.exists():
                sys.exit(f"credentials.json introuvable ({cred_path}). Voir README.")
            flow = InstalledAppFlow.from_client_secrets_file(str(cred_path), SCOPES)
            creds = flow.run_local_server(port=0, login_hint=account)
        token_path.write_text(creds.to_json())
        os.chmod(token_path, 0o600)
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def score_filter(f: dict) -> tuple[int, list[str]]:
    """Score de suspicion d'un filtre Gmail (0-100) + raisons."""
    score, reasons = 0, []
    crit = f.get("criteria", {})
    act = f.get("action", {})

    if act.get("forward"):
        score += 40
        reasons.append(f"redirige vers {mask_email(act['forward'])}")
    if "TRASH" in act.get("addLabelIds", []):
        score += 40
        reasons.append("supprime automatiquement (met à la corbeille)")
    if act.get("removeLabelIds") and "UNREAD" in act["removeLabelIds"]:
        score += 20
        reasons.append("marque comme lu automatiquement")
    if act.get("removeLabelIds") and "INBOX" in act["removeLabelIds"]:
        score += 15
        reasons.append("archive (retire de la boîte de réception)")

    haystack = " ".join(str(crit.get(k, "")) for k in ("from", "to", "subject", "query")).lower()
    hit = [kw for kw in SUSPECT_KEYWORDS if kw in haystack]
    if hit:
        score += 25
        reasons.append("cible des mots sensibles: " + ", ".join(sorted(set(hit))[:6]))

    # Un filtre qui masque/supprime des messages de sécurité = critique.
    if hit and (score >= 40):
        reasons.append("⚠ masque potentiellement des alertes de sécurité")

    return min(score, 100), reasons


def audit(account: str) -> dict:
    svc = get_service(account)
    users = svc.users()
    report: dict = {
        "account": account,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": [],
    }

    def add(kind, severity, score, detail, evidence):
        report["findings"].append({
            "kind": kind, "severity": severity, "score": score,
            "detail": detail, "evidence": evidence,
        })

    # Profil
    try:
        p = users.getProfile(userId="me").execute()
        report["profile"] = {
            "emailAddress": p.get("emailAddress"),
            "messagesTotal": p.get("messagesTotal"),
            "threadsTotal": p.get("threadsTotal"),
        }
        log(f"Profil: {mask_email(p.get('emailAddress',''))} — {p.get('messagesTotal')} messages")
    except HttpError as e:
        log(f"Profil: erreur {e}")

    settings = users.settings()

    # Transferts automatiques
    try:
        fwd = settings.forwardingAddresses().list(userId="me").execute().get("forwardingAddresses", [])
        report["forwardingAddresses"] = fwd
        for a in fwd:
            add("forwarding_address", "ÉLEVÉE", 60,
                f"Adresse de transfert configurée: {mask_email(a.get('forwardingEmail',''))} "
                f"(état: {a.get('verificationStatus')})",
                a)
        if not fwd:
            log("Transferts: aucun")
    except HttpError as e:
        log(f"forwardingAddresses: {e}")

    # POP / IMAP
    try:
        pop = settings.getPop(userId="me").execute()
        imap = settings.getImap(userId="me").execute()
        report["pop"] = pop
        report["imap"] = imap
        if pop.get("accessWindow") not in (None, "disabled"):
            add("pop_enabled", "MOYENNE", 30, f"POP activé: {pop.get('accessWindow')}", pop)
        if imap.get("enabled"):
            add("imap_enabled", "INFORMATION", 15, "IMAP activé (normal si client mail utilisé)", imap)
    except HttpError as e:
        log(f"pop/imap: {e}")

    # Filtres
    try:
        filters = settings.filters().list(userId="me").execute().get("filter", [])
        report["filters_count"] = len(filters)
        report["filters"] = filters
        log(f"Filtres: {len(filters)}")
        for f in filters:
            s, reasons = score_filter(f)
            if s > 0:
                sev = "CRITIQUE" if s >= 60 else "ÉLEVÉE" if s >= 40 else "MOYENNE" if s >= 25 else "FAIBLE"
                add("suspicious_filter", sev, s, "Filtre suspect: " + "; ".join(reasons), f)
    except HttpError as e:
        log(f"filters: {e}")

    # Délégués
    try:
        deleg = settings.delegates().list(userId="me").execute().get("delegates", [])
        report["delegates"] = deleg
        for d in deleg:
            add("delegate", "ÉLEVÉE", 50,
                f"Délégué sur la boîte: {mask_email(d.get('delegateEmail',''))} ({d.get('verificationStatus')})", d)
        if not deleg:
            log("Délégués: aucun")
    except HttpError as e:
        log(f"delegates: {e}")

    # Send-As
    try:
        sendas = settings.sendAs().list(userId="me").execute().get("sendAs", [])
        report["sendAs"] = sendas
        for s in sendas:
            if not s.get("isPrimary"):
                add("send_as", "MOYENNE", 25,
                    f"Identité 'Envoyer en tant que': {mask_email(s.get('sendAsEmail',''))} "
                    f"(vérifiée: {s.get('verificationStatus')})", s)
    except HttpError as e:
        log(f"sendAs: {e}")

    # Réponse automatique
    try:
        vac = settings.getVacation(userId="me").execute()
        report["vacation"] = vac
        if vac.get("enableAutoReply"):
            add("vacation", "FAIBLE", 15, "Réponse automatique ACTIVE (vérifier le contenu)", vac)
    except HttpError as e:
        log(f"vacation: {e}")

    return report


def write_outputs(report: dict, account: str) -> None:
    OUT.mkdir(exist_ok=True)
    try:
        os.chmod(OUT, 0o700)
    except OSError:
        pass
    safe = redact(report)
    json_path = OUT / f"{account}-gmail-audit.json"
    json_path.write_text(json.dumps(safe, ensure_ascii=False, indent=2))

    csv_path = OUT / f"{account}-gmail-findings.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["account", "kind", "severity", "score", "detail"])
        for f in sorted(report["findings"], key=lambda x: -x["score"]):
            w.writerow([account, f["kind"], f["severity"], f["score"], redact(f["detail"])])
    log(f"Rapport: {json_path}")
    log(f"Constats: {csv_path}")

    findings = report["findings"]
    log(f"=== {len(findings)} constat(s). "
        f"CRITIQUE={sum(f['severity']=='CRITIQUE' for f in findings)} "
        f"ÉLEVÉE={sum(f['severity']=='ÉLEVÉE' for f in findings)} ===")
    for f in sorted(findings, key=lambda x: -x["score"])[:10]:
        log(f"  [{f['severity']:>11}] ({f['score']:>3}) {redact(f['detail'])}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Audit read-only d'un compte Gmail.")
    ap.add_argument("--account", required=True, help="Adresse Gmail à auditer (compte que tu contrôles).")
    args = ap.parse_args()
    log(f"Audit read-only de {mask_email(args.account)}")
    report = audit(args.account)
    write_outputs(report, args.account)


if __name__ == "__main__":
    main()
