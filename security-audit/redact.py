"""Masquage de données sensibles dans les sorties d'audit.

Aucune donnée sensible (code OTP, jeton, clé API, cookie) ne doit apparaître en
clair dans un rapport. Ce module fournit `redact()` appliqué à toute chaîne avant
écriture CSV/JSON.
"""
from __future__ import annotations

import re

# Motifs de secrets courants -> remplacés par un marqueur.
_PATTERNS = [
    # Codes de vérification / OTP : 6 à 8 chiffres isolés (ou groupés).
    (re.compile(r"\b\d{6,8}\b"), "«CODE_MASQUÉ»"),
    (re.compile(r"\b\d{3}[- ]\d{3}\b"), "«CODE_MASQUÉ»"),
    # Jetons de type JWT / OAuth / bearer.
    (re.compile(r"\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "«JWT_MASQUÉ»"),
    (re.compile(r"\bya29\.[A-Za-z0-9._-]+"), "«GOOGLE_TOKEN_MASQUÉ»"),
    (re.compile(r"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}\b"), "«GITHUB_TOKEN_MASQUÉ»"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "«API_KEY_MASQUÉE»"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "«AWS_KEY_MASQUÉE»"),
    # Numéros de carte (Luhn non vérifié, prudence).
    (re.compile(r"\b(?:\d[ -]?){13,16}\b"), "«PAN_MASQUÉ»"),
]


def redact(value):
    """Retourne `value` avec les secrets connus masqués. Traverse dicts/lists."""
    if isinstance(value, str):
        out = value
        for pattern, replacement in _PATTERNS:
            out = pattern.sub(replacement, out)
        return out
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def mask_email(addr: str) -> str:
    """Masque partiellement une adresse e-mail pour les logs (garde le domaine)."""
    if not addr or "@" not in addr:
        return addr
    local, _, domain = addr.partition("@")
    if len(local) <= 2:
        shown = local[:1]
    else:
        shown = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{shown}@{domain}"


if __name__ == "__main__":
    samples = [
        "Ton code de sécurité est 428193",
        "token ya29.a0AfB_byC3xyz-longtoken-value-1234567890",
        "carte 4111 1111 1111 1111",
    ]
    for s in samples:
        print(f"{s!r}\n -> {redact(s)!r}\n")
