"""Deterministic relevance classifier for filesystem (MACB) events.

Forensic triage: a super-timeline of a real disk holds thousands to millions of MACB
events; only a handful matter for an investigation. This module tags the ones that do —
credentials, SSH material, shell history, persistence/autostart, auth/system logs,
executables dropped in temp dirs, web artifacts, and system binaries that were CREATED or
MODIFIED (not merely accessed).

Pure & deterministic (CLAUDE.md RULE 2: no invented data — every "relevant" event is a
real MACB event tagged with WHY; RULE 3: logic lives here, the router/UI are thin). Path
matching is case-insensitive and normalizes ``\\`` → ``/`` so it covers both unix and
windows layouts. It is a triage heuristic, never a verdict: the operator still reads the
evidence.
"""

from __future__ import annotations

import re
from typing import Any

#: Cap on how many relevant events one super-timeline reports. Relevance is already highly
#: selective; the cap is a backstop and its overflow is reported (never hidden — RULE 2).
DEFAULT_RELEVANT_LIMIT = 500


class _Rule:
    """One relevance rule: a path pattern → (category, human reason, weight).

    ``macb_gate`` (optional): the event's MACB letters must intersect it for the rule to
    fire — e.g. ``"mb"`` restricts a match to *modified* or *born* (created) events, so a
    plain read of a system binary is not flagged while a freshly dropped one is.
    """

    __slots__ = ("pattern", "category", "reason", "weight", "macb_gate")

    def __init__(
        self,
        pattern: str,
        category: str,
        reason: str,
        weight: int,
        macb_gate: str | None = None,
    ) -> None:
        self.pattern = re.compile(pattern)
        self.category = category
        self.reason = reason
        self.weight = weight
        self.macb_gate = macb_gate


# Ordered by priority: the FIRST rule that fires wins, so put the most specific / most
# important first. Weights (1..5) rank importance within the relevant list.
_RULES: tuple[_Rule, ...] = (
    _Rule(
        r"(/etc/(shadow|gshadow|sudoers)(/|$)|/etc/passwd$|(^|/)(sam|security|ntds\.dit)$)",
        "credenciales",
        "Fichero de credenciales del sistema",
        5,
    ),
    _Rule(
        r"(/\.ssh/|(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys|known_hosts)(\.pub)?$)",
        "ssh",
        "Material de claves SSH",
        5,
    ),
    _Rule(
        r"/\.(bash|zsh|sh|ksh|python|mysql|psql|node_repl)_history$|/consolehost_history\.txt$",
        "historial",
        "Historial de shell",
        4,
    ),
    _Rule(
        r"(/etc/cron|/var/spool/cron|/etc/init\.d/|/etc/rc[0-9s.]|/etc/systemd/|\.service$"
        r"|/\.(bashrc|bash_profile|profile|zshrc|zprofile)$"
        r"|/start\s?menu/programs/startup/|/system32/tasks/|/\.config/autostart/)",
        "persistencia",
        "Mecanismo de persistencia o autoarranque",
        4,
    ),
    _Rule(
        r"(/tmp/|/var/tmp/|/dev/shm/|/temp/|/appdata/local/temp/)"
        r".*\.(sh|bash|elf|bin|exe|dll|scr|ps1|bat|cmd|vbs|py|pl|php|jsp|so)$",
        "ejecutable_temporal",
        "Ejecutable o script en un directorio temporal",
        4,
    ),
    _Rule(
        r"/(var/www|srv/www|inetpub/wwwroot)/.*\.(php|phtml|jsp|jspx|asp|aspx|cgi|sh|pl)$",
        "web",
        "Artefacto ejecutable en un directorio web",
        4,
    ),
    _Rule(
        r"(/var/log/(auth\.log|secure|syslog|messages)|(^|/)(wtmp|btmp|utmp|lastlog)$)",
        "logs",
        "Registro de autenticación o del sistema",
        3,
    ),
    _Rule(
        r"/(bin|sbin|usr/bin|usr/sbin|usr/local/bin|usr/local/sbin|windows/system32)/",
        "binario_sistema",
        "Binario de sistema creado o modificado",
        3,
        macb_gate="mb",
    ),
)


def classify(path: str, macb: str) -> dict[str, Any] | None:
    """Return ``{category, reason, weight}`` for a relevant event, or ``None``.

    ``path`` is matched case-insensitively with ``\\`` normalized to ``/``; ``macb`` is the
    four-letter MACB string (e.g. ``"m.c."``) used by the optional MACB gate.
    """
    norm = path.replace("\\", "/").lower()
    macb_letters = macb.lower()
    for rule in _RULES:
        if rule.macb_gate is not None and not any(c in macb_letters for c in rule.macb_gate):
            continue
        if rule.pattern.search(norm):
            return {"category": rule.category, "reason": rule.reason, "weight": rule.weight}
    return None


def select_relevant_events(
    events: list[dict[str, Any]], *, limit: int = DEFAULT_RELEVANT_LIMIT
) -> tuple[list[dict[str, Any]], int]:
    """Pick the forensically relevant events out of a full MACB event list.

    Each kept event is the original event enriched with ``category`` / ``reason`` /
    ``weight``. The result is sorted by importance (weight desc) then chronologically, and
    capped at ``limit``. Returns ``(relevant, total)`` where ``total`` is how many were
    relevant before the cap, so the caller can report truncation (RULE 2: never hide it).
    """
    scored: list[dict[str, Any]] = []
    for event in events:
        hit = classify(event.get("path", ""), event.get("macb", ""))
        if hit is None:
            continue
        scored.append({**event, **hit})
    scored.sort(key=lambda e: (-e["weight"], e["ts"], e["path"]))
    total = len(scored)
    if limit is not None and total > limit:
        return scored[:limit], total
    return scored, total
