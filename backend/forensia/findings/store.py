"""Append-only JSONL store of structured findings, one file per case.

Layout: ``~/.forensia/cases/<case-id>/findings.jsonl`` — one JSON object per
line. The agent writes a finding via the internal ``record_finding`` tool;
the UI reads them in chronological order.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from forensia.cases import CaseManager, case_manager
from forensia.mitre import catalog

logger = logging.getLogger(__name__)

_VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass(frozen=True)
class Finding:
    id: str
    case_id: str
    title: str
    summary: str
    severity: str
    evidence_id: str | None
    tool_id: str | None
    run_id: str | None
    created_at: str
    #: Técnicas ATT&CK que este hallazgo *sugiere* (``["T1547.001", …]``), tal y
    #: como los prompts del paquete ya prescriben (`agentes/*/prompts/system.md`,
    #: «Esquema de hallazgo»). Es una propuesta del agente, no un veredicto: sólo
    #: el operador dictamina (ver forensia.mitre.coverage).
    #:
    #: Lleva default para que los hallazgos escritos ANTES de que existiera el
    #: campo sigan construyendo: sin él, ``Finding(**data)`` en ``list()`` lanzaría
    #: TypeError y los hallazgos antiguos desaparecerían de la UI en silencio.
    mitre_hints: list[str] = field(default_factory=list)


def _validate_mitre_hints(raw: Any) -> list[str]:
    """Valida los `mitre_hints` de un hallazgo contra la semilla ATT&CK.

    Enum cerrada: un id que no esté en la semilla se rechaza. Es la misma regla
    que el paquete del orquestador ya impone al modelo (`_orchestrator/mitre.md`,
    regla 1) — aquí se hace cumplir en el servidor, que es donde cuenta
    (SECURITY INVARIANT 5, RULE 2).
    """
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("finding.mitre_hints must be a list of ATT&CK technique ids")

    out: list[str] = []
    for technique_id in raw:
        if not isinstance(technique_id, str):
            raise ValueError("finding.mitre_hints entries must be strings")
        technique_id = technique_id.strip()
        if not catalog.is_known(technique_id):
            reason = catalog.unavailable_reason()
            if reason:
                raise ValueError(reason)
            raise ValueError(
                f"{technique_id!r} is not in the ATT&CK seed "
                f"(agentes/{catalog.SEED_RELPATH}) — the closed enum the agent may "
                f"emit. Refusing to record a hallucinated technique id."
            )
        if technique_id not in out:
            out.append(technique_id)
    return out


class FindingStore:
    def __init__(self, cases: CaseManager) -> None:
        if cases is None:
            raise ValueError("FindingStore requires a CaseManager")
        self._cases = cases

    def append(self, case_id: str, data: dict[str, Any]) -> Finding:
        case_dir = self._cases.case_dir(case_id)

        title = (data.get("title") or "").strip()
        summary = (data.get("summary") or "").strip()
        severity = (data.get("severity") or "").strip().lower()
        if not title or len(title) > 200:
            raise ValueError("finding.title must be a non-empty string ≤ 200 chars")
        if not summary or len(summary) > 4000:
            raise ValueError("finding.summary must be a non-empty string ≤ 4000 chars")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"finding.severity must be one of {sorted(_VALID_SEVERITIES)}"
            )

        evidence_id = data.get("evidence_id")
        if evidence_id is not None:
            if not isinstance(evidence_id, str) or not _UUID4_RE.match(evidence_id):
                raise ValueError("finding.evidence_id must be a UUID4 or null")
        tool_id = data.get("tool_id")
        if tool_id is not None and not isinstance(tool_id, str):
            raise ValueError("finding.tool_id must be a string or null")
        run_id = data.get("run_id")
        if run_id is not None:
            if not isinstance(run_id, str) or not _UUID4_RE.match(run_id):
                raise ValueError("finding.run_id must be a UUID4 or null")

        finding = Finding(
            id=str(uuid.uuid4()),
            case_id=case_id,
            title=title,
            summary=summary,
            severity=severity,
            evidence_id=evidence_id,
            tool_id=tool_id,
            run_id=run_id,
            created_at=_utc_now_iso(),
            mitre_hints=_validate_mitre_hints(data.get("mitre_hints")),
        )

        path = case_dir / "findings.jsonl"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(finding), sort_keys=True) + "\n")
        return finding

    def list(self, case_id: str) -> list[Finding]:
        case_dir = self._cases.case_dir(case_id)
        path = case_dir / "findings.jsonl"
        if not path.is_file():
            return []
        out: list[Finding] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("skipping malformed finding line: %s", exc)
                continue
            try:
                out.append(Finding(**data))
            except TypeError as exc:
                logger.warning("skipping finding with unknown fields: %s", exc)
        return out


finding_store = FindingStore(case_manager)
