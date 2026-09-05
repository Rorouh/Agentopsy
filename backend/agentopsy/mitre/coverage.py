"""Cobertura ATT&CK de un caso — dos ejes que NUNCA se funden.

1. **Propuesta del agente** (`proposed_by`): técnicas citadas en los `mitre_hints`
   de los hallazgos reales que el agente persistió con `record_finding`. Es una
   sugerencia derivada de evidencia, con la lista de hallazgos que la sostienen.
   Se **recalcula** en cada lectura: es un derivado, no un estado.

2. **Dictamen del operador** (`adjudication`): el perito decide si la técnica
   queda `confirmada`, `sospechosa` o `descartada`, y **por qué**. Sólo esto es
   veredicto, y sólo esto se persiste.

Fundir los dos ejes rompería el sistema en las dos direcciones: o la sugerencia
del agente se disfraza de dictamen pericial, o la siguiente pasada del agente
pisa el dictamen del perito. Son campos distintos y la UI muestra ambos.

Es el patrón ya sancionado en el repo: la máquina sugiere, el operador ancla
(ver `CaseManager.anchor_os_profile` y la acción de audit `os_profile_anchored`).
Una técnica propuesta y no dictaminada NO cuenta como confirmada en ningún
recuento: gris significa **no evaluada**, nunca «ausente».

Los dictámenes son **append-only** (`mitre_adjudications.jsonl`, el último gana)
y cada uno entra en el log hash-encadenado: afirmar «T1055 confirmada» es un acto
pericial que acaba en un informe con firma (FORENSIC INVARIANT 4).
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from agentopsy.audit.log import AuditLog
from agentopsy.cases import CaseManager, case_manager
from agentopsy.findings.store import FindingStore, finding_store
from agentopsy.mitre import catalog

logger = logging.getLogger(__name__)

#: Veredictos que el operador puede emitir. ``none`` retira el dictamen.
STATUSES = frozenset({"confirmada", "sospechosa", "descartada"})
UNMARK = "none"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass(frozen=True)
class Adjudication:
    technique_id: str
    status: str
    #: Por qué. Un "confirmada" sin motivo no vale nada en un informe pericial.
    rationale: str
    #: Los hallazgos contra los que se dictaminó: ancla el veredicto a la evidencia
    #: que lo sostenía en ese momento. Si el agente vuelve a correr y los hallazgos
    #: cambian, se sigue sabiendo sobre qué se dictaminó.
    related_finding_ids: list[str] = field(default_factory=list)
    adjudicated_at: str = ""


class CoverageStore:
    def __init__(self, cases: CaseManager, findings: FindingStore) -> None:
        if cases is None or findings is None:
            raise ValueError("CoverageStore requires a CaseManager and a FindingStore")
        self._cases = cases
        self._findings = findings

    # ── eje 1: lo que propone el agente (derivado, recomputable) ─────────────

    def proposals(self, case_id: str) -> dict[str, list[str]]:
        """`technique_id -> [finding_id, …]` a partir de los `mitre_hints` reales.

        Dos fuentes, ambas propuestas del agente (mismo eje 1, nunca dictamen):
        el campo `mitre_hints` que el hallazgo llevaba al registrarse, y las
        anotaciones de correlación que el agente ancló después con
        `annotate` (`mitre_proposals.jsonl`). Se fusionan por hallazgo. Sigue
        siendo un derivado recomputado en cada lectura, no un estado."""
        annotations = self.annotations_by_finding(case_id)
        out: dict[str, list[str]] = {}
        for finding in self._findings.list(case_id):
            techniques = list(finding.mitre_hints)
            for technique_id in annotations.get(finding.id, []):
                if technique_id not in techniques:
                    techniques.append(technique_id)
            for technique_id in techniques:
                # El agente propone ids de la SEMILLA (posibles sub-técnicas); se
                # pintan en la celda Enterprise correspondiente (la padre si es una
                # sub-técnica), que es lo que ve el perito.
                display_id = catalog.enterprise_display_id(technique_id)
                bucket = out.setdefault(display_id, [])
                if finding.id not in bucket:
                    bucket.append(finding.id)
        return out

    def annotations_by_finding(self, case_id: str) -> dict[str, list[str]]:
        """`finding_id -> [technique_id, …]` desde `mitre_proposals.jsonl`.

        Append-only, **la última línea de cada hallazgo gana** (re-correlacionar
        un hallazgo reemplaza su conjunto; una lista vacía lo retira). Anotaciones
        de hallazgos que ya no existen se ignoran al fusionar en `proposals`."""
        case_dir = self._cases.case_dir(case_id)
        path = case_dir / "mitre_proposals.jsonl"
        if not path.is_file():
            return {}
        out: dict[str, list[str]] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("skipping malformed mitre proposal: %s", exc)
                continue
            finding_id = rec.get("finding_id")
            techniques = rec.get("technique_ids")
            if isinstance(finding_id, str) and isinstance(techniques, list):
                out[finding_id] = [t for t in techniques if isinstance(t, str)]
        return out

    def annotate(
        self,
        case_id: str,
        finding_id: str,
        technique_ids: list[str],
        note: str | None = None,
    ) -> dict[str, Any]:
        """Ancla técnicas ATT&CK a un hallazgo YA registrado (propuesta del agente,
        eje 1). Falla fuerte: rechaza un `finding_id` inexistente o un id fuera de
        la semilla — nunca ancla una técnica alucinada ni a un hallazgo fantasma.

        Es idempotente por hallazgo: cada llamada REEMPLAZA el conjunto anterior
        (la última línea gana), así que reenvía la lista completa; una lista vacía
        retira la correlación del hallazgo."""
        case_dir = self._cases.case_dir(case_id)  # 404 si el caso no existe

        known = {f.id for f in self._findings.list(case_id)}
        if finding_id not in known:
            raise ValueError(
                f"finding_id {finding_id!r} not found in case {case_id}, refusing "
                f"to anchor a technique to a finding that does not exist"
            )
        if not isinstance(technique_ids, list):
            raise ValueError("technique_ids must be a list of ATT&CK technique ids")

        validated: list[str] = []
        for raw in technique_ids:
            if not isinstance(raw, str):
                raise ValueError("technique_ids entries must be strings")
            technique_id = raw.strip()
            if not catalog.is_known(technique_id):
                reason = catalog.unavailable_reason()
                if reason:
                    raise ValueError(reason)
                raise ValueError(
                    f"{technique_id!r} is not in the ATT&CK seed, refusing to "
                    f"anchor a technique the agent may not even emit"
                )
            if technique_id not in validated:
                validated.append(technique_id)

        note = (note or "").strip()
        if len(note) > 2000:
            raise ValueError("mitre proposal note must be ≤ 2000 chars")

        rec: dict[str, Any] = {
            "finding_id": finding_id,
            "technique_ids": validated,
            "note": note,
            "proposed_at": _utc_now_iso(),
        }
        path = case_dir / "mitre_proposals.jsonl"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")

        AuditLog(case_dir / "audit.jsonl").append({
            "action": "mitre_proposed",
            "case_id": case_id,
            "finding_id": finding_id,
            "technique_ids": validated,
            "note": note,
            "ts_utc": rec["proposed_at"],
        })
        return rec

    # ── eje 2: lo que dictamina el operador (persistido, auditado) ───────────

    def adjudicate(
        self,
        case_id: str,
        technique_id: str,
        status: str,
        rationale: str,
        related_finding_ids: list[str] | None = None,
    ) -> Adjudication:
        """Registra el veredicto del perito. Falla fuerte, nunca normaliza en silencio."""
        case_dir = self._cases.case_dir(case_id)

        # El perito dictamina sobre el catálogo Enterprise COMPLETO (no sólo la
        # semilla del agente): puede anclar un veredicto en cualquier técnica real
        # de ATT&CK que su análisis sostenga.
        if not catalog.enterprise_is_known(technique_id):
            reason = catalog.enterprise_unavailable_reason()
            if reason:
                raise ValueError(reason)
            raise ValueError(
                f"{technique_id!r} is not in the ATT&CK Enterprise catalog, "
                f"refusing to adjudicate a technique that does not exist"
            )
        if status not in STATUSES and status != UNMARK:
            raise ValueError(
                f"mitre status must be one of {sorted(STATUSES)} or {UNMARK!r}; "
                f"got {status!r}"
            )
        if not isinstance(rationale, str):
            raise ValueError("mitre rationale must be a string")
        rationale = rationale.strip()
        # Retirar un dictamen no exige motivo; emitirlo, sí.
        if status != UNMARK and not rationale:
            raise ValueError(
                f"adjudicating {technique_id} as {status!r} requires a rationale, "
                f"an unexplained verdict is worthless in a forensic report"
            )
        if len(rationale) > 2000:
            raise ValueError("mitre rationale must be ≤ 2000 chars")

        known = {f.id for f in self._findings.list(case_id)}
        related = list(related_finding_ids or [])
        unknown = [fid for fid in related if fid not in known]
        if unknown:
            raise ValueError(
                f"related_finding_ids not found in this case: {unknown}"
            )

        adj = Adjudication(
            technique_id=technique_id,
            status=status,
            rationale=rationale,
            related_finding_ids=related,
            adjudicated_at=_utc_now_iso(),
        )

        path = case_dir / "mitre_adjudications.jsonl"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(adj), sort_keys=True) + "\n")

        AuditLog(case_dir / "audit.jsonl").append({
            "action": "mitre_adjudicated",
            "case_id": case_id,
            "technique_id": technique_id,
            "status": status,
            "rationale": rationale,
            "related_finding_ids": related,
            "ts_utc": adj.adjudicated_at,
        })
        return adj

    def adjudications(self, case_id: str) -> dict[str, Adjudication]:
        """El dictamen vigente de cada técnica (la última línea gana)."""
        case_dir = self._cases.case_dir(case_id)
        path = case_dir / "mitre_adjudications.jsonl"
        if not path.is_file():
            return {}

        out: dict[str, Adjudication] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                adj = Adjudication(**json.loads(line))
            except (json.JSONDecodeError, TypeError) as exc:
                logger.warning("skipping malformed mitre adjudication: %s", exc)
                continue
            if adj.status == UNMARK:
                out.pop(adj.technique_id, None)
            else:
                out[adj.technique_id] = adj
        return out

    # ── vista consolidada ────────────────────────────────────────────────────

    def coverage(self, case_id: str) -> list[dict[str, Any]]:
        """Una entrada por técnica tocada — propuesta, dictaminada, o ambas."""
        self._cases.case_dir(case_id)  # 404 si el caso no existe
        proposals = self.proposals(case_id)
        adjudications = self.adjudications(case_id)

        entries: list[dict[str, Any]] = []
        for technique_id in sorted(set(proposals) | set(adjudications)):
            adj = adjudications.get(technique_id)
            tactic_id = (
                catalog.enterprise_technique(technique_id).tactic_id
                if catalog.enterprise_is_known(technique_id)
                else None
            )
            entries.append({
                "technique_id": technique_id,
                "tactic_id": tactic_id,
                "proposed_by": proposals.get(technique_id, []),
                "status": adj.status if adj else None,
                "rationale": adj.rationale if adj else "",
                "adjudicated_at": adj.adjudicated_at if adj else None,
                "related_finding_ids": adj.related_finding_ids if adj else [],
            })
        return entries


coverage_store = CoverageStore(case_manager, finding_store)
