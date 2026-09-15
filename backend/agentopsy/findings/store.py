"""Append-only JSONL store of structured findings, one file per case.

Layout: ``~/.agentopsy/cases/<case-id>/findings.jsonl`` — one JSON object per
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

from agentopsy.i18n import Mensaje
from agentopsy.cases import CaseManager, case_manager
from agentopsy.mitre import catalog

logger = logging.getLogger(__name__)

_VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
#: Naturaleza del hallazgo. Un ``afirmacion`` afirma algo sobre la evidencia y por
#: tanto EXIGE procedencia (``run_id``): un hecho pericial sin el run que lo sostiene
#: es indistinguible de una alucinación (RULE 2 / SECURITY INVARIANT 5). Un
#: ``descarte`` documenta que una vía NO aportó (p. ej. «el timeline no muestra
#: ejecución de X»); es un resultado legítimo que puede no tener un ArtifactRun con
#: salida útil, así que queda EXENTO del requisito de procedencia.
_VALID_FINDING_KINDS = frozenset({"afirmacion", "descarte"})
_DEFAULT_FINDING_KIND = "afirmacion"
_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)

#: El rechazo de `observed_at` viaja al modelo como cuerpo de error del tool result,
#: así que tiene que ser ACCIONABLE: el formato esperado con ejemplo, y qué hacer
#: cuando la zona del sistema investigado no se puede determinar. Un mensaje que solo
#: dijera "valor inválido" convertiría el reintento en un hallazgo perdido.
_OBSERVED_AT_ERROR = (
    "finding.observed_at debe ser ISO-8601 con la zona EXPLÍCITA (offset o Z), "
    "por ejemplo 2021-03-23T19:24:35Z o 2021-03-23T20:24:35+01:00. "
    "Recibido: {recibido!r}. Es la hora del HECHO en el dispositivo investigado, "
    "no la del análisis: si el artefacto da hora LOCAL (MFT, registro, logs de "
    "Windows), conviértela a UTC y di en el summary en qué zona venía. Si no "
    "puedes determinar la zona del sistema investigado, omite el campo: un "
    "hallazgo sin fecha es un hueco declarado, uno con la fecha mal convertida es "
    "una afirmación falsa."
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
    #: como `agentes/agent.md` (§8, correlación MITRE) prescribe al agente. Es una
    #: propuesta del agente, no un veredicto: sólo el operador dictamina (ver
    #: agentopsy.mitre.coverage).
    #:
    #: Lleva default para que los hallazgos escritos ANTES de que existiera el
    #: campo sigan construyendo: sin él, ``Finding(**data)`` en ``list()`` lanzaría
    #: TypeError y los hallazgos antiguos desaparecerían de la UI en silencio.
    mitre_hints: list[str] = field(default_factory=list)
    #: Confianza CALIBRADA del agente en el hallazgo (0..1), tal y como los prompts
    #: del paquete la prescriben («Esquema de hallazgo»). El motor la descartaba
    #: (`additionalProperties: false`) — mismo bug que `mitre_hints`. Opcional.
    confidence: float | None = None
    #: Marca temporal del ARTEFACTO que sostiene el hallazgo (cuándo ocurrió el hecho
    #: en la evidencia), ISO-8601 con offset o ``Z`` EXPLÍCITOS — distinta de
    #: ``created_at`` (cuándo se registró el hallazgo). Opcional; validada al
    #: escribirse (ver ``_validate_observed_at``), nunca al releerse.
    observed_at: str | None = None
    #: Procedencia a nivel de artefacto: SHA-256 del output del ``run_id`` que
    #: sostiene el hallazgo (cadena de custodia del derivado, FORENSIC INVARIANT 4).
    #: Opcional; el ``run_id`` es el ancla obligatoria para un hallazgo afirmativo.
    artifact_sha256: str | None = None
    #: ``afirmacion`` (default) | ``descarte``. Gobierna el requisito de procedencia
    #: (ver ``_VALID_FINDING_KINDS``). Lleva default para que los hallazgos previos al
    #: campo sigan construyendo en ``list()``.
    finding_kind: str = _DEFAULT_FINDING_KIND
    #: Línea LITERAL de la salida del ``run_id`` que sostiene el hallazgo. Es la
    #: procedencia a nivel de LÍNEA, un escalón por debajo de ``artifact_sha256``: el
    #: hash dice qué fichero lo sostiene, la cita dice qué renglón de ese fichero.
    #:
    #: El motor local-fit-llm la exige en toda ``afirmacion`` y comprueba que aparece
    #: en el artefacto sellado y que el agente la leyó (ver
    #: ``agentopsy-local-fit-llm/custodia/cita.py``). Un ``descarte`` no cita: deja
    #: constancia de que una vía no aportó, y no hay línea que señalar.
    #:
    #: Opcional y con default, como ``mitre_hints``: sin él, ``Finding(**data)`` en
    #: ``list()`` lanzaría TypeError y CADA hallazgo con cita desaparecería de la UI
    #: con solo un warning en el log.
    quote: str | None = None


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
                f"(agentes/{catalog.SEED_RELPATH}), the closed enum the agent may "
                f"emit. Refusing to record a hallucinated technique id."
            )
        if technique_id not in out:
            out.append(technique_id)
    return out


def _validate_observed_at(raw: Any) -> str | None:
    """Valida la marca del ARTEFACTO: ISO-8601 con zona EXPLÍCITA, o nada.

    Hace cumplir en el servidor lo que el esquema de la tool ya promete. La zona no
    se supone: una marca sin offset no es UTC salvo que lo diga, y darla por UTC es
    el default silencioso que prohíbe RULE 2. Rechaza por tanto tanto el texto que
    no es una fecha como la fecha sin zona (incluida la fecha suelta ``2021-03-23``,
    que además no tiene hora que situar en un eje).

    El rechazo tira el hallazgo entero, igual que un id ATT&CK alucinado
    (:func:`_validate_mitre_hints`), pero no se pierde: viaja al modelo como cuerpo
    de error del tool result (``agent.py``, "record_finding rejected"). Para que el
    coste sea un reintento y no un hallazgo perdido, el mensaje dice el formato
    esperado CON ejemplo y qué hacer cuando la zona no se puede determinar.

    Devuelve el valor LITERAL (recortado), no una forma normalizada: un
    ``+01:00`` dice de qué zona venía el artefacto, y eso es dato del caso. Quien
    lo pinte en un eje lo normaliza (``agentopsy.timeline.hallazgos``).
    """
    if raw is None:
        return None
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(_OBSERVED_AT_ERROR.format(recibido=raw))
    texto = raw.strip()
    # `fromisoformat` acepta la `Z` desde Python 3.11; se sustituye igualmente para
    # no depender de esa versión mínima.
    candidato = texto[:-1] + "+00:00" if texto.endswith(("Z", "z")) else texto
    try:
        parsed = datetime.fromisoformat(candidato)
    except ValueError:
        raise ValueError(_OBSERVED_AT_ERROR.format(recibido=texto)) from None
    if parsed.tzinfo is None:
        raise ValueError(_OBSERVED_AT_ERROR.format(recibido=texto))
    return texto


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

        confidence = data.get("confidence")
        if confidence is not None:
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
                raise ValueError("finding.confidence must be a number in [0, 1] or null")
            confidence = float(confidence)
            if not 0.0 <= confidence <= 1.0:
                raise ValueError("finding.confidence must be within [0, 1]")

        observed_at = _validate_observed_at(data.get("observed_at"))

        artifact_sha256 = data.get("artifact_sha256")
        if artifact_sha256 is not None:
            if not isinstance(artifact_sha256, str) or not _SHA256_RE.match(artifact_sha256):
                raise ValueError("finding.artifact_sha256 must be a 64-char hex SHA-256 or null")
            artifact_sha256 = artifact_sha256.lower()

        finding_kind = (data.get("finding_kind") or _DEFAULT_FINDING_KIND)
        if not isinstance(finding_kind, str) or finding_kind.strip().lower() not in _VALID_FINDING_KINDS:
            raise ValueError(
                f"finding.finding_kind must be one of {sorted(_VALID_FINDING_KINDS)}"
            )
        finding_kind = finding_kind.strip().lower()

        # Anti-alucinación (RULE 2 / SECURITY INVARIANT 5): un hallazgo AFIRMATIVO
        # (algo que se afirma sobre la evidencia) DEBE anclarse a la procedencia del
        # run que lo sostiene — sin `run_id` no es distinguible de una alucinación.
        # Un `descarte` (una vía que NO aportó) queda exento: es un resultado legítimo
        # que puede no tener un ArtifactRun con salida útil.
        if finding_kind != "descarte" and not run_id:
            raise ValueError(
                Mensaje("findings.needProvenance")
            )

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
            confidence=confidence,
            observed_at=observed_at,
            artifact_sha256=artifact_sha256,
            finding_kind=finding_kind,
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
