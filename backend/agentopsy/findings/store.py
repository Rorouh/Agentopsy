"""Append-only JSONL store of structured findings, one file per case.

Layout: ``~/.agentopsy/cases/<case-id>/findings.jsonl`` — one JSON object per
line. The agent writes a finding via the internal ``record_finding`` tool; the
REST route writes the same way; the UI reads them in chronological order.

**Provenance is checked HERE, not in the prompt.** Both write paths go through
the same domain service (``agentopsy.findings.procedencia``), so a finding cannot
carry a source that does not exist: the run has to exist, belong to this case,
have read the evidence it names, have been executed by the tool it names, have
produced the artifact it cites, and that artifact's bytes have to still hash to
what the manifest recorded. Until 2026-09-08 only the SHAPE of the identifiers
was checked, so a run id that had never existed, the tool ``nonexistent`` and a
hash of sixty-four ``f`` were accepted and persisted (auditoría 2026-09-07, F03).

**Three natures, and the difference is the point** (``_VALID_FINDING_KINDS``):

- ``afirmacion`` asserts something about the evidence, so it REQUIRES a verified
  source from a run that finished cleanly.
- ``limitacion`` documents that something could NOT be examined: a tool that
  failed, an output that came back partial. It is the only kind that may cite a
  run with a non-zero exit, and it must say what was left unexamined. A failed
  run is forensic information, not noise, but it does not become a positive
  assertion by being written up as one.
- ``descarte`` says a line of enquiry did not contribute, and must declare what
  was examined, with which tool and with what limit. "It could not be analysed"
  and "it was not found" are not the same statement.

**Revisions are kept, never overwritten.** The file stays append-only: revising a
finding appends a new line with the SAME ``id``, ``revision`` incremented and
``supersedes`` pointing at the content hash it replaces. ``list()`` serves the
latest revision of each finding; ``revisions()`` serves the whole history, so a
report that cites revision 2 keeps meaning what it meant even after revision 3
exists.

**A write with no custody record is not a completed write.** The store writes the
provenance entry to the hash-chained audit BEFORE persisting the line, and the
audit is written ONCE per operation (the agent no longer adds its own event: two
entries for one write would double-count the same act in the chain).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from agentopsy.artifacts.store import ArtifactStore
from agentopsy.audit.log import AuditLog
from agentopsy.cases import CaseManager, case_manager
from agentopsy.evidence import EvidenceManager
from agentopsy.findings import procedencia
from agentopsy.findings.procedencia import (
    MAX_REFERENCIAS,
    ProcedenciaError,
    Referencia,
    verificar_referencia,
)
from agentopsy.i18n import Mensaje
from agentopsy.mitre import catalog

logger = logging.getLogger(__name__)

_VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
#: Naturaleza del hallazgo. Ver el docstring del módulo: gobierna qué procedencia
#: admite y qué tiene que declarar.
_VALID_FINDING_KINDS = frozenset({"afirmacion", "descarte", "limitacion"})
_DEFAULT_FINDING_KIND = "afirmacion"
#: Los tipos que NO afirman: pueden vivir sin una fuente íntegra, pero tienen que
#: decir qué se examinó y con qué límite.
_KINDS_SIN_AFIRMACION = frozenset({"descarte", "limitacion"})
_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)

#: Origen de la escritura, para que el audit distinga quién la hizo. No cambia
#: ninguna validación: la política es la MISMA por las dos vías.
_ORIGENES = frozenset({"agent", "rest", "mcp"})

#: Tope del texto que declara el alcance de un descarte o de una limitación.
MAX_ALCANCE = 2000

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
    #: Se conserva por compatibilidad y como atajo de lectura; la procedencia
    #: COMPLETA vive en ``references``.
    artifact_sha256: str | None = None
    #: ``afirmacion`` (default) | ``descarte`` | ``limitacion``. Gobierna el
    #: requisito de procedencia (ver ``_VALID_FINDING_KINDS``). Lleva default para
    #: que los hallazgos previos al campo sigan construyendo en ``list()``.
    finding_kind: str = _DEFAULT_FINDING_KIND
    #: Las FUENTES verificadas del hallazgo, en el contrato tipado de
    #: ``agentopsy.findings.procedencia``. Un hallazgo puede tener varias: un
    #: mismo hecho puede sostenerse en el $MFT y en un EVTX, y perder una de las
    #: dos empobrece el peritaje. Vacía en los hallazgos anteriores al contrato.
    references: list[dict[str, Any]] = field(default_factory=list)
    #: Qué se examinó, con qué herramienta y con qué límite. OBLIGATORIO en un
    #: ``descarte`` y en una ``limitacion``: es lo que impide leer «no se pudo
    #: analizar» como «no se encontró».
    alcance_examinado: str | None = None
    #: Número de revisión, desde 1. Una revisión no sobrescribe: añade una línea
    #: con el mismo ``id`` y este número mayor.
    revision: int = 1
    #: SHA-256 del CONTENIDO canónico de esta revisión. Es lo que un informe cita
    #: para referirse a una revisión concreta y no a "el hallazgo, como esté hoy".
    content_sha256: str = ""
    #: El ``content_sha256`` de la revisión que esta sustituye. ``None`` en la 1.
    supersedes: str | None = None
    #: Por qué se revisó. Obligatorio al revisar; ``None`` en la primera.
    motivo_revision: str | None = None
    #: Por dónde entró la escritura (``agent`` / ``rest`` / ``mcp``).
    origin: str = "rest"
    #: ``verificada`` cuando la procedencia se comprobó al escribirla;
    #: ``no_verificada`` en los hallazgos históricos, que se conservan y se leen
    #: pero NO reciben las garantías nuevas (compatibilidad honesta).
    provenance_state: str = "no_verificada"


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


#: Campos del hallazgo que entran en su hash de contenido. Se enumeran (no "todo
#: el dataclass") para que la identidad de una revisión NO dependa de metadatos
#: de escritura (quién la escribió, cuándo) sino de lo que el hallazgo AFIRMA.
_CAMPOS_CONTENIDO = (
    "id",
    "case_id",
    "title",
    "summary",
    "severity",
    "evidence_id",
    "tool_id",
    "run_id",
    "mitre_hints",
    "confidence",
    "observed_at",
    "artifact_sha256",
    "finding_kind",
    "references",
    "alcance_examinado",
    "revision",
)


def content_sha256(data: dict[str, Any]) -> str:
    """SHA-256 del contenido canónico de una revisión de hallazgo.

    Determinista y estable: es lo que un informe cita para fijar «esta revisión»
    y lo que el audit ancla para que revisar un hallazgo citado sea visible en
    lugar de silencioso.
    """
    canonico = {campo: data.get(campo) for campo in _CAMPOS_CONTENIDO}
    payload = json.dumps(
        canonico, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class FindingStore:
    """El almacén de hallazgos y la puerta de su procedencia.

    Los almacenes que la verificación necesita (artefactos y evidencias) se atan
    al MISMO ``CaseManager`` que el de los hallazgos. No es una comodidad de
    test: si el almacén de hallazgos mirase un case root y el de artefactos otro,
    la comprobación de procedencia estaría mirando a un caso distinto del que
    escribe, que es la clase de incoherencia que esta capa existe para impedir.
    """

    def __init__(
        self,
        cases: CaseManager,
        *,
        artifacts: ArtifactStore | None = None,
        evidence: EvidenceManager | None = None,
    ) -> None:
        if cases is None:
            raise ValueError("FindingStore requires a CaseManager")
        self._cases = cases
        self._artifacts = artifacts or ArtifactStore(cases)
        self._evidence = evidence or EvidenceManager(cases)

    # -- lectura --------------------------------------------------------------

    def _leer_lineas(self, case_id: str) -> list[dict[str, Any]]:
        case_dir = self._cases.case_dir(case_id)
        path = case_dir / "findings.jsonl"
        if not path.is_file():
            return []
        out: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                logger.warning("skipping malformed finding line: %s", exc)
        return out

    @staticmethod
    def _construir(data: dict[str, Any]) -> Finding | None:
        try:
            return Finding(**data)
        except TypeError as exc:
            logger.warning("skipping finding with unknown fields: %s", exc)
            return None

    def list(self, case_id: str) -> list[Finding]:
        """La revisión VIGENTE de cada hallazgo, en orden de primer registro.

        El fichero es append-only y una revisión añade una línea con el mismo
        ``id``: aquí se colapsa a la de mayor ``revision``, que es la que el
        perito está mirando. La historia completa no se pierde, se pide con
        :meth:`revisions`.
        """
        vigentes: dict[str, Finding] = {}
        orden: list[str] = []
        for data in self._leer_lineas(case_id):
            finding = self._construir(data)
            if finding is None:
                continue
            previo = vigentes.get(finding.id)
            if previo is None:
                orden.append(finding.id)
                vigentes[finding.id] = finding
            elif finding.revision >= previo.revision:
                vigentes[finding.id] = finding
        return [vigentes[fid] for fid in orden]

    def revisions(self, case_id: str, finding_id: str) -> list[Finding]:
        """TODAS las revisiones de un hallazgo, de la más antigua a la más nueva.

        Es lo que hace inspeccionable una corrección: un informe que citó la
        revisión 2 sigue pudiendo enseñar exactamente qué decía, aunque hoy vaya
        por la 4.
        """
        out = [
            f
            for data in self._leer_lineas(case_id)
            if (f := self._construir(data)) is not None and f.id == finding_id
        ]
        out.sort(key=lambda f: f.revision)
        return out

    def get(self, case_id: str, finding_id: str, revision: int | None = None) -> Finding:
        """Una revisión CONCRETA (o la vigente). ``KeyError`` si no existe."""
        historial = self.revisions(case_id, finding_id)
        if not historial:
            raise KeyError(
                Mensaje("provenance.unknownFinding", finding_id=finding_id, case_id=case_id)
            )
        if revision is None:
            return historial[-1]
        for f in historial:
            if f.revision == revision:
                return f
        raise KeyError(
            Mensaje("provenance.unknownFinding", finding_id=finding_id, case_id=case_id)
        )

    def sources(
        self, case_id: str, finding_id: str, revision: int | None = None
    ) -> dict[str, Any]:
        """Las FUENTES de un hallazgo, abiertas y verificadas AHORA.

        Vive en el almacén, y no suelta en el módulo de procedencia, porque la
        resolución tiene que usar los MISMOS gestores de artefactos y evidencias
        que este almacén: una superficie que los sustituya (un test, otro case
        root) no puede acabar leyendo el caso equivocado.
        """
        finding = self.get(case_id, finding_id, revision=revision)
        return {
            "finding_id": finding.id,
            "revision": finding.revision,
            "content_sha256": finding.content_sha256,
            "finding_kind": finding.finding_kind,
            "provenance_state": finding.provenance_state,
            "alcance_examinado": finding.alcance_examinado,
            "fuentes": procedencia.resolver_fuentes(
                case_id, finding, store=self._artifacts, evidence=self._evidence
            ),
        }

    # -- escritura ------------------------------------------------------------

    def append(
        self,
        case_id: str,
        data: dict[str, Any],
        *,
        origin: str = "rest",
        artifacts: Any = None,
        evidence: Any = None,
    ) -> Finding:
        """Registra un hallazgo NUEVO con su procedencia verificada.

        Los almacenes son inyectables para los tests (``artifacts`` /
        ``evidence``); en producción son los singletons del dominio.

        Levanta ``ValueError`` (``ProcedenciaError`` es uno) con el motivo exacto
        cuando la procedencia no se sostiene. NADA se persiste en ese caso, y el
        motivo vuelve al modelo como cuerpo de error del tool result.
        """
        campos = self._validar(case_id, data, artifacts=artifacts, evidence=evidence)
        return self._persistir(
            case_id,
            {
                **campos,
                "id": str(uuid.uuid4()),
                "case_id": case_id,
                "created_at": _utc_now_iso(),
                "revision": 1,
                "supersedes": None,
                "motivo_revision": None,
                "origin": self._origen(origin),
            },
            accion="finding_recorded",
        )

    def revise(
        self,
        case_id: str,
        finding_id: str,
        data: dict[str, Any],
        *,
        origin: str = "rest",
        artifacts: Any = None,
        evidence: Any = None,
    ) -> Finding:
        """Añade una REVISIÓN de un hallazgo existente, conservando la anterior.

        No sobrescribe: el fichero es append-only, así que la revisión previa
        sigue ahí y ``revisions()`` la sirve. Un informe que citó una revisión
        concreta sigue apuntando a lo que citó (RULE 2: reparar un hallazgo no
        puede cambiar en silencio lo que ya se afirmó sobre él).
        """
        vigente = self.get(case_id, finding_id)
        motivo = str(data.get("motivo_revision") or "").strip()
        if not motivo:
            raise ValueError(Mensaje("provenance.revisionNeedsReason"))
        campos = self._validar(case_id, data, artifacts=artifacts, evidence=evidence)
        return self._persistir(
            case_id,
            {
                **campos,
                "id": finding_id,
                "case_id": case_id,
                "created_at": _utc_now_iso(),
                "revision": vigente.revision + 1,
                "supersedes": vigente.content_sha256,
                "motivo_revision": motivo[:2000],
                "origin": self._origen(origin),
            },
            accion="finding_revised",
        )

    # -- internos -------------------------------------------------------------

    @staticmethod
    def _origen(origin: str) -> str:
        # No es una validación de negocio, es higiene del audit: un origen
        # desconocido se registra como tal en vez de colarse como "rest".
        texto = str(origin or "").strip().lower()
        return texto if texto in _ORIGENES else "desconocido"

    def _validar(
        self,
        case_id: str,
        data: dict[str, Any],
        *,
        artifacts: Any,
        evidence: Any,
    ) -> dict[str, Any]:
        """Valida el contenido y la PROCEDENCIA. Devuelve los campos ya limpios."""
        self._cases.case_dir(case_id)  # KeyError/ValueError si el caso no existe

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
                raise ValueError(
                    "finding.artifact_sha256 must be a 64-char hex SHA-256 or null"
                )
            artifact_sha256 = artifact_sha256.lower()

        finding_kind = data.get("finding_kind") or _DEFAULT_FINDING_KIND
        if (
            not isinstance(finding_kind, str)
            or finding_kind.strip().lower() not in _VALID_FINDING_KINDS
        ):
            raise ValueError(
                f"finding.finding_kind must be one of {sorted(_VALID_FINDING_KINDS)}"
            )
        finding_kind = finding_kind.strip().lower()

        alcance = data.get("alcance_examinado")
        alcance = str(alcance).strip() if alcance is not None else ""
        if finding_kind in _KINDS_SIN_AFIRMACION and not alcance:
            # «No se pudo analizar» y «no se encontró» no son la misma frase, y un
            # descarte sin alcance permite leer la primera como la segunda.
            raise ValueError(
                Mensaje(
                    "provenance.discardNeedsScope"
                    if finding_kind == "descarte"
                    else "provenance.limitationNeedsScope"
                )
            )

        referencias = self._verificar_referencias(
            case_id,
            data,
            run_id=run_id,
            evidence_id=evidence_id,
            tool_id=tool_id,
            artifact_sha256=artifact_sha256,
            finding_kind=finding_kind,
            artifacts=artifacts,
            evidence=evidence,
        )

        # La procedencia del hallazgo se DERIVA de sus fuentes verificadas: los
        # campos sueltos son un atajo de lectura, no una segunda fuente de verdad.
        if referencias:
            principal = referencias[0]
            evidence_id = principal.evidence_id or evidence_id
            tool_id = principal.tool_id or tool_id
            run_id = principal.run_id
            artifact_sha256 = principal.sha256

        return {
            "title": title,
            "summary": summary,
            "severity": severity,
            "evidence_id": evidence_id,
            "tool_id": tool_id,
            "run_id": run_id,
            "mitre_hints": _validate_mitre_hints(data.get("mitre_hints")),
            "confidence": confidence,
            "observed_at": observed_at,
            "artifact_sha256": artifact_sha256,
            "finding_kind": finding_kind,
            "references": [r.como_dict() for r in referencias],
            "alcance_examinado": alcance[:MAX_ALCANCE] or None,
            "provenance_state": "verificada" if referencias else "no_verificada",
        }

    def _verificar_referencias(
        self,
        case_id: str,
        data: dict[str, Any],
        *,
        run_id: str | None,
        evidence_id: str | None,
        tool_id: str | None,
        artifact_sha256: str | None,
        finding_kind: str,
        artifacts: Any,
        evidence: Any,
    ) -> list[Referencia]:
        """Las fuentes del hallazgo, verificadas contra el registro.

        Acepta el contrato NUEVO (``references``, varias fuentes con artefacto y
        localizador) y el HISTÓRICO (``run_id`` / ``tool_id`` /
        ``artifact_sha256`` sueltos), que se sintetiza como UNA fuente. Sintetizar
        no es adivinar: los valores que la cita omite salen del manifiesto de la
        propia ejecución, donde son únicos.
        """
        deps: dict[str, Any] = {
            "store": artifacts or self._artifacts,
            "evidence": evidence or self._evidence,
        }
        # Solo una `limitacion` puede apoyarse en una ejecución que no terminó
        # bien: es la que documenta precisamente eso.
        parcial_ok = finding_kind == "limitacion"

        crudas = data.get("references")
        if crudas is None:
            if not run_id:
                if finding_kind in _KINDS_SIN_AFIRMACION:
                    # Legítimo: una vía que no aportó puede no tener un
                    # ArtifactRun con salida útil. El alcance ya es obligatorio.
                    return []
                raise ValueError(Mensaje("provenance.affirmationNeedsSource"))
            crudas = [
                {
                    "run_id": run_id,
                    "evidence_id": evidence_id,
                    "tool_id": tool_id,
                    "sha256": artifact_sha256,
                }
            ]
        elif not isinstance(crudas, list):
            raise ProcedenciaError(Mensaje("provenance.referencesNotList"))
        elif not crudas:
            if finding_kind in _KINDS_SIN_AFIRMACION:
                return []
            raise ValueError(Mensaje("provenance.affirmationNeedsSource"))

        if len(crudas) > MAX_REFERENCIAS:
            raise ProcedenciaError(
                Mensaje(
                    "provenance.tooManyReferences",
                    max=MAX_REFERENCIAS,
                    count=len(crudas),
                )
            )

        return [
            verificar_referencia(
                case_id, cruda, permitir_parcial=parcial_ok, **deps
            )
            for cruda in crudas
        ]

    def _persistir(
        self, case_id: str, campos: dict[str, Any], *, accion: str
    ) -> Finding:
        """Ancla la escritura en el audit y SOLO ENTONCES la persiste.

        El orden importa. El audit encadenado lleva la identidad, la revisión, el
        hash del contenido, las fuentes y el origen de la escritura: es el
        registro de custodia del acto. Si esa entrada no se puede escribir, el
        hallazgo NO se registra, porque una escritura sin registro obligatorio de
        procedencia no es una escritura completada. Y si es la persistencia la
        que falla después, queda auditada como fallida en vez de desaparecer.

        Se audita UNA vez por operación: el bucle del agente ya no añade su
        propio evento, que duplicaría el mismo acto en la cadena.
        """
        campos["content_sha256"] = content_sha256(campos)
        finding = Finding(**campos)
        audit = AuditLog(self._cases.case_dir(case_id) / "audit.jsonl")

        try:
            audit.append(
                {
                    "action": accion,
                    "case_id": case_id,
                    "finding_id": finding.id,
                    "revision": finding.revision,
                    "content_sha256": finding.content_sha256,
                    "supersedes": finding.supersedes,
                    "finding_kind": finding.finding_kind,
                    "severity": finding.severity,
                    "evidence_id": finding.evidence_id,
                    "tool_id": finding.tool_id,
                    "run_id": finding.run_id,
                    # Las fuentes, no el texto: el cuerpo del hallazgo vive en
                    # findings.jsonl y su hash ya está aquí.
                    "references": [
                        {
                            "run_id": r.get("run_id"),
                            "tool_id": r.get("tool_id"),
                            "evidence_id": r.get("evidence_id"),
                            "artefacto": r.get("artefacto"),
                            "relpath": r.get("relpath"),
                            "sha256": r.get("sha256"),
                            "localizador": r.get("localizador"),
                            "estado": r.get("estado"),
                            "resultado_parcial": r.get("resultado_parcial"),
                        }
                        for r in finding.references
                    ],
                    "provenance_state": finding.provenance_state,
                    "origin": finding.origin,
                    "motivo_revision": finding.motivo_revision,
                }
            )
        except Exception as exc:  # noqa: BLE001 — sin custodia no hay escritura
            raise ValueError(
                Mensaje("provenance.auditRequired", detail=f"{type(exc).__name__}: {exc}")
            ) from exc

        path = self._cases.case_dir(case_id) / "findings.jsonl"
        try:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(finding), sort_keys=True) + "\n")
        except OSError as exc:
            # El audit ya dice que se registró; que no llegara al almacén tiene
            # que constar también, o la cadena mentiría por omisión.
            audit.append(
                {
                    "action": "finding_write_failed",
                    "case_id": case_id,
                    "finding_id": finding.id,
                    "revision": finding.revision,
                    "content_sha256": finding.content_sha256,
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                }
            )
            raise
        return finding


finding_store = FindingStore(case_manager)

__all__ = [
    "Finding",
    "FindingStore",
    "MAX_ALCANCE",
    "ProcedenciaError",
    "content_sha256",
    "finding_store",
    "procedencia",
]
