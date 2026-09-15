"""The forensic agent loop.

ONE agent configured by the single ``agentes/agent.md``: the reasoning loop is
identical; what changes per profile is only the tool allowlist (the catalog
filtered by ``os_profile``). The behavioral instructions are shared. The executor that answers each
``next_action`` is the one the OPERATOR selected for the request (Claude Code,
Codex CLI, Gemini CLI or Ollama — adapted by ``agentopsy.models.ExecutorBackend``);
the loop neither knows nor cares which one it is (diseño Fase 2 §5).

``run()`` drives a bounded provider-agnostic tool-calling loop:

1. Build messages = system (package prompts + case context) + user (prompt).
2. Loop up to ``max_iterations``:
   - ``model.next_action(state, tools)`` → ``ToolCall`` | ``FinalAnswer``
   - ``ToolCall``: validate the id against the package allowlist, INJECT the
     evidence path from ``EvidenceManager`` (the LLM never picks an absolute
     path — defense in depth against prompt-injected paths), then
     ``dispatcher.execute(case_id=...)``. Append the tool result message and
     continue.
   - ``FinalAnswer``: return.

Safety (THREAT_MODEL gates 5-7):
- The model proposes a ``tool_id`` from a closed allowlist (the package's
  ``policy/tools.yaml``). Anything outside the allowlist is refused as a tool
  message and the loop continues so the model can recover.
- Evidence paths and output directories are injected by Agentopsy, not by the
  model.
- Every tool run goes through the dispatcher → ``ArtifactRun`` + ``audit.jsonl``.

Egress border (THREAT_MODEL gate 9 / FORENSIC_SOUNDNESS §5):
- When the backend is NOT local, the conversation handed to ``next_action`` is
  redacted with the package's ``redaction_patterns`` at a single point — the raw
  conversation is kept internally for replay, only the wire payload is minimized.
- A cloud run no longer requires a recorded consent (removed 2026-07-16); the
  optional ``consent_ref`` is only threaded into the audit as a label when a
  caller provides one. Local runs never leave the host.
- The agent chains run-start, each cloud egress (hash of the redacted payload),
  and each finding into the case ``audit.jsonl`` — metadata/hashes only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from collections.abc import Callable
from typing import Any

from agentopsy.i18n import Mensaje, t
from agentopsy.agent.context import (
    session_context_budget_chars,
    transcript_chars,
    window_messages,
)
from agentopsy.agent.package import AgentPackage
from agentopsy.agent.redaction import redact_messages
from agentopsy.agent.tool_schemas import (
    internal_tool_specs,
    tool_specs,
)
from agentopsy.artifacts.store import artifact_store
from agentopsy.audit import AuditLog
from agentopsy.evidence import EvidenceManager
from agentopsy.evidence_context import EvidenceContext
from agentopsy.findings.atribucion import atribuir_evidencia
from agentopsy.findings.store import finding_store
from agentopsy.knowledge import knowledge_store
from agentopsy.mitre.coverage import coverage_store
from agentopsy.timeline import query_filesystem_timeline
from agentopsy.models.base import (
    FinalAnswer,
    ModelBackend,
    ResponseContractError,
    ToolBatch,
    ToolCall,
)
from agentopsy.path_policy import inject_evidence_path
from agentopsy.toolkit.catalog import BY_ID as TOOL_BY_ID
from agentopsy.toolkit.tool import Tool

logger = logging.getLogger(__name__)

#: Rondas de CORRECCIÓN SEGUIDAS que se le conceden al modelo cuando su
#: respuesta no cumple el contrato de formato (``ResponseContractError``): el
#: contador se pone a cero en cuanto vuelve a emitir un envoltorio válido, así
#: que lo que se prohíbe son dos incumplimientos consecutivos, no dos en toda
#: una corrida de veinte iteraciones. Mismo criterio que
#: ``reports.writer.MAX_REPARACIONES`` y por la misma razón: tirar una corrida
#: entera, con sus iteraciones ya pagadas, porque el modelo puso el nombre de una
#: herramienta en ``action`` en vez de en ``tool_id`` no protege nada, solo
#: pierde el trabajo. NO es un fallback (RULE 2): el mismo ejecutor, el mismo
#: contrato, ninguna tolerancia nueva en el parser, y el motivo exacto devuelto
#: al modelo. Si la corrección tampoco cumple, la corrida se aborta como antes.
#: La ronda CONSUME una iteración del presupuesto porque cuesta una llamada real
#: al ejecutor: el coste se ve en el contador, nunca se esconde.
MAX_REPARACIONES_CONTRATO = 1


def _contract_repair_message(exc: ResponseContractError) -> str:
    """El mensaje que devuelve al modelo el defecto EXACTO de su envoltorio.

    Es autocontenido a propósito (cita la muestra de lo que emitió) para que
    valga igual con transporte de sesión, donde el modelo ya tiene su turno en la
    conversación, que con un ejecutor stateless, donde no lo tiene.
    """
    muestra = exc.raw_text.strip()
    bloque = f"\nEsto es lo que emitiste:\n{muestra}\n" if muestra else "\n"
    return (
        t("agentLoop.repairHead")
        + f"{exc}."
        + f"{bloque}"
        + t("agentLoop.repairTail")
    )


def _max_tool_attempts() -> int:
    """Anti-loop guardrail (Bug 001): how many times a tool may FAIL (exit≠0 or an
    execution error) in one session before the loop refuses to run it again. Keeps the
    model from fixating on a tool that keeps failing instead of changing approach.
    Default 3 when ``AGENTOPSY_MAX_TOOL_ATTEMPTS`` is unset (a designed default, not a
    fallback). A value that IS set but invalid (non-integer or < 1) fails loud instead
    of silently becoming 3 (RULE 2)."""
    raw = os.environ.get("AGENTOPSY_MAX_TOOL_ATTEMPTS")
    if raw is None:
        return 3
    try:
        value = int(raw)
    except ValueError:
        value = None
    if value is None or value < 1:
        raise RuntimeError(
            Mensaje("agent.badMaxAttempts", raw=repr(raw))
        )
    return value


def _reasoning_from(raw: object) -> str:
    """The prose the model emitted BEFORE its JSON action — i.e. its reasoning for
    this step. Everything up to the first ``{`` (the action envelope), fence-tolerant."""
    if not isinstance(raw, str):
        return ""
    text = raw.strip()
    if text.startswith("```"):
        text = text.lstrip("`")
        if text[:4].lower() == "json":
            text = text[4:]
    idx = text.find("{")
    prose = (text[:idx] if idx != -1 else text).strip()
    return prose[:600]


def _preview_params(params: dict[str, Any]) -> dict[str, Any]:
    """Display-safe subset of tool params for a progress event (strings truncated)."""
    out: dict[str, Any] = {}
    for key, value in params.items():
        if isinstance(value, str):
            out[key] = value if len(value) <= 120 else value[:117] + "…"
        elif isinstance(value, (int, float, bool)) or value is None:
            out[key] = value
        else:
            out[key] = type(value).__name__
    return out


def _result_summary(result: dict[str, Any]) -> str:
    """One-line human summary of a tool result for the live activity log."""
    parsed = result.get("parsed")
    if isinstance(parsed, dict):
        for key in ("detections", "summary_count", "entries", "count", "lines", "records"):
            value = parsed.get(key)
            if isinstance(value, int):
                return f"{value} {key}"
        for key, value in parsed.items():
            if key != "raw" and isinstance(value, (int, str)):
                return f"{key}={str(value)[:60]}"
    return f"exit {result.get('exit_code')}"


def _consulta_summary(body: dict[str, Any]) -> str:
    """One-line summary of a ``consultar_actividad`` result for the activity log."""
    if body.get("error"):
        return str(body["error"])[:120]
    if body.get("status") == "no_timeline":
        return t("fsTl.noTimelineYet")
    matched = body.get("matched", 0)
    total = body.get("total_events", 0)
    return f"{matched} eventos coinciden (de {total})"


# Hard cap on the chars of ONE tool-result message that reach the executor's
# context (Bug 008). The executor is stateless, so every tool result stays in the
# transcript and is re-sent each iteration — an uncapped result inflates every
# subsequent turn. The full output always lives in the run artifact on disk.
_MAX_TOOL_RESULT_CHARS = 8000

# Spotlighting delimiters for a tool result carrying evidence-derived bytes
# (stdout/stderr/parsed). The model is told, at the border, to treat everything
# between them as DATA, never as an instruction (SECURITY INVARIANTS — hostile
# evidence must not smuggle a prompt-injection payload through a tool result).
def _untrusted_open() -> str:
    """La marca que envuelve la salida de una herramienta, en el idioma del agente.

    Es una barrera de SEGURIDAD (la evidencia es dato hostil), así que el texto
    tiene que estar en la lengua en la que el modelo está razonando.
    """
    return t("agentLoop.untrustedOpen")
_UNTRUSTED_CLOSE = "<<FIN_EVIDENCIA_NO_CONFIABLE>>"


def _bounded_json(body: dict[str, Any], limit: int) -> str:
    """Serialize ``body`` to JSON, kept under ``limit`` chars WITHOUT ever emitting
    invalid JSON. The old code did ``json.dumps(body)[:limit]``, which cut mid
    structure (the model then received unparseable JSON) and, by key order, could
    drop the ``artifact_run`` pointer entirely (Bug 008). Here we shed the heavy
    fields progressively — sample rows, then stdout/stderr previews — and, as a
    last resort, keep only the identifying skeleton. Every return value parses.
    """
    text = json.dumps(body, ensure_ascii=False, default=str)
    if len(text) <= limit:
        return text

    trimmed = dict(body)
    parsed = trimmed.get("parsed")
    if isinstance(parsed, dict) and isinstance(parsed.get("sample"), list):
        parsed = dict(parsed)
        parsed["sample"] = []
        parsed["sample_truncated"] = True
        parsed["omitted"] = "sample elided for context cap, query the run artifact with jq"
        trimmed["parsed"] = parsed
    for key in ("stdout_sample", "stderr_sample"):
        value = trimmed.get(key)
        if isinstance(value, str) and len(value) > 500:
            trimmed[key] = value[:500] + "…"
    text = json.dumps(trimmed, ensure_ascii=False, default=str)
    if len(text) <= limit:
        return text

    # A top-level ``events`` list (consultar_actividad) is the heavy field: shed it
    # PROGRESSIVELY, keeping the summary (status/matched/by_category) and as many events
    # as fit, rather than falling to the all-null skeleton — which would read as "no
    # activity" when the query actually matched (RULE 2: never hide a real result).
    events = trimmed.get("events")
    if isinstance(events, list) and events:
        keep = len(events)
        while keep > 0:
            trimmed["events"] = events[:keep]
            trimmed["events_returned"] = keep
            trimmed["events_truncated_for_context"] = keep < len(events)
            text = json.dumps(trimmed, ensure_ascii=False, default=str)
            if len(text) <= limit:
                return text
            keep //= 2
        trimmed["events"] = []
        trimmed["events_returned"] = 0
        trimmed["events_truncated_for_context"] = True
        text = json.dumps(trimmed, ensure_ascii=False, default=str)
        if len(text) <= limit:
            return text

    skeleton = {
        "tool_id": body.get("tool_id"),
        "exit_code": body.get("exit_code"),
        "run_id": body.get("run_id"),
        "artifact_run": body.get("artifact_run"),
        "truncated": True,
        "note": "tool result too large for context, inspect the run artifact",
    }
    return json.dumps(skeleton, ensure_ascii=False, default=str)


class AgentLoopResult(dict):
    """Convenience dict subclass for typing the run() return."""


class ForensicAgent:
    def __init__(
        self,
        package: AgentPackage,
        model: ModelBackend,
        evidence: EvidenceManager,
        audit: AuditLog | None = None,
    ) -> None:
        self.package = package
        self.os_profile = package.os_profile
        self.model = model
        self.evidence = evidence
        self.audit = audit  # optional — the dispatcher already audits tool runs

    def available_tools(self) -> tuple[Tool, ...]:
        """Tools the agent is ACTUALLY allowed to invoke (allowlist ∩ catalog)."""
        return tuple(TOOL_BY_ID[tool_id] for tool_id in self.package.policy.allowed_tools)

    def available_tool_ids(self) -> tuple[str, ...]:
        return tuple(t for t in self.package.policy.allowed_tools if t in TOOL_BY_ID)

    def run(
        self,
        prompt: str,
        case_id: str,
        consent_ref: str | None = None,
        prior_messages: list[dict[str, Any]] | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
        should_cancel: Callable[[], bool] | None = None,
    ) -> AgentLoopResult:
        """Investiga el caso ``case_id`` sobre TODAS sus evidencias registradas.

        No hay evidencia primaria: el alcance es el conjunto de evidencias del
        caso, todas con el mismo peso. Con varias, cada herramienta nombra la suya
        (``evidence_id`` de un enum cerrado, sin valor por defecto) y un hallazgo
        toma la evidencia de la ejecución que lo sostiene. Centrarse en una
        evidencia es algo que pide el perito en el propio mensaje, no un parámetro
        de la petición.
        """
        # Local import to avoid a circular dep that only matters at call time.
        from agentopsy.toolkit.dispatcher import ToolExecutionError, execute as dispatch_tool

        def emit(event: dict[str, Any]) -> None:
            """Best-effort progress event for the streaming surface; a broken
            consumer must never crash the forensic loop."""
            if on_event is None:
                return
            try:
                on_event(event)
            except Exception:  # noqa: BLE001 — progress is non-critical
                logger.debug("on_event consumer raised; ignoring", exc_info=True)

        if not prompt:
            raise ValueError("prompt is required")
        if not case_id:
            raise ValueError("case_id is required for an LLM-driven run")

        # Egress posture (FORENSIC_SOUNDNESS §5): a non-local backend means
        # evidence-derived content crosses to a third party. Redact at the single
        # egress point. Cloud egress no longer requires a recorded consent (the
        # UI warns; consent is not enforced/recorded — removed 2026-07-16); the
        # optional ``consent_ref`` is threaded into the audit only as a label when
        # a caller supplies one. Local backends never leave the host, so there is
        # nothing to redact.
        is_cloud = not self.model.capabilities().is_local
        model_name = getattr(self.model, "model_name", self.model.name)

        # ALCANCE: TODAS las evidencias del caso, por igual. Un caso real trae varias
        # (RAM + disco, un documento aportado) y la investigación las CORRELACIONA:
        # los TTP y las credenciales viven en la memoria, el «cuándo» fino y los
        # borrados en el disco. No hay evidencia primaria ni una por defecto: con
        # varias, cada herramienta nombra la suya con `evidence_id` (enum cerrado) y
        # la llamada que lo omite se rechaza; con una sola, esa ES el alcance entero.
        # Los paths y el EvidenceContext (que ata cada run a su evidencia por hash en
        # el audit, FORENSIC INVARIANT 4) los inyecta Agentopsy por handle verificado:
        # el modelo solo elige un id de un enum cerrado, nunca una ruta (SECURITY
        # INVARIANT 5-6). Un caso sin evidencias no tiene nada que investigar y falla
        # en alto (RULE 2).
        all_handles = list(self.evidence.list(case_id))
        if not all_handles:
            raise ValueError(Mensaje("agent.noEvidence", case=case_id))
        handles_by_id: dict[str, Any] = {h.evidence_id: h for h in all_handles}
        scope_ids = list(handles_by_id)
        multi_evidence = len(scope_ids) > 1
        evidence_paths = {eid: str(h.original_path) for eid, h in handles_by_id.items()}
        evidence_contexts = {
            eid: EvidenceContext.from_handle(h) for eid, h in handles_by_id.items()
        }
        # Etiqueta legible por evidencia para el selector: «fichero · kind».
        evidence_choices = [
            (eid, f"{h.original_path.name} · {h.detected_kind}")
            for eid, h in handles_by_id.items()
        ]

        def target_evidence(tool_id: str, declared: Any) -> str:
            """La evidencia sobre la que corre UNA llamada, o ``ValueError``.

            La declarada, si es del caso; sin declarar, solo cuando el caso tiene
            una única evidencia (el alcance entero). Con varias, omitirla es un
            error que se le devuelve al modelo con las evidencias válidas: elegir
            una aquí sería resucitar la primaria (RULE 2)."""
            opciones = "; ".join(f"{eid} = {label}" for eid, label in evidence_choices)
            if declared is None or declared == "":
                if multi_evidence:
                    raise ValueError(
                        Mensaje(
                            "agentLoop.evidenceRequired",
                            tool=tool_id,
                            choices=opciones,
                        )
                    )
                return scope_ids[0]
            if not isinstance(declared, str) or declared not in handles_by_id:
                raise ValueError(
                    Mensaje(
                        "agentLoop.evidenceNotInCase",
                        evidence_id=repr(declared),
                        choices=opciones,
                    )
                )
            return declared

        allowed = self.available_tool_ids()
        if not allowed:
            return AgentLoopResult(
                reply=t("agent.noValidTools", id=self.package.id),
                iterations=0,
                tool_calls=[],
            )

        system_text = self._system_prompt(case_id, allowed, all_handles)

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_text},
            *(prior_messages or []),
            {"role": "user", "content": prompt},
        ]
        state: dict[str, Any] = {
            "messages": messages,
            "temperature": float(self.package.model.temperature or 0.2),
        }
        specs = tool_specs(list(allowed), evidence_choices) + internal_tool_specs(
            evidence_choices
        )
        # RULE 2: don't offer consultar_conocimiento when there is NOTHING it could
        # serve. Ahora tiene dos ámbitos, así que hay algo que servir si el paquete
        # trae docs estáticos, si declara un núcleo de nodos por caso, o si el caso
        # ya tiene nodos escritos. `anotar_conocimiento` sí se ofrece siempre: el
        # grafo puede estar vacío y eso es un estado válido (decisión D4).
        try:
            case_nodes = knowledge_store.index(case_id)
        except (KeyError, ValueError, OSError):
            case_nodes = []
        if not (self.package.knowledge or self.package.case_knowledge or case_nodes):
            specs = [
                s for s in specs if s["function"]["name"] != "consultar_conocimiento"
            ]

        max_iter = max(1, int(self.package.model.max_iterations or 8))
        tool_calls_log: list[dict[str, Any]] = []
        # Anti-loop guardrail (Bug 001): failures per tool_id in this session.
        max_attempts = _max_tool_attempts()
        tool_failures: dict[str, int] = {}

        # F3 — anchor the run in the case's hash-chained audit log: which model,
        # which backend, over which evidence. Only metadata/hashes ever land here.
        # The run is anchored to its WHOLE scope (every evidence of the case with
        # its baseline hash), never to a single «primary» one.
        self._audit_event(
            "agent_run_start",
            case_id=case_id,
            evidences=[ctx.audit_fields() for ctx in evidence_contexts.values()],
            backend=self.model.name,
            model_name=model_name,
            consent_ref=consent_ref,
        )

        # Nudge estructural: si el agente encadena herramientas del catálogo sin
        # registrar hallazgos, se le recuerda que registre EN CALIENTE (un análisis
        # largo puede cortarse y se perdería lo no persistido). Refuerza el prompt.
        tools_since_finding = 0
        FINDING_NUDGE_AFTER = 3

        # Correcciones de contrato encadenadas. Se pone a cero en cuanto el
        # modelo vuelve a emitir un envoltorio válido: la garantía es «nunca dos
        # incumplimientos SEGUIDOS», no «uno por corrida». Un desliz aislado en
        # la iteración 2 no debe condenar a la 15, y un modelo que no consigue
        # cumplir el formato dos veces seguidas no va a conseguirlo a la tercera.
        contract_repairs = 0

        # Identificadores del PLANO DE CONTROL: los emite Agentopsy, no salen de la
        # evidencia y el agente los necesita literales para citar procedencia. Se
        # excluyen de la redacción de egress (ver agentopsy.agent.redaction). Crece
        # con cada run: un `run_id` nuevo entra aquí antes de viajar al modelo.
        # Los ids de TODAS las evidencias del alcance van aquí: el agente tiene que
        # poder pasarlos literales en `evidence_id`.
        protected_ids: set[str] = {i for i in (case_id, *scope_ids) if i}

        for iteration in range(max_iter):
            # Parada cooperativa del operador (botón «Parar»). Se comprueba al
            # inicio de cada iteración: no se lanza otra vuelta del modelo ni otra
            # herramienta. Lo persistido en caliente (findings, grafo, artefactos)
            # se conserva — la parada no borra nada.
            if should_cancel is not None and should_cancel():
                stopped = t("agent.stoppedByOperator")
                emit({"type": "final", "iteration": iteration, "text": stopped, "cancelled": True})
                return AgentLoopResult(
                    reply=stopped, iterations=iteration, tool_calls=tool_calls_log
                )
            # Nudge de PRESUPUESTO (fase-turnos §6.4): la corrida medida agotó
            # sus 21 iteraciones sin emitir un solo `final` — 12,97 USD sin
            # respuesta al operador. El agente no conoce el presupuesto salvo
            # que se le diga: a 2 iteraciones del límite se le avisa de que
            # cierre, y en la última se le exige el `final` consolidando lo ya
            # persistido (los hallazgos registrados en caliente nunca se
            # pierden; la RESPUESTA sí se perdía).
            remaining = max_iter - iteration
            if remaining == 2 and max_iter > 2:
                messages.append({
                    "role": "system",
                    "content": t("agentLoop.budgetTwoLeft"),
                })
            elif remaining == 1 and max_iter > 1:
                messages.append({
                    "role": "system",
                    "content": t("agentLoop.budgetLast"),
                })
            # Bug 008 / Fase 3 — provider-agnostic context management. Agentopsy
            # owns the conversation. For a STATELESS executor the whole transcript
            # is re-charged every iteration, so older tool results collapse to
            # stubs (window_messages) to keep a run from growing O(N^2). Under
            # SESSION transport the economics invert: each message crosses the
            # wire once and is then read at cache rate, while a stub planted in
            # the session makes the model burn whole turns re-reading what the
            # stub elided (medido: 12 de 21 turnos, ~42 % de la entrada). Con backend de
            # sesión el tránscrito viaja ÍNTEGRO, salvo que supere el presupuesto
            # de seguridad — y ese recorte se AUDITA, nunca en silencio (RULE 2).
            session_capable = bool(
                getattr(self.model, "supports_session_transport", False)
            )
            trimmed_over_budget = False
            if session_capable:
                if transcript_chars(messages) > session_context_budget_chars():
                    wire_messages = window_messages(messages)
                    trimmed_over_budget = True
                else:
                    wire_messages = [dict(m) for m in messages]
            else:
                wire_messages = window_messages(messages)
            if trimmed_over_budget:
                self._audit_event(
                    "context_window_trimmed",
                    case_id=case_id,
                    evidence_ids=scope_ids,
                    iteration=iteration + 1,
                    message_count=len(messages),
                    transcript_chars=transcript_chars(messages),
                    budget_chars=session_context_budget_chars(),
                )
            # F1 — SINGLE egress point. For a cloud backend, redact the outbound
            # copy with the package's patterns; the canonical `messages` stays
            # raw. F3 — audit each egress with the SHA-256 of the exact payload
            # sent (redacted), never the bytes.
            # `protected_ids`: los identificadores que Agentopsy GENERÓ en esta
            # corrida. Sin ellos, el patrón `guid` del paquete —pensado para tapar
            # el MachineGuid que venga DENTRO de la evidencia— convertía cada
            # `run_id` en `<GUID>`, y el agente no podía citar procedencia: ni
            # encadenar tsk_mactime, ni leer un artefacto, ni registrar un
            # hallazgo. No son datos de la evidencia y no hay nada que minimizar.
            outbound = (
                redact_messages(
                    wire_messages,
                    self.package.policy.redaction_patterns,
                    protected=protected_ids,
                )
                if is_cloud
                else wire_messages
            )
            if is_cloud:
                payload = json.dumps(
                    outbound, sort_keys=True, separators=(",", ":"), default=str
                ).encode("utf-8")
                self._audit_event(
                    "agent_cloud_egress",
                    case_id=case_id,
                    evidence_ids=scope_ids,
                    backend=self.model.name,
                    model_name=model_name,
                    consent_ref=consent_ref,
                    redacted_payload_sha256=hashlib.sha256(payload).hexdigest(),
                    message_count=len(outbound),
                    iteration=iteration,
                )
            # An executor that can CONTINUE its own conversation is sent only the
            # delta (plan.md Fase 1). That path needs the append-only list — with
            # session transport `wire_messages` IS that list (uncut, save the
            # audited over-budget trim), already through the single egress point
            # and the exact payload the cloud-egress audit hashed (F1/F3). The
            # backend decides between delta and full context, and only after
            # `session_guard` can account for the session.
            outbound_full = outbound if session_capable else None
            egress_state = {**state, "messages": outbound, "messages_full": outbound_full}
            try:
                action = self.model.next_action(egress_state, specs)
            except ResponseContractError as exc:
                # El modelo SÍ contestó, pero fuera del contrato. A diferencia de
                # un fallo de ejecución (timeout, CLI caído), aquí el defecto se
                # puede nombrar y se le concede UNA corrección. El parser no se
                # relaja: lo que cambia es que un envoltorio mal formado ya no se
                # lleva por delante el resto de la corrida.
                if contract_repairs >= MAX_REPARACIONES_CONTRATO:
                    logger.warning("response contract violated again: %s", exc)
                    self._audit_event(
                        "agent_contract_repair",
                        case_id=case_id,
                        evidence_ids=scope_ids,
                        backend=self.model.name,
                        model_name=model_name,
                        iteration=iteration + 1,
                        attempt=contract_repairs + 1,
                        repaired=False,
                        reason=str(exc),
                    )
                    return AgentLoopResult(
                        reply=t(
                            "agent.contractBroken",
                            model=model_name,
                            iteration=iteration + 1,
                            error=exc,
                        ),
                        iterations=iteration,
                        tool_calls=tool_calls_log,
                    )
                contract_repairs += 1
                logger.warning(
                    "response contract violated, requesting correction: %s", exc
                )
                self._audit_event(
                    "agent_contract_repair",
                    case_id=case_id,
                    evidence_ids=scope_ids,
                    backend=self.model.name,
                    model_name=model_name,
                    iteration=iteration + 1,
                    attempt=contract_repairs,
                    repaired=True,
                    reason=str(exc),
                )
                messages.append(
                    {"role": "system", "content": _contract_repair_message(exc)}
                )
                continue
            except Exception as exc:  # noqa: BLE001 — surface as friendly reply
                logger.warning("model.next_action failed: %s", exc)
                return AgentLoopResult(
                    reply=t(
                        "agent.iterationFailed",
                        model=getattr(self.model, "model_name", self.model.name),
                        iteration=iteration + 1,
                        error=f"{type(exc).__name__}: {exc}",
                    ),
                    iterations=iteration,
                    tool_calls=tool_calls_log,
                )
            # Envoltorio válido: se cierra la ronda de corrección abierta, si la
            # había. Lo que se acota son los incumplimientos SEGUIDOS.
            contract_repairs = 0

            # The prompt-cache watchdog (plan.md Fase 0). The whole saving of the
            # session transport depends on where the CLI puts its cache
            # breakpoints — an internal detail a version bump can move silently,
            # whose only symptom is a 3-4× bill. Surfacing it in the log AND the
            # hash-chained audit is how the system notices its own regression
            # instead of us finding it on the invoice. Never fatal: a cold cache
            # costs money, it does not corrupt the analysis.
            for notice in getattr(self.model, "notices", []) or []:
                logger.warning("cache regression: %s", notice)
                self._audit_event(
                    "executor_cache_regression",
                    case_id=case_id,
                    evidence_ids=scope_ids,
                    backend=self.model.name,
                    model_name=model_name,
                    iteration=iteration + 1,
                    detail=notice,
                )
            if getattr(self.model, "notices", None):
                self.model.notices.clear()

            if isinstance(action, FinalAnswer):
                emit({"type": "final", "iteration": iteration + 1, "text": action.text})
                return AgentLoopResult(
                    reply=action.text,
                    iterations=iteration + 1,
                    tool_calls=tool_calls_log,
                )

            if isinstance(action, (ToolCall, ToolBatch)):
                if action.assistant_message is not None:
                    messages.append(action.assistant_message)
                    reasoning = _reasoning_from(action.assistant_message.get("content"))
                    if reasoning:
                        emit({"type": "reasoning", "iteration": iteration + 1, "text": reasoning})

                # Un lote se ejecuta ENTERO dentro de esta iteración: el coste de
                # una corrida es contexto × turnos, así que encadenar aquí las
                # herramientas que no dependen unas de otras evita re-enviar el
                # transcript una vez por herramienta. Cada call conserva su
                # ArtifactRun, su audit con el argv literal y su mensaje de
                # resultado — el lote no relaja ninguna garantía, solo agrupa.
                batch = (
                    list(action.calls) if isinstance(action, ToolBatch) else [action]
                )
                for call in batch:

                    # Internal side-channel tools — NOT in the catalog and NOT
                    # subject to the package allowlist. Handled in-process.
                    if call.tool_id == "record_finding":
                        try:
                            params = dict(call.params)
                            # La evidencia del hallazgo es la de la EJECUCIÓN que lo
                            # sostiene (manifiesto del run_id), nunca una primaria ni
                            # la que el modelo diga contra el registro. Sin run_id,
                            # la declarada; sin ninguna, la única del caso o ninguna
                            # (hallazgo del caso entero). Ver findings.atribucion.
                            atribucion = atribuir_evidencia(
                                case_id,
                                run_id=params.get("run_id"),
                                declarada=params.get("evidence_id"),
                                evidencias_del_caso=scope_ids,
                                store=artifact_store,
                            )
                            params["evidence_id"] = atribucion.evidence_id
                            finding = finding_store.append(case_id, params)
                            body = {
                                "finding_id": finding.id,
                                "evidence_id": finding.evidence_id,
                                "stored": True,
                            }
                            protected_ids.add(finding.id)
                            tools_since_finding = 0  # cerró el bucle: registró
                            # F3 — record the finding's provenance in the audit chain
                            # (the id, the evidence it belongs to and HOW that was
                            # determined; the finding body lives in findings.jsonl).
                            self._audit_event(
                                "agent_finding",
                                case_id=case_id,
                                evidence_id=finding.evidence_id,
                                evidence_source=atribucion.origen,
                                run_id=finding.run_id,
                                finding_id=finding.id,
                            )
                            emit({
                                "type": "finding",
                                "iteration": iteration + 1,
                                "title": finding.title,
                                "severity": finding.severity,
                                "evidence_id": finding.evidence_id,
                            })
                        except (KeyError, ValueError) as exc:
                            body = {"error": f"record_finding rejected: {exc}"}
                        messages.append(self._tool_result_msg(call, body))
                        tool_calls_log.append({
                            "tool_id": "record_finding",
                            "finding_id": body.get("finding_id"),
                            "evidence_id": body.get("evidence_id"),
                            "error": body.get("error"),
                        })
                        continue

                    if call.tool_id == "annotate_mitre":
                        # Anchors ATT&CK techniques to an existing finding → shows up on
                        # the MITRE board as an agent proposal (coverage eje 1). Same
                        # in-process side-channel shape as record_finding.
                        try:
                            params = dict(call.params)
                            finding_id = (params.get("finding_id") or "").strip()
                            rec = coverage_store.annotate(
                                case_id,
                                finding_id,
                                params.get("mitre_hints") or [],
                                params.get("note"),
                            )
                            body = {
                                "finding_id": finding_id,
                                "technique_ids": rec["technique_ids"],
                                "annotated": True,
                            }
                        except (KeyError, ValueError) as exc:
                            body = {"error": f"annotate_mitre rejected: {exc}"}
                        messages.append(self._tool_result_msg(call, body))
                        tool_calls_log.append({
                            "tool_id": "annotate_mitre",
                            "finding_id": body.get("finding_id"),
                            "error": body.get("error"),
                        })
                        continue

                    if call.tool_id == "declarar_pivote":
                        # Cambiar de vía cuando una se cierra es la jugada que resuelve
                        # casos reales (el disco no abre → hives desde la RAM). RULE 2
                        # prohíbe el fallback SILENCIOSO, no el pivote: aquí es
                        # explícito, exige el sostén (exit/stderr/run_id) y queda en la
                        # cadena de custodia para que el perito lo vea y lo discuta.
                        try:
                            params = dict(call.params)
                            via = str(params.get("via_cerrada") or "").strip()
                            motivo = str(params.get("motivo") or "").strip()
                            alt = str(params.get("via_alternativa") or "").strip()
                            if not (via and motivo and alt):
                                raise ValueError(
                                    Mensaje("agent.pivotNeedsAll")
                                )
                            body = {"registrado": True, "via_cerrada": via}
                            self._audit_event(
                                "agent_pivot",
                                case_id=case_id,
                                evidence_ids=scope_ids,
                                via_cerrada=via[:200],
                                motivo=motivo[:1000],
                                via_alternativa=alt[:1000],
                                iteration=iteration + 1,
                            )
                        except (KeyError, ValueError) as exc:
                            body = {"error": f"declarar_pivote rejected: {exc}"}
                        messages.append(self._tool_result_msg(call, body))
                        tool_calls_log.append({
                            "tool_id": "declarar_pivote",
                            "via_cerrada": body.get("via_cerrada"),
                            "error": body.get("error"),
                        })
                        emit({
                            "type": "pivot" if not body.get("error") else "tool_result",
                            "iteration": iteration + 1,
                            "tool_id": "declarar_pivote",
                            "status": "ok" if not body.get("error") else "error",
                            "summary": (
                                body.get("via_cerrada") or str(body.get("error"))
                            )[:120],
                        })
                        continue

                    if call.tool_id == "leer_artefacto":
                        # El agente mira lo que él mismo produjo. Sin esto solo ve un
                        # `stdout_sample` de 2000 chars y una salida de regripper o un
                        # árbol de fls le resultan opacos — acaba re-ejecutando la
                        # herramienta o infiriendo sin sostén.
                        # Es un `grep` SIN shell: el modelo pasa un run_id (nunca una
                        # ruta), el store confina el fichero dentro del run y `buscar` es
                        # una subcadena literal, jamás una regex del modelo.
                        try:
                            params = dict(call.params)
                            body = artifact_store.read_run_output(
                                case_id,
                                str(params.get("run_id") or "").strip(),
                                fichero=str(params.get("fichero") or "stdout").strip(),
                                buscar=params.get("buscar"),
                                desde=params.get("desde", 1),
                                lineas=params.get("lineas", 200),
                            )
                        except (KeyError, ValueError, OSError) as exc:
                            body = {"error": f"leer_artefacto rejected: {exc}"}
                        # UNTRUSTED: son bytes derivados de la evidencia (dato hostil),
                        # exactamente igual que el resultado de ejecutar la herramienta.
                        messages.append(
                            self._tool_result_msg(call, body, untrusted=True)
                        )
                        tool_calls_log.append({
                            "tool_id": "leer_artefacto",
                            "run_id": body.get("run_id"),
                            "devueltas": body.get("devueltas"),
                            "error": body.get("error"),
                        })
                        emit({
                            "type": "tool_result",
                            "iteration": iteration + 1,
                            "tool_id": "leer_artefacto",
                            "status": "ok" if not body.get("error") else "error",
                            "summary": (
                                t(
                                    "agentLoop.linesOf",
                                    returned=body.get("devueltas"),
                                    relevant=body.get("lineas_relevantes"),
                                    tool=body.get("tool_id"),
                                )
                                if not body.get("error")
                                else str(body.get("error"))
                            )[:120],
                        })
                        continue

                    if call.tool_id == "anotar_conocimiento":
                        # Lado de ESCRITURA del grafo por caso. Nunca toca la evidencia ni
                        # los artefactos: escribe bajo `cases/<id>/knowledge/`, append-only
                        # con vista consolidada. El modelo emite un ID de charset cerrado,
                        # jamás una ruta (SECURITY INVARIANT 5-6).
                        doc_id = ""
                        try:
                            params = dict(call.params)
                            doc_id = str(params.get("doc_id") or "").strip()
                            block = knowledge_store.append(
                                case_id,
                                doc_id,
                                str(params.get("section") or ""),
                                str(params.get("content") or ""),
                                iteration=iteration + 1,
                            )
                            body = {
                                "doc_id": block.doc_id,
                                "section": block.section,
                                "stored": True,
                            }
                            # F3 — metadatos y hash en la cadena, nunca el contenido.
                            self._audit_event(
                                "knowledge_written",
                                case_id=case_id,
                                evidence_ids=scope_ids,
                                doc_id=block.doc_id,
                                section=block.section,
                                content_sha256=block.sha256,
                                content_chars=len(block.content),
                                iteration=iteration + 1,
                            )
                        except (KeyError, ValueError, OSError) as exc:
                            body = {"error": f"anotar_conocimiento rejected: {exc}"}
                        messages.append(self._tool_result_msg(call, body))
                        tool_calls_log.append({
                            "tool_id": "anotar_conocimiento",
                            "doc_id": doc_id,
                            "error": body.get("error"),
                        })
                        emit({
                            "type": "tool_result",
                            "iteration": iteration + 1,
                            "tool_id": "anotar_conocimiento",
                            "status": "ok" if not body.get("error") else "error",
                            "summary": (
                                f"{body.get('doc_id')} · {body.get('section')}"
                                if not body.get("error")
                                else str(body.get("error"))
                            )[:120],
                        })
                        continue

                    if call.tool_id == "consultar_conocimiento":
                        # Mapa de memoria. Resuelve en DOS ámbitos, en este orden:
                        #   1. Nodo del grafo de ESTE caso (lo escribió el agente) →
                        #      vuelve marcado NO CONFIABLE: sus notas citan cadenas
                        #      derivadas de la evidencia, y releerlas como contexto de
                        #      confianza sería un canal de blanqueo de prompt-injection.
                        #   2. Doc estático del paquete → contenido de CONFIANZA (autoría
                        #      nuestra, cargado y path-confinado al arrancar), sin
                        #      spotlighting.
                        doc = None
                        node = None
                        try:
                            # str(): el modelo podría emitir doc_id no-string (Ollama texto);
                            # coerciona sin crashear el run (simetría con los otros handlers).
                            doc_id = str(dict(call.params).get("doc_id") or "").strip()
                            try:
                                node = knowledge_store.read(case_id, doc_id)
                            except (KeyError, ValueError):
                                node = None  # id no válido como nodo → puede ser doc estático
                            if node is not None:
                                body = {
                                    "doc_id": node.doc_id,
                                    "scope": "caso",
                                    "sections": list(node.sections),
                                    "content": node.markdown,
                                }
                            else:
                                doc = next(
                                    (d for d in self.package.knowledge if d.id == doc_id), None
                                )
                                if doc is None:
                                    valid = [d.id for d in self.package.knowledge]
                                    nodes = [n.doc_id for n in knowledge_store.index(case_id)]
                                    body = {
                                        "error": t(
                                            "agentLoop.unknownDocId",
                                            doc_id=repr(doc_id),
                                            valid=valid,
                                            nodes=nodes,
                                        )
                                    }
                                else:
                                    body = {
                                        "doc_id": doc.id,
                                        "scope": "paquete",
                                        "title": doc.title,
                                        "content": doc.content,
                                    }
                        except (KeyError, ValueError, TypeError, AttributeError) as exc:
                            body = {"error": f"consultar_conocimiento rejected: {exc}"}
                        messages.append(
                            self._tool_result_msg(call, body, untrusted=node is not None)
                        )
                        tool_calls_log.append({
                            "tool_id": "consultar_conocimiento",
                            "doc_id": doc_id,
                            "error": body.get("error"),
                        })
                        emit({
                            "type": "tool_result",
                            "iteration": iteration + 1,
                            "tool_id": "consultar_conocimiento",
                            "status": "ok" if not body.get("error") else "error",
                            "summary": (
                                node.doc_id if node else doc.title if doc
                                else body.get("error", "")
                            )[:120],
                        })
                        continue

                    if call.tool_id == "consultar_actividad":
                        # Read-only projection over the persisted super-timeline of ONE
                        # evidence, the one the model names (closed enum; required when
                        # the case has several) — answers date-range / category / path
                        # queries WITHOUT re-running fls (the mapa vivo). In-process
                        # side-channel like record_finding.
                        target_eid: str | None = None
                        try:
                            params = dict(call.params)
                            target_eid = target_evidence(
                                "consultar_actividad", params.get("evidence_id")
                            )
                            body = query_filesystem_timeline(
                                case_id,
                                target_eid,
                                date_from=params.get("date_from"),
                                date_to=params.get("date_to"),
                                category=params.get("category"),
                                path_contains=params.get("path_contains"),
                                limit=params.get("limit", 100),
                            )
                        except (KeyError, ValueError, RuntimeError, OSError) as exc:
                            body = {"error": f"consultar_actividad rejected: {exc}"}
                        messages.append(
                            self._tool_result_msg(call, body, untrusted=True)
                        )
                        tool_calls_log.append({
                            "tool_id": "consultar_actividad",
                            "evidence_id": target_eid,
                            "matched": body.get("matched"),
                            "status": body.get("status"),
                            "error": body.get("error"),
                        })
                        emit({
                            "type": "tool_result",
                            "iteration": iteration + 1,
                            "tool_id": "consultar_actividad",
                            "evidence_id": target_eid,
                            "status": "ok" if not body.get("error") else "error",
                            "summary": _consulta_summary(body),
                        })
                        continue

                    if call.tool_id not in allowed:
                        refusal = t(
                            "agentLoop.notInAllowlist",
                            tool=call.tool_id,
                            package=self.package.id,
                            allowed=", ".join(f"`{tool}`" for tool in allowed),
                        )
                        messages.append(self._tool_result_msg(call, {"error": refusal}))
                        tool_calls_log.append(
                            {"tool_id": call.tool_id, "refused": True, "reason": "not_in_allowlist"}
                        )
                        emit({
                            "type": "tool_result",
                            "iteration": iteration + 1,
                            "tool_id": call.tool_id,
                            "status": "refused",
                            "summary": t("agentLoop.refusedSummary"),
                        })
                        continue

                    # Guardrail anti-bucle (Bug 001): no reintentes una tool que ya falló
                    # `max_attempts` veces en esta sesión — fuerza al modelo a cambiar de
                    # herramienta o a cerrar, en vez de repetir un exit≠0 hasta agotar
                    # iteraciones. Solo cuentan los FALLOS: una tool que va bien puede
                    # llamarse cuantas veces haga falta (p. ej. tsk_icat por inodo).
                    if tool_failures.get(call.tool_id, 0) >= max_attempts:
                        blocked = t(
                            "agentLoop.blockedTool",
                            tool=call.tool_id,
                            attempts=max_attempts,
                        )
                        messages.append(
                            self._tool_result_msg(call, {"error": blocked, "blocked": True})
                        )
                        tool_calls_log.append(
                            {"tool_id": call.tool_id, "blocked": True, "reason": "max_failed_attempts"}
                        )
                        emit({
                            "type": "tool_result",
                            "iteration": iteration + 1,
                            "tool_id": call.tool_id,
                            "status": "blocked",
                            "summary": f"bloqueado tras {max_attempts} fallos",
                        })
                        continue

                    target_eid = None
                    try:
                        # MULTI-EVIDENCIA: el modelo dice a qué evidencia apunta esta
                        # herramienta (enum cerrado). Se saca de los params (NO va al
                        # argv), se valida contra las evidencias del caso y se
                        # resuelven SU path y SU contexto de auditoría. Con varias
                        # evidencias es obligatoria: no hay primaria a la que caer.
                        raw_params = dict(call.params)
                        try:
                            target_eid = target_evidence(
                                call.tool_id, raw_params.pop("evidence_id", None)
                            )
                        except ValueError as exc:
                            raise ToolExecutionError(*exc.args) from exc
                        target_path = evidence_paths[target_eid]
                        target_context = evidence_contexts[target_eid]
                        params = self._inject_runtime_paths(
                            call.tool_id, raw_params, target_path
                        )
                        emit({
                            "type": "tool_call",
                            "iteration": iteration + 1,
                            "tool_id": call.tool_id,
                            "evidence_id": target_eid,
                            "params": _preview_params(params),
                        })
                        result = dispatch_tool(
                            call.tool_id,
                            params,
                            case_id=case_id,
                            os_profile=self.os_profile,
                            evidence_context=target_context,
                        )
                    except ToolExecutionError as exc:
                        tool_failures[call.tool_id] = tool_failures.get(call.tool_id, 0) + 1
                        messages.append(
                            self._tool_result_msg(call, {"error": f"ToolExecutionError: {exc}"})
                        )
                        tool_calls_log.append(
                            {"tool_id": call.tool_id, "evidence_id": target_eid, "error": str(exc)}
                        )
                        emit({
                            "type": "tool_result",
                            "iteration": iteration + 1,
                            "tool_id": call.tool_id,
                            "evidence_id": target_eid,
                            "status": "error",
                            "summary": str(exc)[:200],
                        })
                        continue
                    except Exception as exc:  # noqa: BLE001 — never crash the loop
                        tool_failures[call.tool_id] = tool_failures.get(call.tool_id, 0) + 1
                        messages.append(
                            self._tool_result_msg(call, {"error": f"{type(exc).__name__}: {exc}"})
                        )
                        tool_calls_log.append(
                            {"tool_id": call.tool_id, "evidence_id": target_eid, "error": str(exc)}
                        )
                        emit({
                            "type": "tool_result",
                            "iteration": iteration + 1,
                            "tool_id": call.tool_id,
                            "evidence_id": target_eid,
                            "status": "error",
                            "summary": f"{type(exc).__name__}: {exc}"[:200],
                        })
                        continue

                    exit_code = result.get("exit_code")
                    if isinstance(exit_code, int) and exit_code != 0:
                        tool_failures[call.tool_id] = tool_failures.get(call.tool_id, 0) + 1

                    # El run_id recién creado NO puede redactarse: es la clave con
                    # la que el agente encadenará, leerá el artefacto y citará
                    # procedencia en su hallazgo.
                    if isinstance(result.get("run_id"), str):
                        protected_ids.add(result["run_id"])

                    emit({
                        "type": "tool_result",
                        "iteration": iteration + 1,
                        "tool_id": call.tool_id,
                        "evidence_id": target_eid,
                        "status": "ok" if exit_code == 0 else "nonzero",
                        "exit_code": exit_code,
                        "run_id": result.get("run_id"),
                        # El argv LITERAL que se ejecutó, para que el perito VEA el
                        # comando lanzado en el chat (no sólo el resultado).
                        "argv": result.get("argv"),
                        "summary": _result_summary(result),
                    })
                    messages.append(
                        self._tool_result_msg(
                            call, self._tool_result_payload(result), untrusted=True
                        )
                    )
                    tool_calls_log.append(
                        {
                            "tool_id": call.tool_id,
                            "evidence_id": target_eid,
                            "run_id": result.get("run_id"),
                            "exit_code": exit_code,
                        }
                    )
                    # Nudge: si acumula herramientas sin registrar, se lo recuerda de
                    # forma explícita (además del prompt). Reinicia el contador para no
                    # repetir cada iteración.
                    tools_since_finding += 1
                    if tools_since_finding >= FINDING_NUDGE_AFTER:
                        messages.append({
                            "role": "system",
                            "content": t(
                                "agentLoop.findingReminder", count=tools_since_finding
                            ),
                        })
                        tools_since_finding = 0
                continue

            raise RuntimeError(
                f"Model returned an unexpected action type: {type(action).__name__}"
            )

        exhausted = t("agentLoop.exhausted", max=max_iter, case=case_id)
        emit({"type": "final", "iteration": max_iter, "text": exhausted, "exhausted": True})
        return AgentLoopResult(
            reply=exhausted,
            iterations=max_iter,
            tool_calls=tool_calls_log,
        )

    # ---- internals ---------------------------------------------------------

    def _audit_event(self, event: str, **fields: Any) -> None:
        """Append one event to the case audit chain, if an AuditLog was wired.

        The dispatcher already audits each tool run (the literal argv); this adds
        the agent-level events the dispatcher cannot see — run start, cloud
        egress, and findings (F3). Never records raw evidence bytes, only
        metadata and hashes. Best-effort: an audit failure must not crash a run.
        """
        if self.audit is None:
            return
        try:
            self.audit.append({"event": event, **fields})
        except Exception as exc:  # noqa: BLE001 — audit must never break the loop
            logger.warning("audit append failed for event %s: %s", event, exc)

    def _case_graph_block(self, case_id: str) -> str:
        """Índice del grafo del caso: una línea por nodo, sin contenido.

        Lleva los NOMBRES DE SECCIÓN, no un resumen redactado: es la granularidad
        con la que el agente decide «¿necesito cargar este nodo?», y no obliga a
        nadie a inventar prosa. El núcleo declarado por el paquete se lista aunque
        esté vacío, para que el agente sepa dónde escribir cada cosa.

        Un caso puede empezar sin ningún nodo y sin encargo declarado: es un estado
        válido (decisión D4). Sin núcleo declarado y sin nodos escritos, la sección
        entera desaparece del prompt en vez de prometer algo que no existe.
        """
        try:
            nodes = knowledge_store.index(case_id)
        except (KeyError, ValueError, OSError):
            nodes = []
        written = {n.doc_id: n for n in nodes}
        core = {n.id: n.description for n in self.package.case_knowledge}
        if not written and not core:
            return ""

        lines: list[str] = []
        for doc_id in [*core, *(d for d in written if d not in core)]:
            node = written.get(doc_id)
            if node is not None:
                secciones = ", ".join(f"`{s}`" for s in node.sections)
                lines.append(f"- `{doc_id}`, secciones: {secciones}")
            else:
                lines.append(f"- `{doc_id}`, {t('agentLoop.emptyNode')} {core[doc_id]}")

        listado = "\n".join(lines)
        return t("agentCtx.knowledge") + f"{listado}\n"

    def _system_prompt(
        self,
        case_id: str,
        allowed: tuple[str, ...],
        evidences: list[Any],
    ) -> str:
        """El system prompt de una corrida sobre ``evidences``: TODAS las del caso.

        Las evidencias se enumeran por igual (id, fichero, triage), sin ninguna
        primaria. Con varias viaja además la regla de alcance: la petición del
        perito se aplica a todas salvo que pida expresamente centrarse en alguna.
        """
        # Bug 008 — only the playbook branch that matches the evidence kind travels
        # in the system prompt (re-sent every stateless iteration). RULE 2: for an
        # `unknown` kind both branches stay; nothing is hidden silently.
        pkg_parts = [
            self.package.prompts.system,
            self.package.prompts.identity,
            self.package.prompts.playbook,  # opcional; vacío desde 2026-07-28
        ]
        identity_block = "\n\n".join(p.strip() for p in pkg_parts if p and p.strip())

        # Build a profile-mismatch warning ONLY for the evidence whose triage
        # fingerprint disagrees with the case's os_profile. The agent's system
        # prompt already carries a hard rule (guard rail) that tells it to stop and
        # request reassignment in this case — this block makes the mismatch
        # impossible to miss. Every evidence is checked, not only one: with several,
        # the block names the ones that disagree and the rest are analysed normally.
        multi = len(evidences) > 1
        desajustadas = [
            h for h in evidences if h.detected_os not in ("unknown", self.os_profile)
        ]
        mismatch_block = ""
        if desajustadas and not multi:
            mismatch_block = t(
                "agentCtx.mismatchBlock",
                profile=self.os_profile,
                detected=desajustadas[0].detected_os,
            )
        elif desajustadas:
            mismatch_block = t(
                "agentCtx.mismatchMulti",
                profile=self.os_profile,
                evidences=", ".join(
                    f"`{h.evidence_id}` (`{h.original_path.name}`, "
                    f"detected_os `{h.detected_os}`)"
                    for h in desajustadas
                ),
            )

        # Route the model to the right playbook section based on detected_kind.
        # Without this, the agent always starts at section A (disk image) of the
        # playbook and burns iterations on tsk_mmls/tsk_fls failures before
        # pivoting to section B (memory) — even when the evidence is clearly
        # a memdump.
        # Mapa de memoria (híbrido): un índice compacto SIEMPRE presente que dice qué
        # referencia existe y cuándo consultarla; el contenido pesado viaja solo cuando
        # el agente llama a consultar_conocimiento(doc_id). Vacío si el paquete no trae
        # docs (y entonces la tool ni se ofrece).
        memory_map = ""
        if self.package.knowledge:
            docs = "\n".join(
                f"- `{d.id}`, {d.description}" for d in self.package.knowledge
            )
            memory_map = t("agentCtx.memoryMap") + f"{docs}\n"

        # RUTA PRINCIPAL: objetivo → artefacto → herramienta. Sustituye al playbook
        # (borrado 2026-07-28), que entraba por TIPO DE EVIDENCIA con una marcha
        # numerada y que el agente seguía literalmente: para responder «¿se accedió
        # a este documento?» empezaba inventariando el disco entero. Compacto a
        # propósito — viaja en cada iteración; el detalle está en `knowledge/`.
        objetivos_block = ""
        if self.package.objetivos:
            filas = []
            for o in self.package.objetivos:
                tools = ", ".join(f"`{t}`" for t in o.herramientas)
                fila = (
                    f"### {o.pregunta}\n"
                    f"- **Artefactos:** {o.artefactos}\n"
                    f"- **Herramientas:** {tools}"
                )
                if o.knowledge:
                    fila += f"\n- **Detalle:** `consultar_conocimiento(\"{o.knowledge}\")`"
                filas.append(fila)
            objetivos_block = (
                t("agentCtx.objectives") + "\n\n".join(filas) + "\n"
            )

        # Grafo de conocimiento DE ESTE CASO. Igual que el mapa de memoria, aquí
        # viaja SOLO el índice (id + secciones): el contenido se trae con
        # `consultar_conocimiento(doc_id)`. Es lo que evita que el estado del
        # análisis tenga que vivir en la conversación —que se reenvía entera cada
        # iteración y se recorta con el windowing— y con él, que el agente pierda
        # un `run_id` a los pocos turnos.
        case_graph = self._case_graph_block(case_id)

        # El triage dice QUÉ es cada evidencia; ya NO dice qué hacer con ella. Antes
        # aquí se le ordenaba «salta a la sección A/B del playbook», y el agente
        # obedecía: para responder «¿se accedió a este documento?» arrancaba
        # inventariando el disco entero. La ruta la marca ahora el objetivo; esto
        # solo evita que gaste llamadas en herramientas incompatibles con el soporte.
        # Con VARIAS evidencias este bloque (que habla de UN soporte) se calla:
        # diría «volatility no aplica» ante un disco en un caso que SÍ tiene una
        # memoria. La guía correcta la da la regla de alcance (`multiEvidence`).
        kind_routing = ""
        if not multi:
            detected_kind = evidences[0].detected_kind
            if detected_kind == "memory":
                kind_routing = t("agentCtx.kindMemory")
            elif detected_kind == "document":
                kind_routing = t("agentCtx.kindDocument")
            elif detected_kind in ("disk", "container_disk"):
                contenedor = (
                    " Va dentro de un contenedor (VMDK/VDI/QCOW/VHD/E01); las "
                    "herramientas TSK lo abren correctamente."
                    if detected_kind == "container_disk"
                    else ""
                )
                kind_routing = t(
                    "agentCtx.kindDisk", kind=detected_kind, container=contenedor
                )

        # LAS EVIDENCIAS DEL CASO, todas por igual: id (lo que el agente pasa en
        # `evidence_id`), fichero y triage. Ninguna va marcada como primaria y el
        # orden no es una prioridad. Con varias viaja además la regla de ALCANCE:
        # la petición se aplica a todas salvo que el perito pida centrarse en alguna.
        evidence_block = t("agentCtx.evidenceHeader", count=len(evidences)) + "".join(
            f"- `{h.evidence_id}`: `{h.original_path.name}`, "
            f"detected_kind `{h.detected_kind}`, detected_os `{h.detected_os}`\n"
            for h in evidences
        )
        scope_block = t("agentCtx.multiEvidence") if multi else ""

        return (
            f"{identity_block}\n\n"
            + t("agentCtx.caseHeader", case=case_id, profile=self.os_profile)
            + "\n"
            + evidence_block
            + f"{scope_block}"
            + f"{kind_routing}"
            + f"{mismatch_block}\n"
            + t("agentCtx.toolkitHeader")
            + ", ".join(f"`{tool}`" for tool in allowed)
            + "\n\n"
            + t("agentCtx.timelineTool")
            + f"{objetivos_block}\n"
            + f"{memory_map}\n"
            + f"{case_graph}\n"
            + t("agentCtx.conduct")
        )

    @staticmethod
    def _inject_runtime_paths(
        tool_id: str, params: dict[str, Any], evidence_path: str
    ) -> dict[str, Any]:
        tool = TOOL_BY_ID[tool_id]
        return inject_evidence_path(tool.path_parameters, params, evidence_path)

    @staticmethod
    def _tool_result_msg(
        call: ToolCall, body: dict[str, Any], *, untrusted: bool = False
    ) -> dict[str, Any]:
        content = _bounded_json(body, _MAX_TOOL_RESULT_CHARS)
        # Anti-inyección (SECURITY INVARIANTS: evidencia hostil → tools → host). El
        # cuerpo de un resultado de tool REAL (stdout/stderr/parsed) son bytes de la
        # evidencia: se envuelven en delimitadores de NO-confianza (spotlighting) para
        # que el modelo los lea como DATOS y nunca como instrucciones. Los resultados
        # de las tools internas (record_finding/annotate_mitre) y los rechazos los
        # genera Agentopsy — son de confianza y NO se envuelven.
        if untrusted:
            content = f"{_untrusted_open()}\n{content}\n{_UNTRUSTED_CLOSE}"
        return {
            "role": "tool",
            "tool_call_id": call.call_id,
            "content": content,
        }

    @staticmethod
    def _tool_result_payload(result: dict[str, Any]) -> dict[str, Any]:
        # Order matters: `artifact_run` (the hashed pointer to the full output on
        # disk) comes BEFORE `parsed` so that if the payload is ever shed under the
        # context cap, the pointer to custody survives (Bug 008 — the old blind
        # `[:8000]` slice could drop it and also corrupt the JSON mid-structure).
        return {
            "tool_id": result.get("tool_id"),
            "exit_code": result.get("exit_code"),
            "run_id": result.get("run_id"),
            "artifact_run": _trim_artifact(result.get("artifact_run")),
            "parsed": result.get("parsed"),
            "stdout_sample": (result.get("stdout_sample") or "")[:2000],
            "stderr_sample": (result.get("stderr_sample") or "")[:2000],
        }


def _trim_artifact(art: Any) -> Any:
    if not isinstance(art, dict):
        return None
    files = art.get("output_files") or []
    return {
        "run_id": art.get("run_id"),
        "exit_code": art.get("exit_code"),
        "output_files_count": len(files),
        "output_files": [
            {"relpath": f.get("relpath"), "size": f.get("size")}
            for f in files[:10]
        ],
    }


__all__ = ["ForensicAgent", "AgentLoopResult"]
