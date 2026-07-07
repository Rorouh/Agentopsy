"""The forensic agent loop.

ONE agent parametrized by an ``AgentPackage`` loaded from ``agentes/<id>/``: the
reasoning loop is identical; what changes per profile is the package (prompts,
allowlist of tools, redaction policy). The executor that answers each
``next_action`` is the one the OPERATOR selected for the request (Claude Code,
Codex CLI, Gemini CLI or Ollama — adapted by ``forensia.models.ExecutorBackend``);
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
- Evidence paths and output directories are injected by FORENSIA, not by the
  model.
- Every tool run goes through the dispatcher → ``ArtifactRun`` + ``audit.jsonl``.

Egress border (THREAT_MODEL gate 9 / FORENSIC_SOUNDNESS §5):
- When the backend is NOT local, the conversation handed to ``next_action`` is
  redacted with the package's ``redaction_patterns`` at a single point — the raw
  conversation is kept internally for replay, only the wire payload is minimized.
- A cloud run REFUSES to start without a ``consent_ref`` (recorded per-case
  consent); local runs never leave the host and need none.
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

from forensia.agent.context import select_playbook_section, window_messages
from forensia.agent.package import AgentPackage
from forensia.agent.redaction import redact_messages
from forensia.agent.tool_schemas import (
    AUTO_INJECTED,
    internal_tool_specs,
    tool_specs,
)
from forensia.audit import AuditLog
from forensia.evidence import EvidenceManager
from forensia.findings.store import finding_store
from forensia.models.base import FinalAnswer, ModelBackend, ToolCall
from forensia.toolkit.catalog import BY_ID as TOOL_BY_ID
from forensia.toolkit.tool import Tool

logger = logging.getLogger(__name__)


def _max_tool_attempts() -> int:
    """Anti-loop guardrail (Bug 001): how many times a tool may FAIL (exit≠0 or an
    execution error) in one session before the loop refuses to run it again. Keeps the
    model from fixating on a tool that keeps failing instead of changing approach.
    Default 3; per-deployment override via ``FORENSIA_MAX_TOOL_ATTEMPTS``."""
    try:
        return max(1, int(os.environ.get("FORENSIA_MAX_TOOL_ATTEMPTS", "3")))
    except ValueError:
        return 3


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


# Map tool_id → which auto-injected key receives the resolved evidence path.
# Tools not in this map don't take the evidence directly (e.g. jq accepts an
# operator-supplied input_path that points to another artifact).
_EVIDENCE_INJECTION: dict[str, str] = {
    "file_info": "image_path",
    "xxd_head": "image_path",
    "strings_head": "image_path",
    "tsk_mmls": "image_path",
    "tsk_fls": "image_path",
    "tsk_icat": "image_path",
    "tsk_mactime": "bodyfile_path",
    "ewf_info": "image_path",
    "bulk_extractor": "image_path",
    "hashdeep": "image_path",
    "foremost": "image_path",
    "plaso_log2timeline": "image_path",
    "plaso_psort": "plaso_path",
    "qemu_nbd": "image_path",
    "yara": "target_path",
    "volatility3": "dump_path",
    "hayabusa": "evtx_dir",
    "chainsaw": "target_dir",
    "regripper": "hive_path",
    "evtxecmd": "evtx_path",
    "mftecmd": "mft_path",
}


# Hard cap on the chars of ONE tool-result message that reach the executor's
# context (Bug 008). The executor is stateless, so every tool result stays in the
# transcript and is re-sent each iteration — an uncapped result inflates every
# subsequent turn. The full output always lives in the run artifact on disk.
_MAX_TOOL_RESULT_CHARS = 8000


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
        parsed["omitted"] = "sample elided for context cap — query the run artifact with jq"
        trimmed["parsed"] = parsed
    for key in ("stdout_sample", "stderr_sample"):
        value = trimmed.get(key)
        if isinstance(value, str) and len(value) > 500:
            trimmed[key] = value[:500] + "…"
    text = json.dumps(trimmed, ensure_ascii=False, default=str)
    if len(text) <= limit:
        return text

    skeleton = {
        "tool_id": body.get("tool_id"),
        "exit_code": body.get("exit_code"),
        "run_id": body.get("run_id"),
        "artifact_run": body.get("artifact_run"),
        "truncated": True,
        "note": "tool result too large for context — inspect the run artifact",
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
        evidence_id: str,
        consent_ref: str | None = None,
        prior_messages: list[dict[str, Any]] | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> AgentLoopResult:
        # Local import to avoid a circular dep that only matters at call time.
        from forensia.toolkit.dispatcher import ToolExecutionError, execute as dispatch_tool

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
        if not evidence_id:
            raise ValueError("evidence_id is required for an LLM-driven run")

        # Egress posture (THREAT_MODEL gate 9 / FORENSIC_SOUNDNESS §5): a non-local
        # backend means evidence-derived content crosses to a third party. Redact
        # at the single egress point and REFUSE without a recorded per-case
        # consent_ref (RULE 2 — no silent egress). Local backends never leave the
        # host, so there is nothing to redact or consent to.
        is_cloud = not self.model.capabilities().is_local
        if is_cloud and not consent_ref:
            raise ValueError(
                "cloud egress requires a recorded consent_ref for this case "
                "(THREAT_MODEL gate 9): refusing to send evidence-derived content "
                "to a third party without registered consent."
            )
        model_name = getattr(self.model, "model_name", self.model.name)

        handle = self.evidence.get(case_id, evidence_id)
        evidence_path = str(handle.original_path)
        evidence_filename = handle.original_path.name
        detected_os = handle.detected_os
        detected_kind = handle.detected_kind

        allowed = self.available_tool_ids()
        if not allowed:
            return AgentLoopResult(
                reply=(
                    f"El paquete `{self.package.id}` no tiene tools válidos en su "
                    "allowlist (cruzado contra `catalog.py`). Revisa "
                    "`policy/tools.yaml`."
                ),
                iterations=0,
                tool_calls=[],
            )

        system_text = self._system_prompt(
            case_id, evidence_filename, allowed, detected_os, detected_kind
        )

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_text},
            *(prior_messages or []),
            {"role": "user", "content": prompt},
        ]
        state: dict[str, Any] = {
            "messages": messages,
            "temperature": float(self.package.model.temperature or 0.2),
        }
        specs = tool_specs(list(allowed)) + internal_tool_specs()

        max_iter = max(1, int(self.package.model.max_iterations or 8))
        tool_calls_log: list[dict[str, Any]] = []
        # Anti-loop guardrail (Bug 001): failures per tool_id in this session.
        max_attempts = _max_tool_attempts()
        tool_failures: dict[str, int] = {}

        # F3 — anchor the run in the case's hash-chained audit log: which model,
        # which backend, over which evidence. Only metadata/hashes ever land here.
        self._audit_event(
            "agent_run_start",
            case_id=case_id,
            evidence_id=evidence_id,
            evidence_sha256=handle.sha256,
            backend=self.model.name,
            model_name=model_name,
            consent_ref=consent_ref,
        )

        for iteration in range(max_iter):
            # Bug 008 — provider-agnostic context management. FORENSIA owns the
            # conversation; the executor is stateless and re-charges the whole
            # transcript each iteration. Project the canonical `messages` to a
            # windowed OUTBOUND copy (older tool results collapsed to stubs) so a
            # single run doesn't grow O(N^2). The canonical list stays raw.
            windowed = window_messages(messages)
            # F1 — SINGLE egress point. For a cloud backend, redact the windowed
            # copy with the package's patterns; the canonical `messages` stays
            # raw. F3 — audit each egress with the SHA-256 of the exact payload
            # sent (windowed + redacted), never the bytes.
            outbound = (
                redact_messages(windowed, self.package.policy.redaction_patterns)
                if is_cloud
                else windowed
            )
            if is_cloud:
                payload = json.dumps(
                    outbound, sort_keys=True, separators=(",", ":"), default=str
                ).encode("utf-8")
                self._audit_event(
                    "agent_cloud_egress",
                    case_id=case_id,
                    evidence_id=evidence_id,
                    backend=self.model.name,
                    model_name=model_name,
                    consent_ref=consent_ref,
                    redacted_payload_sha256=hashlib.sha256(payload).hexdigest(),
                    message_count=len(outbound),
                    iteration=iteration,
                )
            egress_state = {**state, "messages": outbound}
            try:
                action = self.model.next_action(egress_state, specs)
            except Exception as exc:  # noqa: BLE001 — surface as friendly reply
                logger.warning("model.next_action failed: %s", exc)
                return AgentLoopResult(
                    reply=(
                        f"El modelo `{getattr(self.model, 'model_name', self.model.name)}` "
                        f"falló durante la iteración {iteration + 1}: "
                        f"`{type(exc).__name__}: {exc}`."
                    ),
                    iterations=iteration,
                    tool_calls=tool_calls_log,
                )

            if isinstance(action, FinalAnswer):
                emit({"type": "final", "iteration": iteration + 1, "text": action.text})
                return AgentLoopResult(
                    reply=action.text,
                    iterations=iteration + 1,
                    tool_calls=tool_calls_log,
                )

            if isinstance(action, ToolCall):
                if action.assistant_message is not None:
                    messages.append(action.assistant_message)
                    reasoning = _reasoning_from(action.assistant_message.get("content"))
                    if reasoning:
                        emit({"type": "reasoning", "iteration": iteration + 1, "text": reasoning})

                # Internal side-channel tools — NOT in the catalog and NOT
                # subject to the package allowlist. Handled in-process.
                if action.tool_id == "record_finding":
                    try:
                        params = dict(action.params)
                        # Inject evidence_id automatically if the model didn't.
                        if not params.get("evidence_id"):
                            params["evidence_id"] = evidence_id
                        finding = finding_store.append(case_id, params)
                        body = {"finding_id": finding.id, "stored": True}
                        # F3 — record the finding's provenance in the audit chain
                        # (only the id; the finding body lives in findings.jsonl).
                        self._audit_event(
                            "agent_finding",
                            case_id=case_id,
                            evidence_id=evidence_id,
                            finding_id=finding.id,
                        )
                        emit({
                            "type": "finding",
                            "iteration": iteration + 1,
                            "title": finding.title,
                            "severity": finding.severity,
                        })
                    except (KeyError, ValueError) as exc:
                        body = {"error": f"record_finding rejected: {exc}"}
                    messages.append(self._tool_result_msg(action, body))
                    tool_calls_log.append({
                        "tool_id": "record_finding",
                        "finding_id": body.get("finding_id"),
                        "error": body.get("error"),
                    })
                    continue

                if action.tool_id not in allowed:
                    refusal = (
                        f"El tool `{action.tool_id}` no está en la allowlist del "
                        f"paquete `{self.package.id}`. Elige uno de: "
                        + ", ".join(f"`{t}`" for t in allowed)
                    )
                    messages.append(self._tool_result_msg(action, {"error": refusal}))
                    tool_calls_log.append(
                        {"tool_id": action.tool_id, "refused": True, "reason": "not_in_allowlist"}
                    )
                    emit({
                        "type": "tool_result",
                        "iteration": iteration + 1,
                        "tool_id": action.tool_id,
                        "status": "refused",
                        "summary": "no está en la allowlist del agente",
                    })
                    continue

                # Guardrail anti-bucle (Bug 001): no reintentes una tool que ya falló
                # `max_attempts` veces en esta sesión — fuerza al modelo a cambiar de
                # herramienta o a cerrar, en vez de repetir un exit≠0 hasta agotar
                # iteraciones. Solo cuentan los FALLOS: una tool que va bien puede
                # llamarse cuantas veces haga falta (p. ej. tsk_icat por inodo).
                if tool_failures.get(action.tool_id, 0) >= max_attempts:
                    blocked = (
                        f"El tool `{action.tool_id}` ya se intentó {max_attempts} veces en "
                        f"esta sesión y todas fallaron (exit≠0). NO lo reintentes: elige OTRA "
                        f"herramienta del allowlist o, si ya tienes suficiente, responde con tu "
                        f"análisis final."
                    )
                    messages.append(
                        self._tool_result_msg(action, {"error": blocked, "blocked": True})
                    )
                    tool_calls_log.append(
                        {"tool_id": action.tool_id, "blocked": True, "reason": "max_failed_attempts"}
                    )
                    emit({
                        "type": "tool_result",
                        "iteration": iteration + 1,
                        "tool_id": action.tool_id,
                        "status": "blocked",
                        "summary": f"bloqueado tras {max_attempts} fallos",
                    })
                    continue

                params = self._inject_runtime_paths(
                    action.tool_id, dict(action.params), evidence_path
                )
                emit({
                    "type": "tool_call",
                    "iteration": iteration + 1,
                    "tool_id": action.tool_id,
                    "params": _preview_params(params),
                })

                try:
                    result = dispatch_tool(
                        action.tool_id, params, case_id=case_id, os_profile=self.os_profile
                    )
                except ToolExecutionError as exc:
                    tool_failures[action.tool_id] = tool_failures.get(action.tool_id, 0) + 1
                    messages.append(
                        self._tool_result_msg(action, {"error": f"ToolExecutionError: {exc}"})
                    )
                    tool_calls_log.append(
                        {"tool_id": action.tool_id, "error": str(exc)}
                    )
                    emit({
                        "type": "tool_result",
                        "iteration": iteration + 1,
                        "tool_id": action.tool_id,
                        "status": "error",
                        "summary": str(exc)[:200],
                    })
                    continue
                except Exception as exc:  # noqa: BLE001 — never crash the loop
                    tool_failures[action.tool_id] = tool_failures.get(action.tool_id, 0) + 1
                    messages.append(
                        self._tool_result_msg(action, {"error": f"{type(exc).__name__}: {exc}"})
                    )
                    tool_calls_log.append(
                        {"tool_id": action.tool_id, "error": str(exc)}
                    )
                    emit({
                        "type": "tool_result",
                        "iteration": iteration + 1,
                        "tool_id": action.tool_id,
                        "status": "error",
                        "summary": f"{type(exc).__name__}: {exc}"[:200],
                    })
                    continue

                exit_code = result.get("exit_code")
                if isinstance(exit_code, int) and exit_code != 0:
                    tool_failures[action.tool_id] = tool_failures.get(action.tool_id, 0) + 1

                emit({
                    "type": "tool_result",
                    "iteration": iteration + 1,
                    "tool_id": action.tool_id,
                    "status": "ok" if exit_code == 0 else "nonzero",
                    "exit_code": exit_code,
                    "run_id": result.get("run_id"),
                    "summary": _result_summary(result),
                })
                messages.append(self._tool_result_msg(action, self._tool_result_payload(result)))
                tool_calls_log.append(
                    {
                        "tool_id": action.tool_id,
                        "run_id": result.get("run_id"),
                        "exit_code": exit_code,
                    }
                )
                continue

            raise RuntimeError(
                f"Model returned an unexpected action type: {type(action).__name__}"
            )

        exhausted = (
            f"Se alcanzó el máximo de iteraciones ({max_iter}) sin respuesta "
            "final. Revisa los runs en "
            f"`~/.forensia/cases/{case_id}/artifacts/` para ver lo ejecutado."
        )
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

    def _system_prompt(
        self,
        case_id: str,
        evidence_filename: str,
        allowed: tuple[str, ...],
        detected_os: str,
        detected_kind: str,
    ) -> str:
        # Bug 008 — only the playbook branch that matches the evidence kind travels
        # in the system prompt (re-sent every stateless iteration). RULE 2: for an
        # `unknown` kind both branches stay; nothing is hidden silently.
        pkg_parts = [
            self.package.prompts.system,
            self.package.prompts.identity,
            select_playbook_section(self.package.prompts.playbook, detected_kind),
        ]
        identity_block = "\n\n".join(p.strip() for p in pkg_parts if p and p.strip())

        # Build a profile-mismatch warning ONLY when the triage fingerprint
        # disagrees with the case's os_profile. The agent's system prompt
        # already carries a hard rule (guard rail) that tells it to stop and
        # request reassignment in this case — this block makes the mismatch
        # impossible to miss.
        mismatch_block = ""
        if detected_os not in ("unknown", self.os_profile):
            mismatch_block = (
                "\n\n## ⚠️ DESAJUSTE DE PERFIL DETECTADO\n"
                f"El caso declara `os_profile = {self.os_profile}` pero el triage "
                f"de FORENSIA fingerprintó la evidencia como `{detected_os}`.\n"
                "Aplica la regla del guard rail de perfil: **no ejecutes "
                "herramientas**. Responde al usuario en lenguaje natural "
                f"pidiéndole cerrar el caso y reabrirlo con `os_profile = "
                f"{detected_os}` (lo llevará "
                f"`forensia-{detected_os}`). No improvises plugins del SO "
                "equivocado.\n"
            )

        # Route the model to the right playbook section based on detected_kind.
        # Without this, the agent always starts at section A (disk image) of the
        # playbook and burns iterations on tsk_mmls/tsk_fls failures before
        # pivoting to section B (memory) — even when the evidence is clearly
        # a memdump.
        kind_routing = ""
        if detected_kind == "memory":
            kind_routing = (
                "\n## Ruta del playbook — MEMORY DUMP\n"
                "El triage clasificó la evidencia como `kind=memory`. **Salta "
                "directamente a la sección B del playbook** («Volcado de "
                "memoria RAM»). La sección A (imagen de disco) NO APLICA — no "
                "ejecutes `tsk_mmls`, `tsk_fls`, `tsk_mactime` ni `ewf_info` "
                "sobre esta evidencia: van a fallar y no producirán hallazgos.\n"
            )
        elif detected_kind == "disk":
            kind_routing = (
                "\n## Ruta del playbook — DISK IMAGE\n"
                "El triage clasificó la evidencia como `kind=disk`. Sigue la "
                "sección A del playbook. La sección B (volcado RAM) NO APLICA — "
                "no llames a plugins `windows.*` / `linux.*` de Volatility "
                "sobre esta evidencia: la imagen no contiene un volcado de "
                "memoria física.\n"
            )
        elif detected_kind == "container_disk":
            kind_routing = (
                "\n## Ruta del playbook — DISK IMAGE EN CONTENEDOR\n"
                "La evidencia es una imagen de disco dentro de un contenedor "
                "(VMDK / VDI / QCOW / VHD / E01). Trátala como sección A del "
                "playbook; las herramientas TSK la abren correctamente. No "
                "intentes Volatility — no es un volcado de memoria.\n"
            )

        return (
            f"{identity_block}\n\n"
            f"## Caso activo\n"
            f"- Caso: `{case_id}`\n"
            f"- Perfil del sistema operativo: `{self.os_profile}`\n"
            f"- Evidencia: `{evidence_filename}` — FORENSIA te inyecta su path "
            "absoluto en cada tool call; NUNCA incluyas un path absoluto tú.\n\n"
            f"## Contexto de evidencia (triage de FORENSIA)\n"
            f"- detected_os: `{detected_os}`\n"
            f"- detected_kind: `{detected_kind}`\n"
            "Los valores los computa `forensia.triage.fingerprint_evidence` "
            "con un escaneo determinista de cabeceras + marcadores byte-string "
            "sobre el handle read-only. `unknown` significa que no hay señal "
            "clara; está permitido un único probe diagnóstico para confirmar.\n"
            f"{kind_routing}"
            f"{mismatch_block}\n"
            f"## Toolkit disponible\n"
            "Elige siempre las herramientas por su id. FORENSIA valida cada llamada "
            "contra tu allowlist y resuelve el path real de la evidencia "
            "automáticamente. Los outputs (CSV, body files) van a un directorio "
            "que también te inyecta el dispatcher — no lo pongas tú.\n\n"
            "Allowlist (tool ids): " + ", ".join(f"`{t}`" for t in allowed) + "\n\n"
            "## Postura por defecto: AGÉNTICA, NO CONVERSACIONAL\n"
            "El caso y la evidencia YA están anclados al request — no preguntes "
            "\"¿es esta la evidencia?\" ni pidas confirmación. Si el prompt es "
            "genérico (\"analiza el archivo\"), arranca **inmediatamente** con "
            "tool calls siguiendo tu playbook. No saludes y luego esperes — "
            "saluda E invoca tools en la misma respuesta si quieres, pero NUNCA "
            "te quedes esperando una clarificación que el sistema ya te dio.\n\n"
            "## Registra hallazgos a medida que avanzas\n"
            "Tienes una tool especial `record_finding(title, summary, severity, "
            "tool_id?, run_id?)`. Cada vez que llegues a una conclusión "
            "concreta (tipo de archivo identificado, kernel detectado, IOC "
            "encontrado, hipótesis confirmada o descartada), LLÁMALA antes de "
            "seguir. Se persisten en el caso y la UI las pinta en el panel "
            "lateral.\n\n"
            "## NUNCA sugieras el siguiente paso — EJECÚTALO\n"
            "Si tras los pasos 0 ves indicadores de \"memdump Windows\", NO "
            "termines con \"sugiero correr volatility3 windows.info\". "
            "EJECÚTALO en el mismo turno como otro tool call. Sigue invocando "
            "tools hasta agotar el playbook o las iteraciones — solo entonces "
            "compones la respuesta final. La respuesta final es para *resumir* "
            "lo que ya hiciste, NUNCA para proponer lo que harías.\n\n"
            "## Cuando un tool falle (exit_code != 0)\n"
            "1. NO devuelvas la respuesta final con un \"hubo un error\" genérico.\n"
            "2. Cita el contenido literal de `stderr_sample` que te devolvió el "
            "dispatcher — eso es lo que la herramienta de verdad imprimió.\n"
            "3. Decide si tiene sentido intentar OTRA tool. Pista común: si "
            "`tsk_mmls` falla con \"Cannot determine partition type\", la evidencia "
            "probablemente NO es una imagen de disco — prueba `volatility3` con un "
            "plugin como `linux.pslist.PsList` o `windows.pslist.PsList`. Si "
            "`volatility3` falla con \"not a valid memory image\" es al revés, "
            "intenta `tsk_mmls`. No te rindas tras el primer fallo si el max_iterations "
            "lo permite.\n\n"
            "## Cuando tengas suficiente información\n"
            "Contesta al usuario en lenguaje natural sin más tool calls. Incluye los "
            "exit codes y los hallazgos concretos (números, nombres, hashes) que viste "
            "en los runs."
        )

    @staticmethod
    def _inject_runtime_paths(
        tool_id: str, params: dict[str, Any], evidence_path: str
    ) -> dict[str, Any]:
        target_key = _EVIDENCE_INJECTION.get(tool_id)
        if target_key:
            params[target_key] = evidence_path
        for k in list(params.keys()):
            if k in AUTO_INJECTED and k != target_key:
                # Strip other auto-injected keys the model tried to set; the
                # dispatcher will fill output_dir itself when needed.
                params.pop(k, None)
        return params

    @staticmethod
    def _tool_result_msg(call: ToolCall, body: dict[str, Any]) -> dict[str, Any]:
        return {
            "role": "tool",
            "tool_call_id": call.call_id,
            "content": _bounded_json(body, _MAX_TOOL_RESULT_CHARS),
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
