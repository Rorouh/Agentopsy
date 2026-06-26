"""The forensic agent loop.

ONE agent parametrized by an ``AgentPackage`` loaded from ``agentes/<id>/``: the
reasoning loop is identical; what changes per profile is the package (prompts,
model backend, allowlist of tools, redaction policy).

When the loaded package's model backend is wired (``MODEL_BACKEND=cloud`` +
``OPENAI_API_KEY`` + ``MODEL_NAME``), ``run()`` drives an OpenAI tool-calling
loop:

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
"""

from __future__ import annotations

import json
import logging
from typing import Any

from forensia.agent.package import AgentPackage
from forensia.agent.tool_schemas import AUTO_INJECTED, openai_tool_specs
from forensia.audit import AuditLog
from forensia.evidence import EvidenceManager
from forensia.models.base import FinalAnswer, ModelBackend, ToolCall
from forensia.toolkit.catalog import BY_ID as TOOL_BY_ID
from forensia.toolkit.tool import Tool

logger = logging.getLogger(__name__)


# Map tool_id → which auto-injected key receives the resolved evidence path.
# Tools not in this map don't take the evidence directly (e.g. jq accepts an
# operator-supplied input_path that points to another artifact).
_EVIDENCE_INJECTION: dict[str, str] = {
    "file_info": "image_path",
    "xxd_head": "image_path",
    "strings_head": "image_path",
    "tsk_mmls": "image_path",
    "tsk_fls": "image_path",
    "tsk_mactime": "bodyfile_path",
    "ewf_info": "image_path",
    "bulk_extractor": "image_path",
    "yara": "target_path",
    "volatility3": "dump_path",
    "hayabusa": "evtx_dir",
    "chainsaw": "target_dir",
    "regripper": "hive_path",
    "evtxecmd": "evtx_path",
    "mftecmd": "mft_path",
}


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

    def run(self, prompt: str, case_id: str, evidence_id: str) -> AgentLoopResult:
        # Local import to avoid a circular dep that only matters at call time.
        from forensia.toolkit.dispatcher import ToolExecutionError, execute as dispatch_tool

        if not prompt:
            raise ValueError("prompt is required")
        if not case_id:
            raise ValueError("case_id is required for an LLM-driven run")
        if not evidence_id:
            raise ValueError("evidence_id is required for an LLM-driven run")

        handle = self.evidence.get(case_id, evidence_id)
        evidence_path = str(handle.original_path)
        evidence_filename = handle.original_path.name

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

        system_text = self._system_prompt(case_id, evidence_filename, allowed)

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_text},
            {"role": "user", "content": prompt},
        ]
        state: dict[str, Any] = {
            "messages": messages,
            "temperature": float(self.package.model.temperature or 0.2),
        }
        tool_specs = openai_tool_specs(list(allowed))

        max_iter = max(1, int(self.package.model.max_iterations or 8))
        tool_calls_log: list[dict[str, Any]] = []

        for iteration in range(max_iter):
            try:
                action = self.model.next_action(state, tool_specs)
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
                return AgentLoopResult(
                    reply=action.text,
                    iterations=iteration + 1,
                    tool_calls=tool_calls_log,
                )

            if isinstance(action, ToolCall):
                if action.assistant_message is not None:
                    messages.append(action.assistant_message)

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
                    continue

                params = self._inject_runtime_paths(
                    action.tool_id, dict(action.params), evidence_path
                )

                try:
                    result = dispatch_tool(action.tool_id, params, case_id=case_id)
                except ToolExecutionError as exc:
                    messages.append(
                        self._tool_result_msg(action, {"error": f"ToolExecutionError: {exc}"})
                    )
                    tool_calls_log.append(
                        {"tool_id": action.tool_id, "error": str(exc)}
                    )
                    continue
                except Exception as exc:  # noqa: BLE001 — never crash the loop
                    messages.append(
                        self._tool_result_msg(action, {"error": f"{type(exc).__name__}: {exc}"})
                    )
                    tool_calls_log.append(
                        {"tool_id": action.tool_id, "error": str(exc)}
                    )
                    continue

                messages.append(self._tool_result_msg(action, self._tool_result_payload(result)))
                tool_calls_log.append(
                    {
                        "tool_id": action.tool_id,
                        "run_id": result.get("run_id"),
                        "exit_code": result.get("exit_code"),
                    }
                )
                continue

            raise RuntimeError(
                f"Model returned an unexpected action type: {type(action).__name__}"
            )

        return AgentLoopResult(
            reply=(
                f"Se alcanzó el máximo de iteraciones ({max_iter}) sin respuesta "
                "final. Revisa los runs en "
                f"`~/.forensia/cases/{case_id}/artifacts/` para ver lo ejecutado."
            ),
            iterations=max_iter,
            tool_calls=tool_calls_log,
        )

    # ---- internals ---------------------------------------------------------

    def _system_prompt(
        self,
        case_id: str,
        evidence_filename: str,
        allowed: tuple[str, ...],
    ) -> str:
        pkg_parts = [
            self.package.prompts.system,
            self.package.prompts.identity,
            self.package.prompts.playbook,
        ]
        identity_block = "\n\n".join(p.strip() for p in pkg_parts if p and p.strip())
        return (
            f"{identity_block}\n\n"
            f"## Caso activo\n"
            f"- Caso: `{case_id}`\n"
            f"- Perfil del sistema operativo: `{self.os_profile}`\n"
            f"- Evidencia: `{evidence_filename}` — FORENSIA te inyecta su path "
            "absoluto en cada tool call; NUNCA incluyas un path absoluto tú.\n\n"
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
            "content": json.dumps(body)[:8000],
        }

    @staticmethod
    def _tool_result_payload(result: dict[str, Any]) -> dict[str, Any]:
        return {
            "tool_id": result.get("tool_id"),
            "exit_code": result.get("exit_code"),
            "run_id": result.get("run_id"),
            "parsed": result.get("parsed"),
            "stdout_sample": (result.get("stdout_sample") or "")[:2000],
            "stderr_sample": (result.get("stderr_sample") or "")[:2000],
            "artifact_run": _trim_artifact(result.get("artifact_run")),
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
