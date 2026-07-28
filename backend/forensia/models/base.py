"""Bridge between the agent loop and the execution layer.

``ForensicAgent.run`` drives a provider-agnostic ReAct loop over ``next_action``
(``ToolCall`` | ``FinalAnswer``). Since the 2026-07-02 pivot there are no SDK
backends: ``ExecutorBackend`` adapts the operator-selected ``PromptExecutor``
(Claude Code, Codex CLI, Gemini CLI or Ollama — ``forensia.executors``) to that
contract via the *degraded path* (diseño Fase 2 §8): the running conversation +
the tool schemas are rendered into ONE structured prompt, and the executor's
text reply is parsed STRICTLY into a tool call or a final answer.

The model only ever emits a closed-enum ``tool_id`` + typed params — never a
command string (SECURITY INVARIANT 5); the agent loop validates the id against
the package allowlist and the dispatcher resolves the real argv.
"""

from __future__ import annotations

import json
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from forensia.executors.base import PromptExecutor


@dataclass(frozen=True)
class ModelCapabilities:
    supports_native_tools: bool
    json_mode: bool
    max_context: int
    is_local: bool


@dataclass(frozen=True)
class ToolCall:
    tool_id: str
    params: dict[str, Any]
    # Identifier the agent loop uses to anchor the tool-result message back to
    # the assistant turn that requested it. Generated locally (uuid) — there is
    # no provider-side id in the executor world.
    call_id: str = ""
    # Optional: the assistant message that issued the call. The agent loop
    # appends this to the conversation BEFORE the tool result so the transcript
    # stays coherent across iterations.
    assistant_message: dict[str, Any] | None = None


@dataclass(frozen=True)
class ToolBatch:
    """Varias herramientas pedidas en UN turno del modelo.

    El coste de una corrida es ``contexto × turnos``: el ejecutor es stateless y
    Agentopsy le reenvía el transcript entero en cada iteración. Encadenar de una
    vez las herramientas cuyo resultado no condiciona a la siguiente (un lote de
    plugins de Volatility, ``mmls``+``fls``, extraer varios hives) es la diferencia
    entre 25 turnos y 3 — y es como trabaja un analista real, que no espera a leer
    un plugin para lanzar el siguiente.

    El loop las ejecuta EN ORDEN dentro de la misma iteración; cada una conserva su
    ArtifactRun, su entrada de audit con el argv literal y su mensaje de resultado.
    """

    calls: tuple[ToolCall, ...]
    assistant_message: dict[str, Any] | None = None


@dataclass(frozen=True)
class FinalAnswer:
    text: str


Action = ToolCall | ToolBatch | FinalAnswer


class ModelBackend(ABC):
    name: str

    @abstractmethod
    def capabilities(self) -> ModelCapabilities: ...

    @abstractmethod
    def next_action(self, state: dict[str, Any], tools: list[dict[str, Any]]) -> Action: ...


# Rendered into every next_action prompt. The strictness is deliberate: for
# executors without native tool-use (Ollama open models) the parser is the only
# contract, and for the CLI executors it stops them from "helpfully" answering
# in prose mid-loop.
_RESPONSE_CONTRACT = (
    "## FORMATO DE RESPUESTA (OBLIGATORIO)\n"
    "Responde ÚNICAMENTE con un objeto JSON, sin texto antes ni después y sin "
    "fences de markdown. Exactamente una de estas dos formas:\n"
    '1. Invocar una herramienta: {"action": "tool_call", "tool_id": "<id de la '
    'allowlist>", "params": { ... }}\n'
    '2. Varias herramientas de una vez: {"action": "tool_batch", "calls": '
    '[{"tool_id": "...", "params": {...}}, {"tool_id": "...", "params": {...}}]}\n'
    '3. Respuesta final al usuario: {"action": "final", "text": "<respuesta en '
    'markdown>"}\n'
    "USA `tool_batch` siempre que puedas: encadena de una vez las herramientas "
    "cuyo resultado NO necesitas leer para decidir la siguiente (un lote de "
    "plugins, mmls+fls, extraer varios artefactos). Cada turno re-envía toda la "
    "conversación, así que 5 herramientas en un turno cuestan mucho menos que 5 "
    "turnos de una. Reserva `tool_call` para cuando de verdad dependas del "
    "resultado anterior.\n"
    "No inventes tool_ids fuera de la lista de especificaciones. No incluyas "
    "paths absolutos en params — Agentopsy los inyecta."
)


class ExecutorBackend(ModelBackend):
    """Adapter: ``PromptExecutor`` → ``ModelBackend`` for ``ForensicAgent``.

    ``run_context`` is forwarded to ``executor.run`` on every iteration; the
    router uses it to thread the case's ``AuditLog`` (literal argv per run,
    FORENSIC INVARIANT 4) and, for Ollama, the resolved model name.
    """

    def __init__(
        self,
        executor: PromptExecutor,
        run_context: dict[str, Any] | None = None,
    ) -> None:
        self.executor = executor
        self.name = executor.id
        self.model_name = executor.name
        self.run_context = dict(run_context or {})

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            # The degraded path is used uniformly for the four executors: the
            # comparison harness keeps a single independent variable (§8).
            supports_native_tools=False,
            json_mode=True,
            max_context=0,  # unknown/executor-managed; not used by the loop
            is_local=self.executor.is_local,
        )

    def next_action(self, state: dict[str, Any], tools: list[dict[str, Any]]) -> Action:
        messages = state.get("messages")
        if not isinstance(messages, list) or not messages:
            raise ValueError("state['messages'] must be a non-empty list")

        context = dict(self.run_context)
        if "temperature" not in context and state.get("temperature") is not None:
            context["temperature"] = state["temperature"]

        prompt = self._render_prompt(messages, tools)
        result = self.executor.run(prompt, context)
        return self._parse_action(result.text)

    # ---- degraded path internals -------------------------------------------

    @staticmethod
    def _render_prompt(messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> str:
        blocks: list[str] = []
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content")
            if role == "system":
                blocks.append(f"## SISTEMA\n{content}")
            elif role == "user":
                blocks.append(f"## USUARIO\n{content}")
            elif role == "assistant":
                rendered = content if isinstance(content, str) and content else json.dumps(
                    {"tool_calls": msg.get("tool_calls")}, ensure_ascii=False
                )
                blocks.append(f"## ASISTENTE (tu turno previo)\n{rendered}")
            elif role == "tool":
                call_id = msg.get("tool_call_id", "")
                blocks.append(f"## RESULTADO DE TOOL (call {call_id})\n{content}")
            else:
                raise ValueError(f"unsupported message role in state: {role!r}")

        # Compact separators, not indent=2: the tool specs are re-serialized and
        # re-sent on EVERY iteration (the executor is stateless — Bug 008). The
        # pretty-print whitespace is ~4.7 KB (~1.2 K tokens) of pure indentation
        # the model does not need. Lossless: identical JSON, fewer bytes on the
        # wire, provider-agnostic.
        specs = json.dumps(tools, ensure_ascii=False, separators=(",", ":"))
        blocks.append(
            "## HERRAMIENTAS DISPONIBLES (especificación function-calling)\n" + specs
        )
        blocks.append(_RESPONSE_CONTRACT)
        return "\n\n".join(blocks)

    @staticmethod
    def _parse_action(text: str) -> Action:
        candidate = text.strip()
        # Tolerate a fenced block despite the contract — it costs nothing and
        # the content is still parsed strictly afterwards.
        if candidate.startswith("```"):
            candidate = candidate.strip("`").strip()
            if candidate.startswith("json"):
                candidate = candidate[4:].strip()
        start = candidate.find("{")
        if start == -1:
            raise ValueError(
                "el ejecutor no devolvió el objeto JSON del contrato de respuesta. "
                f"Respuesta (muestra): {text.strip()[:300]!r}"
            )
        try:
            envelope, _ = json.JSONDecoder().raw_decode(candidate[start:])
        except json.JSONDecodeError as exc:
            raise ValueError(
                "no se pudo parsear el JSON de la respuesta del ejecutor "
                f"({exc}). Respuesta (muestra): {text.strip()[:300]!r}"
            ) from exc
        if not isinstance(envelope, dict):
            raise ValueError("la respuesta del ejecutor no es un objeto JSON")

        action = envelope.get("action")
        if action == "final":
            answer = envelope.get("text")
            if not isinstance(answer, str):
                raise ValueError('la acción "final" no trae el campo "text" de texto')
            return FinalAnswer(text=answer)
        if action == "tool_call":
            tool_id = envelope.get("tool_id")
            if not isinstance(tool_id, str) or not tool_id:
                raise ValueError('la acción "tool_call" no trae un "tool_id" válido')
            params = envelope.get("params")
            if params is None:
                params = {}
            if not isinstance(params, dict):
                raise ValueError('en "tool_call", "params" debe ser un objeto JSON')
            return ToolCall(
                tool_id=tool_id,
                params=params,
                call_id=uuid.uuid4().hex,
                assistant_message={"role": "assistant", "content": text},
            )
        if action == "tool_batch":
            raw_calls = envelope.get("calls")
            if not isinstance(raw_calls, list) or not raw_calls:
                raise ValueError(
                    'la acción "tool_batch" debe traer una lista "calls" no vacía'
                )
            calls: list[ToolCall] = []
            for i, raw in enumerate(raw_calls):
                if not isinstance(raw, dict):
                    raise ValueError(f'calls[{i}] debe ser un objeto JSON')
                tool_id = raw.get("tool_id")
                if not isinstance(tool_id, str) or not tool_id:
                    raise ValueError(f'calls[{i}] no trae un "tool_id" válido')
                params = raw.get("params") or {}
                if not isinstance(params, dict):
                    raise ValueError(f'en calls[{i}], "params" debe ser un objeto JSON')
                calls.append(
                    ToolCall(tool_id=tool_id, params=params, call_id=uuid.uuid4().hex)
                )
            return ToolBatch(
                calls=tuple(calls),
                assistant_message={"role": "assistant", "content": text},
            )
        raise ValueError(
            f'acción desconocida {action!r} en la respuesta del ejecutor '
            '(esperado "tool_call", "tool_batch" o "final")'
        )
