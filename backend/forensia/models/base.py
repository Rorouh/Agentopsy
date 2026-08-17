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
from forensia.executors.cache_health import CacheHealthMonitor
from forensia.executors.session_guard import verify_session


class ResponseContractError(ValueError):
    """The executor answered, but not in the shape ``_parse_action`` demands.

    Split out from every other failure of ``next_action`` on purpose. A timeout,
    an unusable CLI or a crashed subprocess is an EXECUTION failure: retrying it
    would be guessing that the second attempt goes better (RULE 2). A contract
    violation is different in kind: the model DID answer, the answer is in the
    conversation, and the exact defect can be named back to it. That is the one
    thing the agent loop is allowed to correct, once, with the same executor and
    the same contract (mirrors ``reports.writer``'s repair round).

    ``raw_text`` carries a bounded sample of what the model actually emitted, so
    the correction quotes the defect instead of describing it in the abstract.
    """

    def __init__(self, message: str, raw_text: str = "") -> None:
        super().__init__(message)
        self.raw_text = raw_text[:_RAW_SAMPLE_CHARS]


#: How much of a contract-violating reply travels back to the model in the
#: correction. Enough to recognise its own envelope, bounded so a runaway reply
#: cannot re-enter the prompt whole.
_RAW_SAMPLE_CHARS = 600


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

    #: Whether this backend can continue a conversation instead of re-sending it,
    #: and therefore wants the canonical append-only message list alongside the
    #: windowed one. False by default: a backend says so explicitly or the loop
    #: keeps the pre-2026-07-29 behaviour (RULE 2 — no capability is assumed).
    supports_session_transport: bool = False

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
    "fences de markdown. Exactamente una de estas tres formas:\n"
    '1. Invocar una herramienta: {"action": "tool_call", "tool_id": "<id de la '
    'allowlist>", "params": { ... }}\n'
    '2. Varias herramientas de una vez: {"action": "tool_batch", "calls": '
    '[{"tool_id": "...", "params": {...}}, {"tool_id": "...", "params": {...}}]}\n'
    '3. Respuesta final al usuario: {"action": "final", "text": "<respuesta en '
    'markdown>"}\n'
    'El campo "action" admite ESOS TRES literales y ningún otro. El nombre de '
    "una herramienta va SIEMPRE en \"tool_id\", NUNCA en \"action\", y eso "
    "incluye las herramientas internas de Agentopsy, que no son acciones "
    "aparte: `record_finding`, `annotate_mitre`, `anotar_conocimiento`, "
    "`consultar_conocimiento`, `leer_artefacto`, `consultar_actividad` y "
    "`declarar_pivote` se invocan igual que cualquier otra. Se escribe "
    '{"action": "tool_call", "tool_id": "record_finding", "params": {...}}; '
    '{"action": "record_finding", ...} no existe.\n'
    "USA `tool_batch` siempre que puedas: encadena de una vez las herramientas "
    "cuyo resultado NO necesitas leer para decidir la siguiente (un lote de "
    "plugins, mmls+fls, extraer varios artefactos). Cada turno re-envía toda la "
    "conversación, así que 5 herramientas en un turno cuestan mucho menos que 5 "
    "turnos de una. Reserva `tool_call` para cuando de verdad dependas del "
    "resultado anterior.\n"
    "No inventes tool_ids fuera de la lista de especificaciones. No incluyas "
    "paths absolutos en params, Agentopsy los inyecta."
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
        # ---- session transport state (plan.md Fase 1) ------------------------
        #: The executor's conversation id once one exists. None → every turn
        #: sends full context, which is the pre-2026-07-29 behaviour.
        self._session_id: str | None = None
        #: Prompts Agentopsy has itself put into that session. Checked against the
        #: session transcript before any delta is sent (``session_guard``).
        self._prompts_sent = 0
        #: How many canonical messages the session already holds.
        self._delivered = 0
        #: ``num_turns`` the last envelope reported — the CLI-added-turns check.
        self._last_num_turns: int | None = None
        self._turn = 0
        #: Cost-side watchdog. Separate from the guard above on purpose: a cold
        #: cache is a billing problem, a diverged session is a forensic one.
        self.cache_monitor = CacheHealthMonitor()
        #: Actionable notices for the caller to log and audit (never raised: a
        #: cache regression must not abort an analysis that is producing findings).
        self.notices: list[str] = []
        #: One-shot latch for the "resume-capable CLI stopped reporting a
        #: session id" notice, so a broken CLI warns once instead of every turn.
        self._warned_no_session = False

    @property
    def supports_session_transport(self) -> bool:  # type: ignore[override]
        return bool(self.executor.supports_session_resume)

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

        self._turn += 1
        # The canonical (append-only) conversation, already through the loop's
        # single egress point. Only present when the executor can continue a
        # session; the delta path needs an append-only list, because re-sending a
        # windowed STUB of a message the session already holds verbatim would
        # contradict what the model has.
        canonical = state.get("messages_full")
        canonical = canonical if isinstance(canonical, list) and canonical else None

        prompt, resumed, reopen_reason = self._plan_transport(messages, tools, canonical)
        if resumed:
            context["session_id"] = self._session_id
        elif reopen_reason:
            context["reopen_reason"] = reopen_reason

        result = self.executor.run(prompt, context)
        self._absorb(result, resumed=resumed, delivered=len(canonical) if canonical else 0)
        return self._parse_action(result.text)

    # ---- session transport --------------------------------------------------

    def _plan_transport(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        canonical: list[dict[str, Any]] | None,
    ) -> tuple[str, bool, str | None]:
        """Choose between a delta into the live session and full context.

        Returns ``(prompt, resumed, reopen_reason)``. The delta is chosen ONLY
        when ``session_guard`` can positively account for the session; every
        other outcome — including "cannot verify" — sends full context and
        carries the reason into the audit. Sending MORE than needed is the only
        direction this fallback is ever allowed to take (RULE 2).

        Every FULL-context send renders from the CANONICAL list when one is
        available: that prompt SEEDS (or re-seeds) the executor's session, and
        ``_absorb`` will account the canonical messages as delivered. Rendering
        the windowed ``messages`` here would plant STUBS in the session forever —
        the model then burns whole turns re-reading the artifacts its own stubs
        elided (measured: 12 of 21 turns, ~42 % of the run's input —
        ``docs/diseno/tokens-2026-07/fase-turnos.md`` §3).
        """
        base = canonical if canonical else messages
        if not (self.executor.supports_session_resume and self._session_id and canonical):
            return self._render_prompt(base, tools), False, None

        verdict = verify_session(
            self._session_id,
            expected_prompts=self._prompts_sent,
            num_turns=self._last_num_turns,
        )
        if not verdict.can_send_delta:
            self._reset_session()
            return self._render_prompt(base, tools), False, verdict.reason

        pending = canonical[self._delivered:]
        if not pending:
            # Nothing new to say. Re-opening with full context would be cheaper
            # to reason about than inventing a filler turn, and it cannot happen
            # in the normal loop (every iteration appends at least one message).
            self._reset_session()
            return self._render_prompt(base, tools), False, (
                "No hay mensajes nuevos que enviar como delta; se reenvía el "
                "contexto completo."
            )
        return self._render_delta(pending), True, None

    def _absorb(self, result: Any, *, resumed: bool, delivered: int) -> None:
        """Fold one executor result into the session state and cache watchdog."""
        self._last_num_turns = getattr(result, "num_turns", None)
        session_id = getattr(result, "session_id", None)
        if session_id:
            if resumed and session_id == self._session_id:
                self._prompts_sent += 1
            else:
                # A fresh session (turn 1, or a reopen). Its history is exactly
                # the one prompt we just sent.
                self._session_id = session_id
                self._prompts_sent = 1
            self._delivered = delivered
        else:
            if self.executor.supports_session_resume and not self._warned_no_session:
                self._warned_no_session = True
                self.notices.append(
                    f"{self.executor.name} declara reanudación de sesión pero no "
                    "devolvió session_id en su envelope: cada iteración reenviará "
                    "el contexto completo a coste íntegro. Revisa la versión del "
                    "CLI, el ahorro por sesión está desactivado en esta corrida."
                )
            self._reset_session()

        warning = self.cache_monitor.observe(
            getattr(result, "usage", None), session_active=resumed, turn=self._turn
        )
        if warning:
            self.notices.append(warning)

    def _reset_session(self) -> None:
        self._session_id = None
        self._prompts_sent = 0
        self._delivered = 0

    # ---- degraded path internals -------------------------------------------

    @staticmethod
    def _render_message(msg: dict[str, Any]) -> str:
        role = msg.get("role")
        content = msg.get("content")
        if role == "system":
            return f"## SISTEMA\n{content}"
        if role == "user":
            return f"## USUARIO\n{content}"
        if role == "assistant":
            rendered = content if isinstance(content, str) and content else json.dumps(
                {"tool_calls": msg.get("tool_calls")}, ensure_ascii=False
            )
            return f"## ASISTENTE (tu turno previo)\n{rendered}"
        if role == "tool":
            call_id = msg.get("tool_call_id", "")
            return f"## RESULTADO DE TOOL (call {call_id})\n{content}"
        raise ValueError(f"unsupported message role in state: {role!r}")

    @staticmethod
    def _render_prompt(messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> str:
        """Full context: everything the model needs, ordered for prefix caching.

        Block order is deliberate (plan.md Fase 2). A prompt cache matches on a
        PREFIX, so anything placed after a block that changes between turns can
        never be reused. The tool schemas are ~39,5 K characters that are
        byte-identical every turn, and they used to sit AFTER the growing
        transcript — which meant they were re-charged in full on every iteration
        and could never enter a reusable prefix
        (``docs/diseno/tokens-2026-07/diagnostico.md`` §4/H2).

            before:  SISTEMA │ transcript (variable) │ ESQUEMAS │ contrato
            now:     SISTEMA │ ESQUEMAS │ transcript (variable) │ contrato

        The response contract stays LAST on purpose: it is what holds
        ``_parse_action``'s strict JSON envelope together, and a parse failure
        costs a whole retry turn — far more than the ~1 K characters of keeping
        it at the end. Only the stable blocks moved up.
        """
        system_blocks: list[str] = []
        conversation: list[str] = []
        for msg in messages:
            rendered = ExecutorBackend._render_message(msg)
            (system_blocks if msg.get("role") == "system" else conversation).append(rendered)

        # Compact separators, not indent=2: the tool specs are re-serialized and
        # re-sent on EVERY iteration when there is no session to continue. The
        # pretty-print whitespace is ~4.7 KB (~1.2 K tokens) of pure indentation
        # the model does not need. Lossless: identical JSON, fewer bytes on the
        # wire, provider-agnostic.
        specs = json.dumps(tools, ensure_ascii=False, separators=(",", ":"))
        blocks = [
            *system_blocks,
            "## HERRAMIENTAS DISPONIBLES (especificación function-calling)\n" + specs,
            *conversation,
            _RESPONSE_CONTRACT,
        ]
        return "\n\n".join(blocks)

    @staticmethod
    def _render_delta(pending: list[dict[str, Any]]) -> str:
        """Only what the session does not have yet, plus the response contract.

        The system prompt and the tool schemas are deliberately absent: they are
        already in the session the executor is resuming, and re-sending them
        would be the very cost this transport exists to remove. The contract is
        repeated because it governs THIS reply's format and is cheap.

        This prompt is what the audit records literally, with ``resume: true``
        and the session id beside it, so the run stays reconstructible turn by
        turn: opening prompt + deltas (FORENSIC INVARIANT 4).
        """
        blocks = [ExecutorBackend._render_message(msg) for msg in pending]
        blocks.append(_RESPONSE_CONTRACT)
        return "\n\n".join(blocks)

    @staticmethod
    def _parse_action(text: str) -> Action:
        """Strict parse of the response envelope.

        Every rejection here is a ``ResponseContractError``, which the agent loop
        may correct ONCE by naming the defect back to the model. The strictness
        does not move: what changes is that a malformed envelope no longer throws
        away the rest of a run (see ``ResponseContractError``).
        """
        candidate = text.strip()
        # Tolerate a fenced block despite the contract — it costs nothing and
        # the content is still parsed strictly afterwards.
        if candidate.startswith("```"):
            candidate = candidate.strip("`").strip()
            if candidate.startswith("json"):
                candidate = candidate[4:].strip()
        start = candidate.find("{")
        if start == -1:
            raise ResponseContractError(
                "el ejecutor no devolvió el objeto JSON del contrato de respuesta. "
                f"Respuesta (muestra): {text.strip()[:300]!r}",
                text,
            )
        try:
            envelope, _ = json.JSONDecoder().raw_decode(candidate[start:])
        except json.JSONDecodeError as exc:
            raise ResponseContractError(
                "no se pudo parsear el JSON de la respuesta del ejecutor "
                f"({exc}). Respuesta (muestra): {text.strip()[:300]!r}",
                text,
            ) from exc
        if not isinstance(envelope, dict):
            raise ResponseContractError(
                "la respuesta del ejecutor no es un objeto JSON", text
            )

        action = envelope.get("action")
        if action == "final":
            answer = envelope.get("text")
            if not isinstance(answer, str):
                raise ResponseContractError(
                    'la acción "final" no trae el campo "text" de texto', text
                )
            return FinalAnswer(text=answer)
        if action == "tool_call":
            tool_id = envelope.get("tool_id")
            if not isinstance(tool_id, str) or not tool_id:
                raise ResponseContractError(
                    'la acción "tool_call" no trae un "tool_id" válido', text
                )
            params = envelope.get("params")
            if params is None:
                params = {}
            if not isinstance(params, dict):
                raise ResponseContractError(
                    'en "tool_call", "params" debe ser un objeto JSON', text
                )
            return ToolCall(
                tool_id=tool_id,
                params=params,
                call_id=uuid.uuid4().hex,
                assistant_message={"role": "assistant", "content": text},
            )
        if action == "tool_batch":
            raw_calls = envelope.get("calls")
            if not isinstance(raw_calls, list) or not raw_calls:
                raise ResponseContractError(
                    'la acción "tool_batch" debe traer una lista "calls" no vacía', text
                )
            calls: list[ToolCall] = []
            for i, raw in enumerate(raw_calls):
                if not isinstance(raw, dict):
                    raise ResponseContractError(f'calls[{i}] debe ser un objeto JSON', text)
                tool_id = raw.get("tool_id")
                if not isinstance(tool_id, str) or not tool_id:
                    raise ResponseContractError(
                        f'calls[{i}] no trae un "tool_id" válido', text
                    )
                params = raw.get("params") or {}
                if not isinstance(params, dict):
                    raise ResponseContractError(
                        f'en calls[{i}], "params" debe ser un objeto JSON', text
                    )
                calls.append(
                    ToolCall(tool_id=tool_id, params=params, call_id=uuid.uuid4().hex)
                )
            return ToolBatch(
                calls=tuple(calls),
                assistant_message={"role": "assistant", "content": text},
            )
        # The measured failure (2026-08-16): the model put the TOOL NAME in
        # `action` (`{"action": "record_finding", ...}`), which the prompt had
        # invited by teaching the internal tools in call-signature notation. The
        # message names that specific confusion because it is the one the
        # correction round has to undo.
        raise ResponseContractError(
            f'acción desconocida {action!r} en la respuesta del ejecutor '
            '(esperado "tool_call", "tool_batch" o "final"). Si es el id de una '
            'herramienta, va en "tool_id" dentro de un "tool_call", nunca en '
            '"action"',
            text,
        )
