"""Capa de modelos CONFIGURABLE: una interfaz común y tres backends seleccionables
(Ollama local, Anthropic, OpenAI). Cada backend traduce un transcript neutro y la
lista de herramientas a su formato nativo de tool-calling y devuelve un AssistantTurn.

Transcript neutro (lista de dicts):
  {"role": "system",    "content": str}
  {"role": "user",      "content": str}
  {"role": "assistant", "content": str, "tool_calls": [{"id","name","arguments":{}}]}
  {"role": "tool",      "tool_call_id": str, "name": str, "content": str}
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import List


@dataclass
class AssistantTurn:
    text: str = ""
    tool_calls: List[dict] = field(default_factory=list)  # [{"id","name","arguments"}]


def _get(obj, key, default=None):
    """Lee `key` tanto de un dict como de un objeto/pydantic."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


# ============================ Ollama (local) =================================
class OllamaProvider:
    def __init__(self, cfg):
        try:
            import ollama  # noqa
        except ImportError as e:
            raise RuntimeError("Falta el paquete 'ollama'. Instala: pip install ollama") from e
        import ollama
        self._client = ollama.Client(host=cfg.ollama_host)
        self.model = cfg.resolved_model()

    def generate(self, transcript, tools) -> AssistantTurn:
        msgs = []
        for e in transcript:
            r = e["role"]
            if r in ("system", "user"):
                msgs.append({"role": r, "content": e["content"]})
            elif r == "assistant":
                m = {"role": "assistant", "content": e.get("content") or ""}
                if e.get("tool_calls"):
                    m["tool_calls"] = [{"function": {"name": tc["name"], "arguments": tc["arguments"]}}
                                       for tc in e["tool_calls"]]
                msgs.append(m)
            elif r == "tool":
                msgs.append({"role": "tool", "content": e["content"]})
        tool_specs = [{"type": "function", "function": t} for t in tools]
        resp = self._client.chat(model=self.model, messages=msgs, tools=tool_specs)
        msg = _get(resp, "message", {})
        text = _get(msg, "content", "") or ""
        calls = []
        for i, tc in enumerate(_get(msg, "tool_calls", []) or []):
            fn = _get(tc, "function", {})
            args = _get(fn, "arguments", {}) or {}
            if isinstance(args, str):
                args = json.loads(args or "{}")
            calls.append({"id": f"call_{i}_{int(time.time() * 1000)}",
                          "name": _get(fn, "name"), "arguments": args})
        return AssistantTurn(text, calls)


# ============================ Anthropic ======================================
class AnthropicProvider:
    def __init__(self, cfg):
        try:
            import anthropic  # noqa
        except ImportError as e:
            raise RuntimeError("Falta el paquete 'anthropic'. Instala: pip install anthropic") from e
        import anthropic
        if not cfg.anthropic_api_key:
            raise RuntimeError("Falta ANTHROPIC_API_KEY en el entorno o .env")
        self._client = anthropic.Anthropic(api_key=cfg.anthropic_api_key)
        self.model = cfg.resolved_model()

    def generate(self, transcript, tools) -> AssistantTurn:
        system = "\n\n".join(e["content"] for e in transcript if e["role"] == "system")
        msgs, pending_tool_results = [], []

        def flush():
            if pending_tool_results:
                msgs.append({"role": "user", "content": list(pending_tool_results)})
                pending_tool_results.clear()

        for e in transcript:
            r = e["role"]
            if r == "system":
                continue
            if r == "user":
                flush()
                msgs.append({"role": "user", "content": e["content"]})
            elif r == "assistant":
                flush()
                content = []
                if e.get("content"):
                    content.append({"type": "text", "text": e["content"]})
                for tc in e.get("tool_calls", []):
                    content.append({"type": "tool_use", "id": tc["id"],
                                    "name": tc["name"], "input": tc["arguments"]})
                msgs.append({"role": "assistant", "content": content or ""})
            elif r == "tool":
                pending_tool_results.append({"type": "tool_result",
                                             "tool_use_id": e["tool_call_id"],
                                             "content": e["content"]})
        flush()

        tool_specs = [{"name": t["name"], "description": t["description"],
                       "input_schema": t["parameters"]} for t in tools]
        kwargs = dict(model=self.model, max_tokens=2048, messages=msgs, tools=tool_specs)
        if system:
            kwargs["system"] = system
        resp = self._client.messages.create(**kwargs)

        text, calls = "", []
        for b in resp.content:
            if b.type == "text":
                text += b.text
            elif b.type == "tool_use":
                calls.append({"id": b.id, "name": b.name, "arguments": b.input})
        return AssistantTurn(text, calls)


# ============================ OpenAI =========================================
class OpenAIProvider:
    def __init__(self, cfg):
        try:
            import openai  # noqa
        except ImportError as e:
            raise RuntimeError("Falta el paquete 'openai'. Instala: pip install openai") from e
        from openai import OpenAI
        if not cfg.openai_api_key:
            raise RuntimeError("Falta OPENAI_API_KEY en el entorno o .env")
        self._client = OpenAI(api_key=cfg.openai_api_key)
        self.model = cfg.resolved_model()

    def generate(self, transcript, tools) -> AssistantTurn:
        msgs = []
        for e in transcript:
            r = e["role"]
            if r in ("system", "user"):
                msgs.append({"role": r, "content": e["content"]})
            elif r == "assistant":
                m = {"role": "assistant", "content": e.get("content") or None}
                if e.get("tool_calls"):
                    m["tool_calls"] = [{"id": tc["id"], "type": "function",
                                        "function": {"name": tc["name"],
                                                     "arguments": json.dumps(tc["arguments"])}}
                                       for tc in e["tool_calls"]]
                msgs.append(m)
            elif r == "tool":
                msgs.append({"role": "tool", "tool_call_id": e["tool_call_id"], "content": e["content"]})
        tool_specs = [{"type": "function", "function": t} for t in tools]
        resp = self._client.chat.completions.create(
            model=self.model, messages=msgs, tools=tool_specs, tool_choice="auto")
        msg = resp.choices[0].message
        calls = []
        for tc in (msg.tool_calls or []):
            calls.append({"id": tc.id, "name": tc.function.name,
                          "arguments": json.loads(tc.function.arguments or "{}")})
        return AssistantTurn(msg.content or "", calls)


_PROVIDERS = {"ollama": OllamaProvider, "anthropic": AnthropicProvider, "openai": OpenAIProvider}


def build_provider(cfg):
    key = cfg.provider.lower()
    if key not in _PROVIDERS:
        raise RuntimeError(f"Backend desconocido: {cfg.provider!r}. Opciones: {list(_PROVIDERS)}")
    return _PROVIDERS[key](cfg)
