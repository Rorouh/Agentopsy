"""Orquestador: bucle de tool-calling que conecta el modelo con el maletín.

Flujo: prompt del usuario → el modelo decide herramienta(s) → se ejecutan vía
`docker exec` en el contenedor del agente → la salida vuelve al modelo → repite
hasta que el modelo responde sin más llamadas (o se alcanza max_steps).
"""
from __future__ import annotations

from typing import Callable, List, Optional

from .catalog import BY_NAME, tools_for_agent
from .prompts import system_prompt
from .runner import ToolError, exec_in_container


class Orchestrator:
    def __init__(self, cfg, provider, agent: str):
        self.cfg = cfg
        self.provider = provider          # puede ser None (modo run-tool directo)
        self.agent = agent
        self.tools = tools_for_agent(agent)
        self.specs = [t.spec() for t in self.tools]
        self.transcript: List[dict] = [{"role": "system", "content": system_prompt(agent)}]

    # ---- ejecución de una herramienta concreta (con o sin modelo) ----
    def run_tool(self, name: str, args: dict) -> str:
        tool = BY_NAME.get(name)
        if tool is None or tool not in self.tools:
            return f"ERROR: herramienta no disponible para el agente '{self.agent}': {name}"
        try:
            argv = tool.build(args or {}, self.cfg)
        except (ToolError, KeyError) as e:
            return f"ERROR de validación en {name}: {e}"
        container = self._container_for(tool)
        res = exec_in_container(container, argv, timeout=tool.timeout,
                                max_chars=self.cfg.max_tool_chars)
        header = f"$ docker exec {container} {' '.join(argv)}\n(exit={res['exit_code']})\n"
        body = res.get("stdout", "") or ""
        if res.get("stderr"):
            body += f"\n[stderr]\n{res['stderr']}"
        if res.get("truncated"):
            body += "\n[...salida truncada...]"
        return header + body

    def _container_for(self, tool) -> str:
        if tool.agent == "unix":
            return self.cfg.unix_container
        if tool.agent == "windows":
            return self.cfg.win_container
        # "both": usa el contenedor del agente activo
        return self.cfg.unix_container if self.agent == "unix" else self.cfg.win_container

    # ---- turno completo con tool-calling ----
    def ask(self, user_text: str, emit: Callable[[str, str], None]) -> Optional[str]:
        if self.provider is None:
            raise RuntimeError("No hay backend de modelo configurado para conversar.")
        self.transcript.append({"role": "user", "content": user_text})
        for _ in range(self.cfg.max_steps):
            turn = self.provider.generate(self.transcript, self.specs)
            self.transcript.append({"role": "assistant", "content": turn.text or "",
                                    "tool_calls": turn.tool_calls})
            if turn.text:
                emit("assistant", turn.text)
            if not turn.tool_calls:
                return turn.text
            for tc in turn.tool_calls:
                emit("tool_call", f"{tc['name']}({tc['arguments']})")
                result = self.run_tool(tc["name"], tc["arguments"])
                preview = result if len(result) < 1600 else result[:1600] + " […]"
                emit("tool_result", preview)
                self.transcript.append({"role": "tool", "tool_call_id": tc["id"],
                                        "name": tc["name"], "content": result})
        emit("system", "Se alcanzó el límite de pasos (max_steps).")
        return None
