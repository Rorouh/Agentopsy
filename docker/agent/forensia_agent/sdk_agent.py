"""Backend basado en el **Claude Agent SDK**, autenticado con tu SUSCRIPCIÓN
(Pro/Max) a través de Claude Code — sin API key de pago.

A diferencia de los backends de `providers.py` (donde nuestro orquestador maneja
el bucle), aquí el propio Agent SDK conduce el bucle de tool-calling. Nosotros le
ofrecemos las herramientas del maletín como un servidor MCP in-process: cada tool
ejecuta `docker exec` en el contenedor del agente, reutilizando catalog + runner.

Requisitos en el equipo del usuario:
  - pip install claude-agent-sdk   (incluye el CLI de Claude Code)
  - Haber iniciado sesión con tu plan:  claude  ->  /login   (o: claude setup-token)
  - NO tener ANTHROPIC_API_KEY en el entorno (si está, se facturaría por API).
"""
from __future__ import annotations

import os

from .orchestrator import Orchestrator
from .prompts import system_prompt
from .report import write_report

# Herramientas de Claude Code que NO queremos que use el agente: debe operar
# EXCLUSIVAMENTE con las herramientas del maletín (docker exec), no con el host.
_BLOCKED_BUILTINS = ["Bash", "Write", "Edit", "NotebookEdit", "Read", "Glob",
                     "Grep", "WebFetch", "WebSearch", "Task", "TodoWrite"]

_REPORT_INSTRUCTION = (
    "Redacta ahora un INFORME FORENSE en Markdown basándote EXCLUSIVAMENTE en los "
    "resultados de las herramientas de esta sesión, con: 1) Resumen ejecutivo, "
    "2) Evidencia y cadena de custodia, 3) Hallazgos (herramienta y comando usados, "
    "dato y significado), 4) Línea temporal si aplica, 5) Conclusiones, "
    "6) Recomendaciones. No inventes datos. Devuelve solo el Markdown."
)


def available() -> bool:
    try:
        import claude_agent_sdk  # noqa: F401
        return True
    except Exception:
        return False


async def run_chat(cfg, agent: str, case: str, report_format: str = "md") -> None:
    """Sesión interactiva por prompts usando el Agent SDK (suscripción)."""
    import anyio
    from claude_agent_sdk import (
        AssistantMessage, ClaudeAgentOptions, ClaudeSDKClient, TextBlock,
        ToolUseBlock, create_sdk_mcp_server, tool,
    )

    C_AGENT, C_TOOL, C_DIM, C_RESET = "\033[96m", "\033[93m", "\033[2m", "\033[0m"

    if os.getenv("ANTHROPIC_API_KEY"):
        print(f"{C_TOOL}[i] Aviso: ANTHROPIC_API_KEY está definida; el SDK la usaría "
              f"(facturación por API). Bórrala si quieres usar tu suscripción.{C_RESET}")

    # Orquestador solo para reutilizar run_tool (build argv + docker exec). Sin modelo.
    orch = Orchestrator(cfg, provider=None, agent=agent)

    def make_handler(tool_name):
        async def handler(args):
            result = await anyio.to_thread.run_sync(orch.run_tool, tool_name, dict(args))
            return {"content": [{"type": "text", "text": result}]}
        return handler

    sdk_tools = []
    for t in orch.tools:
        decorated = tool(t.name, t.description, t.parameters)(make_handler(t.name))
        sdk_tools.append(decorated)

    server = create_sdk_mcp_server(name="forensia", version="0.1.0", tools=sdk_tools)
    allowed = [f"mcp__forensia__{t.name}" for t in orch.tools]

    opts = dict(
        system_prompt=system_prompt(agent),
        mcp_servers={"forensia": server},
        allowed_tools=allowed,
        disallowed_tools=_BLOCKED_BUILTINS,
        permission_mode="bypassPermissions",  # auto-aprueba SOLO las herramientas permitidas
    )
    if cfg.model:
        opts["model"] = cfg.model
    options = ClaudeAgentOptions(**opts)
    model_label = cfg.model or "suscripción (Claude Code)"

    async def collect(printing: bool):
        """Itera la respuesta del turno actual; imprime y devuelve el texto."""
        parts = []
        async for msg in client.receive_response():
            if isinstance(msg, AssistantMessage):
                for b in msg.content:
                    if isinstance(b, TextBlock):
                        parts.append(b.text)
                        if printing:
                            print(f"\n{C_AGENT}🕵  {b.text}{C_RESET}")
                    elif isinstance(b, ToolUseBlock):
                        if printing:
                            print(f"{C_TOOL}  → ejecutando {b.name} {b.input}{C_RESET}")
        return "\n".join(parts)

    async with ClaudeSDKClient(options=options) as client:
        print(f"== FORENSIA · sesión (Agent SDK / suscripción) ==  agente={agent}  "
              f"proyecto={case}  modelo={model_label}")
        print("Prompt libre. Comandos: [proceed-to-report] · [back-to-analysis] · exit\n")
        while True:
            try:
                line = (await anyio.to_thread.run_sync(input, "forensia> ")).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            if line.lower() in ("exit", "quit", ":q"):
                break
            if line == "[back-to-analysis]":
                print("[i] Continúa el análisis.")
                continue
            if line == "[proceed-to-report]":
                await client.query(_REPORT_INSTRUCTION)
                markdown = await collect(printing=False)
                path = write_report(cfg, agent, model_label, case,
                                    markdown or "(sin contenido)", fmt=report_format)
                print(f"{C_AGENT}[i] Informe generado: {path}{C_RESET}")
                continue
            await client.query(line)
            await collect(printing=True)
