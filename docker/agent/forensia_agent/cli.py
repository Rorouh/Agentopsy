"""Aplicación de terminal de FORENSIA (la 'aplicación de terminal' del documento).

Subcomandos:
  doctor                 Comprueba docker, contenedores del maletín y lista herramientas.
  tools  [--agent A]     Lista las herramientas disponibles para un agente.
  run-tool NAME k=v ...  Ejecuta UNA herramienta directamente (sin modelo). Útil
                         para verificar la capa docker. Ej.:
                         run-tool regripper hive_path=/evidence/SYSTEM profile=system
  chat   [--agent A]     Sesión interactiva por prompts con tool-calling.
                         Comandos dentro de la sesión:
                           [proceed-to-report]  genera el informe
                           [back-to-analysis]   continúa el análisis
                           exit / quit          salir
"""
from __future__ import annotations

import argparse
import sys

from .catalog import tools_for_agent
from .config import Config, load_dotenv
from .orchestrator import Orchestrator
from .report import generate_report
from .runner import container_running, docker_available

C_RESET, C_DIM, C_AGENT, C_TOOL, C_WARN = "\033[0m", "\033[2m", "\033[96m", "\033[93m", "\033[91m"


def _emit(kind: str, text: str) -> None:
    if kind == "assistant":
        print(f"\n{C_AGENT}🕵  {text}{C_RESET}")
    elif kind == "tool_call":
        print(f"{C_TOOL}  → ejecutando {text}{C_RESET}")
    elif kind == "tool_result":
        print(f"{C_DIM}{text}{C_RESET}")
    elif kind == "system":
        print(f"{C_WARN}[i] {text}{C_RESET}")


def _container_for_agent(cfg: Config, agent: str) -> str:
    return cfg.unix_container if agent == "unix" else cfg.win_container


def cmd_doctor(cfg: Config, args) -> int:
    print("== FORENSIA · diagnóstico ==")
    print(f"docker disponible : {'sí' if docker_available() else 'NO'}")
    for name in (cfg.win_container, cfg.unix_container):
        print(f"contenedor {name}: {'en ejecución' if container_running(name) else 'parado/ausente'}")
    print(f"backend modelo    : {cfg.provider} (modelo: {cfg.resolved_model() or 'por defecto/suscripción'})")
    try:
        from .sdk_agent import available as _sdk_ok
        print(f"claude-agent-sdk  : {'instalado' if _sdk_ok() else 'no instalado'}")
    except Exception:
        print("claude-agent-sdk  : no instalado")
    print(f"evidencia (cont.) : {cfg.evidence_root}   casos (cont.): {cfg.cases_root}")
    print(f"casos (host)      : {cfg.cases_host}")
    for agent in ("windows", "unix"):
        names = ", ".join(t.name for t in tools_for_agent(agent))
        print(f"tools [{agent}]   : {names}")
    return 0


def cmd_tools(cfg: Config, args) -> int:
    for t in tools_for_agent(args.agent):
        req = ", ".join(t.parameters.get("required", [])) or "—"
        print(f"- {t.name}  [{t.agent}]  (req: {req})\n    {t.description}")
    return 0


def cmd_run_tool(cfg: Config, args) -> int:
    params = {}
    for pair in args.kv:
        if "=" not in pair:
            print(f"{C_WARN}argumento inválido (usa clave=valor): {pair}{C_RESET}")
            return 2
        k, _, v = pair.partition("=")
        params[k.strip()] = v.strip()
    orch = Orchestrator(cfg, provider=None, agent=args.agent)
    print(orch.run_tool(args.name, params))
    return 0


def _chat_with_sdk(cfg: Config, args) -> int:
    """Sesión usando el Claude Agent SDK con tu suscripción (sin API key)."""
    from .sdk_agent import available, run_chat
    if not available():
        print(f"{C_WARN}Falta el paquete 'claude-agent-sdk'. Instala: "
              f"pip install claude-agent-sdk{C_RESET}")
        print("Y autentícate con tu plan: ejecuta 'claude' y usa /login "
              "(o 'claude setup-token'). No definas ANTHROPIC_API_KEY.")
        return 1
    cont = _container_for_agent(cfg, args.agent)
    if not container_running(cont):
        print(f"{C_WARN}[i] El contenedor '{cont}' no está en ejecución. "
              f"Levanta el maletín: docker compose up -d{C_RESET}")
    case = args.project or "caso-demo"
    try:
        import anyio
    except ImportError:
        print(f"{C_WARN}Falta 'anyio' (viene con claude-agent-sdk).{C_RESET}")
        return 1
    try:
        anyio.run(run_chat, cfg, args.agent, case, args.report_format)
    except Exception as e:
        print(f"{C_WARN}Error en la sesión (Agent SDK): {e}{C_RESET}")
        return 1
    return 0


def cmd_chat(cfg: Config, args) -> int:
    if cfg.provider in ("claude-agent", "claude-sdk", "claude_agent"):
        return _chat_with_sdk(cfg, args)
    try:
        from .providers import build_provider
        provider = build_provider(cfg)
    except Exception as e:
        print(f"{C_WARN}No se pudo iniciar el modelo: {e}{C_RESET}")
        print("Sugerencia: usa 'doctor' y 'run-tool' (no necesitan modelo) para "
              "verificar el maletín, o configura el backend en .env.")
        return 1

    agent = args.agent
    case = args.project or "caso-demo"
    cont = _container_for_agent(cfg, agent)
    if not container_running(cont):
        print(f"{C_WARN}[i] El contenedor '{cont}' no está en ejecución. "
              f"Levanta el maletín: docker compose up -d{C_RESET}")

    orch = Orchestrator(cfg, provider, agent)
    print(f"== FORENSIA · sesión ==  agente={agent}  proyecto={case}  "
          f"modelo={cfg.provider}:{provider.model}")
    print("Escribe tu prompt. Comandos: [proceed-to-report] · [back-to-analysis] · exit\n")

    while True:
        try:
            line = input("forensia> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        if line.lower() in ("exit", "quit", ":q"):
            break
        if line == "[proceed-to-report]":
            path = generate_report(orch, case, fmt=args.report_format)
            print(f"{C_AGENT}[i] Informe generado: {path}{C_RESET}")
            continue
        if line == "[back-to-analysis]":
            print("[i] Continúa el análisis.")
            continue
        try:
            orch.ask(line, _emit)
        except Exception as e:
            print(f"{C_WARN}Error durante el análisis: {e}{C_RESET}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="forensia-agent",
                                description="Orquestador de agentes forenses de FORENSIA.")
    p.add_argument("--provider", help="ollama|anthropic|openai (sobreescribe el entorno)")
    p.add_argument("--model", help="nombre del modelo (sobreescribe el entorno)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="comprueba el entorno").set_defaults(func=cmd_doctor)

    pt = sub.add_parser("tools", help="lista herramientas")
    pt.add_argument("--agent", choices=["windows", "unix"], default="windows")
    pt.set_defaults(func=cmd_tools)

    pr = sub.add_parser("run-tool", help="ejecuta una herramienta sin modelo")
    pr.add_argument("--agent", choices=["windows", "unix"], default="windows")
    pr.add_argument("name", help="nombre de la herramienta")
    pr.add_argument("kv", nargs="*", help="argumentos clave=valor")
    pr.set_defaults(func=cmd_run_tool)

    pc = sub.add_parser("chat", help="sesión interactiva por prompts")
    pc.add_argument("--agent", choices=["windows", "unix"], default="windows")
    pc.add_argument("--project", help="nombre del proyecto/caso (carpeta de salida)")
    pc.add_argument("--report-format", choices=["md", "pdf"], default="md")
    pc.set_defaults(func=cmd_chat)
    return p


def main(argv=None) -> int:
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = Config()
    if args.provider:
        cfg.provider = args.provider
    if args.model:
        cfg.model = args.model
    return args.func(cfg, args)


if __name__ == "__main__":
    sys.exit(main())
