"""Helper de tests: construye un ``AgentPackage`` desde el único ``agentes/agent.md``.

Sustituye al viejo ``load_package(AGENTES_DIR / "forensia-<perfil>")`` (el contrato de
paquetes por directorio se retiró el 2026-07-28). Un test que necesita un agente para
ejercitar el loop llama a ``make_package("unix")`` / ``make_package("windows")``;
puede sobreescribir ``allowed_tools``, ``redaction_patterns``, etc.
"""

from __future__ import annotations

from pathlib import Path

from forensia.agent.loader import build_package, read_instructions

AGENTES_DIR = Path(__file__).resolve().parents[2] / "agentes"
INSTRUCTIONS = read_instructions(AGENTES_DIR)


def make_package(os_profile: str = "unix", **overrides):
    """Agente del perfil pedido, con el texto real de ``agent.md``.

    ``overrides`` se pasa tal cual a ``build_package`` (``allowed_tools``,
    ``redaction_patterns``, ``max_iterations``, …).
    """
    instructions = overrides.pop("instructions", INSTRUCTIONS)
    return build_package(os_profile, instructions, agents_dir=AGENTES_DIR, **overrides)
