"""Descubrimiento del agente a partir de ``agentes/agent.md``.

Resolución del directorio ``agentes/`` (en orden, sin fallbacks silenciosos):

1. ``FORENSIA_AGENTS_DIR`` (env). En el compose lo fija el servicio ``api``
   (``/opt/forensia/agentes``, con ``./agentes`` del repo montado read-only).
2. Si no hay env, se busca un ``agentes/`` como hermano del directorio ``backend/``
   que contiene este paquete. Funciona al correr ``python -m forensia.server`` desde
   el repo.

Desde 2026-07-28 no hay paquetes por directorio: un **único** ``agent.md`` configura el
comportamiento, y Agentopsy construye un agente por perfil de SO (``unix``,
``windows``) que comparte ese texto y difiere solo en la allowlist (catálogo filtrado
por perfil). Si ``agent.md`` no existe, la registry arranca vacía y
``get_for_profile`` lanza ``KeyError``; la UI degrada explícitamente (sin agente
fallback — CLAUDE.md RULE 2).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from forensia.agent.loader import AgentPackageError, load_packages
from forensia.agent.package import AgentPackage

logger = logging.getLogger(__name__)


class AgentRegistryError(RuntimeError):
    """Inconsistencia al cargar el agente. Mensaje siempre accionable."""


def _default_agents_dir() -> Path:
    """Resuelve la carpeta ``agentes/`` por defecto (env override o repo).

    No comprueba existencia: la registry lo hace luego para poder reportar
    "no agents loaded" en vez de explotar al importar.
    """
    env = os.environ.get("FORENSIA_AGENTS_DIR")
    if env:
        return Path(env).resolve()
    # backend/forensia/agent/registry.py → backend/forensia/agent → backend/forensia
    # → backend → <repo_root> → <repo_root>/agentes
    return (Path(__file__).resolve().parents[3] / "agentes").resolve()


class AgentRegistry:
    """Carga única en construcción. Re-cargar requiere reinstanciar."""

    def __init__(self, root: Path | None = None) -> None:
        self.root: Path = Path(root).resolve() if root is not None else _default_agents_dir()
        self._by_id: dict[str, AgentPackage] = {}
        self._by_profile: dict[str, AgentPackage] = {}
        self._load()

    # ---- public API --------------------------------------------------------

    def list(self) -> list[AgentPackage]:
        return sorted(self._by_id.values(), key=lambda a: a.id)

    def get(self, agent_id: str) -> AgentPackage:
        try:
            return self._by_id[agent_id]
        except KeyError as exc:
            raise KeyError(f"unknown agent id: {agent_id!r}") from exc

    def has_profile(self, os_profile: str) -> bool:
        return os_profile in self._by_profile

    def get_for_profile(self, os_profile: str) -> AgentPackage:
        try:
            return self._by_profile[os_profile]
        except KeyError as exc:
            raise KeyError(
                f"no agent loaded for os_profile={os_profile!r}. "
                f"Drop an '{'agent.md'}' under {self.root} (see agentes/README.md)."
            ) from exc

    # ---- internals ---------------------------------------------------------

    def _load(self) -> None:
        if not self.root.is_dir():
            logger.warning(
                "agentes dir %s does not exist — no agent loaded; the UI will degrade "
                "explicitly (no fallback agent, RULE 2).",
                self.root,
            )
            return
        try:
            packages = load_packages(self.root)
        except AgentPackageError as exc:
            # agent.md ausente o vacío: registry vacía, la UI degrada (sin fallback).
            logger.warning("no agent loaded from %s: %s", self.root, exc)
            return
        for profile, pkg in packages.items():
            self._by_profile[profile] = pkg
            self._by_id[pkg.id] = pkg
        logger.info(
            "loaded agent from %s for profiles: %s",
            self.root,
            ", ".join(sorted(self._by_profile)),
        )


# Singleton usado por los routers / capabilities. Reinstanciar para recargar.
agent_registry = AgentRegistry()
