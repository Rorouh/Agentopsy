"""Descubrimiento del agente a partir de ``agentes/agent.md``.

Resolución del directorio ``agentes/`` (en orden, sin fallbacks silenciosos):

1. ``AGENTOPSY_AGENTS_DIR`` (env). En el compose lo fija el servicio ``api``
   (``/opt/agentopsy/agentes``, con ``./agentes`` del repo montado read-only).
2. Si no hay env, se busca un ``agentes/`` como hermano del directorio ``backend/``
   que contiene este paquete. Funciona al correr ``python -m agentopsy.server`` desde
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

from agentopsy.agent.loader import (
    AgentPackageError,
    agent_md_filename,
    load_packages,
)
from agentopsy.i18n import current_lang
from agentopsy.agent.package import AgentPackage

logger = logging.getLogger(__name__)


class AgentRegistryError(RuntimeError):
    """Inconsistencia al cargar el agente. Mensaje siempre accionable."""


def _default_agents_dir() -> Path:
    """Resuelve la carpeta ``agentes/`` por defecto (env override o repo).

    No comprueba existencia: la registry lo hace luego para poder reportar
    "no agents loaded" en vez de explotar al importar.
    """
    env = os.environ.get("AGENTOPSY_AGENTS_DIR")
    if env:
        return Path(env).resolve()
    # backend/agentopsy/agent/registry.py → backend/agentopsy/agent → backend/agentopsy
    # → backend → <repo_root> → <repo_root>/agentes
    return (Path(__file__).resolve().parents[3] / "agentes").resolve()


class AgentRegistry:
    """Carga PEREZOSA por idioma, cacheada. Re-cargar requiere reinstanciar.

    El agente se configura con un fichero de comportamiento POR IDIOMA
    (``agent.md`` / ``agent.en.md``), así que el registro no puede ser una sola
    tabla: guarda una por idioma y carga la del idioma en curso la primera vez
    que se le pide. Cargar en el constructor volvía a fijar el idioma de
    arranque para toda la vida del proceso, y el perito puede cambiarlo sin
    reiniciar nada.

    Un idioma cuyo fichero falte deja SU tabla vacía, no la de los demás: la UI
    degrada explícitamente para ese idioma (RULE 2, sin agente de repuesto).
    """

    def __init__(self, root: Path | None = None) -> None:
        self.root: Path = Path(root).resolve() if root is not None else _default_agents_dir()
        self._por_idioma: dict[str, tuple[dict[str, AgentPackage], dict[str, AgentPackage]]] = {}
        # La del idioma de partida se carga ya: `capabilities` la consulta en el
        # primer arranque y un registro vacío ahí se leería como «sin agente».
        self._tablas()

    # ---- public API --------------------------------------------------------

    def list(self) -> list[AgentPackage]:
        por_id, _ = self._tablas()
        return sorted(por_id.values(), key=lambda a: a.id)

    def get(self, agent_id: str) -> AgentPackage:
        por_id, _ = self._tablas()
        try:
            return por_id[agent_id]
        except KeyError as exc:
            raise KeyError(f"unknown agent id: {agent_id!r}") from exc

    def has_profile(self, os_profile: str) -> bool:
        _, por_perfil = self._tablas()
        return os_profile in por_perfil

    def get_for_profile(self, os_profile: str) -> AgentPackage:
        _, por_perfil = self._tablas()
        try:
            return por_perfil[os_profile]
        except KeyError as exc:
            raise KeyError(
                f"no agent loaded for os_profile={os_profile!r}. "
                f"Drop an '{agent_md_filename()}' under {self.root} "
                "(see agentes/README.md)."
            ) from exc

    # ---- internals ---------------------------------------------------------

    def _tablas(self) -> tuple[dict[str, AgentPackage], dict[str, AgentPackage]]:
        """Las dos tablas del idioma en curso, cargándolas si es la primera vez."""
        idioma = current_lang()
        if idioma not in self._por_idioma:
            self._por_idioma[idioma] = self._load()
        return self._por_idioma[idioma]

    def _load(self) -> tuple[dict[str, AgentPackage], dict[str, AgentPackage]]:
        por_id: dict[str, AgentPackage] = {}
        por_perfil: dict[str, AgentPackage] = {}
        if not self.root.is_dir():
            logger.warning(
                "agentes dir %s does not exist, no agent loaded; the UI will degrade "
                "explicitly (no fallback agent, RULE 2).",
                self.root,
            )
            return por_id, por_perfil
        try:
            packages = load_packages(self.root)
        except AgentPackageError as exc:
            # El fichero del idioma falta o está vacío: SU tabla queda vacía y la
            # UI degrada (sin agente de repuesto ni caída al otro idioma).
            logger.warning("no agent loaded from %s: %s", self.root, exc)
            return por_id, por_perfil
        for profile, pkg in packages.items():
            por_perfil[profile] = pkg
            por_id[pkg.id] = pkg
        logger.info(
            "loaded agent from %s (%s) for profiles: %s",
            self.root,
            agent_md_filename(),
            ", ".join(sorted(por_perfil)),
        )
        return por_id, por_perfil


# Singleton usado por los routers / capabilities. Reinstanciar para recargar.
agent_registry = AgentRegistry()
