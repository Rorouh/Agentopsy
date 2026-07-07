"""Discovery + indexing of agent packages dropped in ``agentes/`` at repo root.

Resolución del directorio raíz (en orden, sin fallbacks silenciosos):

1. ``FORENSIA_AGENTS_DIR`` (env). En el compose lo fija el servicio ``api``
   (``/opt/forensia/agentes``, con ``./agentes`` del repo montado read-only).
2. Si no hay env, se busca un ``agentes/`` como hermano del directorio
   ``backend/`` que contiene este paquete. Funciona automáticamente cuando se
   corre ``python -m forensia.server`` desde el repo.

Si NINGUNA de las dos opciones existe, la registry se inicia vacía y cualquier
``get_for_profile`` lanza ``KeyError``. La UI degrada explícitamente (sin
agente fallback — CLAUDE.md RULE 2).

Invariante adicional (también RULE 2): **dos paquetes válidos no pueden declarar
el mismo ``os_profile``**. El ``os_profile`` se determina por contenido de la
evidencia (triage) y el orquestador enruta al paquete de ese perfil; permitir
dos cargas para el mismo perfil reintroduce un default silencioso. Si esto
ocurre, la registry falla en seco al arranque.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from forensia.agent.loader import AgentPackageError, load_package
from forensia.agent.package import AgentPackage

logger = logging.getLogger(__name__)


class AgentRegistryError(RuntimeError):
    """Inconsistencia detectada al escanear ``agentes/`` (p.ej. dos agentes
    declarando el mismo os_profile). Mensaje siempre accionable."""


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
    """Escaneo único en construcción. Re-cargar requiere reinstanciar."""

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

    def get_for_profile(self, os_profile: str) -> AgentPackage:
        try:
            return self._by_profile[os_profile]
        except KeyError as exc:
            raise KeyError(
                f"no agent loaded for os_profile={os_profile!r}. "
                f"Drop a package under {self.root} (see agentes/README.md)."
            ) from exc

    def has_profile(self, os_profile: str) -> bool:
        return os_profile in self._by_profile

    # ---- internals ---------------------------------------------------------

    def _load(self) -> None:
        if not self.root.is_dir():
            logger.warning(
                "[agents] agentes dir not found at %s; chat will degrade until a "
                "package is dropped",
                self.root,
            )
            return

        for entry in sorted(self.root.iterdir()):
            if not entry.is_dir() or entry.name.startswith((".", "_")):
                continue
            # README.md / hidden files at the top of agentes/ are ignored on purpose.
            try:
                pkg = load_package(entry)
            except AgentPackageError as exc:
                # A bad package never silently disables a good one — but we don't
                # want a single typo to kill the whole api service. Log and skip.
                logger.error("[agents] skipping %s: %s", entry, exc)
                continue

            if pkg.id in self._by_id:
                raise AgentRegistryError(
                    f"duplicate agent id {pkg.id!r}: already loaded from "
                    f"{self._by_id[pkg.id].path}, refused at {entry}"
                )
            if pkg.os_profile in self._by_profile:
                other = self._by_profile[pkg.os_profile]
                raise AgentRegistryError(
                    f"two agents declare os_profile={pkg.os_profile!r}: "
                    f"{other.id} at {other.path} and {pkg.id} at {entry}. "
                    "Only ONE agent per os_profile is allowed (see agentes/README.md)."
                )

            self._by_id[pkg.id] = pkg
            self._by_profile[pkg.os_profile] = pkg
            logger.info(
                "[agents] loaded %s v%s for os_profile=%s",
                pkg.id, pkg.version, pkg.os_profile,
            )


# Module-level singleton. Surfaces (routers, capabilities) import this — never
# construct their own — so the scan happens exactly once per process.
agent_registry = AgentRegistry()
