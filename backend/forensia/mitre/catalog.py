"""MITRE ATT&CK — catálogo de referencia, derivado de la SEMILLA del orquestador.

**Una sola fuente de verdad.** El catálogo NO se teclea aquí: se parsea de
``agentes/_orchestrator/knowledge/mitre_attack_seed.md``, que es la **enum
cerrada** que `agentes/_orchestrator/mitre.md` (regla 1) autoriza al agente a
emitir. Duplicar la lista en Python crearía un validador que acepta ids que el
agente tiene prohibido usar, y una matriz cuyo denominador de cobertura sería
ficticio.

Cuando el corpus Enterprise completo aterrice (S5), se amplía la semilla y este
módulo la sigue sin cambios — o se sustituye la fuente por el STIX oficial de
MITRE. Lo que no se hace nunca es transcribir técnicas a mano.

Si la semilla no está (``agentes/`` sin montar), el catálogo queda vacío y las
superficies degradan explícitamente con un motivo accionable — nunca se
sustituye por una lista "por defecto" (RULE 2).
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

SEED_RELPATH = Path("_orchestrator") / "knowledge" / "mitre_attack_seed.md"


def _agents_dir() -> Path:
    """Misma resolución que `forensia.agent.registry._default_agents_dir`.

    Se reimplementa en vez de importarla: `forensia.findings.store` consume este
    módulo y `forensia.agent` consume el store, así que importar `forensia.agent`
    aquí cerraría un ciclo de imports.
    """
    env = os.environ.get("FORENSIA_AGENTS_DIR")
    if env:
        return Path(env).resolve()
    # forensia/mitre/catalog.py → forensia/mitre → forensia → backend → <repo>
    return (Path(__file__).resolve().parents[3] / "agentes").resolve()

_TACTIC_HEADER_RE = re.compile(r"^##\s+(TA\d{4})\s+—\s+(.+?)\s*$")
_ROW_RE = re.compile(r"^\|\s*(T\d{4}(?:\.\d{3})?)\s*\|\s*([^|]+?)\s*\|\s*([^|]*?)\s*\|\s*$")

#: Etiqueta en español de cada táctica (presentación de la UI; ATT&CK sólo da
#: el nombre en inglés). No aporta semántica forense.
_TACTIC_ES: dict[str, str] = {
    "TA0002": "Ejecución",
    "TA0003": "Persistencia",
    "TA0004": "Escalada de privilegios",
    "TA0005": "Evasión de defensas",
    "TA0006": "Acceso a credenciales",
    "TA0007": "Descubrimiento",
    "TA0008": "Movimiento lateral",
    "TA0009": "Recolección",
    "TA0010": "Exfiltración",
    "TA0011": "Mando y control",
    "TA0040": "Impacto",
}

#: Agrupación **editorial** de FORENSIA para la matriz (ATT&CK no define fases).
_TACTIC_PHASE: dict[str, str] = {
    "TA0002": "access",
    "TA0003": "root",
    "TA0004": "root",
    "TA0005": "root",
    "TA0006": "act",
    "TA0007": "act",
    "TA0008": "act",
    "TA0009": "goal",
    "TA0011": "goal",
    "TA0010": "goal",
    "TA0040": "goal",
}

PHASES: tuple[tuple[str, str], ...] = (
    ("access", "Acceso"),
    ("root", "Persistencia y evasión"),
    ("act", "Acción interna"),
    ("goal", "Objetivo"),
)


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic_id: str
    #: Qué artefacto forense la sostiene (columna «Se sostiene con» de la semilla).
    supported_by: str
    #: ``T1059`` para ``T1059.001``; ``None`` si es técnica de primer nivel.
    parent_id: str | None


@dataclass(frozen=True)
class Tactic:
    id: str
    name: str
    name_es: str
    phase: str
    techniques: tuple[Technique, ...]


@dataclass(frozen=True)
class Catalog:
    source: Path | None
    tactics: tuple[Tactic, ...]

    @property
    def available(self) -> bool:
        return bool(self.tactics)


def seed_path() -> Path:
    return _agents_dir() / SEED_RELPATH


def _parse(text: str) -> tuple[Tactic, ...]:
    tactics: list[Tactic] = []
    current: tuple[str, str] | None = None
    rows: list[Technique] = []

    def flush() -> None:
        if current is None:
            return
        tactic_id, name = current
        tactics.append(
            Tactic(
                id=tactic_id,
                name=name,
                name_es=_TACTIC_ES.get(tactic_id, name),
                phase=_TACTIC_PHASE.get(tactic_id, "act"),
                techniques=tuple(rows),
            )
        )

    for line in text.splitlines():
        header = _TACTIC_HEADER_RE.match(line)
        if header:
            flush()
            current = (header.group(1), header.group(2))
            rows = []
            continue
        if current is None:
            continue
        row = _ROW_RE.match(line)
        if not row:
            continue
        tech_id, tech_name, supports = row.group(1), row.group(2), row.group(3)
        parent = tech_id.split(".")[0] if "." in tech_id else None
        rows.append(
            Technique(
                id=tech_id,
                name=tech_name,
                tactic_id=current[0],
                supported_by=supports,
                parent_id=parent,
            )
        )
    flush()
    return tuple(tactics)


@lru_cache(maxsize=1)
def load() -> Catalog:
    """Parsea la semilla. Cacheado: es dato estático durante la vida del proceso."""
    path = seed_path()
    if not path.is_file():
        logger.warning(
            "[mitre] seed not found at %s; the ATT&CK surface will degrade until "
            "agentes/ is mounted",
            path,
        )
        return Catalog(source=None, tactics=())
    tactics = _parse(path.read_text(encoding="utf-8"))
    if not tactics:
        logger.warning("[mitre] seed at %s parsed to zero tactics", path)
    return Catalog(source=path, tactics=tactics)


def _index() -> dict[str, Technique]:
    return {
        tech.id: tech for tactic in load().tactics for tech in tactic.techniques
    }


def technique(technique_id: str) -> Technique:
    """La técnica con ese id. `KeyError` si no está en la semilla (sin fallback)."""
    try:
        return _index()[technique_id]
    except KeyError:
        raise KeyError(
            f"{technique_id!r} is not in the ATT&CK seed "
            f"(agentes/{SEED_RELPATH}) — the closed enum the agent may emit"
        ) from None


def is_known(technique_id: str) -> bool:
    return technique_id in _index()


def unavailable_reason() -> str | None:
    """Motivo accionable si el catálogo no está disponible; `None` si lo está."""
    if load().available:
        return None
    return (
        f"MITRE ATT&CK seed not found at {seed_path()}. It ships in the repo under "
        f"agentes/{SEED_RELPATH}; mount agentes/ into the api container "
        f"(FORENSIA_AGENTS_DIR) so the closed technique enum can be loaded."
    )


def as_dict() -> dict:
    """El catálogo completo, serializable — lo que sirve `GET /api/mitre/catalog`."""
    cat = load()
    return {
        "available": cat.available,
        "reason": unavailable_reason(),
        "source": str(cat.source) if cat.source else None,
        "phases": [{"key": k, "label": label} for k, label in PHASES],
        "tactics": [
            {
                "id": t.id,
                "name": t.name,
                "name_es": t.name_es,
                "phase": t.phase,
                "techniques": [
                    {
                        "id": te.id,
                        "name": te.name,
                        "supported_by": te.supported_by,
                        "parent_id": te.parent_id,
                    }
                    for te in t.techniques
                ],
            }
            for t in cat.tactics
        ],
    }
