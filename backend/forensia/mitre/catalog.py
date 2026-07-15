"""MITRE ATT&CK — DOS catálogos, dos ejes que no se confunden.

1. **Semilla del orquestador** (``load`` / ``is_known`` / ``technique``): la
   **enum cerrada** que el AGENTE puede proponer. Se parsea de
   ``agentes/_orchestrator/knowledge/mitre_attack_seed.md``, que es lo que
   `agentes/_orchestrator/mitre.md` (regla 1) autoriza. Valida los ``mitre_hints``
   de los hallazgos y las anotaciones del agente (anti-alucinación). NO se teclea
   aquí: duplicarla crearía un validador que acepta ids prohibidos al agente.

2. **Catálogo Enterprise COMPLETO** (``load_enterprise`` / ``enterprise_*``): las
   ~240 técnicas padre de ATT&CK Enterprise que PINTA la matriz y contra las que
   el PERITO dictamina. Se envía con la imagen en ``enterprise.json`` (RULE 1) y
   se le fusiona la columna «Se sostiene con» de la semilla (mismo id). El perito
   puede anclar un veredicto en cualquier técnica Enterprise real; el agente,
   sólo en la semilla. Las propuestas del agente (ids de la semilla, posibles
   sub-técnicas) se pintan en su celda Enterprise vía ``enterprise_display_id``
   (a la técnica padre si son sub-técnicas).

Si una fuente no está, la superficie afectada degrada explícitamente con un
motivo accionable — nunca se sustituye por una lista "por defecto" (RULE 2).
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

SEED_RELPATH = Path("_orchestrator") / "knowledge" / "mitre_attack_seed.md"

#: Catálogo ATT&CK Enterprise COMPLETO — lo que PINTA la matriz y contra lo que
#: el PERITO dictamina. Se envía con la imagen (RULE 1). Es un eje distinto de la
#: semilla: la semilla es la enum cerrada que el AGENTE puede proponer
#: (anti-alucinación); Enterprise es la referencia de contexto sobre la que el
#: perito ancla su veredicto. Las propuestas del agente (ids de la semilla) se
#: mapean a la celda Enterprise (a la técnica padre si son sub-técnicas).
ENTERPRISE_PATH = Path(__file__).resolve().parent / "enterprise.json"


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
    #: Nº de sub-técnicas (catálogo Enterprise, que enumera padres + conteo). 0 en
    #: la semilla, que sí lista las sub-técnicas concretas que el agente puede citar.
    sub: int = 0


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
    """La SEMILLA completa, serializable. La UI pinta el catálogo Enterprise
    (``enterprise_as_dict``); esto queda para depurar la enum del agente."""
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
                        "sub": te.sub,
                    }
                    for te in t.techniques
                ],
            }
            for t in cat.tactics
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Catálogo ATT&CK Enterprise COMPLETO — display + dictamen del perito
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class EnterpriseCatalog:
    source: Path | None
    phases: tuple[tuple[str, str], ...]  # (key, label), en orden
    tactics: tuple[Tactic, ...]

    @property
    def available(self) -> bool:
        return bool(self.tactics)


@lru_cache(maxsize=1)
def load_enterprise() -> EnterpriseCatalog:
    """Carga el catálogo Enterprise del JSON que se envía con la imagen y le
    fusiona la columna «Se sostiene con» de la semilla (mismo id → mismo
    artefacto forense). Cacheado: dato estático durante la vida del proceso."""
    if not ENTERPRISE_PATH.is_file():
        logger.warning("[mitre] enterprise catalog not found at %s", ENTERPRISE_PATH)
        return EnterpriseCatalog(source=None, phases=(), tactics=())
    try:
        data = json.loads(ENTERPRISE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("[mitre] enterprise catalog unreadable: %s", exc)
        return EnterpriseCatalog(source=None, phases=(), tactics=())

    # supported_by de la semilla, por id (para no perder el artefacto forense).
    seed_support = {te.id: te.supported_by for te in _index().values()}

    tactics: list[Tactic] = []
    for t in data.get("tactics", []):
        techs = tuple(
            Technique(
                id=te["id"],
                name=te["name"],
                tactic_id=t["id"],
                supported_by=seed_support.get(te["id"], ""),
                parent_id=None,  # Enterprise enumera padres; la sub va como conteo
                sub=int(te.get("sub", 0)),
            )
            for te in t.get("techniques", [])
        )
        tactics.append(
            Tactic(
                id=t["id"], name=t["name"], name_es=t.get("name_es", t["name"]),
                phase=t.get("phase", "act"), techniques=techs,
            )
        )
    phases = tuple((p["key"], p["label"]) for p in data.get("phases", []))
    return EnterpriseCatalog(source=ENTERPRISE_PATH, phases=phases, tactics=tuple(tactics))


def _enterprise_index() -> dict[str, Technique]:
    return {
        tech.id: tech
        for tactic in load_enterprise().tactics
        for tech in tactic.techniques
    }


def enterprise_is_known(technique_id: str) -> bool:
    return technique_id in _enterprise_index()


def enterprise_technique(technique_id: str) -> Technique:
    try:
        return _enterprise_index()[technique_id]
    except KeyError:
        raise KeyError(
            f"{technique_id!r} is not in the ATT&CK Enterprise catalog"
        ) from None


def enterprise_display_id(technique_id: str) -> str:
    """La celda Enterprise en la que se pinta una técnica de la semilla. Si el id
    exacto no está en Enterprise (es una sub-técnica: Enterprise enumera padres),
    cae a la técnica padre — que SÍ está (verificado: todo padre de la semilla
    existe en Enterprise)."""
    if enterprise_is_known(technique_id):
        return technique_id
    return technique_id.split(".")[0]


def enterprise_unavailable_reason() -> str | None:
    if load_enterprise().available:
        return None
    return (
        f"MITRE ATT&CK Enterprise catalog not found at {ENTERPRISE_PATH}. It ships "
        "with the api image under forensia/mitre/enterprise.json."
    )


def enterprise_as_dict() -> dict:
    """El catálogo Enterprise completo, serializable — lo que sirve
    ``GET /api/mitre/catalog`` y pinta la matriz."""
    cat = load_enterprise()
    return {
        "available": cat.available,
        "reason": enterprise_unavailable_reason(),
        "source": str(cat.source) if cat.source else None,
        "phases": [{"key": k, "label": label} for k, label in cat.phases],
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
                        "sub": te.sub,
                    }
                    for te in t.techniques
                ],
            }
            for t in cat.tactics
        ],
    }
