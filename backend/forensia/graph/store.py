"""Almacén de grafos del caso, por hallazgo y por REVISIÓN.

Un grafo vive en ``<case_dir>/graphs/<finding_id>.v<N>.json``. Volver a
extraerlo no sobrescribe: escribe ``v<N+1>``, y la vista sirve la última. Es la
misma razón por la que un informe pericial emite una revisión nueva en vez de
reescribirse: el grafo que alguien citó en un informe tiene que seguir siendo
recuperable tal y como se citó, aunque el modelo proponga otra cosa mañana.

El ``sha256`` se calcula sobre el CONTENIDO canónico (nodos, relaciones y de qué
hallazgo salen), no sobre el fichero entero, así que no depende del orden en que
se serialicen las claves ni de la ficha de extracción. Cada extracción queda en
el log encadenado (``graph_extracted``) junto al ``argv`` literal de la corrida
del ejecutor, que ya escribe la capa de ejecutores (FORENSIC INVARIANT 4).

RULE 2: nada se inventa. Un hallazgo sin grafo levanta ``KeyError`` accionable,
nunca un grafo vacío que parezca una extracción que dio cero.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from forensia.i18n import Mensaje
from forensia.audit.log import AuditLog
from forensia.cases import CaseManager, case_manager

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

#: ``<finding_id>.v<N>.json``. El número de revisión va en el NOMBRE para que el
#: contenido del directorio se lea sin abrir un solo fichero.
_FICHERO_RE = re.compile(r"^(?P<fid>[0-9a-f-]{36})\.v(?P<rev>\d+)\.json$")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass(frozen=True)
class Graph:
    case_id: str
    finding_id: str
    revision: int
    created_at: str
    #: ``[{"tipo", "valor"}]`` ya validados contra la enum y contra el texto.
    nodos: list[dict[str, str]]
    #: ``[{"origen", "destino", "tipo", "nota"?}]``.
    relaciones: list[dict[str, str]]
    #: SHA-256 del contenido canónico, fijado al persistir.
    sha256: str
    #: Ficha de CÓMO se obtuvo (ejecutor, modelo, intentos, tokens). Es
    #: procedencia, no contenido: queda fuera del hash a propósito, porque dos
    #: extracciones que proponen el mismo grafo son el mismo grafo.
    extraction: dict[str, Any] = field(default_factory=dict)

    def ficha(self) -> dict[str, Any]:
        """La entrada de LISTA: sin nodos ni relaciones, con sus recuentos."""
        d = asdict(self)
        d.pop("nodos", None)
        d.pop("relaciones", None)
        d["n_nodos"] = len(self.nodos)
        d["n_relaciones"] = len(self.relaciones)
        return d


def _canonical_content(finding_id: str, nodos: Any, relaciones: Any) -> str:
    payload = {"finding_id": finding_id, "nodos": nodos, "relaciones": relaciones}
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _content_sha256(finding_id: str, nodos: Any, relaciones: Any) -> str:
    return hashlib.sha256(
        _canonical_content(finding_id, nodos, relaciones).encode("utf-8")
    ).hexdigest()


class GraphStore:
    def __init__(self, cases: CaseManager) -> None:
        if cases is None:
            raise ValueError("GraphStore requires a CaseManager")
        self._cases = cases

    def _dir(self, case_id: str):
        d = self._cases.case_dir(case_id) / "graphs"
        d.mkdir(parents=True, exist_ok=True)
        return d

    @staticmethod
    def _check_finding_id(finding_id: str) -> str:
        # El id llega desde la URL y se convierte en nombre de fichero: se exige
        # UUID4 para que no pueda contener separadores de ruta (SECURITY
        # INVARIANT 6), igual que en el almacén de documentos.
        if not _UUID4_RE.match(finding_id or ""):
            raise ValueError(f"finding id must be a UUID4, got {finding_id!r}")
        return finding_id

    # ── lectura ──────────────────────────────────────────────────────────────

    def revisions(self, case_id: str, finding_id: str) -> list[int]:
        """Las revisiones existentes de un hallazgo, ascendentes. ``[]`` si no hay."""
        self._check_finding_id(finding_id)
        out: list[int] = []
        for path in self._dir(case_id).glob(f"{finding_id}.v*.json"):
            m = _FICHERO_RE.match(path.name)
            if m:
                out.append(int(m.group("rev")))
        return sorted(out)

    def get(self, case_id: str, finding_id: str, revision: int | None = None) -> Graph:
        """El grafo de un hallazgo. Sin ``revision``, la ÚLTIMA."""
        self._check_finding_id(finding_id)
        revs = self.revisions(case_id, finding_id)
        if not revs:
            raise KeyError(
                Mensaje("graphStore.noGraph", finding_id=finding_id, case_id=case_id)
            )
        rev = revs[-1] if revision is None else int(revision)
        if rev not in revs:
            raise KeyError(
                Mensaje(
                    "graphStore.noRevision",
                    finding_id=finding_id,
                    rev=rev,
                    revs=", ".join(f"v{r}" for r in revs),
                )
            )
        path = self._dir(case_id) / f"{finding_id}.v{rev}.json"
        return Graph(**json.loads(path.read_text(encoding="utf-8")))

    def list_latest(self, case_id: str) -> list[Graph]:
        """El último grafo de cada hallazgo del caso. ``[]`` si no hay ninguno."""
        ultimos: dict[str, int] = {}
        for path in self._dir(case_id).glob("*.v*.json"):
            m = _FICHERO_RE.match(path.name)
            if not m:
                continue
            fid, rev = m.group("fid"), int(m.group("rev"))
            if rev > ultimos.get(fid, -1):
                ultimos[fid] = rev
        out: list[Graph] = []
        for fid, rev in ultimos.items():
            path = self._dir(case_id) / f"{fid}.v{rev}.json"
            try:
                out.append(Graph(**json.loads(path.read_text(encoding="utf-8"))))
            except (OSError, json.JSONDecodeError, TypeError):
                continue  # un fichero corrupto no tumba la lista
        out.sort(key=lambda g: g.created_at, reverse=True)
        return out

    def verify(self, case_id: str, finding_id: str, revision: int | None = None) -> dict[str, Any]:
        """Recomputa el SHA-256 del contenido y lo compara con el de registro."""
        g = self.get(case_id, finding_id, revision)
        recomputed = _content_sha256(g.finding_id, g.nodos, g.relaciones)
        return {
            "finding_id": g.finding_id,
            "revision": g.revision,
            "ok": recomputed == g.sha256,
            "registered_sha256": g.sha256,
            "recomputed_sha256": recomputed,
        }

    # ── escritura ────────────────────────────────────────────────────────────

    def save(self, case_id: str, finding_id: str, grafo: dict[str, Any]) -> Graph:
        """Persiste una REVISIÓN NUEVA del grafo de un hallazgo y la audita."""
        self._check_finding_id(finding_id)
        nodos = list(grafo.get("nodos") or [])
        relaciones = list(grafo.get("relaciones") or [])
        revs = self.revisions(case_id, finding_id)
        revision = (revs[-1] + 1) if revs else 1

        g = Graph(
            case_id=case_id,
            finding_id=finding_id,
            revision=revision,
            created_at=_utc_now_iso(),
            nodos=nodos,
            relaciones=relaciones,
            sha256=_content_sha256(finding_id, nodos, relaciones),
            extraction=dict(grafo.get("extraction") or {}),
        )
        path = self._dir(case_id) / f"{finding_id}.v{revision}.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(asdict(g), sort_keys=True, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        tmp.replace(path)

        AuditLog(self._cases.case_dir(case_id) / "audit.jsonl").append({
            "action": "graph_extracted",
            "case_id": case_id,
            "finding_id": finding_id,
            "revision": revision,
            "sha256": g.sha256,
            "nodes": len(nodos),
            "edges": len(relaciones),
            "executor": g.extraction.get("executor"),
            "model": g.extraction.get("model"),
            "attempts": g.extraction.get("attempts"),
            "resume": g.extraction.get("resume"),
            "ts_utc": g.created_at,
        })
        return g


graph_store = GraphStore(case_manager)


__all__ = ["Graph", "GraphStore", "graph_store"]
