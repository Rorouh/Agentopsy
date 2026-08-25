"""Append-only store con vista consolidada para el grafo de conocimiento del caso.

Layout, por caso::

    cases/<case-id>/knowledge/
    ├── perfil-sistema.md            ← VISTA (lo que se lee y lo que abre el perito)
    ├── cuentas.md
    └── .historial/
        ├── perfil-sistema.jsonl     ← REGISTRO append-only (la garantía forense)
        └── cuentas.jsonl

Escribir añade una línea al ``.jsonl`` y re-renderiza el ``.md``; leer devuelve
solo el ``.md``. El histórico está en disco y auditado, pero no viaja al contexto
salvo que se pida explícitamente (``history()``).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from forensia.i18n import Mensaje
from forensia.cases import CaseManager, case_manager

logger = logging.getLogger(__name__)

#: Juego de caracteres CERRADO del identificador de nodo. Es el control C1 del
#: diseño: el modelo emite un id, jamás una ruta. Sin puntos y sin barras, un
#: ``../`` o un absoluto no se rechazan — es que no son expresables (SECURITY
#: INVARIANT 5). El backend deriva la ruta a partir de este id.
DOC_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{0,63}$"
_DOC_ID_RE = re.compile(DOC_ID_PATTERN)

#: El nombre de sección es la CLAVE de consolidación: escribir dos veces la misma
#: sección supersede la anterior en la vista (y conserva ambas en el registro).
_SECTION_RE = re.compile(r"^[^\r\n]{1,120}$")

MAX_SECTION_CHARS = 120
#: Un bloque lleva la CONCLUSIÓN y el puntero al artefacto que la sostiene — no es
#: sitio para volcar un bodyfile. Pasarse es un error accionable, nunca un truncado
#: silencioso (RULE 2).
MAX_BLOCK_CHARS = 4000
#: Tope de nodos por caso: evita que el grafo se fragmente en decenas de nodos
#: inútiles y que el índice del prompt deje de ser legible.
MAX_NODES_PER_CASE = 32
MAX_SECTIONS_PER_NODE = 64

_KNOWLEDGE_DIRNAME = "knowledge"
_HISTORY_DIRNAME = ".historial"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass(frozen=True)
class KnowledgeBlock:
    """Una escritura. Inmutable: una vez en el ``.jsonl`` no se toca jamás."""

    doc_id: str
    section: str
    content: str
    created_at: str
    iteration: int | None
    sha256: str

    def as_dict(self) -> dict[str, object]:
        return {
            "doc_id": self.doc_id,
            "section": self.section,
            "content": self.content,
            "created_at": self.created_at,
            "iteration": self.iteration,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class KnowledgeNode:
    """La VISTA consolidada de un nodo: última versión de cada sección."""

    doc_id: str
    sections: tuple[str, ...]
    markdown: str
    updated_at: str
    block_count: int


@dataclass(frozen=True)
class NodeSummary:
    """Una línea del índice que viaja SIEMPRE en el system prompt.

    Deliberadamente NO lleva contenido: lleva los nombres de sección, que es la
    granularidad con la que el agente decide «¿necesito cargar este nodo?». Un
    resumen redactado obligaría a inventar prosa; los nombres de sección los
    eligió el propio agente al escribir.
    """

    doc_id: str
    sections: tuple[str, ...]
    updated_at: str
    block_count: int


def _validate_doc_id(raw: object) -> str:
    doc_id = str(raw or "").strip()
    if not _DOC_ID_RE.match(doc_id):
        raise ValueError(
            Mensaje("knowledge.badDocId", doc_id=repr(doc_id), pattern=DOC_ID_PATTERN)
        )
    return doc_id


def _validate_section(raw: object) -> str:
    section = str(raw or "").strip()
    if not section or not _SECTION_RE.match(section):
        raise ValueError(
            Mensaje("knowledge.badSection", max=MAX_SECTION_CHARS)
        )
    return section


def _validate_content(raw: object) -> str:
    content = str(raw or "").strip()
    if not content:
        raise ValueError(Mensaje("knowledge.emptyContent"))
    if len(content) > MAX_BLOCK_CHARS:
        raise ValueError(
            Mensaje(
                "knowledge.contentTooLong",
                length=len(content),
                max=MAX_BLOCK_CHARS,
            )
        )
    return content


class KnowledgeStore:
    def __init__(self, cases: CaseManager) -> None:
        if cases is None:
            raise ValueError("KnowledgeStore requires a CaseManager")
        self._cases = cases

    # ── rutas (confinamiento: control C2) ──────────────────────────────────

    def _knowledge_dir(self, case_id: str) -> Path:
        # ``case_dir`` ya valida el case_id y comprueba que no se sale de la raíz.
        case_dir = self._cases.case_dir(case_id)
        kdir = (case_dir / _KNOWLEDGE_DIRNAME).resolve()
        if case_dir.resolve() not in kdir.parents:
            raise ValueError(f"knowledge dir escapa del caso: {kdir}")
        return kdir

    def _node_paths(self, case_id: str, doc_id: str) -> tuple[Path, Path]:
        """(vista .md, registro .jsonl) — ambos verificados dentro del caso."""
        kdir = self._knowledge_dir(case_id)
        view = (kdir / f"{doc_id}.md").resolve()
        history = (kdir / _HISTORY_DIRNAME / f"{doc_id}.jsonl").resolve()
        # Belt-and-braces: el charset cerrado ya lo garantiza, pero un cambio futuro
        # del patrón no debe poder abrir un escape silencioso.
        if kdir not in view.parents or kdir not in history.parents:
            raise ValueError(f"doc_id {doc_id!r} resuelve fuera del knowledge del caso")
        return view, history

    # ── lectura ────────────────────────────────────────────────────────────

    def history(self, case_id: str, doc_id: str) -> list[KnowledgeBlock]:
        """El registro íntegro del nodo, en orden de escritura. No viaja al modelo."""
        doc_id = _validate_doc_id(doc_id)
        _, history_path = self._node_paths(case_id, doc_id)
        if not history_path.is_file():
            return []
        blocks: list[KnowledgeBlock] = []
        for line in history_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                # Una línea corrupta no invalida el resto del registro.
                logger.warning("knowledge: línea ilegible en %s", history_path)
                continue
            blocks.append(
                KnowledgeBlock(
                    doc_id=doc_id,
                    section=str(data.get("section") or ""),
                    content=str(data.get("content") or ""),
                    created_at=str(data.get("created_at") or ""),
                    iteration=data.get("iteration"),
                    sha256=str(data.get("sha256") or ""),
                )
            )
        return blocks

    def read(self, case_id: str, doc_id: str) -> KnowledgeNode | None:
        """La vista consolidada. ``None`` si el nodo no existe."""
        doc_id = _validate_doc_id(doc_id)
        view_path, _ = self._node_paths(case_id, doc_id)
        if not view_path.is_file():
            return None
        blocks = self.history(case_id, doc_id)
        latest = self._consolidate(blocks)
        return KnowledgeNode(
            doc_id=doc_id,
            sections=tuple(latest.keys()),
            markdown=view_path.read_text(encoding="utf-8"),
            updated_at=blocks[-1].created_at if blocks else "",
            block_count=len(blocks),
        )

    def index(self, case_id: str) -> list[NodeSummary]:
        """Índice del grafo del caso. Es lo ÚNICO que viaja siempre en el prompt."""
        kdir = self._knowledge_dir(case_id)
        if not kdir.is_dir():
            return []
        out: list[NodeSummary] = []
        for view in sorted(kdir.glob("*.md")):
            doc_id = view.stem
            if not _DOC_ID_RE.match(doc_id):
                continue
            blocks = self.history(case_id, doc_id)
            if not blocks:
                continue
            latest = self._consolidate(blocks)
            out.append(
                NodeSummary(
                    doc_id=doc_id,
                    sections=tuple(latest.keys()),
                    updated_at=blocks[-1].created_at,
                    block_count=len(blocks),
                )
            )
        return out

    # ── escritura ──────────────────────────────────────────────────────────

    def append(
        self,
        case_id: str,
        doc_id: str,
        section: str,
        content: str,
        *,
        iteration: int | None = None,
    ) -> KnowledgeBlock:
        """Añade un bloque y re-renderiza la vista. NUNCA modifica lo ya escrito."""
        doc_id = _validate_doc_id(doc_id)
        section = _validate_section(section)
        content = _validate_content(content)

        view_path, history_path = self._node_paths(case_id, doc_id)
        kdir = self._knowledge_dir(case_id)

        # Tope de nodos: solo si el nodo es NUEVO (añadir a uno existente no cuenta).
        if not view_path.is_file():
            existing = len([p for p in kdir.glob("*.md")]) if kdir.is_dir() else 0
            if existing >= MAX_NODES_PER_CASE:
                raise ValueError(
                    Mensaje(
                        "knowledge.tooManyNodes",
                        existing=existing,
                        max=MAX_NODES_PER_CASE,
                        nodes=sorted(p.stem for p in kdir.glob("*.md")),
                    )
                )

        blocks = self.history(case_id, doc_id)
        if section not in {b.section for b in blocks}:
            distinct = len({b.section for b in blocks})
            if distinct >= MAX_SECTIONS_PER_NODE:
                raise ValueError(
                    Mensaje(
                        "knowledge.tooManySections",
                        doc_id=repr(doc_id),
                        distinct=distinct,
                        max=MAX_SECTIONS_PER_NODE,
                    )
                )

        block = KnowledgeBlock(
            doc_id=doc_id,
            section=section,
            content=content,
            created_at=_utc_now_iso(),
            iteration=iteration,
            sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        )

        history_path.parent.mkdir(parents=True, exist_ok=True)
        # APPEND-ONLY: modo "a", una línea, sin releer ni reescribir lo anterior.
        with history_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(block.as_dict(), ensure_ascii=False) + "\n")

        self._render(view_path, doc_id, [*blocks, block])
        return block

    # ── consolidación y render ─────────────────────────────────────────────

    @staticmethod
    def _consolidate(blocks: list[KnowledgeBlock]) -> dict[str, KnowledgeBlock]:
        """Última versión de cada sección, en orden de PRIMERA aparición.

        Que el orden sea el de primera aparición (y no el de última escritura)
        mantiene el documento estable: corregir una sección no la salta al final
        y no reordena la lectura del perito.
        """
        latest: dict[str, KnowledgeBlock] = {}
        for block in blocks:
            latest[block.section] = block  # dict preserva orden de inserción
        return latest

    def _render(self, view_path: Path, doc_id: str, blocks: list[KnowledgeBlock]) -> None:
        latest = self._consolidate(blocks)
        lines = [
            f"# {doc_id}",
            "",
            "> Nodo del grafo de conocimiento de este caso, escrito por el agente con",
            "> `anotar_conocimiento`. Esta vista muestra la ÚLTIMA versión de cada",
            f"> sección; el registro íntegro está en `{_HISTORY_DIRNAME}/{doc_id}.jsonl`.",
            "> No es un hallazgo pericial: los hallazgos viven en `findings.jsonl` con",
            "> su procedencia.",
            "",
        ]
        for section, block in latest.items():
            lines.append(f"## {section}")
            lines.append("")
            lines.append(block.content)
            lines.append("")
            stamp = f"_(anotado {block.created_at}"
            if block.iteration is not None:
                stamp += f" · iteración {block.iteration}"
            stamp += ")_"
            lines.append(stamp)
            lines.append("")
        rendered = "\n".join(lines)

        # Atómico: tmp + replace, para que un fallo a mitad no deje una vista
        # truncada (mismo patrón que el builder de timeline y el registro de caso).
        view_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = view_path.with_name(f".{view_path.name}.tmp")
        tmp.write_text(rendered, encoding="utf-8")
        os.replace(tmp, view_path)


#: Instancia por defecto, anclada al CaseManager del proceso (igual que finding_store).
knowledge_store = KnowledgeStore(case_manager)
