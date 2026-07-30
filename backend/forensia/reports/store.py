"""Almacén de documentos del caso, con integridad SHA-256 real.

Un documento vive en ``<case_dir>/documents/<doc_id>.json``. El ``sha256`` se
calcula sobre el CONTENIDO canónico (todo menos el estado y el propio hash) al
crearse y NO cambia: firmar un borrador es un cambio de estado, no de contenido,
así que ``verify`` sigue coincidiendo (FORENSIC INVARIANT 2). Crear, firmar y
eliminar quedan en el audit hash-encadenado (FORENSIC INVARIANT 4).

RULE 2: nada se inventa. Un caso sin documentos devuelve ``[]``; un id que no
existe es un ``KeyError`` accionable, nunca "el primero" ni un placeholder.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from forensia.audit.log import AuditLog
from forensia.cases import CaseManager, case_manager

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

STATUSES = frozenset({"draft", "final"})
# Bloques del cuerpo de un informe pericial: párrafo, sub-encabezado, cita,
# lista, bloque de código/comando, pares clave-valor, tabla y hallazgo.
_BLOCK_TYPES = frozenset({"p", "h3", "quote", "list", "code", "kv", "table", "finding"})
_SEVERITIES = frozenset({"critical", "high", "medium", "low"})


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass(frozen=True)
class Document:
    id: str
    case_id: str
    title: str
    type: str
    evidence_id: str | None
    status: str
    created_at: str
    version: str
    author: str
    summary: str
    #: Secciones estructuradas: cada una ``{num, title, blocks:[…]}`` con bloques
    #: ``p`` / ``code`` / ``kv`` / ``table`` / ``finding`` (mismo modelo que la UI).
    sections: list[dict[str, Any]]
    #: SHA-256 del contenido canónico, fijado al crear. La integridad se verifica
    #: recomputándolo y comparando.
    sha256: str
    page_count: int

    def metadata(self) -> dict[str, Any]:
        """La ficha para la LISTA (sin el cuerpo de secciones)."""
        d = asdict(self)
        d.pop("sections", None)
        return d


def _canonical_content(data: dict[str, Any]) -> str:
    """Serialización determinista del CONTENIDO sobre el que se calcula el hash.

    Excluye ``status`` (firmar no altera el contenido) y ``sha256`` (no se hashea
    a sí mismo). El orden de claves fijo hace el hash reproducible."""
    payload = {
        "title": data["title"],
        "type": data["type"],
        "evidence_id": data.get("evidence_id"),
        "created_at": data["created_at"],
        "version": data["version"],
        "author": data["author"],
        "summary": data["summary"],
        "sections": data["sections"],
    }
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _content_sha256(data: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_content(data).encode("utf-8")).hexdigest()


def _estimate_pages(summary: str, sections: list[dict[str, Any]]) -> int:
    """Estimación honesta de páginas: ~3000 chars/página del texto renderizable."""
    chars = len(summary)
    for sec in sections:
        chars += len(sec.get("title", ""))
        for b in sec.get("blocks", []):
            chars += len(b.get("text", "") or "")
            for kv in b.get("pairs", []) or []:
                chars += len(str(kv.get("k", ""))) + len(str(kv.get("v", "")))
            for row in b.get("rows", []) or []:
                chars += sum(len(str(c)) for c in row)
    return max(1, -(-chars // 3000))  # ceil


def _validate_sections(raw: Any) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("document.sections must be a list")
    out: list[dict[str, Any]] = []
    for sec in raw:
        if not isinstance(sec, dict):
            raise ValueError("each section must be an object")
        title = str(sec.get("title", "")).strip()
        if not title:
            raise ValueError("each section needs a non-empty title")
        blocks_raw = sec.get("blocks", [])
        if not isinstance(blocks_raw, list):
            raise ValueError("section.blocks must be a list")
        blocks: list[dict[str, Any]] = []
        for b in blocks_raw:
            if not isinstance(b, dict):
                raise ValueError("each block must be an object")
            t = b.get("t")
            if t not in _BLOCK_TYPES:
                raise ValueError(f"block.t must be one of {sorted(_BLOCK_TYPES)}; got {t!r}")
            if t == "finding" and b.get("sev") not in _SEVERITIES:
                raise ValueError(f"finding block needs sev in {sorted(_SEVERITIES)}")
            if t == "list" and not isinstance(b.get("items"), list):
                raise ValueError("list block needs an 'items' list")
            blocks.append(b)
        out.append({"num": str(sec.get("num", "")), "title": title, "blocks": blocks})
    return out


class DocumentStore:
    def __init__(self, cases: CaseManager) -> None:
        if cases is None:
            raise ValueError("DocumentStore requires a CaseManager")
        self._cases = cases

    def _dir(self, case_id: str):
        d = self._cases.case_dir(case_id) / "documents"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _path(self, case_id: str, doc_id: str):
        if not _UUID4_RE.match(doc_id):
            raise ValueError(f"document id must be a UUID4, got {doc_id!r}")
        return self._dir(case_id) / f"{doc_id}.json"

    # ── lectura ──────────────────────────────────────────────────────────────

    def list(self, case_id: str) -> list[Document]:
        """Los documentos del caso, más recientes primero. `[]` si no hay."""
        d = self._dir(case_id)
        out: list[Document] = []
        for path in d.glob("*.json"):
            try:
                out.append(Document(**json.loads(path.read_text(encoding="utf-8"))))
            except (OSError, json.JSONDecodeError, TypeError):
                continue  # un fichero corrupto no tumba la lista
        out.sort(key=lambda x: x.created_at, reverse=True)
        return out

    def get(self, case_id: str, doc_id: str) -> Document:
        path = self._path(case_id, doc_id)
        if not path.is_file():
            raise KeyError(f"document {doc_id} not found in case {case_id}")
        return Document(**json.loads(path.read_text(encoding="utf-8")))

    # ── escritura ────────────────────────────────────────────────────────────

    def create(self, case_id: str, data: dict[str, Any]) -> Document:
        """Persiste un documento nuevo (estado ``draft``) con su SHA-256 real."""
        title = str(data.get("title", "")).strip()
        summary = str(data.get("summary", "")).strip()
        doc_type = str(data.get("type", "")).strip()
        if not title or len(title) > 300:
            raise ValueError("document.title must be a non-empty string ≤ 300 chars")
        if not doc_type:
            raise ValueError("document.type is required")
        evidence_id = data.get("evidence_id")
        if evidence_id is not None and not isinstance(evidence_id, str):
            raise ValueError("document.evidence_id must be a string or null")
        sections = _validate_sections(data.get("sections"))
        version = str(data.get("version") or "v0.1").strip()
        author = str(data.get("author") or "").strip() or "Agentopsy agent"

        content = {
            "title": title, "type": doc_type, "evidence_id": evidence_id,
            "created_at": _utc_now_iso(), "version": version, "author": author,
            "summary": summary, "sections": sections,
        }
        doc = Document(
            id=str(uuid.uuid4()), case_id=case_id, status="draft",
            sha256=_content_sha256(content), page_count=_estimate_pages(summary, sections),
            **content,
        )
        self._write(case_id, doc)
        self._audit(case_id, "document_created", doc)
        return doc

    def verify(self, case_id: str, doc_id: str) -> dict[str, Any]:
        """Recomputa el SHA-256 del contenido y lo compara con el de registro."""
        doc = self.get(case_id, doc_id)
        recomputed = _content_sha256(asdict(doc))
        return {
            "document_id": doc_id,
            "ok": recomputed == doc.sha256,
            "registered_sha256": doc.sha256,
            "recomputed_sha256": recomputed,
        }

    def sign(self, case_id: str, doc_id: str) -> Document:
        """Marca un borrador como ``final`` (acto pericial, auditado). Idempotente
        sobre un final. El contenido no cambia, así que el hash sigue válido."""
        doc = self.get(case_id, doc_id)
        if doc.status == "final":
            return doc
        signed = Document(**{**asdict(doc), "status": "final"})
        self._write(case_id, signed)
        self._audit(case_id, "document_signed", signed)
        return signed

    def delete(self, case_id: str, doc_id: str) -> None:
        """Elimina un BORRADOR. Un documento ``final`` no se borra (cadena de
        custodia): falla fuerte."""
        doc = self.get(case_id, doc_id)
        if doc.status == "final":
            raise ValueError(
                "a signed (final) document cannot be deleted, chain of custody"
            )
        self._path(case_id, doc_id).unlink(missing_ok=True)
        self._audit(case_id, "document_deleted", doc)

    # ── internos ─────────────────────────────────────────────────────────────

    def _write(self, case_id: str, doc: Document) -> None:
        path = self._path(case_id, doc.id)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(asdict(doc), sort_keys=True, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        tmp.replace(path)

    def _audit(self, case_id: str, action: str, doc: Document) -> None:
        AuditLog(self._cases.case_dir(case_id) / "audit.jsonl").append({
            "action": action,
            "case_id": case_id,
            "document_id": doc.id,
            "title": doc.title,
            "status": doc.status,
            "sha256": doc.sha256,
            "ts_utc": _utc_now_iso(),
        })


document_store = DocumentStore(case_manager)
