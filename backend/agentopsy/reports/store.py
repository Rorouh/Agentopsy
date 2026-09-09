"""Almacén de documentos del caso, con integridad SHA-256 real.

Un documento vive en ``<case_dir>/documents/<doc_id>.json``. El ``sha256`` se
calcula sobre el CONTENIDO canónico (todo menos el estado, los campos de
aprobación y el propio hash) al crearse y NO cambia: aprobar un borrador es un
cambio de estado, no de contenido, así que ``verify`` sigue coincidiendo
(FORENSIC INVARIANT 2). Crear, aprobar y eliminar quedan en el audit
hash-encadenado (FORENSIC INVARIANT 4).

**Aprobar exige que el contenido esté íntegro.** Hasta 2026-09-08 ``sign``
marcaba ``final`` un documento cuya verificación devolvía falso, y volvía a
devolverlo tal cual si ya lo era: «ya era final» valía como respuesta correcta
para un documento alterado (auditoría 2026-09-07, F04). Ahora la comprobación
(``agentopsy.reports.aprobacion``) precede a las dos cosas, y las comprueba TODAS
las rutas, porque deshabilitar un botón no impide una llamada al API.

**No es una firma digital.** Es una aprobación humana AUDITADA: identidad del
perito, instante y hash del contenido aprobado, anclados en la cadena. La ruta
pública sigue llamándose ``sign`` por compatibilidad, pero lo que hace, lo que
registra y lo que la interfaz dice es «Aprobar como final».

**Cada documento declara SUS fuentes** (``fuentes``): el snapshot de evidencias,
artefactos y revisiones de hallazgo que lo sostenían al generarse. Sin él, «las
fuentes del informe» serían «lo que el caso tenga hoy», y una evidencia
registrada mañana cambiaría retroactivamente el respaldo de un informe aprobado.

RULE 2: nada se inventa. Un caso sin documentos devuelve ``[]``; un id que no
existe es un ``KeyError`` accionable, nunca "el primero" ni un placeholder.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from filelock import FileLock

from agentopsy.audit.log import AuditLog
from agentopsy.cases import CaseManager, case_manager
from agentopsy.i18n import Mensaje
from agentopsy.reports.fuentes import digest_de_fuentes, validar_refs

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

STATUSES = frozenset({"draft", "final"})

#: Versión de esquema que escriben los documentos NUEVOS.
#:
#: - 1: histórico, sin manifiesto de fuentes.
#: - 2: declara ``fuentes``, pero su hash NO las cubría: sustituir el manifiesto
#:   dejaba el hash intacto y el informe aprobable (reauditoría 2026-09-08, RA01).
#: - 3: el contenido canónico incluye la IDENTIDAD del documento (caso e id) y el
#:   DIGEST de su manifiesto, así que el hash cubre a los dos y el ancla auditada
#:   los cubre a través de él. Es la única versión que puede aprobarse.
#:
#: Un documento de esquema anterior se lee y se exporta como borrador. No se le
#: recalcula el hash con el esquema nuevo: eso lo haría parecer comprobado sin
#: haberlo comprobado nunca.
SCHEMA_VERSION = 3
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
    #: El SNAPSHOT de fuentes que sostenían el documento al generarse
    #: (``agentopsy.reports.aprobacion.manifiesto_de_fuentes``). Vacío en los
    #: documentos anteriores al contrato: se leen y se exportan como borrador,
    #: pero no se aprueban, porque no hay nada que volver a comprobar.
    fuentes: dict[str, Any] = field(default_factory=dict)
    #: El DIGEST canónico de ``fuentes`` (``reports.fuentes.digest_de_fuentes``).
    #: Entra en el contenido canónico desde el esquema 3, así que el ``sha256``
    #: del documento cubre su manifiesto: retirarlo, sustituirlo o vaciarlo
    #: cambia este digest y con él el hash, que deja de casar con su ancla.
    #: Vacío en los documentos de esquema anterior, y NO se rellena a posteriori.
    fuentes_sha256: str = ""
    #: Cuándo y quién APROBÓ el documento como final, y qué contenido exacto
    #: aprobó. ``None`` mientras es borrador. No es una firma criptográfica: es
    #: la traza de un acto humano auditado.
    approved_at: str | None = None
    approved_by: str | None = None
    approved_sha256: str | None = None
    #: Versión de esquema del documento. Sube cuando cambia lo que un documento
    #: GARANTIZA, para que un histórico se pueda leer sin atribuirle garantías
    #: que no tiene. 1 = anterior al manifiesto de fuentes.
    schema_version: int = 1

    def metadata(self) -> dict[str, Any]:
        """La ficha para la LISTA (sin el cuerpo de secciones ni el manifiesto)."""
        d = asdict(self)
        d.pop("sections", None)
        # El manifiesto entero no cabe en una ficha de lista, pero su digest sí,
        # y es lo que permite ver de un vistazo que dos revisiones no descansan
        # en el mismo material.
        d.pop("fuentes", None)
        return d


def _canonical_content(data: dict[str, Any]) -> str:
    """Serialización determinista del CONTENIDO sobre el que se calcula el hash.

    Excluye ``status`` y los campos de aprobación (aprobar no altera el
    contenido) y ``sha256`` (no se hashea a sí mismo). El orden de claves fijo
    hace el hash reproducible.

    **Depende del esquema, y por eso lo lleva dentro.** Desde el esquema 3 el
    payload incluye tres cosas más, y cada una cierra un agujero concreto:

    - ``id`` y ``case_id``: la IDENTIDAD. Sin ellos, dos documentos con el mismo
      texto tenían el mismo hash, y una aprobación registrada para uno servía
      para el otro (RA04 f).
    - ``fuentes_sha256``: el digest del manifiesto de procedencia. Sin él, el
      hash cubría el texto pero no el respaldo, y se podía retirar el respaldo
      entero sin invalidar nada (RA01).
    - ``schema_version``: para que el payload de un esquema no se pueda hacer
      pasar por el de otro.

    Un documento de esquema anterior se sigue hasheando con SU payload. Cambiarle
    la forma de calcular el hash rompería su verificación o, peor, la haría pasar
    con garantías que ese documento nunca tuvo."""
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
    try:
        esquema = int(data.get("schema_version") or 1)
    except (TypeError, ValueError):
        esquema = 1
    if esquema >= 3:
        payload = {
            **payload,
            "schema_version": esquema,
            "id": data.get("id"),
            "case_id": data.get("case_id"),
            "fuentes_sha256": data.get("fuentes_sha256") or "",
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
            # RA07: un bloque puede declarar en qué revisión de qué hallazgo se
            # apoya (``refs``) o qué limitación declara (``limitacion``). La
            # FORMA se valida aquí, en el almacén, porque un documento puede
            # llegar por la ruta REST y no solo del redactor. Que esas citas
            # existan y estén íntegras lo comprueba la aprobación, que es la que
            # abre las fuentes.
            validar_refs(b, num=str(sec.get("num", "")))
            limitacion = b.get("limitacion")
            if limitacion is not None and not isinstance(limitacion, str):
                raise ValueError("block.limitacion must be a string code")
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
        fuentes = data.get("fuentes")
        if fuentes is not None and not isinstance(fuentes, dict):
            raise ValueError("document.fuentes must be an object or null")

        content = {
            "title": title, "type": doc_type, "evidence_id": evidence_id,
            "created_at": _utc_now_iso(), "version": version, "author": author,
            "summary": summary, "sections": sections,
        }
        manifiesto = dict(fuentes or {})
        # La IDENTIDAD se fija antes del hash porque forma parte de él desde el
        # esquema 3: el documento no puede firmarse a sí mismo sin decir quién es.
        doc_id = str(uuid.uuid4())
        identidad = {
            "id": doc_id,
            "case_id": case_id,
            "schema_version": SCHEMA_VERSION,
            "fuentes_sha256": digest_de_fuentes(manifiesto) if manifiesto else "",
        }
        doc = Document(
            id=doc_id, case_id=case_id, status="draft",
            sha256=_content_sha256({**content, **identidad}),
            page_count=_estimate_pages(summary, sections),
            fuentes=manifiesto,
            fuentes_sha256=identidad["fuentes_sha256"],
            schema_version=SCHEMA_VERSION,
            **content,
        )
        self._write(case_id, doc)
        self._audit(case_id, "document_created", doc)
        return doc

    def verify(self, case_id: str, doc_id: str) -> dict[str, Any]:
        """Recomputa el SHA-256 del contenido y lo compara con el de registro.

        Desde el esquema 3 devuelve además el digest de procedencia recomputado
        DESDE el manifiesto que hay en el disco, junto al que el documento
        declara. Que los dos casen es lo que dice que el manifiesto es el que
        era; que no casen es que se le ha cambiado el respaldo, y eso arrastra al
        hash del contenido porque el digest entra en él (RA01).
        """
        doc = self.get(case_id, doc_id)
        datos = asdict(doc)
        recomputed = _content_sha256(datos)
        salida = {
            "document_id": doc_id,
            "ok": recomputed == doc.sha256,
            "registered_sha256": doc.sha256,
            "recomputed_sha256": recomputed,
            "schema_version": doc.schema_version,
        }
        if doc.schema_version >= 3:
            actual = digest_de_fuentes(doc.fuentes)
            salida["registered_fuentes_sha256"] = doc.fuentes_sha256
            salida["recomputed_fuentes_sha256"] = actual
            salida["fuentes_ok"] = actual == doc.fuentes_sha256
        return salida

    def approve(
        self,
        case_id: str,
        doc_id: str,
        *,
        sha256_revisado: str,
        revisor: str,
        comprobar_fn: Any = None,
    ) -> Document:
        """APRUEBA COMO FINAL un documento, tras cruzar todas sus comprobaciones.

        No es una firma digital: es una aprobación humana AUDITADA. Queda quién
        la hizo, cuándo y sobre QUÉ contenido exacto, anclado en la cadena.

        ``sha256_revisado`` es el hash del contenido que el investigador acaba de
        leer. Si entre su revisión y esta llamada el contenido cambió, no se
        aprueba: aprobaría algo que nadie ha mirado (F04, comprobación h).

        Idempotente sobre un documento que YA es final, pero solo después de
        comprobar su integridad: «ya era final» no convierte en válido un
        documento ahora alterado, que es exactamente lo que ocurría antes.

        La transición se hace bajo el MISMO cerrojo que la comprobación, así que
        un escritor concurrente de la aplicación no puede colar un contenido
        distinto entre lo que se verificó y lo que se aprueba.
        """
        from agentopsy.reports.aprobacion import AprobacionBloqueada, comprobar

        comprobar_fn = comprobar_fn or comprobar
        with self._lock(case_id, doc_id):
            comprobacion = comprobar_fn(
                case_id,
                doc_id,
                documents=self,
                cases=self._cases,
                sha256_revisado=sha256_revisado,
            )
            if not comprobacion.aprobable:
                raise AprobacionBloqueada(comprobacion)

            doc = self.get(case_id, doc_id)
            if doc.status == "final":
                # Íntegro y ya aprobado: no se reescribe ni se vuelve a auditar,
                # pero se ha COMPROBADO antes de decirlo.
                return doc

            aprobado = Document(**{
                **asdict(doc),
                "status": "final",
                "approved_at": _utc_now_iso(),
                "approved_by": (revisor or "").strip() or doc.author,
                "approved_sha256": comprobacion.sha256_actual,
            })
            # Persistir ANTES de auditar dejaría un documento aprobado sin
            # registro; auditar antes de persistir dejaría un registro de algo
            # que no ocurrió. Se persiste, se audita, y si la auditoría falla se
            # deshace la transición: no queda un final sin su acta.
            self._write(case_id, aprobado)
            try:
                self._audit(case_id, "document_approved", aprobado)
            except Exception:
                self._write(case_id, doc)
                raise
            return aprobado

    def sign(self, case_id: str, doc_id: str, **kwargs: Any) -> Document:
        """Alias histórico de :meth:`approve`.

        La ruta pública ``…/documents/{id}/sign`` se conserva por compatibilidad
        (RULE 4: no se rompe un cliente por renombrar), pero lo que ocurre, lo
        que se registra y lo que la interfaz dice es «Aprobar como final».
        """
        return self.approve(case_id, doc_id, **kwargs)

    def delete(self, case_id: str, doc_id: str) -> None:
        """Elimina un BORRADOR. Un documento ``final`` no se borra (cadena de
        custodia): falla fuerte.

        Toma el MISMO cerrojo por documento que :meth:`approve`, y esto no es
        simetría decorativa: sin él, leer el estado y borrar el fichero eran dos
        pasos, y una aprobación concurrente podía colarse entre ellos y dejar
        aprobado un documento que se estaba borrando (RA04 i). El protocolo es
        uno solo: todo escritor de un documento entra por su cerrojo, y dentro
        del cerrojo vuelve a leer el estado en lugar de fiarse del que traía.
        """
        with self._lock(case_id, doc_id):
            doc = self.get(case_id, doc_id)
            if doc.status == "final":
                raise ValueError(
                    "a signed (final) document cannot be deleted, chain of custody"
                )
            self._path(case_id, doc_id).unlink(missing_ok=True)
            self._audit(case_id, "document_deleted", doc)

    # ── internos ─────────────────────────────────────────────────────────────

    def _lock_path(self, case_id: str, doc_id: str):
        """Cerrojo por documento: la comprobación y la transición de estado
        ocurren dentro de él, así que no se aprueba un contenido distinto del que
        se verificó."""
        return self._path(case_id, doc_id).with_suffix(".json.lock")

    def _lock(self, case_id: str, doc_id: str) -> FileLock:
        """El cerrojo de UN documento, reentrante dentro del mismo proceso.

        El protocolo es uno solo y se enuncia aquí para no tener que deducirlo:

        1. Todo escritor de un documento (aprobar, borrar) entra por ESTE
           cerrojo, y solo por este. No hay un segundo ámbito.
        2. Dentro del cerrojo se vuelve a LEER el estado en lugar de fiarse del
           que se traía: entre pedir el cerrojo y obtenerlo puede haber pasado
           cualquier cosa.
        3. No se toma ningún otro cerrojo mientras se tiene este. La escritura de
           hallazgos tiene el suyo (``findings.jsonl.lock``, en ``AuditLog`` y en
           ``FindingStore``) y esta capa nunca lo pide: sin anidamiento no hay
           orden de bloqueo que respetar ni abrazo mortal que evitar.

        ``is_singleton`` lo hace REENTRANTE en el proceso: dos instancias del
        almacén sobre el mismo documento se serializan en vez de estrellarse
        contra la detección de abrazo mortal de ``filelock``. Sin eso, componer
        dos operaciones del dominio en una sola llamada revienta, que es
        exactamente el "bloqueo anidado incompatible" que hay que evitar.

        **Lo que este cerrojo NO hace**: proteger frente a quien edita los
        ficheros del caso por fuera de la aplicación. Serializa a los escritores
        de la aplicación, y nada más. Atribuirle lo otro sería prometer una
        garantía que no existe.
        """
        return FileLock(str(self._lock_path(case_id, doc_id)), is_singleton=True)

    def registrar_exportacion(
        self,
        case_id: str,
        doc_id: str,
        *,
        sha256: str,
        bytes_: int,
        generador: str,
        borrador: bool,
    ) -> dict[str, Any]:
        """Ancla en el audit el SHA-256 de los BYTES EXACTOS del PDF servido.

        Es un hash DISTINTO del ``sha256`` del documento: aquel cubre el
        contenido estructurado, este los bytes del fichero que sale por la red.
        Confundirlos sería atribuirle al PDF una verificación que no se le ha
        hecho. Viajan juntos el documento, su revisión, la versión del generador
        y si salió marcado como borrador.

        Una exportación FINAL ya registrada no se sustituye en silencio: si el
        caso ya tiene una y los bytes no coinciden, falla fuerte (RULE 2).
        """
        doc = self.get(case_id, doc_id)
        log = AuditLog(self._cases.case_dir(case_id) / "audit.jsonl")
        if not borrador:
            previas = [
                e
                for e in log.entries()
                if e.get("action") == "document_exported"
                and e.get("document_id") == doc_id
                and e.get("draft") is False
            ]
            distinta = next(
                (e for e in previas if e.get("pdf_sha256") != sha256), None
            )
            if distinta is not None:
                raise ValueError(
                    Mensaje(
                        "approval.pdfOverwrite",
                        document_id=doc_id,
                        sha256=distinta.get("pdf_sha256"),
                    )
                )
        evento = {
            "action": "document_exported",
            "case_id": case_id,
            "document_id": doc_id,
            "version": doc.version,
            "status": doc.status,
            "document_sha256": doc.sha256,
            "pdf_sha256": sha256,
            "pdf_bytes": bytes_,
            "generator": generador,
            "draft": borrador,
            "ts_utc": _utc_now_iso(),
        }
        log.append(evento)
        return evento

    def _write(self, case_id: str, doc: Document) -> None:
        path = self._path(case_id, doc.id)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(asdict(doc), sort_keys=True, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        tmp.replace(path)

    def _audit(self, case_id: str, action: str, doc: Document) -> None:
        evento: dict[str, Any] = {
            "action": action,
            "case_id": case_id,
            "document_id": doc.id,
            "title": doc.title,
            "status": doc.status,
            # El ancla del CONTENIDO: la comprobación de aprobación recomputa el
            # hash y lo compara con este, así que alterar el documento Y su hash
            # local no basta, hay que reescribir la cadena y eso la rompe.
            "sha256": doc.sha256,
            "version": doc.version,
            "schema_version": doc.schema_version,
            "ts_utc": _utc_now_iso(),
        }
        if doc.approved_at:
            evento["approved_at"] = doc.approved_at
            evento["approved_by"] = doc.approved_by
            evento["approved_sha256"] = doc.approved_sha256
        # El ANCLA de la PROCEDENCIA. Los contadores solos no anclaban nada:
        # sustituir el manifiesto por otro con los mismos tres números pasaba sin
        # que la cadena lo notase (RA01). El digest sí lo ancla, y viaja separado
        # del ``sha256`` del contenido para que se vea que son dos cosas: qué
        # dice el informe y en qué se apoya.
        evento["fuentes_sha256"] = doc.fuentes_sha256
        fuentes = doc.fuentes or {}
        if fuentes:
            evento["fuentes"] = {
                "evidencias": len(fuentes.get("evidencias") or []),
                "artefactos": len(fuentes.get("artefactos") or []),
                "hallazgos": len(fuentes.get("hallazgos") or []),
                "limitaciones_exigidas": list(
                    fuentes.get("limitaciones_exigidas") or []
                ),
            }
        AuditLog(self._cases.case_dir(case_id) / "audit.jsonl").append(evento)


document_store = DocumentStore(case_manager)

__all__ = [
    "SCHEMA_VERSION",
    "STATUSES",
    "Document",
    "DocumentStore",
    "document_store",
]
