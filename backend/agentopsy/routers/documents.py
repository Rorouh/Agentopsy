"""Superficie HTTP de documentos / informes. Adaptador fino sobre
``agentopsy.reports`` (RULE 3). Todas las escrituras exigen el token de sesión
(SECURITY INVARIANT 3); el checkeo de origen/host es del middleware.

El informe pericial se emite en UN solo acto del operador: **finalizar la
investigación** (``POST …/documents/finalize``). No hay borrador automático al
cerrar un análisis, ni síntesis determinista, ni redacción "asistida" de unas
secciones sueltas — todo eso se retiró el 2026-07-30. El ejecutor que el operador
seleccionó redacta el informe completo (``agentopsy.reports.writer``) y Agentopsy
valida el índice, el modelo de bloques, los referentes del material y los
comandos auditados antes de persistir nada.

Redactar un informe entero es una llamada larga a un modelo (minutos), así que
corre DESACOPLADA de la petición HTTP en el registro de jobs compartido
(``agentopsy.agent.jobs``, el mismo que sirve al análisis del agente): el cliente
recibe un ``job_id`` al instante y lo sondea. Cerrar la pestaña no aborta la
redacción.

**Aprobar y exportar cruzan la MISMA puerta** (``agentopsy.reports.aprobacion``),
y la cruzan aquí, en el servidor: la interfaz deshabilita un botón, pero el
cliente puede llamar a estas rutas directamente y hasta 2026-09-08 lo conseguía
(un documento alterado se marcaba final y se exportaba sin una sola comprobación,
auditoría 2026-09-07, F04). La ruta pública sigue llamándose ``/sign`` por
compatibilidad; lo que hace es «Aprobar como final», que es una aprobación humana
AUDITADA y no una firma digital criptográfica.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
from typing import Any

import hashlib

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from agentopsy import __version__
from agentopsy.i18n import t, traducir_excepcion
from agentopsy.agent.jobs import job_registry
from agentopsy.audit import AuditLog
from agentopsy.cases import case_manager
from agentopsy.config import config
from agentopsy.executors import (
    EXECUTOR_IDS,
    MODEL_CONFIG_KEY,
    REASONING_CONFIG_KEY,
    get_executor,
)
from agentopsy.findings.store import finding_store
from agentopsy.reports import document_store
from agentopsy.reports.aprobacion import AprobacionBloqueada, comprobar
from agentopsy.reports.citas import abrir_cita
from agentopsy.reports.pdf import render_pdf
from agentopsy.reports.writer import write_report
from agentopsy.security import require_token

router = APIRouter()

#: ``kind`` del job de redacción en el registro compartido, para distinguirlo de
#: un ``analyze`` del agente.
REPORT_JOB_KIND = "report"


class CreateDocumentRequest(BaseModel):
    title: str
    type: str
    summary: str = ""
    evidence_id: str | None = None
    version: str | None = None
    author: str | None = None
    sections: list[dict[str, Any]] = []


class FinalizeInvestigationRequest(BaseModel):
    """«Finalizar investigación»: el ejecutor seleccionado redacta el informe.

    ``executor`` es OBLIGATORIO — es el modelo que escribe el informe de
    principio a fin, y Agentopsy no elige uno por el operador (RULE 2). Se acepta
    también la selección que el operador ya fijó explícitamente en Configuración
    (``DEFAULT_EXECUTOR``), que es agencia suya, no un default inventado.

    Los datos del perito son opcionales: en su ausencia figura el examinador del
    caso, que es el dato autoritativo del expediente. ``version`` sin valor se
    deriva de las revisiones que el caso ya tiene registradas.
    """

    executor: str | None = None
    name: str | None = None
    colegiado: str | None = None
    organization: str | None = None
    email: str | None = None
    version: str | None = None


class ApproveDocumentRequest(BaseModel):
    """«Aprobar como final»: el acto pericial, con la revisión que se revisó.

    ``sha256`` es el hash del contenido que el investigador ACABA de leer. Es
    obligatorio y no es burocracia: sin él, entre la pantalla que revisó y esta
    llamada podría haber cambiado el contenido, y se estaría aprobando algo que
    nadie ha mirado (F04, comprobación h).

    ``approved_by`` identifica a quien aprueba. Es una aprobación humana
    auditada, no una firma criptográfica: queda quién dijo aprobarlo, no una
    prueba de identidad.
    """

    sha256: str
    approved_by: str | None = None


def _svc_error(exc: Exception) -> HTTPException:
    if isinstance(exc, AprobacionBloqueada):
        # 409: el documento existe y la petición es correcta; lo que no se
        # sostiene es su estado. Los bloqueos viajan ENTEROS para que la
        # interfaz los pinte todos y no se descubran de uno en uno.
        return HTTPException(
            status_code=409,
            detail={
                "message": traducir_excepcion(exc),
                **exc.comprobacion.como_dict(),
            },
        )
    if isinstance(exc, KeyError):
        return HTTPException(status_code=404, detail=traducir_excepcion(exc).strip('"'))
    return HTTPException(status_code=422, detail=traducir_excepcion(exc))


@router.get("/api/cases/{case_id}/documents", dependencies=[Depends(require_token)])
def list_documents(case_id: str) -> list[dict[str, Any]]:
    """Fichas de los documentos del caso (sin el cuerpo). `[]` si no hay."""
    try:
        return [d.metadata() for d in document_store.list(case_id)]
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc


@router.post("/api/cases/{case_id}/documents", dependencies=[Depends(require_token)])
def create_document(case_id: str, req: CreateDocumentRequest) -> dict[str, Any]:
    try:
        return asdict(document_store.create(case_id, req.model_dump()))
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc


# NOTA de orden: las rutas literales (`/finalize`, `/jobs`) se declaran ANTES de
# `/{doc_id}`. FastAPI resuelve por orden de declaración, así que al revés
# `/documents/jobs` entraría por `{doc_id}="jobs"` y moriría en el validador de
# UUID del almacén.
@router.post(
    "/api/cases/{case_id}/documents/finalize",
    dependencies=[Depends(require_token)],
)
def finalize_investigation(
    case_id: str, req: FinalizeInvestigationRequest
) -> dict[str, Any]:
    """Finaliza la investigación: el ejecutor seleccionado REDACTA el informe
    pericial del caso, completo, y se persiste como documento en estado
    ``draft``.

    Arranca en segundo plano y devuelve el ``job_id`` al instante; el estado se
    sonda en ``GET …/documents/jobs/{job_id}``. Lo que se valida AQUÍ, síncrono,
    es lo que permite fallar rápido con el código HTTP correcto: caso inexistente
    (404), caso sin hallazgos (422), ejecutor sin seleccionar o desconocido
    (422), ejecutor inutilizable (503). El resto —el contrato de respuesta y las
    cuatro puertas de custodia— lo comprueba el redactor y aparece como error del
    job.
    """
    try:
        case = case_manager.load(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=traducir_excepcion(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc

    # Sin un solo hallazgo no hay investigación que informar. El redactor lo
    # vuelve a comprobar (es su invariante), pero fallar aquí ahorra la llamada
    # al modelo y deja el motivo en el botón, no en el estado de un job.
    if not finding_store.list(case_id):
        raise HTTPException(
            status_code=422,
            detail=t("api.noFindingsForReport"),
        )

    executor_id = req.executor or config.get("DEFAULT_EXECUTOR")
    if not executor_id:
        raise HTTPException(
            status_code=422,
            detail=t("api.reportExecutorRequired", ids=" | ".join(EXECUTOR_IDS)),
        )
    try:
        executor = get_executor(str(executor_id))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc

    availability = executor.is_available()
    if not availability.available:
        raise HTTPException(status_code=503, detail=availability.reason)

    try:
        audit = AuditLog(case_manager.case_dir(case_id) / "audit.jsonl")
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc

    # Modelo elegido por el operador para ese ejecutor (Configuración), igual que
    # en /api/agent/query — nunca uno inventado aquí (RULE 2).
    model = config.get(MODEL_CONFIG_KEY[executor.id])
    # Nivel de razonamiento, solo si ese ejecutor declara clave (hoy, Codex).
    reasoning_key = REASONING_CONFIG_KEY.get(executor.id)
    reasoning_effort = config.get(reasoning_key) if reasoning_key else None
    perito = req.model_dump(exclude_none=True, exclude={"executor"})

    # ``should_cancel`` lo exige la firma del registro de jobs, pero aquí no se
    # consulta y eso es HONESTO: la redacción es UNA llamada al ejecutor, no un
    # bucle con puntos de parada entre iteraciones como el análisis del agente.
    # No hay dónde cortar limpio, así que no se ofrece un «Parar» que mentiría.
    def _work(
        emit: Callable[[dict[str, Any]], None],
        should_cancel: Callable[[], bool],
    ) -> dict[str, Any]:
        data = write_report(
            case_id,
            executor=executor,
            audit=audit,
            perito=perito or None,
            model=model,
            reasoning_effort=reasoning_effort,
            on_progress=emit,
        )
        doc = document_store.create(case_id, data)
        emit({"type": "report_ready", "doc_id": doc.id, "title": doc.title})
        return {
            "doc_id": doc.id,
            "title": doc.title,
            "version": doc.version,
            "page_count": doc.page_count,
            "sha256": doc.sha256,
        }

    job = job_registry.submit(
        case_id,
        REPORT_JOB_KIND,
        _work,
        meta={
            "case_name": case.name,
            "executor": {"id": executor.id, "name": executor.name, "local": executor.is_local},
        },
    )
    return job.public()


@router.get(
    "/api/cases/{case_id}/documents/jobs", dependencies=[Depends(require_token)]
)
def list_report_jobs(case_id: str) -> list[dict[str, Any]]:
    """Las redacciones de informe del caso, más recientes primero — para que la
    SPA vuelva a engancharse a una en curso al montar la vista."""
    return [
        j for j in job_registry.list_for_case(case_id) if j.get("kind") == REPORT_JOB_KIND
    ]


@router.get(
    "/api/cases/{case_id}/documents/jobs/{job_id}",
    dependencies=[Depends(require_token)],
)
def get_report_job(case_id: str, job_id: str, since: int = 0) -> dict[str, Any]:
    """Estado de una redacción en curso: running / done (con el documento) /
    error (con el motivo accionable del redactor)."""
    snap = job_registry.snapshot(job_id, since=max(0, since))
    if snap is None or snap.get("case_id") != case_id:
        raise HTTPException(
            status_code=404,
            detail=t("api.reportJobNotFound", job_id=job_id, case_id=case_id),
        )
    return snap


@router.get("/api/cases/{case_id}/documents/{doc_id}", dependencies=[Depends(require_token)])
def get_document(case_id: str, doc_id: str) -> dict[str, Any]:
    try:
        return asdict(document_store.get(case_id, doc_id))
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc


@router.post(
    "/api/cases/{case_id}/documents/{doc_id}/verify",
    dependencies=[Depends(require_token)],
)
def verify_document(case_id: str, doc_id: str) -> dict[str, Any]:
    """Integridad del CONTENIDO del documento. Es la comprobación mínima; la
    completa (fuentes, cadena, hallazgos, limitaciones) es ``/checks``."""
    try:
        return document_store.verify(case_id, doc_id)
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc


@router.get(
    "/api/cases/{case_id}/documents/{doc_id}/checks",
    dependencies=[Depends(require_token)],
)
def document_checks(case_id: str, doc_id: str) -> dict[str, Any]:
    """TODO lo que hay que comprobar antes de aprobar, con sus bloqueos.

    Es lo que la pantalla de aprobación pinta: la revisión exacta que se va a
    aprobar, el estado de cada fuente y lo que falta. No aprueba nada; es la
    lectura previa a decidir.
    """
    try:
        return comprobar(
            case_id, doc_id, documents=document_store, cases=case_manager
        ).como_dict()
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc


@router.get(
    "/api/cases/{case_id}/documents/{doc_id}/citas/{finding_id}",
    dependencies=[Depends(require_token)],
)
def document_citation(
    case_id: str, doc_id: str, finding_id: str, revision: int = 1
) -> dict[str, Any]:
    """Abre la FUENTE de una conclusión del informe, desde la conclusión.

    El cliente manda el documento, el hallazgo y la revisión; el backend
    resuelve la ejecución, el artefacto, el localizador y el extracto, y los
    verifica AHORA (SECURITY INVARIANT 5: nada de lo que el modelo escribió se
    usa como enlace de confianza).

    404 si el documento no cita esa revisión: la ruta del informe no es una
    puerta por la que pedir cualquier hallazgo del caso.
    """
    try:
        return abrir_cita(
            case_id,
            doc_id,
            finding_id,
            revision=revision,
            documents=document_store,
            cases=case_manager,
            findings=finding_store,
        )
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc


@router.post(
    "/api/cases/{case_id}/documents/{doc_id}/sign",
    dependencies=[Depends(require_token)],
)
def sign_document(
    case_id: str, doc_id: str, req: ApproveDocumentRequest
) -> dict[str, Any]:
    """APRUEBA COMO FINAL el documento (ruta histórica ``/sign``).

    Aprobación humana AUDITADA, nunca una firma digital: queda quién la hizo,
    cuándo y sobre qué contenido exacto. Cruza todas las comprobaciones de
    ``agentopsy.reports.aprobacion``, y las cruza AQUÍ aunque el cliente llame
    directamente: la interfaz no es la que decide (F04).
    """
    try:
        doc = document_store.approve(
            case_id,
            doc_id,
            sha256_revisado=req.sha256,
            revisor=req.approved_by or "",
        )
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc
    return asdict(doc)


@router.delete("/api/cases/{case_id}/documents/{doc_id}", dependencies=[Depends(require_token)])
def delete_document(case_id: str, doc_id: str) -> dict[str, Any]:
    try:
        document_store.delete(case_id, doc_id)
        return {"deleted": True, "document_id": doc_id}
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc


@router.get(
    "/api/cases/{case_id}/documents/{doc_id}/pdf",
    dependencies=[Depends(require_token)],
)
def document_pdf(case_id: str, doc_id: str) -> Response:
    """Genera el PDF real del documento (fpdf2). La web lo descarga con el token.

    Un documento FINAL se exporta como tal solo si sus comprobaciones siguen
    pasando: uno alterado después de aprobarse no sale como si fuera válido,
    sale marcado como borrador y con sus bloqueos listados en la portada. Un
    borrador se exporta siempre, marcado en todas sus páginas.

    El SHA-256 de los BYTES exactos que se sirven queda en el audit, junto al
    documento, su revisión y la versión del generador. Es un hash DISTINTO del
    del contenido: confundirlos sería atribuirle al PDF una comprobación que no
    se le ha hecho.
    """
    try:
        doc = document_store.get(case_id, doc_id)
        comprobacion = comprobar(
            case_id, doc_id, documents=document_store, cases=case_manager
        )
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc

    bloqueos = [b.como_dict() for b in comprobacion.bloqueos]
    # Un documento que ya no supera sus comprobaciones NO se exporta como final,
    # aunque su estado diga «final»: se degrada a borrador CON sus motivos, que
    # es la única salida honesta (RULE 2: no se sustituye en silencio, se dice).
    borrador = doc.status != "final" or bool(bloqueos)
    pdf_bytes = render_pdf(doc, bloqueos=bloqueos)
    sha256 = hashlib.sha256(pdf_bytes).hexdigest()

    try:
        document_store.registrar_exportacion(
            case_id,
            doc_id,
            sha256=sha256,
            bytes_=len(pdf_bytes),
            generador=f"Agentopsy {__version__} fpdf2",
            borrador=borrador,
        )
    except ValueError as exc:
        # Una exportación final ya registrada no se sustituye en silencio.
        raise HTTPException(status_code=409, detail=traducir_excepcion(exc)) from exc

    filename = f"{doc.id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            # El hash de lo servido viaja también en la respuesta: quien lo
            # descarga puede comprobarlo sin abrir el audit.
            "X-Agentopsy-Pdf-Sha256": sha256,
            "X-Agentopsy-Pdf-Draft": "1" if borrador else "0",
        },
    )
