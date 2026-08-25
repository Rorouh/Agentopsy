"""Superficie HTTP de documentos / informes. Adaptador fino sobre
``forensia.reports`` (RULE 3). Todas las escrituras exigen el token de sesión
(SECURITY INVARIANT 3); el checkeo de origen/host es del middleware.

El informe pericial se emite en UN solo acto del operador: **finalizar la
investigación** (``POST …/documents/finalize``). No hay borrador automático al
cerrar un análisis, ni síntesis determinista, ni redacción "asistida" de unas
secciones sueltas — todo eso se retiró el 2026-07-30. El ejecutor que el operador
seleccionó redacta el informe completo (``forensia.reports.writer``) y Agentopsy
valida el índice, el modelo de bloques, los referentes del material y los
comandos auditados antes de persistir nada.

Redactar un informe entero es una llamada larga a un modelo (minutos), así que
corre DESACOPLADA de la petición HTTP en el registro de jobs compartido
(``forensia.agent.jobs``, el mismo que sirve al análisis del agente): el cliente
recibe un ``job_id`` al instante y lo sondea. Cerrar la pestaña no aborta la
redacción.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from forensia.i18n import t, traducir_excepcion
from forensia.agent.jobs import job_registry
from forensia.audit import AuditLog
from forensia.cases import case_manager
from forensia.config import config
from forensia.executors import (
    EXECUTOR_IDS,
    MODEL_CONFIG_KEY,
    REASONING_CONFIG_KEY,
    get_executor,
)
from forensia.findings.store import finding_store
from forensia.reports import document_store
from forensia.reports.pdf import render_pdf
from forensia.reports.writer import write_report
from forensia.security import require_token

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


def _svc_error(exc: Exception) -> HTTPException:
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
    try:
        return document_store.verify(case_id, doc_id)
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc


@router.post(
    "/api/cases/{case_id}/documents/{doc_id}/sign",
    dependencies=[Depends(require_token)],
)
def sign_document(case_id: str, doc_id: str) -> dict[str, Any]:
    try:
        return asdict(document_store.sign(case_id, doc_id))
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc


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
    """Genera el PDF real del documento (fpdf2). La web lo descarga con el token."""
    try:
        doc = document_store.get(case_id, doc_id)
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc
    pdf_bytes = render_pdf(doc)
    filename = f"{doc.id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
