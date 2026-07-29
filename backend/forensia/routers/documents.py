"""Superficie HTTP de documentos / informes. Adaptador fino sobre
``forensia.reports`` (RULE 3). Todas las escrituras exigen el token de sesión
(SECURITY INVARIANT 3); el checkeo de origen/host es del middleware.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from forensia.audit import AuditLog
from forensia.cases import case_manager
from forensia.config import config
from forensia.executors import MODEL_CONFIG_KEY, get_executor
from forensia.executors.base import ExecutorError
from forensia.reports import build_pericial_report, document_store
from forensia.reports.humanize import ReportHumanizeError, humanize_report
from forensia.reports.pdf import render_pdf
from forensia.security import require_token

router = APIRouter()


class CreateDocumentRequest(BaseModel):
    title: str
    type: str
    summary: str = ""
    evidence_id: str | None = None
    version: str | None = None
    author: str | None = None
    sections: list[dict[str, Any]] = []


class GenerateReportRequest(BaseModel):
    """Datos opcionales del perito para la síntesis del informe pericial. Todos
    son opcionales: en su ausencia el informe usa el examinador del caso como
    perito (no un default silencioso de negocio — es el dato autoritativo del
    caso). El cuerpo del informe se sintetiza de los hallazgos / custodia / MITRE
    reales (forensia.reports.build_pericial_report) con la narrativa
    determinista de forensia.reports.narrative.

    ``executor``: si el operador lo selecciona, la prosa del resumen ejecutivo y
    de las conclusiones se reescribe además a través de ese ejecutor y se valida
    contra los referentes del informe (forensia.reports.humanize). SIN valor no
    hay llamada a ningún modelo — la redacción determinista es el producto, no
    un fallback (RULE 2: nada sale hacia un ejecutor que el operador no pidió).
    """

    name: str | None = None
    colegiado: str | None = None
    organization: str | None = None
    email: str | None = None
    version: str | None = None
    executor: str | None = None


def _svc_error(exc: Exception) -> HTTPException:
    if isinstance(exc, KeyError):
        return HTTPException(status_code=404, detail=str(exc).strip('"'))
    return HTTPException(status_code=422, detail=str(exc))


@router.get("/api/cases/{case_id}/documents", dependencies=[Depends(require_token)])
def list_documents(case_id: str) -> list[dict[str, Any]]:
    """Fichas de los documentos del caso (sin el cuerpo). `[]` si no hay."""
    try:
        return [d.metadata() for d in document_store.list(case_id)]
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc


@router.get("/api/cases/{case_id}/documents/{doc_id}", dependencies=[Depends(require_token)])
def get_document(case_id: str, doc_id: str) -> dict[str, Any]:
    try:
        return asdict(document_store.get(case_id, doc_id))
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc


@router.post("/api/cases/{case_id}/documents", dependencies=[Depends(require_token)])
def create_document(case_id: str, req: CreateDocumentRequest) -> dict[str, Any]:
    try:
        return asdict(document_store.create(case_id, req.model_dump()))
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc


@router.post(
    "/api/cases/{case_id}/documents/generate",
    dependencies=[Depends(require_token)],
)
def generate_report(case_id: str, req: GenerateReportRequest) -> dict[str, Any]:
    """Sintetiza el informe pericial del caso (resumen ejecutivo narrativo +
    metadatos + custodia + metodología + relato de la investigación + hallazgos
    + correlación MITRE + conclusiones) y lo persiste como documento (estado
    ``draft``). Con ``executor`` seleccionado, la prosa de §1/§8 pasa además por
    la redacción humanizada VALIDADA (forensia.reports.humanize); un ejecutor no
    disponible o una prosa que no valida son errores accionables — nunca se
    persiste prosa sin validar (RULE 2). El PDF se obtiene después con el
    endpoint ``…/pdf``. Falla fuerte si el caso no existe."""
    perito = req.model_dump(exclude_none=True, exclude={"executor"})
    try:
        data = build_pericial_report(case_id, perito)
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc

    if req.executor:
        try:
            executor = get_executor(req.executor)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        availability = executor.is_available()
        if not availability.available:
            raise HTTPException(status_code=503, detail=availability.reason)
        try:
            audit = AuditLog(case_manager.case_dir(case_id) / "audit.jsonl")
        except (KeyError, ValueError) as exc:
            raise _svc_error(exc) from exc
        # Modelo elegido por el operador para ese ejecutor (Settings), igual que
        # en /api/agent/query — nunca uno inventado aquí (RULE 2).
        model = config.get(MODEL_CONFIG_KEY[executor.id])
        try:
            data = humanize_report(
                case_id, data, executor=executor, audit=audit, model=model
            )
        except ReportHumanizeError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ExecutorError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    try:
        return asdict(document_store.create(case_id, data))
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
