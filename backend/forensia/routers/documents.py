"""Superficie HTTP de documentos / informes. Adaptador fino sobre
``forensia.reports`` (RULE 3). Todas las escrituras exigen el token de sesión
(SECURITY INVARIANT 3); el checkeo de origen/host es del middleware.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from forensia.reports import document_store
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
