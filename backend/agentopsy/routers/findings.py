"""Per-case findings HTTP surface. Thin adapter over agentopsy.findings.store.

The contract MIRRORS the store's, field for field. It used to drift: the REST
body carried a subset of what the store persisted, so a field the agent could
write was silently unreachable over HTTP and a client that sent it lost it
(auditoría 2026-09-07, F03). Provenance is validated in the DOMAIN
(``agentopsy.findings.procedencia``), so both write paths get the same policy:
this router adds no rule of its own and skips none.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from agentopsy.findings.store import finding_store
from agentopsy.i18n import traducir_excepcion
from agentopsy.security import require_token
from agentopsy.toolkit.usage import tool_usage

router = APIRouter()


class Localizador(BaseModel):
    """Dónde, dentro del artefacto, está lo que el hallazgo afirma."""

    tipo: str
    desde: int | None = None
    hasta: int | None = None
    valor: str | None = None


class Referencia(BaseModel):
    """Una FUENTE del hallazgo. Espejo de ``agentopsy.findings.procedencia``.

    Solo ``run_id`` es obligatorio: los demás campos, cuando la relación es
    inequívoca, se completan DESDE EL REGISTRO (el manifiesto de la ejecución),
    nunca eligiendo un candidato. Lo que se declare tiene que casar.
    """

    run_id: str
    evidence_id: str | None = None
    tool_id: str | None = None
    artefacto: str | None = None
    relpath: str | None = None
    sha256: str | None = None
    localizador: Localizador | None = None
    extracto: str | None = None


class AppendFindingRequest(BaseModel):
    title: str
    summary: str
    severity: str
    evidence_id: str | None = None
    tool_id: str | None = None
    run_id: str | None = None
    #: Técnicas ATT&CK que sostiene el hallazgo. Enum cerrada validada contra la
    #: semilla en agentopsy.findings.store — la ruta HTTP y la del agente comparten
    #: el mismo contrato, no pueden divergir.
    mitre_hints: list[str] = []
    #: Confianza calibrada (0..1) y marca del ARTEFACTO (ISO-8601 con zona).
    confidence: float | None = None
    observed_at: str | None = None
    #: Procedencia de artefacto en su forma histórica. La completa viaja en
    #: ``references``; se conservan las dos porque un cliente antiguo sigue
    #: mandando esta y su hallazgo tiene que seguir registrándose.
    artifact_sha256: str | None = None
    #: ``afirmacion`` | ``descarte`` | ``limitacion``.
    finding_kind: str | None = None
    #: Qué se examinó, con qué herramienta y con qué límite. Obligatorio en un
    #: descarte y en una limitación.
    alcance_examinado: str | None = None
    #: Las fuentes verificadas del hallazgo (contrato tipado de citas).
    references: list[Referencia] | None = None


class ReviseFindingRequest(AppendFindingRequest):
    """Una REVISIÓN de un hallazgo: mismo contenido más el motivo, obligatorio.

    No sobrescribe la revisión anterior, que sigue siendo inspeccionable: un
    informe que citó la revisión 2 tiene que seguir apuntando a lo que citó.
    """

    motivo_revision: str


def _svc_error(exc: Exception) -> HTTPException:
    if isinstance(exc, KeyError):
        return HTTPException(status_code=404, detail=traducir_excepcion(exc).strip('"'))
    return HTTPException(status_code=422, detail=traducir_excepcion(exc))


@router.get(
    "/api/cases/{case_id}/findings",
    dependencies=[Depends(require_token)],
)
def list_findings(case_id: str) -> list[dict[str, Any]]:
    """La revisión VIGENTE de cada hallazgo del caso."""
    try:
        return [asdict(f) for f in finding_store.list(case_id)]
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc


@router.get(
    "/api/cases/{case_id}/findings/{finding_id}/revisions",
    dependencies=[Depends(require_token)],
)
def list_finding_revisions(case_id: str, finding_id: str) -> list[dict[str, Any]]:
    """TODAS las revisiones de un hallazgo, de la más antigua a la más nueva.

    Es lo que hace inspeccionable una corrección: un informe que citó la revisión
    2 sigue pudiendo enseñar exactamente qué decía.
    """
    try:
        revisiones = finding_store.revisions(case_id, finding_id)
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc
    if not revisiones:
        raise HTTPException(
            status_code=404,
            detail=f"finding {finding_id} not found in case {case_id}",
        )
    return [asdict(f) for f in revisiones]


@router.get(
    "/api/cases/{case_id}/findings/{finding_id}/sources",
    dependencies=[Depends(require_token)],
)
def resolve_finding_sources(
    case_id: str, finding_id: str, revision: int | None = None
) -> dict[str, Any]:
    """Abre las FUENTES de un hallazgo y devuelve qué se ve en cada una.

    Es lo que la interfaz necesita para «abrir la cita»: la evidencia, la
    ejecución, la herramienta, el artefacto, el localizador, el extracto y el
    estado de integridad. La resolución la hace el BACKEND a partir del id del
    hallazgo: el cliente nunca manda una ruta, y nada de lo que el modelo
    escribió se usa como enlace de confianza.

    La respuesta distingue las dos cosas que no se pueden confundir: la
    VALIDACIÓN TÉCNICA (los bytes son los que se registraron) y la REVISIÓN
    HUMANA (si el perito da por buena la interpretación). Lo primero lo dice
    ``estado``; lo segundo no lo dice esta ruta, porque no lo sabe.
    """
    try:
        return finding_store.sources(case_id, finding_id, revision=revision)
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc


@router.get(
    "/api/cases/{case_id}/tool-usage",
    dependencies=[Depends(require_token)],
)
def list_tool_usage(case_id: str) -> list[dict[str, Any]]:
    """Per-tool run counts for the case (Tools panel). Aggregated from audit.jsonl."""
    try:
        return tool_usage(case_id)
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc


def _payload(req: AppendFindingRequest) -> dict[str, Any]:
    """El cuerpo tal y como el almacén lo espera, sin campos vacíos inventados."""
    data = req.model_dump(exclude_none=True)
    if req.references is not None:
        data["references"] = [
            r.model_dump(exclude_none=True) for r in req.references
        ]
    return data


@router.post(
    "/api/cases/{case_id}/findings",
    dependencies=[Depends(require_token)],
)
def append_finding(case_id: str, req: AppendFindingRequest) -> dict[str, Any]:
    try:
        finding = finding_store.append(case_id, _payload(req), origin="rest")
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc
    return asdict(finding)


@router.post(
    "/api/cases/{case_id}/findings/{finding_id}/revise",
    dependencies=[Depends(require_token)],
)
def revise_finding(
    case_id: str, finding_id: str, req: ReviseFindingRequest
) -> dict[str, Any]:
    """Añade una revisión conservando la anterior (nunca la sobrescribe)."""
    try:
        finding = finding_store.revise(
            case_id, finding_id, _payload(req), origin="rest"
        )
    except (KeyError, ValueError) as exc:
        raise _svc_error(exc) from exc
    return asdict(finding)
