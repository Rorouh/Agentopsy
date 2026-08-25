"""Superficie HTTP de los grafos de relaciones. Adaptador fino sobre
``forensia.graph`` (RULE 3): aquí no se valida un grafo ni se funde nada.

- ``POST …/graphs/extract`` lanza la extracción como JOB de fondo y devuelve el
  ``job_id`` al momento. Cerrar la pestaña no aborta nada, y el lote no muere en
  el primer rechazo (ver ``forensia.graph.lote``).
- ``GET …/graphs/jobs`` y ``…/graphs/jobs/{id}`` dejan que la vista se reenganche
  al montarse, como ya hacen el informe y el registro de evidencia.
- ``GET …/graphs`` la ficha del último grafo de cada hallazgo, con la previsión
  de coste de extraer los que faltan.
- ``GET …/graphs/case`` el grafo del CASO, fundido, con su geometría.
- ``GET …/graphs/{finding_id}`` el grafo de un hallazgo, con su geometría y la
  procedencia VERIFICADA del hallazgo del que salió.

RULE 2 en las tres puertas: sin ejecutor seleccionado, 422 nombrando los válidos;
ejecutor inutilizable, 503 con la razón accionable (que nombra el comando de
login); ``finding_ids`` es obligatorio y explícito, nunca «los que falten»
deducido por el servidor.
"""

from __future__ import annotations

from typing import Any, Callable

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from forensia.i18n import t, traducir_excepcion
from forensia.agent.jobs import job_registry
from forensia.audit.log import AuditLog
from forensia.cases.manager import case_manager
from forensia.config import config
from forensia.executors import (
    EXECUTOR_IDS,
    MODEL_CONFIG_KEY,
    REASONING_CONFIG_KEY,
    get_executor,
)
from forensia.export_hoja import export_basename, iso_utc_ahora
from forensia.findings import finding_store
from forensia.graph.fusion import merge_case_graph
from forensia.graph.layout import ALTO, ANCHO, layout_caso, layout_hallazgo
from forensia.graph.lote import extraer_lote
from forensia.graph.store import graph_store
from forensia.security import require_token

router = APIRouter()

#: ``kind`` del job en el registro compartido, para que la vista distinga sus
#: jobs de los del informe y los del análisis.
GRAPH_JOB_KIND = "graph"

#: ``kind`` con el que se nombra cada figura al exportarla. La misma función que
#: nombra las dos hojas de cálculo (``export_hoja.export_basename``), para que dos
#: exportaciones del mismo caso no se pisen en la carpeta de descargas y para que
#: la identidad de la figura la resuelva el servidor, no el navegador.
EXPORT_KIND_CASO = "grafo-caso"
EXPORT_KIND_HALLAZGO = "grafo-hallazgo"

#: La etiqueta que acompaña a todo grafo en toda superficie. El grafo es una
#: PROPUESTA del modelo sobre el texto de un hallazgo, no un hecho verificado
#: como un hash o un argv auditado, y esa distinción viaja con el dato, no solo
#: en la maqueta de la vista.
#: El aviso viaja DENTRO de la figura exportada, así que se resuelve por
#: petición: una imagen que se adjunta a un informe se lee en el idioma del
#: informe. La clave vive en el catálogo (`graph.proposalNotice`).
def aviso_propuesta() -> str:
    return t("graph.proposalNotice")


def _case_or_404(case_id: str):
    try:
        return case_manager.load(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=traducir_excepcion(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc


class ExtractRequest(BaseModel):
    #: Los hallazgos cuyo grafo hay que extraer. OBLIGATORIO y explícito: el
    #: servidor no deduce «todos» ni «los que falten» (RULE 2). La vista manda la
    #: lista que el perito ha elegido.
    finding_ids: list[str] | None = None
    #: Ejecutor seleccionado por el operador. Sin él, 422.
    executor: str | None = None


@router.get("/api/cases/{case_id}/graphs", dependencies=[Depends(require_token)])
def list_graphs(case_id: str) -> dict[str, Any]:
    """Ficha del último grafo de cada hallazgo, y los que faltan por extraer."""
    _case_or_404(case_id)
    findings = finding_store.list(case_id)
    grafos = {g.finding_id: g for g in graph_store.list_latest(case_id)}
    pendientes = [f.id for f in findings if f.id not in grafos]
    return {
        "case_id": case_id,
        "aviso": aviso_propuesta(),
        "grafos": [
            {
                **grafos[f.id].ficha(),
                "title": f.title,
                "revisiones": graph_store.revisions(case_id, f.id),
            }
            for f in findings
            if f.id in grafos
        ],
        "pendientes": pendientes,
        "hallazgos": [{"id": f.id, "title": f.title} for f in findings],
    }


@router.get("/api/cases/{case_id}/graphs/case", dependencies=[Depends(require_token)])
def case_graph(case_id: str) -> dict[str, Any]:
    """El grafo del CASO: los grafos de los hallazgos fundidos por entidad.

    No gasta ninguna llamada al modelo: funde lo ya extraído. Un caso sin grafos
    devuelve las listas vacías con el recuento a cero, no un error: no haber
    extraído todavía no es un fallo."""
    case = _case_or_404(case_id)
    grafos = graph_store.list_latest(case_id)
    fundido = merge_case_graph([
        {"finding_id": g.finding_id, "nodos": g.nodos, "relaciones": g.relaciones}
        for g in grafos
    ])
    titulos = {f.id: f.title for f in finding_store.list(case_id)}
    exported_at = iso_utc_ahora()
    return {
        "case_id": case_id,
        "case_name": case.name,
        "aviso": aviso_propuesta(),
        "exported_at": exported_at,
        "export_basename": export_basename(
            case.name, EXPORT_KIND_CASO, exported_at=exported_at
        ),
        "nodos": layout_caso(case_id, fundido["nodos"], fundido["relaciones"]),
        "relaciones": fundido["relaciones"],
        "hallazgos": [
            {"id": fid, "title": titulos.get(fid, "")} for fid in fundido["hallazgos"]
        ],
        "lienzo": {"ancho": ANCHO, "alto": ALTO},
    }


@router.post("/api/cases/{case_id}/graphs/extract", dependencies=[Depends(require_token)])
def start_extraction(case_id: str, req: ExtractRequest) -> dict[str, Any]:
    """Lanza la extracción de los hallazgos indicados como job de fondo.

    Valida rápido y en este hilo (caso, hallazgos, ejecutor) para fallar antes de
    encolar nada; la extracción corre desacoplada de la petición."""
    case = _case_or_404(case_id)

    if not req.finding_ids:
        raise HTTPException(
            status_code=422,
            detail=t("api.findingIdsRequired"),
        )

    por_id = {f.id: f for f in finding_store.list(case_id)}
    desconocidos = [fid for fid in req.finding_ids if fid not in por_id]
    if desconocidos:
        raise HTTPException(
            status_code=404,
            detail=t("api.unknownFindings", case_id=case_id, ids=", ".join(desconocidos)),
        )
    # Se respeta el orden en que los pidió el operador, sin repetir.
    pedidos: list[str] = []
    for fid in req.finding_ids:
        if fid not in pedidos:
            pedidos.append(fid)
    findings = [por_id[fid] for fid in pedidos]

    executor_id = req.executor or config.get("DEFAULT_EXECUTOR")
    if not executor_id:
        raise HTTPException(
            status_code=422,
            detail=t("api.graphExecutorRequired", ids=" | ".join(EXECUTOR_IDS)),
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
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc

    model = config.get(MODEL_CONFIG_KEY[executor.id])
    reasoning_key = REASONING_CONFIG_KEY.get(executor.id)
    reasoning_effort = config.get(reasoning_key) if reasoning_key else None

    def _work(
        emit: Callable[[dict[str, Any]], None],
        should_cancel: Callable[[], bool],
    ) -> dict[str, Any]:
        return extraer_lote(
            case_id, findings,
            executor=executor, audit=audit, store=graph_store,
            model=model, reasoning_effort=reasoning_effort,
            emit=emit, should_cancel=should_cancel,
        )

    job = job_registry.submit(
        case_id,
        GRAPH_JOB_KIND,
        _work,
        meta={
            "case_name": case.name,
            "solicitados": len(findings),
            "executor": {"id": executor.id, "name": executor.name, "local": executor.is_local},
        },
    )
    return job.public()


@router.get("/api/cases/{case_id}/graphs/jobs", dependencies=[Depends(require_token)])
def list_graph_jobs(case_id: str) -> dict[str, Any]:
    """Los jobs de extracción del caso, recientes primero, para reengancharse."""
    _case_or_404(case_id)
    jobs = [j for j in job_registry.list_for_case(case_id) if j.get("kind") == GRAPH_JOB_KIND]
    return {"case_id": case_id, "jobs": jobs}


@router.get(
    "/api/cases/{case_id}/graphs/jobs/{job_id}", dependencies=[Depends(require_token)]
)
def get_graph_job(case_id: str, job_id: str, since: int = 0) -> dict[str, Any]:
    """Sondeo de un job de extracción: running / done (con el parte) / error."""
    snap = job_registry.snapshot(job_id, since=max(0, since))
    if snap is None:
        raise HTTPException(status_code=404, detail=t("api.jobNotFound", job_id=job_id))
    if snap.get("case_id") != case_id:
        raise HTTPException(
            status_code=404,
            detail=t("api.jobNotInCase", job_id=job_id, case_id=case_id),
        )
    return snap


@router.get(
    "/api/cases/{case_id}/graphs/{finding_id}", dependencies=[Depends(require_token)]
)
def get_graph(case_id: str, finding_id: str, revision: int | None = None) -> dict[str, Any]:
    """El grafo de UN hallazgo, con su geometría y la procedencia del hallazgo.

    ``procedencia`` es la mitad VERIFICADA de la ficha (run_id, herramienta,
    SHA-256 del artefacto, ``observed_at``): sale del hallazgo registrado, no del
    modelo, y la vista la separa visualmente de lo propuesto."""
    case = _case_or_404(case_id)
    try:
        g = graph_store.get(case_id, finding_id, revision)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=traducir_excepcion(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc

    finding = next((f for f in finding_store.list(case_id) if f.id == finding_id), None)
    exported_at = iso_utc_ahora()
    return {
        "case_id": case_id,
        "case_name": case.name,
        "exported_at": exported_at,
        "export_basename": export_basename(
            case.name, EXPORT_KIND_HALLAZGO, exported_at=exported_at
        ),
        "finding_id": finding_id,
        "revision": g.revision,
        "revisiones": graph_store.revisions(case_id, finding_id),
        "created_at": g.created_at,
        "sha256": g.sha256,
        "extraction": g.extraction,
        "aviso": aviso_propuesta(),
        "nodos": layout_hallazgo(finding_id, g.nodos, g.relaciones),
        "relaciones": g.relaciones,
        "lienzo": {"ancho": ANCHO, "alto": ALTO},
        "hallazgo": None if finding is None else {
            "id": finding.id,
            "title": finding.title,
            "summary": finding.summary,
            "severity": finding.severity,
        },
        "procedencia": None if finding is None else {
            "run_id": finding.run_id,
            "tool_id": finding.tool_id,
            "evidence_id": finding.evidence_id,
            "artifact_sha256": finding.artifact_sha256,
            "observed_at": finding.observed_at,
            "created_at": finding.created_at,
        },
    }
