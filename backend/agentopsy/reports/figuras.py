"""El ANEXO C del informe pericial: las figuras del caso, compuestas por Agentopsy.

El modelo redacta el informe entero salvo esto. Las dos figuras que el perito ya
tiene en la aplicación, la línea de tiempo del incidente y el grafo de relaciones
del caso, se DIBUJAN con los datos registrados, no se describen: un modelo que
«pinta» un grafo en prosa es exactamente la reconstrucción que el informe no
admite (FORENSIC INVARIANT 4). Así que el redactor (``writer.write_report``) pide
este anexo, lo añade después de las cuatro puertas de custodia y lo audita.

Tres decisiones:

- **Se congelan en el documento.** Cada figura viaja como un bloque ``figure``
  con su SVG dentro de las secciones, y por tanto dentro del contenido cuyo
  SHA-256 fija el almacén. Un informe firmado enseña para siempre las figuras
  que se firmaron, aunque el caso gane hallazgos o grafos al día siguiente;
  pintarlas al abrir el PDF haría que el mismo documento cambiase de figuras con
  el hash intacto.
- **Se componen a la vez que el material**, antes de llamar al modelo: el texto y
  las figuras de una revisión describen el MISMO estado del caso.
- **Nada se omite en silencio** (RULE 2). Sin eventos en el eje, el anexo dice por
  qué con el mismo mensaje que la vista; sin grafos, dice que no se han extraído
  y dónde se extraen; y si faltan hallazgos por extraer, cuántos.

``componer_anexo`` es lógica pura (RULE 3); ``figuras_del_caso`` es el cargador
que lee los almacenes, con las dependencias inyectables como ``build_material``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from agentopsy.cases import CaseManager, case_manager
from agentopsy.export_hoja import iso_utc_ahora
from agentopsy.findings.store import FindingStore, finding_store
from agentopsy.graph.figura import figura_del_caso
from agentopsy.graph.store import Graph, GraphStore, graph_store
from agentopsy.i18n import t
from agentopsy.mitre.coverage import CoverageStore, coverage_store
from agentopsy.reports.figura_cronologia import svg_linea_de_tiempo
from agentopsy.reports.figura_grafo import svg_grafo_del_caso
from agentopsy.reports.indice import NUM_ANEXO_FIGURAS, titulos
from agentopsy.timeline.hallazgos import assemble_findings_timeline


@dataclass(frozen=True)
class AnexoDeFiguras:
    """La sección del anexo C, lista para el almacén, y cuántos textos reescribió
    la tipografía del informe al componerla."""

    seccion: dict[str, Any]
    estilo_normalizado: int

    def resumen_auditable(self) -> list[dict[str, Any]]:
        """Qué figuras lleva el informe, con el SHA-256 de cada SVG: lo que queda
        en ``report_written`` para saber qué se dibujó sin guardar el dibujo dos
        veces."""
        return [
            {
                "kind": b["kind"],
                "title": b["title"],
                "sha256": hashlib.sha256(b["svg"].encode("utf-8")).hexdigest(),
                "chars": len(b["svg"]),
            }
            for b in self.seccion["blocks"]
            if b.get("t") == "figure"
        ]


def componer_anexo(
    *,
    case_id: str,
    case_name: str,
    compuesta_en: str,
    cronologia: dict[str, Any],
    grafos: Iterable[Graph],
    finding_ids: Iterable[str],
) -> AnexoDeFiguras:
    """El anexo C a partir de lo que el caso tiene registrado.

    ``cronologia`` es la línea de tiempo del incidente ya ensamblada
    (``timeline.hallazgos.assemble_findings_timeline``), ``grafos`` el último
    grafo de cada hallazgo y ``finding_ids`` los hallazgos del caso, para declarar
    los que no tienen grafo."""
    bloques: list[dict[str, Any]] = [
        {"t": "p", "text": t("figure.annex.intro")},
        {"t": "h3", "text": t("figure.annex.timelineHeading")},
    ]

    linea = svg_linea_de_tiempo(cronologia, case_name=case_name, compuesta_en=compuesta_en)
    if linea.partes:
        partes = len(linea.partes)
        for numero, svg in enumerate(linea.partes, 1):
            titulo = (
                t("figure.rail.title")
                if partes == 1
                else t("figure.rail.titlePart", part=numero, parts=partes)
            )
            bloques.append(
                {"t": "figure", "kind": "incident_timeline", "title": titulo, "svg": svg}
            )
    else:
        # Sin eventos en el eje el ensamblador SIEMPRE explica por qué.
        mensaje = cronologia.get("message")
        if not mensaje:
            raise ValueError("an incident timeline without events must say why")
        bloques.append({"t": "p", "text": mensaje})

    bloques.append({"t": "h3", "text": t("figure.annex.graphHeading")})
    grafos = list(grafos)
    figura = figura_del_caso(case_id, grafos)
    entidades = len(figura["nodos"]) + (
        figura["inventario"]["total"] if figura["inventario"] else 0
    )
    if entidades:
        bloques.append({
            "t": "figure",
            "kind": "case_graph",
            "title": t("figure.graph.title"),
            "svg": svg_grafo_del_caso(figura, case_name=case_name, compuesta_en=compuesta_en),
        })
    elif grafos:
        bloques.append({"t": "p", "text": t("figure.graph.empty", count=len(grafos))})
    else:
        bloques.append({"t": "p", "text": t("figure.graph.none")})

    con_grafo = {g.finding_id for g in grafos}
    hallazgos = list(dict.fromkeys(finding_ids))
    pendientes = [fid for fid in hallazgos if fid not in con_grafo]
    if pendientes and grafos:
        bloques.append({
            "t": "p",
            "text": t("figure.graph.pending", pending=len(pendientes), total=len(hallazgos)),
        })

    return AnexoDeFiguras(
        seccion={
            "num": NUM_ANEXO_FIGURAS,
            "title": titulos()[NUM_ANEXO_FIGURAS],
            "blocks": bloques,
        },
        estilo_normalizado=linea.titulos_normalizados,
    )


def figuras_del_caso(
    case_id: str,
    *,
    cases: CaseManager = case_manager,
    findings: FindingStore = finding_store,
    graphs: GraphStore = graph_store,
    coverage: CoverageStore = coverage_store,
) -> AnexoDeFiguras:
    """El anexo C del caso, leído de sus almacenes en este instante.

    Las dependencias son inyectables para los tests; en producción son los
    singletons (RULE 2 permite ``def f(dep=SINGLETON)``). ``KeyError`` si el caso
    no existe."""
    case = cases.load(case_id)
    hallazgos = findings.list(case_id)
    cronologia = assemble_findings_timeline(
        hallazgos, coverage.annotations_by_finding(case_id)
    )
    return componer_anexo(
        case_id=case_id,
        case_name=case.name,
        compuesta_en=iso_utc_ahora(),
        cronologia=cronologia,
        grafos=graphs.list_latest(case_id),
        finding_ids=[f.id for f in hallazgos],
    )


__all__ = ["AnexoDeFiguras", "componer_anexo", "figuras_del_caso"]
