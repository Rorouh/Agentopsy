"""Layer 4 — the INCIDENT timeline, built from the case's findings.

Not the chronology of the investigation (when the agent worked, which is
``builder.assemble_investigation_timeline``), but the chronology of what happened ON
THE INVESTIGATED DEVICE: the line a third party reads first and the one that becomes
section 3 of the pericial report.

The axis is ``Finding.observed_at``, the ARTIFACT's timestamp, and only that.
``created_at`` (when the agent recorded the finding) never substitutes for it: dating
an incident with the hour of the analysis would falsify it. It is the same rule the
report's index already states (``reports.indice``, section 3, "un hallazgo SIN
`observed_at` no entra en la línea de tiempo"), here on screen.

What cannot be placed on the axis is COUNTED and DECLARED, never dropped in silence
(CLAUDE.md RULE 2): ``sin_observed_at`` and ``no_parseable`` travel in the response
and are painted both in the view and inside the exported image. A finding that cannot
be situated is a fact about the case, not a leftover.

Pure logic (RULE 3); ``forensia.routers.timeline`` is a thin adapter over it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from forensia.cases import case_manager
from forensia.export_csv import export_basename, iso_utc_ahora
from forensia.findings.store import Finding, finding_store
from forensia.mitre import catalog
from forensia.mitre.coverage import coverage_store
from forensia.timeline.vocabulario import SEVERITY_LABEL, etiqueta

#: Cota de los valores literales de ``observed_at`` que no se pudieron leer y que se
#: devuelven para que el perito vea QUÉ se escribió. Se declara el recorte
#: (``no_parseable_truncado``) en vez de recortar en silencio.
MAX_VALORES_NO_PARSEABLES = 20

#: Qué es esta exportación, dentro del nombre del fichero. Distingue la figura del
#: incidente de la hoja del timeline de investigación (``timeline``), que es otro
#: objeto y no debe pisarla en la carpeta de descargas.
EXPORT_KIND = "timeline-incidente"


def _parse_observed_at(value: Any) -> datetime | None:
    """La marca del artefacto como ``datetime`` UTC; ``None`` si no se puede situar.

    Exige la zona EXPLÍCITA, y ahí se separa a propósito de
    ``builder._parse_iso_utc``, que sí trata una marca sin zona como UTC. La
    diferencia es de procedencia, no de gusto: el builder normaliza marcas que
    escribe AGENTOPSY (el audit log, ``created_at``), siempre en UTC por
    construcción, mientras que esto normaliza una marca que el modelo afirma sobre un
    dispositivo AJENO, cuyos artefactos (MFT, registro, EVTX) dan hora local. Suponer
    UTC ahí desplazaría el eje las horas que fuese y lo presentaría como dato
    verificado (RULE 2: sin zona declarada no hay zona).

    Los hallazgos escritos ANTES de que el store validara el campo siguen en disco y
    `list()` los reconstruye sin revalidar, así que esta rama sigue siendo alcanzable.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(timezone.utc)


def _dt_to_z(dt: datetime) -> str:
    """ISO-8601 UTC explícito, sin milisegundos: el eje se lee al segundo."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _tactic_names() -> dict[str, str]:
    """``tactic_id -> nombre en castellano`` de la semilla ATT&CK."""
    return {tactic.id: tactic.name_es for tactic in catalog.load().tactics}


def _mitre_of(technique_ids: list[str]) -> list[dict[str, Any]]:
    """Sitúa cada técnica en su táctica. Sin catálogo no hay invención (RULE 2).

    Una técnica que la semilla no conozca conserva su id y se queda SIN táctica: ni se
    adivina a cuál pertenece ni se la omite, porque el agente la propuso y omitirla
    ocultaría una correlación real.
    """
    tactics = _tactic_names()
    out: list[dict[str, Any]] = []
    for technique_id in technique_ids:
        try:
            technique = catalog.technique(technique_id)
        except KeyError:
            out.append({
                "technique_id": technique_id,
                "technique_name": None,
                "tactic_id": None,
                "tactic": None,
            })
            continue
        out.append({
            "technique_id": technique_id,
            "technique_name": technique.name,
            "tactic_id": technique.tactic_id,
            "tactic": tactics.get(technique.tactic_id),
        })
    return out


def assemble_findings_timeline(
    findings: list[Finding],
    annotations: dict[str, list[str]],
) -> dict[str, Any]:
    """Ensambla la línea de tiempo del incidente. Pura: no toca disco.

    ``annotations`` es ``finding_id -> [technique_id, …]`` tal y como lo devuelve
    ``CoverageStore.annotations_by_finding``: las técnicas que el agente ancló DESPUÉS
    con ``annotate_mitre``. Se fusionan con los ``mitre_hints`` del propio hallazgo
    porque son el mismo eje (propuesta del agente, nunca dictamen) y porque medido
    sobre los casos reales la mayoría de la correlación llega por esa segunda vía: sin
    fusionar, la figura saldría casi sin ATT&CK.
    """
    eventos: list[dict[str, Any]] = []
    sin_observed_at = 0
    valores_no_parseables: list[str] = []

    for finding in findings:
        observed_at = getattr(finding, "observed_at", None)
        if not observed_at:
            sin_observed_at += 1
            continue
        momento = _parse_observed_at(observed_at)
        if momento is None:
            valores_no_parseables.append(str(observed_at))
            continue

        tecnicas = list(finding.mitre_hints)
        for technique_id in annotations.get(finding.id, []):
            if technique_id not in tecnicas:
                tecnicas.append(technique_id)

        eventos.append({
            "finding_id": finding.id,
            "ts": _dt_to_z(momento),
            "_orden": momento,
            "title": finding.title,
            "severity": finding.severity,
            "severity_label": etiqueta(SEVERITY_LABEL, finding.severity),
            "evidence_id": finding.evidence_id,
            "run_id": finding.run_id,
            "mitre": _mitre_of(tecnicas),
        })

    # Orden cronológico ASCENDENTE. Sin desempate: `sorted` es estable, así que varios
    # hallazgos del MISMO instante (los hay: seis comparten el instante de adquisición
    # de la RAM en un caso real) conservan su orden de registro. Es una DECISIÓN, no
    # una casualidad: el desempate natural sería `created_at`, y esa fecha no entra en
    # este eje ni siquiera como criterio secundario.
    eventos.sort(key=lambda e: e["_orden"])
    for evento in eventos:
        del evento["_orden"]

    return {
        "eventos": eventos,
        "total_hallazgos": len(findings),
        "sin_observed_at": sin_observed_at,
        "no_parseable": len(valores_no_parseables),
        "no_parseable_valores": valores_no_parseables[:MAX_VALORES_NO_PARSEABLES],
        "no_parseable_truncado": len(valores_no_parseables) > MAX_VALORES_NO_PARSEABLES,
        "message": _mensaje(len(findings), eventos, sin_observed_at, len(valores_no_parseables)),
    }


def _mensaje(
    total: int, eventos: list[dict[str, Any]], sin_observed_at: int, no_parseable: int
) -> str | None:
    """Por qué el eje está vacío, en términos accionables. ``None`` si tiene eventos.

    Un eje vacío sin explicación sugiere que se midió algo y no salió nada; son dos
    situaciones distintas y cada una se dice por su nombre.
    """
    if eventos:
        return None
    if total == 0:
        return (
            "El caso no tiene hallazgos registrados todavía. La línea de tiempo del "
            "incidente se construye con ellos: analiza la evidencia desde "
            "Investigación y el agente los irá registrando."
        )
    partes = []
    if sin_observed_at:
        partes.append(
            f"{sin_observed_at} sin marca temporal del artefacto"
        )
    if no_parseable:
        partes.append(
            f"{no_parseable} con una marca que no se puede leer como fecha con zona"
        )
    sujeto = (
        "El único hallazgo del caso no se puede situar"
        if total == 1
        else f"Ninguno de los {total} hallazgos del caso se puede situar"
    )
    return (
        f"{sujeto} en el tiempo "
        f"({', '.join(partes)}). Un hallazgo entra en esta línea de tiempo por su "
        "observed_at, la hora del hecho en el dispositivo investigado; fecharlo con "
        "la hora del análisis falsearía el incidente, así que se queda fuera y se "
        "declara aquí."
    )


def build_findings_timeline(case_id: str) -> dict[str, Any]:
    """La línea de tiempo del incidente de un caso. ``KeyError`` si el caso no existe.

    Añade la PROCEDENCIA de la figura: el nombre del caso, el instante de la
    exportación y el nombre de fichero, este último por ``export_csv.export_basename``,
    la misma función que nombra las dos hojas de cálculo. La figura se dibuja en el
    navegador, pero su identidad se resuelve aquí: escribir una segunda versión del
    nombre en TypeScript serían dos nombres para la misma exportación.

    Por eso la marca temporal es la de ESTA respuesta y el cliente vuelve a pedirla al
    exportar: una figura que dice cuándo se exportó tiene que decir la verdad.
    """
    case = case_manager.load(case_id)
    findings = finding_store.list(case_id)
    annotations = coverage_store.annotations_by_finding(case_id)
    timeline = assemble_findings_timeline(findings, annotations)
    exported_at = iso_utc_ahora()
    return {
        **timeline,
        "case_name": case.name,
        "exported_at": exported_at,
        "export_basename": export_basename(
            case.name, EXPORT_KIND, exported_at=exported_at
        ),
    }


__all__ = [
    "MAX_VALORES_NO_PARSEABLES",
    "assemble_findings_timeline",
    "build_findings_timeline",
]
