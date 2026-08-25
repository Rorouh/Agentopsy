"""Exportaciones de la cobertura ATT&CK de un caso — CSV y ATT&CK Navigator layer.

El perito necesita llevarse los datos fuera de Agentopsy. Dos formatos, ambos
**derivados de la cobertura real** (`CoverageStore.coverage`): las propuestas del
agente (eje 1) y los dictámenes del perito (eje 2), sin fundirlos.

- ``coverage_to_hoja`` — una HOJA de cálculo real (``forensia.export_hoja``: un
  `.xlsx` con bloque de procedencia y una línea vacía antes de la tabla) con una
  fila por técnica evaluada, propuesta, dictaminada o ambas. Los nombres/tácticas salen del
  catálogo Enterprise (``forensia.mitre.catalog``); NO se inventan. Si el
  catálogo Enterprise no está montado, la columna del nombre/táctica degrada a
  vacío y el id queda como única referencia honesta (RULE 2: nunca una lista
  "por defecto").
- ``coverage_to_navigator_layer`` — un *layer* del **MITRE ATT&CK Navigator**
  (formato de layer **4.5**, ``domain: "enterprise-attack"``) que colorea las
  técnicas propuestas/adjudicadas para cargarlo en el Navigator oficial. Emitimos
  sólo ``versions.layer`` (la versión del formato que producimos): no fabricamos una
  versión de ATT&CK ni de Navigator que no conocemos (RULE 2).

Puro (CLAUDE.md RULE 3): sin I/O ni acceso a disco. El router pasa las entradas de
``CoverageStore.coverage`` y devuelve el texto/JSON con las cabeceras de descarga.
"""

from __future__ import annotations

from typing import Any

from forensia.i18n import current_lang, t
from forensia.export_hoja import build_workbook, iso_utc_ahora, unir
from forensia.mitre import catalog

#: Versión del formato de *layer* del ATT&CK Navigator que emitimos. Es lo único que
#: declaramos en ``versions``: no fingimos una versión de ATT&CK/Navigator concreta.
NAVIGATOR_LAYER_VERSION = "4.5"

#: Colores del layer por estado (hex, como espera el Navigator). Dos ejes que no se
#: funden: el dictamen del perito manda el color; si no hay dictamen pero el agente la
#: propuso, se pinta como "propuesta".
_VERDICT_COLORS: dict[str, str] = {
    "confirmada": "#c1121f",  # rojo — confirmada por el perito
    "sospechosa": "#e08a00",  # ámbar — en sospecha
    "descartada": "#8a8f98",  # gris — descartada tras revisión
}
_PROPOSED_COLOR = "#2f6fed"  # azul — propuesta del agente, sin dictaminar

_VERDICT_LABEL: dict[str, str] = {
    "confirmada": "Confirmada",
    "sospechosa": "Sospechosa",
    "descartada": "Descartada",
}

#: Lo que se escribe en la columna del veredicto cuando el perito no ha
#: dictaminado. No es lo mismo que «ausente»: la técnica está en la hoja porque
#: el análisis la propuso, y sigue sin evaluar.
#: Constante del castellano, conservada por compatibilidad con lo ya exportado.
#: Quien escribe una celda usa `sin_dictamen()`, que la resuelve en el idioma de
#: la hoja.
SIN_DICTAMEN = "No dictaminada"


def sin_dictamen() -> str:
    """Lo que dice la columna de veredicto cuando el perito no ha dictaminado."""
    return t("mitreSheet.noVerdict")

#: Cabecera de la tabla de cobertura. Orden estable, es un contrato que los tests
#: fijan. En castellano porque la hoja la lee una persona (el canal de máquina es
#: el layer del Navigator, que no cambia). Las dos primeras columnas de datos son
#: las que identifican la técnica; el motivo del veredicto va al final porque es
#: la única de longitud libre y arrastraría el ancho de las demás.
#: Las CLAVES de la cabecera, en su orden estable (el orden es el contrato que
#: los tests fijan). El rótulo lo resuelve `hoja_header()` en el idioma de la
#: hoja; el canal de MÁQUINA (el layer del Navigator) no cambia.
HOJA_HEADER_KEYS: tuple[str, ...] = (
    "tlSheet.col.n",
    "mitreSheet.col.techniqueId",
    "mitreSheet.col.technique",
    "mitreSheet.col.tacticId",
    "mitreSheet.col.tactic",
    "mitreSheet.col.cell",
    "mitreSheet.col.proposed",
    "mitreSheet.col.proposers",
    "mitreSheet.col.verdict",
    "mitreSheet.col.verdictDate",
    "mitreSheet.col.findingIds",
    "mitreSheet.col.rationale",
)


def hoja_header() -> tuple[str, ...]:
    """La cabecera de la tabla, en el idioma de la hoja."""
    return tuple(t(k) for k in HOJA_HEADER_KEYS)


def _tactic_names() -> dict[str, str]:
    """``tactic_id -> nombre`` desde el catálogo Enterprise. Vacío si no está montado."""
    ent = catalog.load_enterprise()
    # El nombre OFICIAL de una táctica ATT&CK es el inglés; el castellano es la
    # traducción del catálogo. La hoja usa el del idioma en que se exporta.
    if current_lang() == "es":
        return {tac.id: (tac.name_es or tac.name) for tac in ent.tactics}
    return {tac.id: tac.name for tac in ent.tactics}


def _technique_name(technique_id: str) -> str:
    """Nombre de la técnica desde Enterprise; ``""`` si no se puede resolver (degrada
    al id, que ya viaja en su propia columna — RULE 2, nunca se inventa)."""
    if catalog.enterprise_is_known(technique_id):
        return catalog.enterprise_technique(technique_id).name
    return ""


def _findings_for(entry: dict[str, Any]) -> list[str]:
    """Hallazgos que sostienen la fila: los que la propusieron (eje 1) más los que el
    perito ancló a su dictamen (eje 2), sin duplicar y conservando el orden."""
    out: list[str] = []
    for fid in list(entry.get("proposed_by") or []) + list(
        entry.get("related_finding_ids") or []
    ):
        if isinstance(fid, str) and fid not in out:
            out.append(fid)
    return out


def coverage_to_hoja(
    entries: list[dict[str, Any]],
    *,
    case_id: str = "",
    case_name: str = "",
    exported_at: str | None = None,
) -> bytes:
    """La hoja de cobertura del caso: una fila por técnica evaluada.

    ``entries`` son las entradas de :meth:`CoverageStore.coverage`. Con **cero**
    técnicas evaluadas devuelve la procedencia y la cabecera sin filas (una hoja
    honesta de 0 filas, nunca un error), y el bloque de procedencia lo dice.

    Los dos ejes viajan en columnas SEPARADAS y nunca se funden: «Propuesta por el
    análisis» es una sugerencia con procedencia, «Veredicto del perito» es lo
    único pericial. Sin dictamen la columna dice :data:`SIN_DICTAMEN`, no queda
    vacía: en blanco se leería como «no aplica», y lo que significa es que está
    pendiente de evaluar.

    ``exported_at`` es inyectable para que los tests fijen la marca temporal; sin
    él, la de ahora.
    """
    tactic_names = _tactic_names()
    confirmadas = sum(1 for e in entries if e.get("status") == "confirmada")
    sospechosas = sum(1 for e in entries if e.get("status") == "sospechosa")
    descartadas = sum(1 for e in entries if e.get("status") == "descartada")
    propuestas = sum(1 for e in entries if e.get("proposed_by"))

    procedencia: list[tuple[str, str]] = [
        ("Agentopsy", t("mitreSheet.prov.title")),
        (t("tlSheet.prov.case"), case_name),
        (t("tlSheet.prov.caseId"), case_id),
        (t("tlSheet.prov.exported"), exported_at or iso_utc_ahora()),
        (t("mitreSheet.prov.techniques"), str(len(entries))),
        (t("mitreSheet.prov.proposed"), str(propuestas)),
        (
            t("mitreSheet.prov.adjudicated"),
            t(
                "mitreSheet.prov.adjudicatedValue",
                confirmed=confirmadas,
                suspected=sospechosas,
                discarded=descartadas,
            ),
        ),
        (t("tlSheet.prov.howToRead"), t("mitreSheet.prov.howToReadValue")),
    ]

    filas: list[list[Any]] = []
    for n, entry in enumerate(entries, start=1):
        technique_id = str(entry.get("technique_id", ""))
        tactic_id = entry.get("tactic_id") or ""
        proposed = list(entry.get("proposed_by") or [])
        status = entry.get("status")
        filas.append([
            n,
            technique_id,
            _technique_name(technique_id),
            tactic_id,
            tactic_names.get(tactic_id, "") if tactic_id else "",
            catalog.enterprise_display_id(technique_id) if technique_id else "",
            bool(proposed),
            len(proposed),
            _VERDICT_LABEL.get(status, status) if status else sin_dictamen(),
            entry.get("adjudicated_at") or "",
            unir(_findings_for(entry)),
            entry.get("rationale") or "",
        ])
    return build_workbook(
        procedencia=procedencia,
        cabecera=hoja_header(),
        filas=filas,
        titulo=t("mitreSheet.tabTitle"),
    )


def _navigator_comment(entry: dict[str, Any]) -> str:
    """Comentario de la celda del Navigator: dictamen del perito (con su motivo) y/o la
    propuesta del agente. Los dos ejes conviven, nunca se confunden."""
    parts: list[str] = []
    status = entry.get("status")
    if status:
        label = _VERDICT_LABEL.get(status, status)
        rationale = (entry.get("rationale") or "").strip()
        parts.append(f"Dictamen del perito: {label}" + (f", {rationale}" if rationale else ""))
    proposed = entry.get("proposed_by") or []
    if proposed:
        parts.append(f"Propuesta del agente: {len(proposed)} hallazgo(s) [{', '.join(proposed)}]")
    return "\n".join(parts)


def coverage_to_navigator_layer(
    entries: list[dict[str, Any]],
    *,
    case_id: str,
    case_name: str | None = None,
) -> dict[str, Any]:
    """Construye un *layer* del ATT&CK Navigator (formato 4.5, dominio
    ``enterprise-attack``) coloreando las técnicas propuestas/adjudicadas del caso.

    Cada técnica se pinta en su **celda Enterprise** (la técnica padre): la cobertura
    ya trae ``technique_id`` a nivel Enterprise. El color lo manda el dictamen del
    perito; sin dictamen pero con propuesta del agente, se pinta como "propuesta". Con
    **cero** técnicas evaluadas el layer sale válido y sin celdas coloreadas (honesto).
    """
    techniques: list[dict[str, Any]] = []
    for entry in entries:
        technique_id = str(entry.get("technique_id", ""))
        if not technique_id:
            continue
        display_id = catalog.enterprise_display_id(technique_id)
        status = entry.get("status")
        if status and status in _VERDICT_COLORS:
            color = _VERDICT_COLORS[status]
        elif entry.get("proposed_by"):
            color = _PROPOSED_COLOR
        else:
            # Ni dictamen coloreable (p. ej. un estado retirado) ni propuesta: no se pinta.
            continue
        techniques.append({
            "techniqueID": display_id,
            "color": color,
            "comment": _navigator_comment(entry),
            "enabled": True,
            "metadata": [],
            "showSubtechniques": False,
        })

    name = f"Agentopsy, {case_name}" if case_name else f"Agentopsy, caso {case_id}"
    return {
        "name": name[:255],
        "versions": {"layer": NAVIGATOR_LAYER_VERSION},
        "domain": "enterprise-attack",
        "description": t(
            "mitreSheet.layerDescription", case=case_name or case_id
        ),
        "techniques": techniques,
        "legendItems": [
            {"label": "Confirmada (perito)", "color": _VERDICT_COLORS["confirmada"]},
            {"label": "Sospechosa (perito)", "color": _VERDICT_COLORS["sospechosa"]},
            {"label": "Descartada (perito)", "color": _VERDICT_COLORS["descartada"]},
            {"label": "Propuesta (agente)", "color": _PROPOSED_COLOR},
        ],
        "metadata": [
            {"name": "case_id", "value": case_id},
            {"name": "generated_by", "value": "Agentopsy"},
        ],
        "showTacticRowBackground": False,
        "hideDisabled": False,
    }
