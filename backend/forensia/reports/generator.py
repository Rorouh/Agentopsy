"""Síntesis del **informe pericial** desde los datos reales del caso.

Ensambla las ``sections`` (modelo de bloques de ``forensia.reports.store``) de un
informe pericial en formato "Murciélago" a partir de lo que YA existe en el caso
—nunca inventa nada (RULE 2)—:

- Metadatos del caso (``forensia.cases``: nombre, examinador, os_profile, fechas).
- Cadena de custodia por evidencia (``forensia.custody.build_custody_act``:
  sha256 baseline, tamaño, nivel de solo-lectura, verificación de la cadena hash).
- Metodología y herramientas empleadas (``forensia.toolkit.usage.tool_usage``).
- Hallazgos estructurados agrupados por severidad
  (``forensia.findings.store.finding_store``), cada uno como bloque ``finding``.
- Correlación MITRE ATT&CK (``forensia.mitre.coverage``): técnica ↔ hallazgos que
  la proponen y el veredicto del perito, sin fundir los dos ejes.

Lógica pura (RULE 3): no imprime, no pide por stdin, no toca la red. Devuelve el
``dict`` que ``DocumentStore.create`` valida y persiste; el router es un adaptador
fino que llama aquí y crea el documento. Un caso sin hallazgos produce un informe
HONESTO que lo dice —nunca uno vacío falso—; un caso inexistente falla fuerte
(``KeyError``), igual que ``CaseManager.load``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from forensia import __version__
from forensia.cases import CaseManager, case_manager
from forensia.custody import build_custody_act
from forensia.evidence import EvidenceManager, evidence_manager
from forensia.findings.store import FindingStore, finding_store
from forensia.mitre import catalog
from forensia.mitre.coverage import CoverageStore, coverage_store
from forensia.toolkit.usage import tool_usage

#: Orden de severidad de mayor a menor y su etiqueta en español para los grupos.
_SEV_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low")
_SEV_LABEL: dict[str, str] = {
    "critical": "Críticos",
    "high": "Altos",
    "medium": "Medios",
    "low": "Bajos",
}
#: Etiqueta del veredicto del perito para la tabla MITRE.
_ADJ_LABEL: dict[str | None, str] = {
    "confirmada": "Confirmada",
    "sospechosa": "Sospechosa",
    "descartada": "Descartada",
    None: "No dictaminada",
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _perito_str(perito: dict[str, Any] | None, key: str) -> str:
    if not perito:
        return ""
    value = perito.get(key)
    return value.strip() if isinstance(value, str) else ""


def _tactic_names() -> dict[str, str]:
    """``tactic_id -> nombre`` desde el catálogo Enterprise (para la tabla MITRE).

    Vacío si el catálogo no está montado — la tabla degrada al ``tactic_id`` sin
    inventar un nombre (RULE 2)."""
    try:
        return {t.id: (t.name_es or t.name) for t in catalog.load_enterprise().tactics}
    except Exception:  # noqa: BLE001 — el catálogo es opcional; nunca tumba el informe
        return {}


def build_pericial_report(
    case_id: str,
    perito: dict[str, Any] | None = None,
    *,
    cases: CaseManager = case_manager,
    evidence: EvidenceManager = evidence_manager,
    findings: FindingStore = finding_store,
    coverage: CoverageStore = coverage_store,
    usage_fn: Callable[[str], list[dict[str, Any]]] = tool_usage,
) -> dict[str, Any]:
    """Ensambla el ``dict`` de un informe pericial listo para ``DocumentStore.create``.

    ``perito`` es un mapa opcional con los datos del profesional (``name``,
    ``colegiado``, ``organization``, ``email``, ``version``). Las dependencias son
    inyectables para los tests; en producción son los singletons (RULE 2 permite
    ``def f(dep=SINGLETON)``). Falla fuerte (``KeyError`` / ``ValueError``) si el
    caso no existe o su id es inválido — nunca "el último" ni un placeholder.
    """
    case = cases.load(case_id)  # KeyError/ValueError si no existe o id inválido

    perito_name = _perito_str(perito, "name") or case.examiner
    version = _perito_str(perito, "version") or "v0.1"
    generated_at = _utc_now_iso()

    finding_list = findings.list(case_id)
    evidence_handles = evidence.list(case_id)
    coverage_entries = coverage.coverage(case_id)
    usage = usage_fn(case_id)

    sections: list[dict[str, Any]] = [
        _resumen_ejecutivo(case, finding_list, evidence_handles, coverage_entries),
        _datos_informe(case, perito, perito_name, version, generated_at),
        _cadena_custodia(case_id, evidence_handles, cases=cases, evidence=evidence),
        _metodologia(usage),
        _hallazgos(finding_list),
        _correlacion_mitre(coverage_entries),
        _conclusiones(case, finding_list, coverage_entries),
    ]

    summary = _summary_line(case, finding_list, evidence_handles, coverage_entries)

    return {
        "title": f"Informe pericial forense — {case.name}",
        "type": "pericial",
        "summary": summary,
        # Un informe pericial consolida TODAS las evidencias del caso, así que no se
        # ancla a un único evidence_id (a diferencia de un acta de una evidencia).
        "evidence_id": None,
        "version": version,
        "author": perito_name,
        "sections": sections,
    }


# ── secciones ─────────────────────────────────────────────────────────────────


def _sev_counts(finding_list: list[Any]) -> dict[str, int]:
    counts = {sev: 0 for sev in _SEV_ORDER}
    for f in finding_list:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def _summary_line(
    case: Any, finding_list: list[Any], evidence_handles: list[Any],
    coverage_entries: list[dict[str, Any]],
) -> str:
    n = len(finding_list)
    hallazgos = (
        "sin hallazgos registrados"
        if n == 0
        else f"{n} hallazgo{'s' if n != 1 else ''} estructurado{'s' if n != 1 else ''}"
    )
    return (
        f"Informe pericial del caso «{case.name}» "
        f"({len(evidence_handles)} evidencia{'s' if len(evidence_handles) != 1 else ''}, "
        f"{hallazgos}, {len(coverage_entries)} técnica"
        f"{'s' if len(coverage_entries) != 1 else ''} ATT&CK correlacionada"
        f"{'s' if len(coverage_entries) != 1 else ''})."
    )


def _resumen_ejecutivo(
    case: Any, finding_list: list[Any], evidence_handles: list[Any],
    coverage_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    counts = _sev_counts(finding_list)
    adjudicated = sum(1 for e in coverage_entries if e.get("status"))
    blocks: list[dict[str, Any]] = []

    perfil = case.os_profile or "sin determinar"
    blocks.append({
        "t": "p",
        "text": (
            f"El presente informe recoge el análisis forense post-mortem del caso "
            f"«{case.name}», con perfil de sistema operativo {perfil}, sobre "
            f"{len(evidence_handles)} evidencia(s) registrada(s) bajo cadena de "
            f"custodia verificada. El análisis fue conducido por {case.examiner}."
        ),
    })

    if finding_list:
        desglose = ", ".join(
            f"{counts[sev]} {_SEV_LABEL[sev].lower()}"
            for sev in _SEV_ORDER
            if counts[sev]
        )
        blocks.append({
            "t": "p",
            "text": (
                f"Se documentan {len(finding_list)} hallazgo(s) estructurado(s) "
                f"({desglose}). De las {len(coverage_entries)} técnica(s) MITRE "
                f"ATT&CK correlacionadas, {adjudicated} cuenta(n) con dictamen "
                f"pericial explícito."
            ),
        })
    else:
        blocks.append({
            "t": "p",
            "text": (
                "En el estado actual del caso NO se han registrado hallazgos "
                "estructurados. Este informe deja constancia honesta de ese hecho: "
                "no se afirma ningún resultado que la evidencia analizada no "
                "sostenga (RULE 2)."
            ),
        })

    return {"num": "1", "title": "Resumen ejecutivo", "blocks": blocks}


def _datos_informe(
    case: Any, perito: dict[str, Any] | None, perito_name: str, version: str,
    generated_at: str,
) -> dict[str, Any]:
    pairs: list[dict[str, str]] = [{"k": "Perito", "v": perito_name}]
    colegiado = _perito_str(perito, "colegiado")
    if colegiado:
        pairs.append({"k": "Nº de colegiado", "v": colegiado})
    organization = _perito_str(perito, "organization")
    if organization:
        pairs.append({"k": "Organización", "v": organization})
    email = _perito_str(perito, "email")
    if email:
        pairs.append({"k": "Contacto", "v": email})
    pairs.extend([
        {"k": "Identificador del caso", "v": case.id},
        {"k": "Nombre del caso", "v": case.name},
        {"k": "Examinador", "v": case.examiner},
        {"k": "Perfil de SO", "v": case.os_profile or "sin determinar"},
        {"k": "Origen del perfil", "v": case.os_profile_source or "—"},
        {"k": "Estado del caso", "v": case.status},
        {"k": "Apertura del caso", "v": case.created_at},
        {"k": "Emisión del informe", "v": generated_at},
        {"k": "Versión del informe", "v": version},
        {"k": "Herramienta", "v": f"FORENSIA {__version__}"},
    ])
    return {
        "num": "2",
        "title": "Datos del informe y del perito",
        "blocks": [{"t": "kv", "pairs": pairs}],
    }


def _cadena_custodia(
    case_id: str, evidence_handles: list[Any], *,
    cases: CaseManager, evidence: EvidenceManager,
) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = [{
        "t": "p",
        "text": (
            "Cada evidencia se ingirió a través de EvidenceManager, único dueño de "
            "la evidencia: hash SHA-256 baseline antes de exponer ningún handle, "
            "copia verificada y solo-lectura. Los valores siguientes se leen del "
            "baseline y del log de auditoría hash-encadenado, no se recalculan a "
            "mano (FORENSIC INVARIANTS 1-2 y 4)."
        ),
    }]

    if not evidence_handles:
        blocks.append({
            "t": "p",
            "text": (
                "No hay ninguna evidencia registrada en este caso. Sin evidencia "
                "bajo custodia no hay nada que peritar: el informe lo hace constar."
            ),
        })
        return {"num": "3", "title": "Cadena de custodia", "blocks": blocks}

    for handle in evidence_handles:
        act = build_custody_act(
            case_id, handle.evidence_id, cases=cases, evidence=evidence,
        )
        ev = act["evidence"]
        coc = act["chain_of_custody"]
        ro = act["read_only"]
        blocks.append({
            "t": "h3",
            "text": f"Evidencia {ev.get('original_basename') or ev['evidence_id']}",
        })
        blocks.append({
            "t": "kv",
            "pairs": [
                {"k": "Identificador", "v": ev["evidence_id"]},
                {"k": "Fichero original", "v": str(ev.get("original_basename") or "—")},
                {"k": "SHA-256 baseline", "v": ev["sha256"]},
                {"k": "Tamaño", "v": f"{ev['size_human']} ({ev['size_bytes']} bytes)"},
                {"k": "SO detectado", "v": str(ev.get("detected_os") or "unknown")},
                {"k": "Tipo detectado", "v": str(ev.get("detected_kind") or "unknown")},
                {"k": "Registrada", "v": str(ev.get("registered_at") or "—")},
                {"k": "Nivel de solo-lectura", "v": f"{ro['level']} — {ro['label']}"},
                {"k": "Hash de registro (custodia)", "v": str(coc.get("register_entry_hash") or "—")},
                {"k": "Cadena de auditoría verificada", "v": "sí" if coc.get("hash_chain_verified") else "NO"},
            ],
        })

    return {"num": "3", "title": "Cadena de custodia", "blocks": blocks}


def _metodologia(usage: list[dict[str, Any]]) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = [{
        "t": "p",
        "text": (
            "El análisis es post-mortem: las herramientas forenses leen la imagen a "
            "través de un handle de solo-lectura que expone EvidenceManager, sin "
            "montar el sistema de ficheros de la evidencia original. Cada ejecución "
            "de herramienta quedó registrada en el log de auditoría con su argv "
            "literal, versión y códigos de salida (FORENSIC INVARIANT 4). El recuento "
            "de uso siguiente se agrega de ese mismo log."
        ),
    }]

    if usage:
        rows = [
            [str(u["tool_id"]), str(u["total"]), str(u["ok"]), str(u["failed"])]
            for u in usage
        ]
        blocks.append({
            "t": "table",
            "headers": ["Herramienta", "Ejecuciones", "Correctas", "Con error"],
            "rows": rows,
        })
    else:
        blocks.append({
            "t": "p",
            "text": (
                "No consta ninguna ejecución de herramienta forense en el log de "
                "auditoría de este caso todavía."
            ),
        })

    return {"num": "4", "title": "Metodología y herramientas empleadas", "blocks": blocks}


def _hallazgos(finding_list: list[Any]) -> dict[str, Any]:
    if not finding_list:
        return {
            "num": "5",
            "title": "Hallazgos",
            "blocks": [{
                "t": "p",
                "text": (
                    "No se han registrado hallazgos estructurados en este caso. El "
                    "informe no fabrica resultados: cuando el análisis persista "
                    "hallazgos (record_finding), aparecerán aquí agrupados por "
                    "severidad."
                ),
            }],
        }

    blocks: list[dict[str, Any]] = []
    for sev in _SEV_ORDER:
        group = [f for f in finding_list if f.severity == sev]
        if not group:
            continue
        blocks.append({"t": "h3", "text": f"{_SEV_LABEL[sev]} ({len(group)})"})
        for f in group:
            tags: list[str] = []
            if f.tool_id:
                tags.append(str(f.tool_id))
            tags.extend(f.mitre_hints)
            blocks.append({
                "t": "finding",
                "sev": sev,
                "title": f.title,
                "text": f.summary,
                "tags": tags,
            })

    return {"num": "5", "title": "Hallazgos", "blocks": blocks}


def _correlacion_mitre(coverage_entries: list[dict[str, Any]]) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = [{
        "t": "p",
        "text": (
            "Correlación con MITRE ATT&CK. Dos ejes que no se funden: la técnica "
            "PROPUESTA por el análisis (derivada de los hallazgos) y el VEREDICTO "
            "del perito (confirmada / sospechosa / descartada). Una técnica "
            "propuesta y no dictaminada no cuenta como confirmada."
        ),
    }]

    if not coverage_entries:
        blocks.append({
            "t": "p",
            "text": (
                "Ninguna técnica ATT&CK ha sido correlacionada ni dictaminada en "
                "este caso."
            ),
        })
        return {"num": "6", "title": "Correlación MITRE ATT&CK", "blocks": blocks}

    tactic_names = _tactic_names()
    rows: list[list[str]] = []
    for entry in coverage_entries:
        tid = str(entry["technique_id"])
        name = (
            catalog.enterprise_technique(tid).name
            if catalog.enterprise_is_known(tid)
            else "—"
        )
        tactic_id = entry.get("tactic_id")
        tactic = tactic_names.get(tactic_id, tactic_id or "—") if tactic_id else "—"
        proposed = entry.get("proposed_by") or []
        veredicto = _ADJ_LABEL.get(entry.get("status"), str(entry.get("status")))
        rows.append([
            tid,
            name,
            tactic,
            str(len(proposed)),
            veredicto,
        ])

    blocks.append({
        "t": "table",
        "headers": ["Técnica", "Nombre", "Táctica", "Hallazgos", "Veredicto"],
        "rows": rows,
    })
    return {"num": "6", "title": "Correlación MITRE ATT&CK", "blocks": blocks}


def _conclusiones(
    case: Any, finding_list: list[Any], coverage_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    confirmed = sum(1 for e in coverage_entries if e.get("status") == "confirmada")
    if finding_list:
        text = (
            f"El análisis del caso «{case.name}» ha permitido documentar "
            f"{len(finding_list)} hallazgo(s), con {confirmed} técnica(s) ATT&CK "
            "confirmada(s) por dictamen pericial. Las conclusiones se sostienen "
            "exclusivamente sobre la evidencia analizada bajo cadena de custodia "
            "verificada y son reproducibles a partir del log de auditoría."
        )
    else:
        text = (
            f"En el estado actual, el caso «{case.name}» no arroja hallazgos "
            "estructurados que sostener. Este informe deja constancia del alcance "
            "examinado sin afirmar conclusiones que la evidencia no respalde."
        )
    return {
        "num": "7",
        "title": "Conclusiones",
        "blocks": [
            {"t": "p", "text": text},
            {
                "t": "p",
                "text": (
                    "Documento generado en estado BORRADOR. Adquiere validez pericial "
                    "al firmarse (paso a versión final), acto que queda registrado en "
                    "el log de auditoría hash-encadenado."
                ),
            },
        ],
    }
