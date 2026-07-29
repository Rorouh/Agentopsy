"""Síntesis del **informe pericial** desde los datos reales del caso.

Ensambla las ``sections`` (modelo de bloques de ``forensia.reports.store``) de un
informe pericial en formato "Murciélago" a partir de lo que YA existe en el caso
—nunca inventa nada (RULE 2)—:

- Metadatos del caso (``forensia.cases``: nombre, examinador, os_profile, fechas).
- Cadena de custodia por evidencia (``forensia.custody.build_custody_act``:
  sha256 baseline, tamaño, nivel de solo-lectura, verificación de la cadena hash).
- Metodología y herramientas empleadas (``forensia.toolkit.usage.tool_usage``).
- **Relato de la investigación** (``forensia.reports.narrative``): la
  reconstrucción narrativa de los hechos — cronología por ``observed_at``, lo
  establecido sin fecha, las vías descartadas y lo que queda abierto — con el
  detalle técnico íntegro de cada hallazgo. El resumen ejecutivo y las
  conclusiones se sintetizan del MISMO hilo (2026-07-30: el informe dejó de
  enumerar y pasó a narrar; la narrativa elige orden y tejido conectivo, nunca
  contenido — RULE 2).
- Hallazgos estructurados agrupados por severidad
  (``forensia.findings.store.finding_store``), cada uno como bloque ``finding``.
- Correlación MITRE ATT&CK (``forensia.mitre.coverage``): técnica ↔ hallazgos que
  la proponen y el veredicto del perito, sin fundir los dos ejes.

Lógica pura (RULE 3): no imprime, no pide por stdin, no toca la red. Devuelve el
``dict`` que ``DocumentStore.create`` valida y persiste; el router es un adaptador
fino que llama aquí y crea el documento. Un caso sin hallazgos produce un informe
HONESTO que lo dice —nunca uno vacío falso—; un caso inexistente falla fuerte
(``KeyError``), igual que ``CaseManager.load``.

Además, ``generate_draft_report`` es el helper compartido que deja/actualiza un
BORRADOR automático al CERRAR un análisis (identificado por un título reservado,
refrescado sin apilar, sin tocar nunca un documento firmado). A diferencia de
``build_pericial_report`` sí persiste (crea/borra en ``DocumentStore``), pero sigue
sin tocar la red ni la E/S de las superficies.
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
from forensia.reports import narrative
from forensia.reports.store import Document, DocumentStore, document_store
from forensia.toolkit.usage import tool_usage

#: Título reservado que identifica el BORRADOR generado AUTOMÁTICAMENTE al cerrar
#: un análisis (a diferencia del que crea el operador con «Generar informe»). Es el
#: ancla para refrescarlo sin apilar: ``generate_draft_report`` borra el borrador
#: anterior con este título antes de crear el nuevo — pero NUNCA un documento
#: firmado (``final``), aunque lleve este título (cadena de custodia).
AUTO_DRAFT_TITLE = "Informe pericial (borrador automático)"

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
        narrative.story_section(
            case, finding_list, evidence_handles, coverage_entries, usage
        ),
        _hallazgos(finding_list),
        _correlacion_mitre(coverage_entries, finding_list),
        _conclusiones(case, finding_list, coverage_entries),
    ]

    summary = narrative.summary_line(
        case, finding_list, evidence_handles, coverage_entries
    )

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


def generate_draft_report(
    case_id: str,
    perito: dict[str, Any] | None = None,
    *,
    documents: DocumentStore = document_store,
    cases: CaseManager = case_manager,
    evidence: EvidenceManager = evidence_manager,
    findings: FindingStore = finding_store,
    coverage: CoverageStore = coverage_store,
    usage_fn: Callable[[str], list[dict[str, Any]]] = tool_usage,
) -> Document | None:
    """Deja/actualiza el BORRADOR automático del informe pericial del caso.

    Pensado para engancharse al CIERRE de un análisis: si el caso tiene ≥1
    hallazgo registrado, sintetiza el informe (``build_pericial_report``) y lo
    persiste como documento en estado ``draft``; si NO hay ninguno, devuelve
    ``None`` sin crear nada (RULE 2: no se fabrica un informe que no sostiene
    ningún hallazgo).

    **Refresco sin apilar:** el borrador auto se identifica por un TÍTULO
    reservado (``AUTO_DRAFT_TITLE``) — no por un campo nuevo en el schema del
    documento. Antes de crear el nuevo, borra el borrador auto ANTERIOR del caso
    (solo documentos ``draft`` con ese título), de modo que siempre hay como
    mucho UN borrador auto, al día. **Un documento ``final`` (firmado) NUNCA se
    borra**, aunque lleve el título reservado — cadena de custodia (el store lo
    haría fallar; aquí ni se intenta).

    Las dependencias son inyectables para los tests; en producción son los
    singletons (los mismos que cablea ``POST …/documents/generate``). Falla fuerte
    (``KeyError`` / ``ValueError``) si el caso no existe — igual que el resto de
    ``forensia.reports``.
    """
    if not findings.list(case_id):
        return None

    data = build_pericial_report(
        case_id,
        perito,
        cases=cases,
        evidence=evidence,
        findings=findings,
        coverage=coverage,
        usage_fn=usage_fn,
    )
    # El título reservado es el ancla del refresco: sobreescribe el título normal
    # del informe (``… — <nombre del caso>``) para poder reconocer el borrador auto.
    data["title"] = AUTO_DRAFT_TITLE

    # Refresco sin apilar: borra SOLO borradores auto previos (mismo título), nunca
    # un final firmado — cadena de custodia (FORENSIC INVARIANT 2).
    for doc in documents.list(case_id):
        if doc.title == AUTO_DRAFT_TITLE and doc.status == "draft":
            documents.delete(case_id, doc.id)

    return documents.create(case_id, data)


# ── secciones ─────────────────────────────────────────────────────────────────


def _resumen_ejecutivo(
    case: Any, finding_list: list[Any], evidence_handles: list[Any],
    coverage_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    """El resumen ejecutivo NARRA (2026-07-30): encuadre del encargo, la
    secuencia de hechos que la evidencia sostiene, el estado del dictamen con su
    desglose técnico, y el mapa del informe — el mismo hilo que §5 y §8
    desarrollan. La prosa la sintetiza ``forensia.reports.narrative`` desde los
    datos persistidos, nunca desde conjeturas (RULE 2)."""
    return {
        "num": narrative.SEC_RESUMEN,
        "title": "Resumen ejecutivo",
        "blocks": narrative.executive_blocks(
            case, finding_list, evidence_handles, coverage_entries
        ),
    }


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
        {"k": "Redacción narrativa", "v": "determinista (sintetizada de los datos del caso)"},
        {"k": "Identificador del caso", "v": case.id},
        {"k": "Nombre del caso", "v": case.name},
        {"k": "Examinador", "v": case.examiner},
        {"k": "Perfil de SO", "v": case.os_profile or "sin determinar"},
        {"k": "Origen del perfil", "v": case.os_profile_source or "—"},
        {"k": "Estado del caso", "v": case.status},
        {"k": "Apertura del caso", "v": case.created_at},
        {"k": "Emisión del informe", "v": generated_at},
        {"k": "Versión del informe", "v": version},
        {"k": "Herramienta", "v": f"Agentopsy {__version__}"},
    ])
    return {
        "num": narrative.SEC_DATOS,
        "title": "Datos del informe y del perito",
        "blocks": [{"t": "kv", "pairs": pairs}],
    }


def _cadena_custodia(
    case_id: str, evidence_handles: list[Any], *,
    cases: CaseManager, evidence: EvidenceManager,
) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = [narrative.transition(
        "El relato que este informe desarrolla vale lo que valga su base: esta "
        "sección fija QUÉ evidencia se examinó y con qué garantías de "
        "integridad, antes de narrar hecho alguno."
    ), {
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
        return {
            "num": narrative.SEC_CUSTODIA,
            "title": "Cadena de custodia",
            "blocks": blocks,
        }

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

    return {
        "num": narrative.SEC_CUSTODIA,
        "title": "Cadena de custodia",
        "blocks": blocks,
    }


def _metodologia(usage: list[dict[str, Any]]) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = [narrative.transition(
        "Establecida la custodia, esta sección deja constancia de CÓMO se "
        "interrogó la evidencia: cada corrida que el relato "
        f"(§{narrative.SEC_RELATO}) cita procede de este registro."
    ), {
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

    return {
        "num": narrative.SEC_METODOLOGIA,
        "title": "Metodología y herramientas empleadas",
        "blocks": blocks,
    }


def _hallazgos(finding_list: list[Any]) -> dict[str, Any]:
    if not finding_list:
        return {
            "num": narrative.SEC_HALLAZGOS,
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

    blocks: list[dict[str, Any]] = [narrative.transition(
        f"Los hechos narrados en §{narrative.SEC_RELATO} se descomponen aquí en "
        "hallazgos estructurados, agrupados por severidad, cada uno con su "
        "procedencia (herramienta, corrida y hash del artefacto) verificable "
        "contra el log de auditoría."
    )]
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
            block: dict[str, Any] = {
                "t": "finding",
                "sev": sev,
                "title": f.title,
                "text": f.summary,
                "tags": tags,
            }
            meta = _finding_provenance(f)
            if meta:
                block["meta"] = meta
            blocks.append(block)

    return {"num": narrative.SEC_HALLAZGOS, "title": "Hallazgos", "blocks": blocks}


def _finding_provenance(f: Any) -> str:
    """Línea de confianza + procedencia de un hallazgo para el informe.

    Confianza CALIBRADA (si el agente la dio), marca del artefacto (``observed_at``),
    y la procedencia que ancla el hallazgo a la evidencia (``run_id`` del ArtifactRun,
    SHA-256 del artefacto). Un hallazgo de descarte se etiqueta como tal. Vacío si no
    hay ningún dato — el informe no fabrica procedencia (RULE 2)."""
    parts: list[str] = []
    if getattr(f, "finding_kind", "afirmacion") == "descarte":
        parts.append("Descarte")
    confidence = getattr(f, "confidence", None)
    if confidence is not None:
        parts.append(f"Confianza: {confidence:.2f}")
    observed_at = getattr(f, "observed_at", None)
    if observed_at:
        parts.append(f"Observado: {observed_at}")
    if f.run_id:
        parts.append(f"Run: {f.run_id[:8]}")
    artifact_sha256 = getattr(f, "artifact_sha256", None)
    if artifact_sha256:
        parts.append(f"SHA-256 artefacto: {artifact_sha256[:12]}…")
    return " · ".join(parts)


def _supporting_findings_cell(
    finding_ids: list[str], titles: dict[str, str]
) -> str:
    """Los hallazgos que sostienen una técnica, como ``{id8} título`` por línea.

    Lista los `finding_id`/títulos que la proponen (no solo el recuento), para que el
    perito vea SOBRE QUÉ se apoya la correlación. ``—`` si ninguno."""
    if not finding_ids:
        return "—"
    lines: list[str] = []
    for fid in finding_ids:
        title = titles.get(fid, "")
        short = fid[:8]
        if title:
            snippet = title if len(title) <= 60 else title[:57] + "…"
            lines.append(f"{short} {snippet}")
        else:
            lines.append(short)
    return "\n".join(lines)


def _correlacion_mitre(
    coverage_entries: list[dict[str, Any]], finding_list: list[Any]
) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = [{
        "t": "p",
        "text": (
            "El relato y los hallazgos anteriores se encuadran aquí en el marco "
            "táctico MITRE ATT&CK. Dos ejes que no se funden: la técnica "
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
        return {
            "num": narrative.SEC_MITRE,
            "title": "Correlación MITRE ATT&CK",
            "blocks": blocks,
        }

    tactic_names = _tactic_names()
    titles = {f.id: f.title for f in finding_list}
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
            # Los hallazgos que la sostienen, por id + título (no solo el recuento):
            # el perito ve SOBRE QUÉ se apoya cada técnica propuesta.
            _supporting_findings_cell(proposed, titles),
            veredicto,
        ])

    blocks.append({
        "t": "table",
        "headers": ["Técnica", "Nombre", "Táctica", "Hallazgos que la sostienen", "Veredicto"],
        "rows": rows,
    })
    return {
        "num": narrative.SEC_MITRE,
        "title": "Correlación MITRE ATT&CK",
        "blocks": blocks,
    }


def _conclusiones(
    case: Any, finding_list: list[Any], coverage_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    """Las conclusiones CIERRAN el hilo (2026-07-30): qué lectura de los hechos
    sostiene la evidencia, qué arco táctico confirma el dictamen y por qué todo
    ello es reproducible — prosa de ``forensia.reports.narrative``, sintetizada
    de los mismos datos que el relato (RULE 2: nada que la evidencia no
    sostenga)."""
    return {
        "num": narrative.SEC_CONCLUSIONES,
        "title": "Conclusiones",
        "blocks": narrative.conclusion_blocks(case, finding_list, coverage_entries),
    }
