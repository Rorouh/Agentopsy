"""El MATERIAL de redacción: todo lo que el caso persiste, sin una sola frase.

Agentopsy dejó de ensamblar secciones (la plantilla determinista se retiró el
2026-07-30). Ahora reúne aquí, en un ``dict`` serializable, TODO lo que el caso
tiene registrado —caso y encargo, evidencias con su custodia, hallazgos
íntegros, ejecuciones con su argv auditado, uso de herramientas, correlación
ATT&CK con su veredicto, revisiones previas del informe, traza de la
investigación e integridad— y ``forensia.reports.writer`` se lo entrega al
ejecutor que el operador seleccionó para que redacte el informe de principio a
fin.

Este módulo NO redacta: no elige orden narrativo, no escribe transiciones, no
adjetiva. Solo hay dos decisiones de presentación, y las dos son datos:

- la **naturaleza** de cada evidencia («volcado de memoria RAM», «imagen de
  disco virtual») derivada del ``detected_kind`` del triaje y de la extensión
  literal — un kind desconocido degrada a «evidencia», no se adivina (RULE 2);
- el **orden de enumeración** por volatilidad (la memoria delante), que es una
  afirmación sobre la ENUMERACIÓN del material, nunca sobre el orden en que se
  procesó nada: eso solo lo puede decir el log de auditoría.

**Cotas declaradas.** El material viaja en un prompt, así que las colecciones
largas se acotan con constantes de este módulo y el recorte se DECLARA en
``truncado`` para que el informe lo diga (RULE 2: un recorte silencioso sería un
informe que parece completo y no lo es).

Lógica pura (RULE 3): lee los almacenes del caso, devuelve datos. Sin red, sin
``print``, sin ``sys.exit``.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from forensia import __version__
from forensia.audit.log import AuditLog
from forensia.cases import CaseManager, case_manager
from forensia.custody import build_custody_act
from forensia.evidence import EvidenceManager, evidence_manager
from forensia.findings.store import FindingStore, finding_store
from forensia.mitre import catalog
from forensia.mitre.coverage import CoverageStore, coverage_store
from forensia.reports.store import DocumentStore, document_store
from forensia.reports.works import tool_runs
from forensia.timeline.builder import build_investigation_timeline, load_filesystem_timeline
from forensia.toolkit.usage import tool_usage

#: Cotas del material (ver «Cotas declaradas» en el docstring del módulo).
MAX_HALLAZGOS = 400
MAX_TRABAJOS = 250
MAX_TRAZA = 400

#: Etiqueta del veredicto del perito para una técnica ATT&CK.
_ADJ_LABEL: dict[str | None, str] = {
    "confirmada": "Confirmada",
    "sospechosa": "Sospechosa",
    "descartada": "Descartada",
    None: "No dictaminada",
}

_VIRTUAL_DISK_EXTS = (".vmdk", ".vdi", ".qcow", ".qcow2", ".vhd", ".vhdx")
_FORENSIC_CONTAINER_EXTS = (".e01", ".ex01", ".aff", ".aff4", ".s01", ".l01")

#: Naturaleza de un fichero APORTADO (``kind=document``) según su extensión
#: literal, con el mismo criterio que arriba: se nombra lo que se reconoce y lo
#: demás queda en la categoría general, nunca se adivina (RULE 2). Un informe
#: pericial escribe «documento PDF», no «document».
_MATERIAL_NATURALEZA: dict[str, str] = {
    ".pdf": "documento PDF",
    ".doc": "documento de texto", ".docx": "documento de texto",
    ".odt": "documento de texto", ".rtf": "documento de texto",
    ".xls": "hoja de cálculo", ".xlsx": "hoja de cálculo",
    ".ods": "hoja de cálculo", ".csv": "hoja de cálculo", ".tsv": "hoja de cálculo",
    ".ppt": "presentación", ".pptx": "presentación", ".odp": "presentación",
    ".txt": "fichero de texto plano", ".md": "fichero de texto plano",
    ".json": "fichero de texto plano", ".xml": "fichero de texto plano",
    ".log": "registro de actividad", ".journal": "registro de actividad",
    ".eml": "mensaje de correo electrónico", ".msg": "mensaje de correo electrónico",
    ".mbox": "buzón de correo", ".pst": "buzón de correo", ".ost": "buzón de correo",
    ".png": "imagen fotográfica", ".jpg": "imagen fotográfica",
    ".jpeg": "imagen fotográfica", ".gif": "imagen fotográfica",
    ".bmp": "imagen fotográfica", ".tif": "imagen fotográfica",
    ".tiff": "imagen fotográfica", ".webp": "imagen fotográfica",
    ".heic": "imagen fotográfica", ".heif": "imagen fotográfica",
    ".mp4": "grabación de vídeo", ".mov": "grabación de vídeo",
    ".avi": "grabación de vídeo", ".mkv": "grabación de vídeo",
    ".mp3": "grabación de audio", ".wav": "grabación de audio",
    ".m4a": "grabación de audio", ".ogg": "grabación de audio",
    ".flac": "grabación de audio",
    ".evtx": "registro de eventos de Windows", ".evt": "registro de eventos de Windows",
    ".reg": "exportación del registro de Windows",
    ".pf": "artefacto de ejecución de Windows (prefetch)",
    ".lnk": "acceso directo de Windows",
    ".sqlite": "base de datos SQLite", ".sqlite3": "base de datos SQLite",
    ".db": "base de datos",
    ".pcap": "captura de tráfico de red", ".pcapng": "captura de tráfico de red",
    ".cap": "captura de tráfico de red",
    ".zip": "archivo comprimido", ".7z": "archivo comprimido",
    ".rar": "archivo comprimido", ".tar": "archivo comprimido",
    ".gz": "archivo comprimido", ".tgz": "archivo comprimido",
    ".bz2": "archivo comprimido", ".xz": "archivo comprimido",
    ".exe": "ejecutable de Windows", ".dll": "biblioteca de Windows",
    ".sys": "controlador de Windows", ".so": "biblioteca de Linux",
    ".ps1": "script de PowerShell", ".bat": "script por lotes",
    ".vbs": "script de Visual Basic", ".sh": "script de shell",
    ".py": "script de Python",
}


def naturaleza(handle: Any) -> str:
    """La naturaleza de una evidencia — «volcado de memoria RAM», «imagen de
    disco virtual», «documento PDF» — derivada del ``detected_kind`` del triaje
    y, para un contenedor o un fichero aportado, de la extensión literal del
    fichero. Un kind desconocido degrada a «evidencia»: la naturaleza no se
    adivina (RULE 2)."""
    kind = str(getattr(handle, "detected_kind", "") or "").strip()
    if kind == "memory":
        return "volcado de memoria RAM"
    if kind == "disk":
        return "imagen de disco"
    if kind == "container_disk":
        ext = handle.original_path.suffix.lower()
        if ext in _VIRTUAL_DISK_EXTS:
            return "imagen de disco virtual"
        if ext in _FORENSIC_CONTAINER_EXTS:
            return "imagen forense de disco"
        return "imagen de disco en formato contenedor"
    if kind == "document":
        ext = handle.original_path.suffix.lower()
        return _MATERIAL_NATURALEZA.get(ext, "fichero aportado")
    return "evidencia"


def _basename(path: Any) -> str:
    """El nombre del fichero de una ruta registrada, SIN la ruta. Un informe no
    tiene por qué publicar el árbol de directorios del host del perito."""
    text = str(path or "").strip()
    return PurePosixPath(PureWindowsPath(text).name or text).name if text else ""


def _por_volatilidad(evidence_handles: list[Any]) -> list[Any]:
    """Los handles con la memoria RAM delante (mayor volatilidad) y el resto en
    su orden de registro."""
    memoria = [
        h for h in evidence_handles
        if str(getattr(h, "detected_kind", "") or "") == "memory"
    ]
    resto = [
        h for h in evidence_handles
        if str(getattr(h, "detected_kind", "") or "") != "memory"
    ]
    return memoria + resto


def _perito_material(perito: dict[str, Any] | None, case: Any) -> dict[str, str]:
    """Los datos del profesional que firmará. Sin ``name``, figura el
    examinador del caso — que es el dato autoritativo del expediente, no un
    default inventado."""
    def _s(key: str) -> str:
        if not perito:
            return ""
        value = perito.get(key)
        return value.strip() if isinstance(value, str) else ""

    out = {"nombre": _s("name") or case.examiner}
    for key, label in (
        ("colegiado", "colegiado"),
        ("organization", "organizacion"),
        ("email", "contacto"),
    ):
        value = _s(key)
        if value:
            out[label] = value
    return out


def _caso_material(case: Any) -> dict[str, Any]:
    encargo = " ".join(str(getattr(case, "notes", "") or "").split())
    return {
        "id": case.id,
        "nombre": case.name,
        "examinador": case.examiner,
        # El ENCARGO tal y como lo anotó el perito al abrir el expediente. Vacío
        # significa que no consta: el informe lo dice, no lo rellena (RULE 2).
        "encargo": encargo,
        "perfil_so": case.os_profile or "sin determinar",
        "origen_del_perfil": case.os_profile_source or "",
        "estado": case.status,
        "apertura": case.created_at,
    }


def _evidencias_material(
    case_id: str,
    evidence_handles: list[Any],
    *,
    cases: CaseManager,
    evidence: EvidenceManager,
    fs_timeline_fn: Callable[[str, str], dict[str, Any] | None],
) -> list[dict[str, Any]]:
    """Una entrada por evidencia: identidad, custodia verificada, naturaleza y
    si tiene super-timeline de sistema de ficheros persistida. Todos los valores
    salen del acta de custodia (``forensia.custody``), que a su vez los lee del
    baseline y del audit — no se recalculan aquí."""
    out: list[dict[str, Any]] = []
    for handle in _por_volatilidad(evidence_handles):
        act = build_custody_act(
            case_id, handle.evidence_id, cases=cases, evidence=evidence,
        )
        ev = act["evidence"]
        item: dict[str, Any] = {
            "evidence_id": ev["evidence_id"],
            # Dos nombres distintos, y la diferencia importa en el informe: el
            # fichero que el perito aportó (basename del origen — nunca la ruta
            # completa del host) y el nombre de la COPIA inmutable que vive bajo
            # custodia en el caso, que es la que las herramientas leyeron.
            "fichero_original": _basename(ev.get("source_path")),
            "fichero_en_el_caso": ev.get("original_basename") or "",
            "naturaleza": naturaleza(handle),
            "sha256_baseline": ev["sha256"],
            "tamano": f"{ev['size_human']} ({ev['size_bytes']} bytes)",
            "so_detectado": ev.get("detected_os") or "unknown",
            "tipo_detectado": ev.get("detected_kind") or "unknown",
            "registrada": ev.get("registered_at") or "",
            "solo_lectura": f"{act['read_only']['level']}, {act['read_only']['label']}",
            "hash_de_registro": act["chain_of_custody"].get("register_entry_hash") or "",
            "cadena_auditoria_verificada": bool(
                act["chain_of_custody"].get("hash_chain_verified")
            ),
            "verificacion": act.get("verification"),
        }
        if ev.get("segments"):
            item["segmentos_ewf"] = ev["segments"]
        # Presencia (no contenido) de la super-timeline: §3 debe poder decir con
        # honestidad si existe, sin que decenas de miles de eventos MACB entren
        # en el prompt.
        fs_timeline = fs_timeline_fn(case_id, handle.evidence_id)
        item["super_timeline"] = (
            {"generada": True, "eventos": fs_timeline.get("total_events")}
            if isinstance(fs_timeline, dict)
            else {"generada": False}
        )
        out.append(item)
    return out


def _hallazgos_material(finding_list: list[Any]) -> list[dict[str, Any]]:
    """Los hallazgos ÍNTEGROS: el ``summary`` completo (donde viven las
    entidades concretas — usuarios, equipos, ficheros, direcciones) y la
    procedencia completa, sin truncar hashes (un perito contrario debe poder
    reejecutar)."""
    return [
        {
            "id": f.id,
            "titulo": f.title,
            "detalle": f.summary,
            "severidad": f.severity,
            "tipo": getattr(f, "finding_kind", "afirmacion"),
            "confianza": getattr(f, "confidence", None),
            "observed_at": getattr(f, "observed_at", None),
            "registrado_en": f.created_at,
            "evidence_id": f.evidence_id,
            "tool_id": f.tool_id,
            "run_id": f.run_id,
            "artifact_sha256": getattr(f, "artifact_sha256", None),
            "mitre_hints": list(f.mitre_hints),
        }
        for f in finding_list
    ]


def _mitre_material(
    coverage_entries: list[dict[str, Any]], finding_list: list[Any]
) -> list[dict[str, Any]]:
    """Cada técnica tocada con su nombre y táctica del catálogo Enterprise, los
    hallazgos que la proponen y el veredicto del perito. Los DOS EJES —propuesta
    del análisis y veredicto pericial— viajan separados; fundirlos es
    precisamente lo que el informe no debe hacer."""
    titulos = {f.id: f.title for f in finding_list}
    tacticas: dict[str, str] = {}
    try:
        tacticas = {
            t.id: (t.name_es or t.name) for t in catalog.load_enterprise().tactics
        }
    except Exception:  # noqa: BLE001 — el catálogo es opcional; nunca tumba el material
        tacticas = {}

    out: list[dict[str, Any]] = []
    for entry in coverage_entries:
        tid = str(entry["technique_id"])
        nombre = ""
        try:
            if catalog.enterprise_is_known(tid):
                nombre = catalog.enterprise_technique(tid).name
        except Exception:  # noqa: BLE001 — sin catálogo, el id a secas (RULE 2)
            nombre = ""
        tactic_id = entry.get("tactic_id")
        out.append({
            "technique_id": tid,
            "nombre": nombre,
            "tactica_id": tactic_id or "",
            "tactica": tacticas.get(tactic_id, "") if tactic_id else "",
            "propuesta_por": [
                {"finding_id": fid, "titulo": titulos.get(fid, "")}
                for fid in (entry.get("proposed_by") or [])
            ],
            "veredicto": _ADJ_LABEL.get(entry.get("status"), str(entry.get("status"))),
            "motivacion_del_veredicto": entry.get("rationale") or "",
            "dictaminada_en": entry.get("adjudicated_at") or "",
        })
    return out


def _revisiones_material(
    case_id: str, *, documents: DocumentStore
) -> list[dict[str, Any]]:
    """Las revisiones periciales YA registradas del caso (§1 Control de
    versiones), más antigua primero. La revisión en curso no está aquí: su
    SHA-256 se fija al persistirla."""
    return [
        {
            "version": d.version,
            "fecha": d.created_at,
            "autor": d.author,
            "estado": d.status,
            "sha256": d.sha256,
            "titulo": d.title,
        }
        for d in sorted(
            (d for d in documents.list(case_id) if d.type == "pericial"),
            key=lambda d: d.created_at,
        )
    ]


def _integridad_material(case_id: str, *, cases: CaseManager) -> dict[str, Any]:
    audit_path = cases.case_dir(case_id) / "audit.jsonl"
    return {
        "audit_log": "audit.jsonl",
        "hash_chain_verified": AuditLog(audit_path).verify() if audit_path.is_file() else None,
        "herramienta": f"Agentopsy {__version__}",
    }


def build_material(
    case_id: str,
    perito: dict[str, Any] | None = None,
    *,
    cases: CaseManager = case_manager,
    evidence: EvidenceManager = evidence_manager,
    findings: FindingStore = finding_store,
    coverage: CoverageStore = coverage_store,
    documents: DocumentStore = document_store,
    usage_fn: Callable[[str], list[dict[str, Any]]] = tool_usage,
    runs_fn: Callable[..., list[dict[str, Any]]] = tool_runs,
    traza_fn: Callable[[str], list[dict[str, Any]]] = build_investigation_timeline,
    fs_timeline_fn: Callable[[str, str], dict[str, Any] | None] = load_filesystem_timeline,
) -> dict[str, Any]:
    """Todo lo que el caso tiene persistido, listo para viajar al redactor.

    Las dependencias son inyectables para los tests; en producción son los
    singletons (RULE 2 permite ``def f(dep=SINGLETON)``). Falla fuerte
    (``KeyError`` / ``ValueError``) si el caso no existe o su id es inválido —
    nunca "el último caso" ni un placeholder.
    """
    case = cases.load(case_id)  # KeyError/ValueError si no existe o id inválido

    finding_list = findings.list(case_id)
    evidence_handles = evidence.list(case_id)
    coverage_entries = coverage.coverage(case_id)
    trabajos = runs_fn(case_id, cases=cases, findings=findings)
    traza = traza_fn(case_id)

    truncado: dict[str, Any] = {}
    if len(finding_list) > MAX_HALLAZGOS:
        truncado["hallazgos"] = {
            "total": len(finding_list), "incluidos": MAX_HALLAZGOS,
        }
        finding_list = finding_list[:MAX_HALLAZGOS]
    if len(trabajos) > MAX_TRABAJOS:
        truncado["trabajos"] = {"total": len(trabajos), "incluidos": MAX_TRABAJOS}
        trabajos = trabajos[:MAX_TRABAJOS]
    if len(traza) > MAX_TRAZA:
        truncado["traza"] = {"total": len(traza), "incluidos": MAX_TRAZA}
        traza = traza[-MAX_TRAZA:]

    material: dict[str, Any] = {
        "caso": _caso_material(case),
        "perito": _perito_material(perito, case),
        "evidencias": _evidencias_material(
            case_id, evidence_handles, cases=cases, evidence=evidence,
            fs_timeline_fn=fs_timeline_fn,
        ),
        "hallazgos": _hallazgos_material(finding_list),
        "trabajos": trabajos,
        "uso_de_tools": usage_fn(case_id),
        "mitre": _mitre_material(coverage_entries, finding_list),
        "revisiones": _revisiones_material(case_id, documents=documents),
        "traza": traza,
        "integridad": _integridad_material(case_id, cases=cases),
    }
    if truncado:
        # El recorte se DECLARA para que el informe lo diga (RULE 2).
        material["truncado"] = truncado
    return material


__all__ = [
    "MAX_HALLAZGOS",
    "MAX_TRABAJOS",
    "MAX_TRAZA",
    "build_material",
    "naturaleza",
]
