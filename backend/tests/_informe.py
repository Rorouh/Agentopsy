"""Un caso sintético COMPLETO y aprobable: evidencia, ejecución, hallazgo, informe.

Los tests de aprobación no pueden trabajar sobre un documento de mentira. Desde
la reauditoría de 2026-09-08 la puerta de aprobación recomputa el hash del
contenido de cada hallazgo citado, re-hashea los bytes de cada evidencia, reabre
cada artefacto por la frontera de lectura verificada y exige que cada conclusión
forense cite la revisión que la respalda. Un documento con un manifiesto vacío ya
no se aprueba, y con razón: no hay nada detrás.

Así que estos ayudantes materializan el recorrido entero, de verdad, sobre el
``tmp_path`` del test: se registra una evidencia por la puerta de hash, se cierra
una ejecución con su manifiesto anclado en la cadena, se escribe un hallazgo que
cita una línea concreta de su salida y se crea el informe con el manifiesto de
fuentes que corresponde. Si algo de eso dejara de producir procedencia válida,
los tests fallarían, que es exactamente lo que se quiere de un gate.

No hay evidencia real ni una sola llamada a un proveedor: el disco sintético son
unos cientos de bytes y la salida de la herramienta son tres líneas escritas
aquí.
"""

from __future__ import annotations

from typing import Any

from _procedencia import anclar_run
from agentopsy.artifacts.store import ArtifactStore
from agentopsy.audit.log import AuditLog
from agentopsy.cases import CaseManager
from agentopsy.evidence import EvidenceManager
from agentopsy.findings.store import FindingStore
from agentopsy.reports.aprobacion import manifiesto_de_fuentes
from agentopsy.reports.store import DocumentStore
from agentopsy.reports.works import render_argv

#: La salida de la herramienta: tres líneas, para poder citar la segunda y para
#: que un localizador de líneas tenga un final comprobable.
STDOUT = (
    "r/r 128-128-1: Windows/System32/config/SOFTWARE\n"
    "r/r 512-128-3: Users/jcloudy/AppData/updater.exe\n"
    "r/r 900-128-4: Windows/Tasks/updater.job\n"
)
ARGV = ["tsk_fls", "-r", "-o", "2048", "/evidence/disco con espacio.raw"]


def montar_caso(
    tmp_path: Any,
    *,
    nombre: str = "Recorrido",
    examiner: str = "ramos",
    os_profile: str = "windows",
    stdout: str = STDOUT,
    exit_code: int = 0,
) -> dict[str, Any]:
    """Evidencia registrada y ejecución cerrada CON su manifiesto anclado."""
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name=nombre, examiner=examiner, os_profile=os_profile)

    origen = tmp_path / "disco.raw"
    if not origen.exists():
        origen.write_bytes(b"AGENTOPSY-DISCO-SINTETICO" * 32)
    evidencia = EvidenceManager(cases).register(case.id, str(origen))

    artefactos = ArtifactStore(cases)
    audit = AuditLog(cases.case_dir(case.id) / "audit.jsonl")
    run_id, _out = artefactos.start_run(
        case.id,
        "tsk_fls",
        ARGV,
        evidence_id=evidencia.evidence_id,
        # El baseline REAL de la evidencia: una ejecución que dijera haber leído
        # otro es una incoherencia que la aprobación bloquea, y con motivo.
        evidence_baseline_sha256=evidencia.sha256,
        tool_version="sleuthkit 4.12.1",
    )
    artefactos.set_run_argv(case.id, run_id, ARGV)
    audit.append({
        "action": "tool_run_start", "case_id": case.id, "run_id": run_id,
        "tool_id": "tsk_fls", "argv": ARGV,
        "evidence_id": evidencia.evidence_id,
        "baseline_sha256": evidencia.sha256, "tool_version": "sleuthkit 4.12.1",
    })
    run = artefactos.finalize_run(
        case.id, run_id, exit_code=exit_code, stdout=stdout, stderr=""
    )
    anclar_run(cases, case.id, run)
    return {
        "cases": cases,
        "case": case,
        "evidencia": evidencia,
        "artefactos": artefactos,
        "run": run,
        "run_id": run_id,
        "audit": audit,
        "findings": FindingStore(cases),
        "documents": DocumentStore(cases),
    }


def hallazgo(caso: dict[str, Any], **extra: Any) -> Any:
    """Un hallazgo que cita la SEGUNDA línea de la salida, con su extracto."""
    datos = {
        "title": "Ejecutable de persistencia en el perfil de jcloudy",
        "summary": (
            "El listado del sistema de ficheros sitúa updater.exe en el perfil "
            "de jcloudy, coherente con la tarea programada updater.job."
        ),
        "severity": "high",
        "observed_at": "2026-03-14T08:12:44Z",
        "references": [
            {
                "run_id": caso["run_id"],
                "evidence_id": caso["evidencia"].evidence_id,
                "tool_id": "tsk_fls",
                "artefacto": "stdout",
                "sha256": caso["run"].stdout_sha256,
                "localizador": {"tipo": "lineas", "desde": 2, "hasta": 2},
                "extracto": "r/r 512-128-3: Users/jcloudy/AppData/updater.exe",
            }
        ],
    }
    datos.update(extra)
    return caso["findings"].append(caso["case"].id, datos)


def material_de(caso: dict[str, Any], *hallazgos: Any, **extra: Any) -> dict[str, Any]:
    """El material que se le entregó al redactor, para fijar el manifiesto."""
    material = {
        "caso": {"id": caso["case"].id},
        "evidencias": [{
            "evidence_id": caso["evidencia"].evidence_id,
            "sha256_baseline": caso["evidencia"].sha256,
        }],
        "hallazgos": [{
            "id": h.id,
            "revision": h.revision,
            "content_sha256": h.content_sha256,
            "procedencia": h.provenance_state,
            "tipo": h.finding_kind,
            "referencias": h.references,
        } for h in hallazgos],
        "trabajos": [{
            "run_id": caso["run_id"], "status": "finished",
            "argv": ARGV, "argv_literal": render_argv(ARGV),
        }],
        "integridad": {"hash_chain_verified": True},
    }
    material.update(extra)
    return material


def secciones(
    *hallazgos: Any,
    limitaciones: tuple[str, ...] = (),
    texto_limitacion: str = "No se examinó la memoria RAM del equipo.",
) -> list[dict[str, Any]]:
    """El cuerpo mínimo que cumple el contrato de respaldo.

    Cada conclusión forense (apartados 6 y 9) cita la revisión que la sostiene, y
    cada limitación exigida se declara con su CÓDIGO. Es lo que el redactor tiene
    que producir y lo que la aprobación comprueba, así que el fixture lo escribe
    igual en lugar de rodearlo.
    """
    refs = [{"finding_id": h.id, "revision": h.revision} for h in hallazgos]
    bloques_limitacion = [
        {"t": "p", "text": f"Limitación declarada: {codigo}.", "limitacion": codigo}
        for codigo in limitaciones
    ]
    return [
        {"num": "1", "title": "Control de versiones", "blocks": [
            {"t": "p", "text": "Primera revisión del informe."},
            {"t": "code", "text": render_argv(ARGV)},
        ]},
        {"num": "6", "title": "Hallazgos", "blocks": [
            {
                "t": "finding",
                "sev": "high",
                "title": "Ejecutable de persistencia",
                "text": "updater.exe en el perfil de jcloudy.",
                "refs": refs,
            },
        ]},
        {"num": "9", "title": "Conclusiones y limitaciones", "blocks": [
            {"t": "p", "text": "Se confirma la persistencia en el perfil de jcloudy.",
             "refs": refs},
            {"t": "p", "text": texto_limitacion, "limitacion": "alcance_declarado"},
            *bloques_limitacion,
        ]},
    ]


def informe(
    caso: dict[str, Any],
    *hallazgos: Any,
    material: dict[str, Any] | None = None,
    sections: list[dict[str, Any]] | None = None,
    titulo: str = "Informe pericial del recorrido",
) -> Any:
    """El borrador, con su manifiesto de fuentes y sus conclusiones respaldadas."""
    mat = material if material is not None else material_de(caso, *hallazgos)
    fuentes = manifiesto_de_fuentes(caso["case"].id, mat)
    cuerpo = (
        sections
        if sections is not None
        else secciones(
            *hallazgos,
            limitaciones=tuple(fuentes.get("limitaciones_exigidas") or ()),
        )
    )
    return caso["documents"].create(caso["case"].id, {
        "title": titulo,
        "type": "pericial",
        "author": "ramos",
        "version": "v1.0",
        "summary": "Se confirma la persistencia en el perfil de jcloudy.",
        "sections": cuerpo,
        "fuentes": fuentes,
    })


def aprobar(caso: dict[str, Any], doc: Any, *, revisor: str = "ramos") -> Any:
    """Aprueba declarando la revisión EXACTA, como hace la superficie."""
    documents, case_id = caso["documents"], caso["case"].id
    return documents.approve(
        case_id,
        doc.id,
        sha256_revisado=documents.verify(case_id, doc.id)["recomputed_sha256"],
        revisor=revisor,
    )


__all__ = [
    "ARGV",
    "STDOUT",
    "aprobar",
    "hallazgo",
    "informe",
    "material_de",
    "montar_caso",
    "secciones",
]
