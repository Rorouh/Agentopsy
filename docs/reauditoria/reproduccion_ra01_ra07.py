"""Reejecucion de los siete escenarios de la reauditoria 2026-09-08 sobre el codigo corregido.

Mismos escenarios que reaudit_f02_f04_probes.py, con dos diferencias:

- cada uno se captura (el original abortaba en RA05 al levantar el lector), y
- se registra el resultado ESPERADO junto al observado, para que un tercero vea
  de un vistazo si el escenario adverso queda bloqueado.

Casos sinteticos aislados: ni una evidencia real ni una llamada a un proveedor.
"""
import hashlib
import json
import os
import stat
import sys
import tempfile
import uuid
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

sys.stdout.reconfigure(encoding="utf-8")
#: La raiz del repositorio, deducida de la posicion de este fichero.
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).parent
#: Los datos del caso sintetico van a un temporal, NUNCA al repositorio ni al
#: directorio de casos del investigador. La ruta se mantiene corta a proposito:
#: en Windows, un caso anidado bajo un temporal largo se pasa de MAX_PATH.
DATA = Path(tempfile.gettempdir()) / "agentopsy-reaudit" / uuid.uuid4().hex[:8]
DATA.mkdir(parents=True)
os.environ["AGENTOPSY_HOME"] = str(DATA / "global")
os.environ["AGENTOPSY_AGENTS_DIR"] = str(ROOT / "agentes")
sys.path[:0] = [str(ROOT / "backend"), str(ROOT / "backend/tests")]

from _informe import aprobar, hallazgo, informe, montar_caso  # noqa: E402
from agentopsy.artifacts import lectura  # noqa: E402
from agentopsy.evidence import EvidenceManager  # noqa: E402
from agentopsy.findings.procedencia import verificar_referencia  # noqa: E402
from agentopsy.findings.store import content_sha256  # noqa: E402
from agentopsy.reports.aprobacion import comprobar  # noqa: E402
import agentopsy.routers.documents as router  # noqa: E402

resultados: dict[str, dict] = {}


def montar(nombre: str):
    caso = montar_caso(DATA / nombre, nombre=nombre)
    h = hallazgo(caso)
    return caso, h, informe(caso, h)


def desenlace(caso, doc):
    c = comprobar(caso["case"].id, doc.id, documents=caso["documents"], cases=caso["cases"])
    salida = {"aprobable": c.aprobable, "bloqueos": [b.codigo for b in c.bloqueos]}
    if c.aprobable:
        salida["status"] = aprobar(caso, doc).status
    return salida


def ruta_doc(caso, doc):
    return caso["cases"].case_dir(caso["case"].id) / "documents" / f"{doc.id}.json"


# -- RA02: bytes de la evidencia ---------------------------------------------
caso, f, d = montar("evidence_bytes")
p = caso["evidencia"].original_path
os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
p.write_bytes(b"EVIDENCIA ALTERADA SINTETICA")
resultados["evidence_bytes"] = {
    "esperado": "bloqueada (evidencia_alterada)",
    "real_evidence_verify": EvidenceManager(caso["cases"]).verify(
        caso["case"].id, caso["evidencia"].evidence_id
    ),
    **desenlace(caso, d),
}

# -- RA03.1: resumen alterado conservando content_sha256 ----------------------
caso, f, d = montar("finding_body")
p = caso["cases"].case_dir(caso["case"].id) / "findings.jsonl"
registro = json.loads(p.read_text(encoding="utf-8").strip())
registro["summary"] = "CONCLUSION ALTERADA SIN MODIFICAR EL HASH GUARDADO"
p.write_text(json.dumps(registro) + "\n", encoding="utf-8")
resultados["finding_body"] = {
    "esperado": "bloqueada (hallazgo_alterado)",
    "stored_hash_matches_actual_content": content_sha256(registro) == registro["content_sha256"],
    **desenlace(caso, d),
}

# -- RA03.1b: resumen alterado Y hash recalculado en local --------------------
caso, f, d = montar("finding_rehashed")
p = caso["cases"].case_dir(caso["case"].id) / "findings.jsonl"
registro = json.loads(p.read_text(encoding="utf-8").strip())
registro["summary"] = "CONCLUSION ALTERADA CON SU HASH RECALCULADO"
registro["content_sha256"] = content_sha256(registro)
p.write_text(json.dumps(registro) + "\n", encoding="utf-8")
resultados["finding_rehashed"] = {
    "esperado": "bloqueada (hallazgo_revisado o hallazgo_sin_ancla)",
    **desenlace(caso, d),
}

# -- RA01: fuentes sustituidas por el objeto minimo ---------------------------
caso, f, d = montar("sources_removed")
(caso["cases"].case_dir(caso["case"].id) / "artifacts" / caso["run_id"] / "stdout.txt").write_text(
    "ALTERADO\n", encoding="utf-8"
)
antes = comprobar(caso["case"].id, d.id, documents=caso["documents"], cases=caso["cases"])
p = ruta_doc(caso, d)
registro = json.loads(p.read_text(encoding="utf-8"))
registro["fuentes"] = {"case_id": caso["case"].id}
p.write_text(json.dumps(registro), encoding="utf-8")
resultados["sources_removed"] = {
    "esperado": "bloqueada antes y despues de sustituir las fuentes",
    "blocked_before_removing_sources": not antes.aprobable,
    "document_hash_still_valid": caso["documents"].verify(caso["case"].id, d.id)["ok"],
    **desenlace(caso, d),
}

# -- RA01b: fuentes sustituidas Y digest recalculado en local -----------------
caso, f, d = montar("sources_rehashed")
from agentopsy.reports.fuentes import digest_de_fuentes  # noqa: E402
from agentopsy.reports.store import _content_sha256  # noqa: E402

p = ruta_doc(caso, d)
registro = json.loads(p.read_text(encoding="utf-8"))
registro["fuentes"] = {"case_id": caso["case"].id, "hallazgos": [], "artefactos": [],
                       "evidencias": [], "evidencias_sha256": {}, "limitaciones_exigidas": []}
registro["fuentes_sha256"] = digest_de_fuentes(registro["fuentes"])
registro["sha256"] = _content_sha256(registro)
p.write_text(json.dumps(registro), encoding="utf-8")
resultados["sources_rehashed"] = {
    "esperado": "bloqueada (procedencia_no_casa / ancla_no_casa)",
    **desenlace(caso, d),
}

# -- RA04: estado final forjado sin acta --------------------------------------
caso, f, d = montar("forged_final")
p = ruta_doc(caso, d)
registro = json.loads(p.read_text(encoding="utf-8"))
registro.update(status="final", approved_by="REVISOR FICTICIO",
                approved_at="2026-09-08T00:00:00Z", approved_sha256=d.sha256)
p.write_text(json.dumps(registro), encoding="utf-8")
with patch.object(router, "case_manager", caso["cases"]), patch.object(
    router, "document_store", caso["documents"]
):
    respuesta = router.document_pdf(caso["case"].id, d.id)
resultados["forged_final"] = {
    "esperado": "PDF marcado borrador (X-Agentopsy-Pdf-Draft: 1)",
    "approval_events": sum(
        e.get("action") == "document_approved" for e in caso["audit"].entries()
    ),
    "pdf_status": respuesta.status_code,
    "pdf_draft_header": respuesta.headers.get("X-Agentopsy-Pdf-Draft"),
    "bloqueos": [b.codigo for b in comprobar(
        caso["case"].id, d.id, documents=caso["documents"], cases=caso["cases"]
    ).bloqueos],
}

# -- RA05: artefacto + manifiesto + un evento, sin reparar la cadena ----------
caso, f, d = montar("broken_audit_anchor")
p = caso["cases"].case_dir(caso["case"].id) / "artifacts" / caso["run_id"]
(p / "stdout.txt").write_text("CONTENIDO SINTETICO CAMBIADO\n", encoding="utf-8")
manifiesto = json.loads((p / "manifest.json").read_text(encoding="utf-8"))
manifiesto["stdout_sha256"] = hashlib.sha256((p / "stdout.txt").read_bytes()).hexdigest()
manifiesto["manifest_sha256"] = lectura.manifest_digest(manifiesto)
(p / "manifest.json").write_text(json.dumps(manifiesto), encoding="utf-8")
eventos = caso["audit"].entries()
for evento in eventos:
    if evento.get("action") == "tool_run_finish":
        evento["manifest_sha256"] = manifiesto["manifest_sha256"]
caso["audit"].path.write_text(
    "\n".join(json.dumps(e) for e in eventos) + "\n", encoding="utf-8"
)
ficha = {"esperado": "lectura rechazada (CadenaRotaError)",
         "audit_chain_valid": caso["audit"].verify()}
try:
    with lectura.abrir_verificado(
        caso["case"].id, caso["run_id"], "stdout",
        ambito=lectura.AMBITO_AGENTE, store=caso["artefactos"],
    ) as abierta:
        ficha.update(read_accepted=True, anchor_state=abierta.anclaje,
                     text=abierta.texto().strip())
except lectura.ArtefactoError as exc:
    ficha.update(read_accepted=False, error=type(exc).__name__)
resultados["broken_audit_anchor"] = ficha

# -- RA05b: ancla de una ejecucion MODERNA eliminada --------------------------
caso, f, d = montar("anchor_deleted")
eventos = [e for e in caso["audit"].entries() if e.get("action") != "tool_run_finish"]
caso["audit"].path.write_text(
    "\n".join(json.dumps(e) for e in eventos) + "\n", encoding="utf-8"
)
ficha = {"esperado": "lectura rechazada, nunca degradada a sin_ancla"}
try:
    with lectura.abrir_verificado(
        caso["case"].id, caso["run_id"], "stdout",
        ambito=lectura.AMBITO_AGENTE, store=caso["artefactos"],
    ) as abierta:
        ficha.update(read_accepted=True, anchor_state=abierta.anclaje)
except lectura.ArtefactoError as exc:
    ficha.update(read_accepted=False, error=type(exc).__name__)
resultados["anchor_deleted"] = ficha

# -- RA06: los dos extremos del localizador -----------------------------------
caso, f, d = montar("locator_bounds")
ruta_stdout = caso["cases"].case_dir(caso["case"].id) / "artifacts" / caso["run_id"] / "stdout.txt"
resultados["locator_bounds"] = {
    "esperado": "rechazados; el rango valido se acepta",
    "actual_bytes": len(ruta_stdout.read_bytes()),
    "actual_lines": 3,
}
for tipo, desde, hasta, etiqueta in [
    ("lineas", 1, 999999, "fin_fuera_de_rango"),
    ("lineas", 4, 4, "inicio_fuera_de_rango"),
    ("bytes", 0, 999999, "bytes_fin_fuera_de_rango"),
    ("bytes", 5, 5, "bytes_rango_vacio"),
    ("lineas", 1, 3, "rango_valido"),
]:
    try:
        ref = verificar_referencia(
            caso["case"].id,
            {"run_id": caso["run_id"], "artefacto": "stdout",
             "localizador": {"tipo": tipo, "desde": desde, "hasta": hasta}},
            store=caso["artefactos"], evidence=EvidenceManager(caso["cases"]),
        )
        resultados["locator_bounds"][etiqueta] = {
            "accepted": True, "hasta": ref.localizador.hasta,
        }
    except Exception as exc:  # noqa: BLE001
        resultados["locator_bounds"][etiqueta] = {
            "accepted": False, "error": type(exc).__name__,
        }

# -- RA03.2: hallazgo historico sin referencias en un informe nuevo -----------
caso, f, d = montar("legacy_finding")
p = caso["cases"].case_dir(caso["case"].id) / "findings.jsonl"
registro = asdict(f)
for k in ["references", "content_sha256", "provenance_state", "revision",
          "supersedes", "motivo_revision", "origin", "alcance_examinado"]:
    registro.pop(k, None)
p.write_text(json.dumps(registro) + "\n", encoding="utf-8")
historico = caso["findings"].get(caso["case"].id, f.id)
nuevo_doc = informe(caso, historico)
resultados["legacy_finding"] = {
    "esperado": "legible, pero el informe nuevo NO se aprueba",
    "finding_state": historico.provenance_state,
    "references": historico.references,
    "legible": bool(historico.title),
    **desenlace(caso, nuevo_doc),
}

# -- El RECORRIDO VALIDO -------------------------------------------------------
caso, f, d = montar("recorrido_valido")
antes = comprobar(caso["case"].id, d.id, documents=caso["documents"], cases=caso["cases"])
aprobado = aprobar(caso, d)
despues = comprobar(caso["case"].id, d.id, documents=caso["documents"], cases=caso["cases"])
with patch.object(router, "case_manager", caso["cases"]), patch.object(
    router, "document_store", caso["documents"]
):
    pdf = router.document_pdf(caso["case"].id, d.id)
resultados["recorrido_valido"] = {
    "esperado": "aprobable, final y PDF NO borrador",
    "aprobable": antes.aprobable,
    "bloqueos": [b.codigo for b in antes.bloqueos],
    "status": aprobado.status,
    "reaprobable_tras_aprobar": despues.aprobable,
    "citas": len(antes.citas),
    "pdf_status": pdf.status_code,
    "pdf_draft_header": pdf.headers.get("X-Agentopsy-Pdf-Draft"),
    "cadena_valida": caso["audit"].verify(),
}

(OUT / "resultados-ra01-ra07.json").write_text(
    json.dumps(resultados, ensure_ascii=False, indent=2), encoding="utf-8"
)
print(json.dumps(resultados, ensure_ascii=False, indent=2))
