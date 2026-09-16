"""El MATERIAL de redacción del informe: todo lo persistido, sin una frase.

Los gates que importan (``agentopsy.reports.material``):

- Todo lo que el caso tiene registrado llega al material: encargo, evidencias con
  su custodia verificada, hallazgos ÍNTEGROS (con hashes completos), ejecuciones
  con su argv auditado, uso de herramientas, correlación ATT&CK con veredicto,
  revisiones previas e integridad de la cadena.
- El material NO redacta: ni párrafos, ni transiciones, ni conclusiones. Solo la
  NATURALEZA de cada evidencia y el orden por volatilidad son decisiones de
  presentación, y las dos son datos.
- RULE 2: un encargo ausente queda vacío (no se fabrica), un ``detected_kind``
  desconocido degrada a «evidencia» y un recorte por cota se DECLARA.
"""

from __future__ import annotations

import hashlib
import uuid

import pytest

from agentopsy.i18n import _LANG_ACTUAL, set_current_lang
from agentopsy.audit.log import AuditLog
from agentopsy.cases import CaseManager
from agentopsy.evidence import EvidenceManager
from agentopsy.findings.store import FindingStore
from agentopsy.mitre.coverage import UNMARK, CoverageStore
from agentopsy.reports.material import MAX_HALLAZGOS, build_material, naturaleza
from agentopsy.reports.store import DocumentStore

ARGV = ["tsk_fls", "-r", "-o", "2048", "/evidence/disk.raw"]


@pytest.fixture
def entorno(tmp_path):
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(
        name="Murcielago", examiner="Daniel Ramos", os_profile="windows",
        notes="Determinar si hubo exfiltracion de documentos contables.",
    )
    evidence = EvidenceManager(cases)
    findings = FindingStore(cases)
    documents = DocumentStore(cases)

    src = tmp_path / "disk.raw"
    payload = b"AGENTOPSY-EVIDENCE" * 64
    src.write_bytes(payload)
    handle = evidence.register(case.id, str(src))

    return {
        "cases": cases, "case": case, "evidence": evidence, "findings": findings,
        "documents": documents, "handle": handle,
        "coverage": CoverageStore(cases, findings),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _build(entorno, **over):
    kwargs = {
        "cases": entorno["cases"],
        "evidence": entorno["evidence"],
        "findings": entorno["findings"],
        "documents": entorno["documents"],
        "coverage": entorno["coverage"],
        "usage_fn": lambda _cid: [{"tool_id": "tsk_fls", "total": 1, "ok": 1, "failed": 0}],
        "traza_fn": lambda _cid: [],
        "fs_timeline_fn": lambda _cid, _eid: None,
    }
    kwargs.update(over)
    return build_material(entorno["case"].id, over.pop("perito", None), **kwargs)


def test_the_engagement_travels_verbatim_and_is_never_invented(entorno) -> None:
    material = _build(entorno)
    assert "exfiltracion de documentos contables" in material["caso"]["encargo"]

    sin_encargo = entorno["cases"].create(name="Sin notas", examiner="x", os_profile="unix")
    vacio = build_material(
        sin_encargo.id,
        cases=entorno["cases"], evidence=entorno["evidence"],
        findings=entorno["findings"], documents=entorno["documents"],
        coverage=entorno["coverage"], usage_fn=lambda _cid: [], traza_fn=lambda _cid: [],
        fs_timeline_fn=lambda _cid, _eid: None,
    )
    assert vacio["caso"]["encargo"] == ""  # RULE 2: no se fabrica un encargo


def test_evidence_carries_its_verified_custody(entorno) -> None:
    material = _build(entorno)
    assert len(material["evidencias"]) == 1
    ev = material["evidencias"][0]
    assert ev["sha256_baseline"] == entorno["sha256"]
    # El nombre que el perito aportó, y el de la copia inmutable bajo custodia.
    assert ev["fichero_original"] == "disk.raw"
    assert ev["fichero_en_el_caso"] == "original.raw"
    assert ev["cadena_auditoria_verificada"] is True
    assert ev["hash_de_registro"]
    assert ev["super_timeline"] == {"generada": False}


def test_findings_travel_whole_with_full_hashes(entorno) -> None:
    run_id = str(uuid.uuid4())
    sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    entorno["findings"].append(entorno["case"].id, {
        "title": "Tarea programada de persistencia",
        "summary": "Se crea la tarea `updater` que ejecuta C:/Users/Public/update.exe.",
        "severity": "high", "confidence": 0.9, "observed_at": "2026-03-14T08:12:44Z",
        "run_id": run_id, "artifact_sha256": sha, "tool_id": "tsk_fls",
        "mitre_hints": ["T1053"],
    })
    material = _build(entorno)

    hallazgo = material["hallazgos"][0]
    assert hallazgo["detalle"].endswith("update.exe.")  # el summary ÍNTEGRO
    assert hallazgo["artifact_sha256"] == sha           # sin truncar
    assert hallazgo["run_id"] == run_id
    assert hallazgo["confianza"] == 0.9
    assert hallazgo["mitre_hints"] == ["T1053"]


def test_audited_runs_reach_the_material(entorno) -> None:
    case_id = entorno["case"].id
    audit = AuditLog(entorno["cases"].case_dir(case_id) / "audit.jsonl")
    run_id = str(uuid.uuid4())
    audit.append({
        "action": "tool_run_start", "case_id": case_id, "run_id": run_id,
        "tool_id": "tsk_fls", "argv": ARGV, "tool_version": "4.12.1",
    })
    audit.append({
        "action": "tool_run_finish", "case_id": case_id, "run_id": run_id,
        "status": "finished", "exit_code": 0,
    })

    material = _build(entorno)
    trabajo = next(t for t in material["trabajos"] if t["run_id"] == run_id)
    assert trabajo["argv"] == ARGV
    assert trabajo["argv_literal"] == " ".join(ARGV)
    assert material["uso_de_tools"][0]["tool_id"] == "tsk_fls"


def test_previous_revisions_feed_the_version_control_section(entorno) -> None:
    entorno["documents"].create(entorno["case"].id, {
        "title": "Informe pericial forense — Murcielago", "type": "pericial",
        "version": "v0.1", "author": "Daniel Ramos", "summary": "x",
        "sections": [{"num": "1", "title": "Control de versiones",
                      "blocks": [{"t": "p", "text": "x"}]}],
    })
    # Un documento que NO es pericial no cuenta como revisión del informe.
    entorno["documents"].create(entorno["case"].id, {
        "title": "Acta de adquisicion", "type": "acta", "summary": "x",
        "sections": [{"num": "1", "title": "Acta", "blocks": [{"t": "p", "text": "x"}]}],
    })

    material = _build(entorno)
    assert [r["version"] for r in material["revisiones"]] == ["v0.1"]
    assert material["revisiones"][0]["sha256"]


def test_the_material_holds_no_prose(entorno) -> None:
    """Ni un párrafo, ni una sección, ni un bloque: la redacción es del modelo."""
    material = _build(entorno)
    assert "sections" not in material and "secciones" not in material
    for key in material:
        assert key in {
            "caso", "perito", "evidencias", "hallazgos", "trabajos",
            "uso_de_tools", "mitre", "revisiones", "traza", "integridad",
            "truncado",
        }


def test_a_truncated_collection_is_declared(entorno) -> None:
    case_id = entorno["case"].id
    run_id = str(uuid.uuid4())
    for i in range(MAX_HALLAZGOS + 3):
        entorno["findings"].append(case_id, {
            "title": f"Hallazgo {i}", "summary": f"detalle {i}", "severity": "low",
            "run_id": run_id, "artifact_sha256": "a" * 64,
        })

    material = _build(entorno)
    assert len(material["hallazgos"]) == MAX_HALLAZGOS
    assert material["truncado"]["hallazgos"] == {
        "total": MAX_HALLAZGOS + 3, "incluidos": MAX_HALLAZGOS,
    }


def test_integrity_of_the_hash_chain_is_reported(entorno) -> None:
    material = _build(entorno)
    assert material["integridad"]["hash_chain_verified"] is True


def test_cost_is_only_what_the_provider_reported(entorno) -> None:
    """El coste del anexo NO se calcula: se lee de `cost_usd`, que hoy sólo trae
    el envoltorio de Claude Code. Un ejecutor que devuelve tokens sin precio
    (Codex, Gemini) no entra, porque con caché los tokens no miden el coste:
    hay una corrida medida donde el coste cayó un 79 % mientras los tokens de
    entrada subían un 13,5 %. Sumar unidades distintas sería inventar la cifra.
    """
    audit = AuditLog(entorno["cases"].case_dir(entorno["case"].id) / "audit.jsonl")
    audit.append({
        "action": "executor_run_finish", "executor": "claude-code",
        "cost_usd": 0.1150, "usage_source": "claude_code.usage",
    })
    audit.append({
        "action": "executor_run_finish", "executor": "claude-code",
        "cost_usd": 0.0141, "usage_source": "claude_code.usage",
    })
    # Codex reporta tokens y ningún precio: queda fuera, no se le adjudica cero.
    audit.append({
        "action": "executor_run_finish", "executor": "codex",
        "input_tokens": 4000, "output_tokens": 120, "usage_source": "codex.json",
    })

    coste = _build(entorno)["integridad"]["coste_reportado"]
    assert set(coste) == {"claude-code"}
    assert coste["claude-code"] == {
        "corridas_con_precio": 2, "coste_usd": 0.1291, "fuente": "claude_code.usage",
    }


def test_no_cost_key_at_all_when_nobody_reported_one(entorno) -> None:
    """Sin ninguna corrida con precio, la clave NO viaja: el anexo no menciona el
    coste en vez de escribir un cero, que se leería como «fue gratis» (RULE 2).
    """
    assert "coste_reportado" not in _build(entorno)["integridad"]


def test_the_examiner_signs_when_no_perito_is_given(entorno) -> None:
    assert _build(entorno)["perito"]["nombre"] == "Daniel Ramos"
    material = build_material(
        entorno["case"].id, {"name": "Otra Perita", "colegiado": "COL-1234"},
        cases=entorno["cases"], evidence=entorno["evidence"],
        findings=entorno["findings"], documents=entorno["documents"],
        coverage=entorno["coverage"], usage_fn=lambda _cid: [], traza_fn=lambda _cid: [],
        fs_timeline_fn=lambda _cid, _eid: None,
    )
    assert material["perito"] == {"nombre": "Otra Perita", "colegiado": "COL-1234"}


class _Handle:
    def __init__(self, name: str, kind: str) -> None:
        from pathlib import Path
        self.original_path = Path(name)
        self.detected_kind = kind


@pytest.mark.parametrize(
    "name,kind,expected",
    [
        ("mem.raw", "memory", "volcado de memoria RAM"),
        ("disk.raw", "disk", "imagen de disco"),
        ("vm.vmdk", "container_disk", "imagen de disco virtual"),
        ("caso.E01", "container_disk", "imagen forense de disco"),
        ("raro.bin", "", "evidencia"),
        ("raro.bin", "loquesea", "evidencia"),
    ],
)
def test_nature_comes_from_triage_and_is_never_guessed(name, kind, expected) -> None:
    # La naturaleza se escribe en el idioma del INFORME; los casos de esta
    # tabla están en castellano, así que se fija esa lengua.
    token = set_current_lang("es")
    try:
        assert naturaleza(_Handle(name, kind)) == expected
    finally:
        _LANG_ACTUAL.reset(token)


def test_memory_is_enumerated_first(entorno) -> None:
    """La memoria delante (mayor volatilidad). Es una afirmación sobre la
    ENUMERACIÓN, no sobre el orden en que se procesó nada."""
    class _Ev:
        def __init__(self, handles):
            self._handles = handles

        def list(self, _case_id):
            return self._handles

        def get(self, case_id, evidence_id):  # pragma: no cover — no se usa
            raise KeyError(evidence_id)

    disco = _Handle("disk.raw", "disk")
    memoria = _Handle("mem.raw", "memory")
    from agentopsy.reports.material import _por_volatilidad

    assert _por_volatilidad([disco, memoria]) == [memoria, disco]


# --- el veredicto del perito sobre una técnica ATT&CK -------------------------
#
# El fallo de 2026-08-17: confirmar (o sospechar, o descartar) una técnica en la
# matriz dejaba el caso SIN informe. `_ADJ_KEY` mapeaba el estado a una clave del
# catálogo y sólo estaba declarada la de «sin dictamen», así que el material se
# construía mientras nadie hubiese dictaminado nada y levantaba
# `MensajeDesconocido` en cuanto había un veredicto. Como el informe se publica
# entero o nada, la única salida era retirar el dictamen: renunciar al trabajo
# pericial para poder entregar. Estos tres fijan las tres caras que faltaban.


@pytest.mark.parametrize(
    "status, esperado_es, esperado_en",
    [
        ("confirmada", "Confirmada", "Confirmed"),
        ("sospechosa", "Sospechosa", "Suspected"),
        ("descartada", "Descartada", "Ruled out"),
    ],
)
def test_una_tecnica_dictaminada_por_el_perito_llega_al_material(
    entorno, status, esperado_es, esperado_en
) -> None:
    entorno["coverage"].adjudicate(
        entorno["case"].id, "T1053", status, "Tarea programada creada por el atacante."
    )

    def _veredicto(lang: str) -> dict:
        token = set_current_lang(lang)
        try:
            material = _build(entorno)
        finally:
            _LANG_ACTUAL.reset(token)
        return next(f for f in material["mitre"] if f["technique_id"] == "T1053")

    fila = _veredicto("es")
    assert fila["veredicto"] == esperado_es
    # La motivación y la fecha son del perito: viajan tal cual, en cualquier idioma.
    assert fila["motivacion_del_veredicto"] == "Tarea programada creada por el atacante."
    assert fila["dictaminada_en"]

    assert _veredicto("en")["veredicto"] == esperado_en


def test_una_tecnica_sin_dictamen_sigue_diciendo_que_no_lo_tiene(entorno) -> None:
    """El cuarto caso del mismo eje, el único que funcionaba: no se rompe."""
    entorno["coverage"].adjudicate(
        entorno["case"].id, "T1053", "confirmada", "Motivo."
    )
    entorno["coverage"].adjudicate(entorno["case"].id, "T1053", UNMARK, "")

    material = _build(entorno)
    filas = [f for f in material["mitre"] if f["technique_id"] == "T1053"]
    assert all(f["veredicto"] in ("No dictaminada", "") for f in filas)
