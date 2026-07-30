"""Redacción íntegra del informe pericial por el ejecutor seleccionado.

Los gates que importan (``forensia.reports.writer``):

- El informe es del MODELO: la prosa, el número de bloques y la longitud salen
  de su respuesta, no de una plantilla.
- Lo ÚNICO común entre informes es el índice — y se exige EXACTO: falta una
  sección, sobra una, cambia el orden o cambia un título → nada se publica.
- Las cuatro puertas de custodia rechazan la redacción ENTERA: modelo de
  bloques, referentes cerrados del material, comandos literales auditados y
  «sin hallazgos no hay informe».
- La llamada queda auditada (``report_written``) y el prompt lleva el índice y
  el material, nunca prosa prefabricada.
"""

from __future__ import annotations

import json

import pytest

from forensia.executors.base import ExecutorAvailability, ExecutorResult, PromptExecutor
from forensia.reports.indice import NUMS, TITULOS
from forensia.reports.writer import (
    ENCARGO,
    ReportWriteError,
    build_prompt,
    write_report,
)

ARGV = "tsk_fls -m C:/ -r -o 2048 /evidence/original.E01"
RUN_ID = "7e9f1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b"
SHA_ART = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _material() -> dict:
    return {
        "caso": {
            "id": "caso-1", "nombre": "Murcielago", "examinador": "ramos",
            "encargo": "Determinar si hubo exfiltracion de documentos.",
            "perfil_so": "windows", "origen_del_perfil": "triage",
            "estado": "active", "apertura": "2026-07-01T08:00:00Z",
        },
        "perito": {"nombre": "Daniel Ramos"},
        "evidencias": [{
            "evidence_id": "11111111-2222-4333-8444-555555555555",
            "fichero_original": "original.E01",
            "naturaleza": "imagen forense de disco",
            "sha256_baseline": "a" * 64,
            "tamano": "8,0 GB (8589934592 bytes)",
            "so_detectado": "windows", "tipo_detectado": "container_disk",
            "super_timeline": {"generada": False},
        }],
        "hallazgos": [{
            "id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "titulo": "Tarea programada de persistencia",
            "detalle": "Se crea la tarea `updater` que ejecuta update.exe.",
            "severidad": "high", "tipo": "afirmacion", "confianza": 0.9,
            "observed_at": "2026-03-14T08:12:44Z", "run_id": RUN_ID,
            "artifact_sha256": SHA_ART, "tool_id": "tsk_fls",
            "mitre_hints": ["T1053.005"],
        }],
        "trabajos": [{
            "run_id": RUN_ID, "tool_id": "tsk_fls", "tool_version": "4.12.1",
            "argv": ARGV.split(), "argv_literal": ARGV,
            "status": "finished", "exit_code": 0,
            "finding_ids": ["aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"],
        }],
        "uso_de_tools": [{"tool_id": "tsk_fls", "total": 1, "ok": 1, "failed": 0}],
        "mitre": [{
            "technique_id": "T1053.005", "nombre": "Scheduled Task",
            "tactica_id": "TA0003", "tactica": "Persistencia",
            "propuesta_por": [], "veredicto": "Confirmada",
        }],
        "revisiones": [],
        "traza": [],
        "integridad": {"hash_chain_verified": True, "herramienta": "Agentopsy 0.1.0"},
    }


def _reply(secciones=None, resumen="Informe del caso Murcielago.") -> str:
    if secciones is None:
        secciones = [
            {"num": n, "titulo": TITULOS[n],
             "bloques": [{"t": "p", "text": f"Contenido redactado de la seccion {n}."}]}
            for n in NUMS
        ]
    return json.dumps({"resumen": resumen, "secciones": secciones}, ensure_ascii=False)


class FakeExecutor(PromptExecutor):
    """Ejecutor de prueba: devuelve el texto que se le da y guarda el prompt."""

    id = "claude-code"
    name = "Claude Code"
    is_local = False

    def __init__(self, text: str) -> None:
        self._text = text
        self.prompt: str | None = None
        self.context: dict | None = None

    def is_available(self) -> ExecutorAvailability:
        return ExecutorAvailability(available=True)

    def run(self, prompt: str, context: dict | None = None) -> ExecutorResult:
        self.prompt = prompt
        self.context = context or {}
        return ExecutorResult(
            executor=self.id, text=self._text, argv=("claude", "-p"), exit_code=0,
            duration_ms=1, raw=self._text,
        )


class FakeAudit:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def append(self, event: dict) -> dict:
        self.events.append(event)
        return event


def _write(text: str, material: dict | None = None, **kw):
    executor = FakeExecutor(text)
    audit = FakeAudit()
    doc = write_report(
        "caso-1", executor=executor, audit=audit,
        material=material if material is not None else _material(), **kw,
    )
    return doc, executor, audit


# ── el informe es del modelo ──────────────────────────────────────────────────


def test_the_report_is_what_the_model_wrote() -> None:
    secciones = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": f"Prosa {n}."}]}
        for n in NUMS
    ]
    # Una sección larga y otra corta: la longitud la decide el modelo.
    secciones[5]["bloques"] = [
        {"t": "h3", "text": "6.1 Altos (1)"},
        {"t": "finding", "sev": "high", "title": "6.1 Tarea programada",
         "text": "Se crea la tarea updater.", "tags": ["tsk_fls", "T1053.005"],
         "meta": f"Run: {RUN_ID}"},
        {"t": "kv", "pairs": [{"k": "SHA-256 artefacto", "v": SHA_ART}]},
    ]
    doc, _, _ = _write(_reply(secciones))

    assert doc["type"] == "pericial"
    assert doc["title"] == "Informe pericial forense — Murcielago"
    assert doc["author"] == "Daniel Ramos"
    assert [s["num"] for s in doc["sections"]] == list(NUMS)
    assert doc["sections"][5]["blocks"][1]["t"] == "finding"
    assert doc["sections"][0]["blocks"][0]["text"] == "Prosa 1."


def test_prompt_carries_the_indice_and_the_material_not_prose() -> None:
    _, executor, _ = _write(_reply())
    prompt = executor.prompt or ""
    for num in NUMS:
        assert f"§{num} — {TITULOS[num]}" in prompt
    assert "Murcielago" in prompt and ARGV in prompt
    # El contrato de respuesta va AL FINAL (sostiene el parseo estricto).
    assert prompt.rindex("FORMATO DE RESPUESTA") > prompt.rindex("MATERIAL DEL CASO")
    # Presupuesto de tiempo propio de la redacción, no el del turno del agente.
    assert (executor.context or {}).get("timeout") == 900


def test_version_is_derived_from_the_case_revisions() -> None:
    material = _material()
    material["revisiones"] = [
        {"version": "v0.1", "fecha": "2026-07-02T10:00:00Z", "autor": "ramos",
         "estado": "final", "sha256": "d" * 64},
    ]
    doc, _, _ = _write(_reply(), material=material)
    assert doc["version"] == "v0.2"

    # La versión que declara el operador manda.
    doc2, _, _ = _write(_reply(), material=material, perito={"version": "v2.0"})
    assert doc2["version"] == "v2.0"


def test_the_pass_is_audited() -> None:
    _, _, audit = _write(_reply())
    written = [e for e in audit.events if e["action"] == "report_written"]
    assert len(written) == 1
    assert written[0]["executor"] == "claude-code"
    assert written[0]["sections"] == list(NUMS)


# ── puerta: sin hallazgos no hay informe ──────────────────────────────────────


def test_a_case_without_findings_produces_no_report() -> None:
    material = _material()
    material["hallazgos"] = []
    with pytest.raises(ReportWriteError, match="ningún hallazgo"):
        _write(_reply(), material=material)


# ── puerta 1: el índice, exacto ───────────────────────────────────────────────


def test_a_missing_section_rejects_the_whole_report() -> None:
    secciones = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": "x."}]}
        for n in NUMS if n != "8"
    ]
    with pytest.raises(ReportWriteError, match="índice canónico"):
        _write(_reply(secciones))


def test_an_extra_section_rejects_the_whole_report() -> None:
    secciones = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": "x."}]}
        for n in NUMS
    ]
    secciones.append({"num": "11", "titulo": "Bibliografia",
                      "bloques": [{"t": "p", "text": "x."}]})
    with pytest.raises(ReportWriteError, match="índice canónico"):
        _write(_reply(secciones))


def test_reordering_the_indice_rejects_the_whole_report() -> None:
    nums = list(NUMS)
    nums[2], nums[3] = nums[3], nums[2]
    secciones = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": "x."}]}
        for n in nums
    ]
    with pytest.raises(ReportWriteError, match="orden exacto"):
        _write(_reply(secciones))


def test_a_renamed_section_title_is_rejected() -> None:
    secciones = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": "x."}]}
        for n in NUMS
    ]
    secciones[1]["titulo"] = "Sumario para la direccion"
    with pytest.raises(ReportWriteError, match="no se reescriben"):
        _write(_reply(secciones))


def test_an_empty_section_is_rejected() -> None:
    secciones = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": "x."}]}
        for n in NUMS
    ]
    secciones[9]["bloques"] = []
    with pytest.raises(ReportWriteError, match="sin bloques"):
        _write(_reply(secciones))


# ── puerta 2: el modelo de bloques ────────────────────────────────────────────


def test_an_invented_block_type_is_rejected() -> None:
    secciones = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": "x."}]}
        for n in NUMS
    ]
    secciones[0]["bloques"].append({"t": "figura", "src": "grafico.png"})
    with pytest.raises(ReportWriteError, match="tipo de bloque desconocido"):
        _write(_reply(secciones))


def test_a_finding_block_needs_a_valid_severity() -> None:
    secciones = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": "x."}]}
        for n in NUMS
    ]
    secciones[5]["bloques"] = [
        {"t": "finding", "sev": "gravisima", "title": "6.1 x", "text": "y"}
    ]
    with pytest.raises(ReportWriteError, match="severidad"):
        _write(_reply(secciones))


def test_a_row_wider_than_its_headers_is_rejected() -> None:
    secciones = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": "x."}]}
        for n in NUMS
    ]
    secciones[3]["bloques"] = [
        {"t": "table", "headers": ["Tecnica", "Veredicto"],
         "rows": [["T1053.005", "Confirmada", "sobra"]]}
    ]
    with pytest.raises(ReportWriteError, match="celdas"):
        _write(_reply(secciones))


def test_unknown_block_keys_never_reach_the_store() -> None:
    secciones = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": "x."}]}
        for n in NUMS
    ]
    secciones[0]["bloques"] = [
        {"t": "p", "text": "Prosa.", "estilo": "negrita", "onclick": "alert(1)"}
    ]
    doc, _, _ = _write(_reply(secciones))
    assert doc["sections"][0]["blocks"][0] == {"t": "p", "text": "Prosa."}


# ── puerta 3: referentes cerrados ─────────────────────────────────────────────


def test_an_invented_attck_technique_rejects_the_whole_report() -> None:
    secciones = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": "x."}]}
        for n in NUMS
    ]
    secciones[3]["bloques"] = [{"t": "p", "text": "Se observa T1486 (Data Encrypted)."}]
    with pytest.raises(ReportWriteError, match="T1486"):
        _write(_reply(secciones))


def test_an_invented_hash_rejects_the_whole_report() -> None:
    secciones = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": "x."}]}
        for n in NUMS
    ]
    secciones[7]["bloques"] = [{"t": "p", "text": "Hash del binario: deadbeefcafe1234."}]
    with pytest.raises(ReportWriteError, match="hexadecimal"):
        _write(_reply(secciones))


def test_a_hash_prefix_from_the_material_is_accepted() -> None:
    secciones = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": "x."}]}
        for n in NUMS
    ]
    secciones[5]["bloques"] = [{"t": "p", "text": f"Artefacto {SHA_ART[:12]}…"}]
    doc, _, _ = _write(_reply(secciones))
    assert SHA_ART[:12] in doc["sections"][5]["blocks"][0]["text"]


def test_a_foreign_uuid_rejects_the_whole_report() -> None:
    secciones = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": "x."}]}
        for n in NUMS
    ]
    secciones[5]["bloques"] = [
        {"t": "p", "text": "Hallazgo 99999999-8888-4777-8666-555555555555."}
    ]
    with pytest.raises(ReportWriteError, match="no pertenece a"):
        _write(_reply(secciones))


def test_a_long_decimal_is_not_mistaken_for_a_hash() -> None:
    secciones = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": "x."}]}
        for n in NUMS
    ]
    secciones[4]["bloques"] = [{"t": "p", "text": "La imagen ocupa 8589934592 bytes."}]
    doc, _, _ = _write(_reply(secciones))
    assert "8589934592" in doc["sections"][4]["blocks"][0]["text"]


# ── puerta 4: comandos literales ──────────────────────────────────────────────


def test_an_audited_argv_can_be_quoted_verbatim() -> None:
    secciones = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": "x."}]}
        for n in NUMS
    ]
    secciones[6]["bloques"] = [
        {"t": "kv", "pairs": [{"k": "Herramienta", "v": "tsk_fls 4.12.1"}]},
        {"t": "code", "text": ARGV},
    ]
    doc, _, _ = _write(_reply(secciones))
    assert doc["sections"][6]["blocks"][1] == {"t": "code", "text": ARGV}


def test_a_rewritten_command_rejects_the_whole_report() -> None:
    secciones = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": "x."}]}
        for n in NUMS
    ]
    # Un flag de más: el informe citaría un comando que NUNCA se ejecutó.
    secciones[6]["bloques"] = [{"t": "code", "text": ARGV + " -p"}]
    with pytest.raises(ReportWriteError, match="comando auditado"):
        _write(_reply(secciones))


def test_only_the_whitespace_is_normalised_when_matching_a_command() -> None:
    secciones = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": "x."}]}
        for n in NUMS
    ]
    secciones[6]["bloques"] = [{"t": "code", "text": f"  {ARGV.replace(' ', '   ')}  "}]
    doc, _, _ = _write(_reply(secciones))
    assert doc["sections"][6]["blocks"][0]["text"] == ARGV


# ── contrato de respuesta ─────────────────────────────────────────────────────


def test_a_non_json_answer_is_an_actionable_error() -> None:
    with pytest.raises(ReportWriteError, match="no devolvió el objeto JSON"):
        _write("Claro, aquí tienes el informe: primero el resumen ejecutivo…")


def test_a_truncated_json_names_the_likely_cause() -> None:
    with pytest.raises(ReportWriteError, match="cortado"):
        _write('{"resumen": "x", "secciones": [{"num": "1", "titulo": "Contr')


def test_a_reply_without_summary_is_rejected() -> None:
    with pytest.raises(ReportWriteError, match="`resumen`"):
        _write(_reply(resumen=""))


def test_a_json_inside_a_markdown_fence_is_accepted() -> None:
    doc, _, _ = _write("```json\n" + _reply() + "\n```")
    assert [s["num"] for s in doc["sections"]] == list(NUMS)


def test_the_indice_is_the_only_thing_two_reports_share() -> None:
    """Dos casos, dos redacciones distintas: cambia el contenido y la longitud,
    NO el índice."""
    uno = [
        {"num": n, "titulo": TITULOS[n], "bloques": [{"t": "p", "text": f"Caso A {n}."}]}
        for n in NUMS
    ]
    otro = [
        {"num": n, "titulo": TITULOS[n], "bloques": [
            {"t": "p", "text": f"Caso B, parrafo primero de {n}."},
            {"t": "p", "text": f"Caso B, parrafo segundo de {n}."},
        ]}
        for n in NUMS
    ]
    doc_a, _, _ = _write(_reply(uno))
    doc_b, _, _ = _write(_reply(otro))

    assert [s["num"] for s in doc_a["sections"]] == [s["num"] for s in doc_b["sections"]]
    assert [s["title"] for s in doc_a["sections"]] == [s["title"] for s in doc_b["sections"]]
    assert doc_a["sections"][0]["blocks"] != doc_b["sections"][0]["blocks"]
    assert len(doc_b["sections"][0]["blocks"]) == 2


def test_the_button_is_equivalent_to_sending_the_operators_request() -> None:
    """Pulsar «Finalizar investigación» equivale a pedirle al modelo el informe
    completo: el encargo viaja LITERAL y por delante de todo lo demás."""
    prompt = build_prompt(_material())
    assert prompt.startswith(f"ENCARGO: {ENCARGO}")
    assert "informe de peritaje forense completo" in prompt
    assert "todos los hallazgos y evidencias recopiladas" in prompt


def test_build_prompt_has_no_prefabricated_prose_for_the_sections() -> None:
    """El prompt lleva el CONTRATO de cada sección, no su redacción: nada de lo
    que el modelo debe escribir viene ya escrito."""
    prompt = build_prompt(_material())
    assert "plantilla" in prompt  # ...para decir que NO se rellena una
    assert "No rellenas una plantilla" in prompt
    assert "la LONGITUD de cada sección" in prompt
