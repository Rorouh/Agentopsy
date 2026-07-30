"""Redacción humanizada del informe — validada o rechazada ENTERA (RULE 2).

Los gates que importan:

- La prosa devuelta por el ejecutor sustituye SOLO los bloques ``p`` de §1 y
  §8; el aviso de BORRADOR se re-añade siempre y la procedencia queda declarada
  en §2 y en el audit (``report_humanized``).
- Referentes cerrados: una técnica, un UUID o una cadena hex que el informe
  determinista no contiene rechazan la pasada entera con un error accionable —
  nunca se publica prosa sin validar.
- Un envelope que no cumple el contrato JSON falla fuerte, no «se arregla».
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from forensia.reports import narrative
from forensia.reports.humanize import ReportHumanizeError, humanize_report


class _FakeExecutor:
    id = "fake"
    name = "Fake CLI"
    is_local = True
    supports_session_resume = False

    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.prompts: list[str] = []
        self.contexts: list[dict[str, Any]] = []

    def run(self, prompt: str, context: dict[str, Any] | None = None):
        self.prompts.append(prompt)
        self.contexts.append(dict(context or {}))
        return type("R", (), {"text": self.reply})()


class _ListAudit(list):
    def append(self, event: dict[str, Any]) -> None:  # type: ignore[override]
        super().append(dict(event))


def _report() -> dict[str, Any]:
    return {
        "title": "Informe pericial forense — Caso",
        "type": "pericial",
        "summary": "resumen",
        "evidence_id": None,
        "version": "v0.1",
        "author": "ramos",
        "sections": [
            {"num": narrative.SEC_RESUMEN, "title": "Resumen ejecutivo", "blocks": [
                {"t": "p", "text": "El caso documenta T1003 con el run 11111111."},
            ]},
            {"num": narrative.SEC_DATOS, "title": "Datos", "blocks": [
                {"t": "kv", "pairs": [
                    {"k": "Redacción narrativa", "v": "determinista"},
                ]},
            ]},
            {"num": narrative.SEC_RELATO, "title": "Relato", "blocks": [
                {"t": "p", "text": "El relato completo del caso."},
            ]},
            {"num": narrative.SEC_CONCLUSIONES, "title": "Conclusiones", "blocks": [
                {"t": "p", "text": "Conclusión determinista sobre T1003."},
                {"t": "p", "text": "Documento generado en estado BORRADOR."},
            ]},
        ],
    }


def _reply(resumen: list[str], conclusiones: list[str]) -> str:
    return json.dumps({"resumen": resumen, "conclusiones": conclusiones})


def test_valid_prose_replaces_sections_and_declares_provenance() -> None:
    executor = _FakeExecutor(_reply(
        ["La investigación reconstruye T1003 con el run 11111111."],
        ["En conclusión, T1003 queda documentada."],
    ))
    audit = _ListAudit()

    out = humanize_report("caso-1", _report(), executor=executor, audit=audit)

    resumen = next(s for s in out["sections"] if s["num"] == narrative.SEC_RESUMEN)
    assert resumen["blocks"][0]["text"].startswith("La investigación reconstruye")
    concl = next(s for s in out["sections"] if s["num"] == narrative.SEC_CONCLUSIONES)
    # La prosa nueva + el aviso de BORRADOR re-añadido SIEMPRE al final.
    assert "En conclusión" in concl["blocks"][0]["text"]
    assert "BORRADOR" in concl["blocks"][-1]["text"]
    # Procedencia declarada en §2 y en el audit.
    datos = next(s for s in out["sections"] if s["num"] == narrative.SEC_DATOS)
    kv = datos["blocks"][0]["pairs"][0]
    assert "asistidos por Fake CLI" in kv["v"]
    assert any(e.get("action") == "report_humanized" for e in audit)
    # El ejecutor recibió el audit del caso en su contexto (argv literal auditado).
    assert executor.contexts[0]["case_id"] == "caso-1"
    # El informe de partida NO se muta.
    original = _report()
    assert original["sections"][0]["blocks"][0]["text"].startswith("El caso documenta")


def test_prompt_carries_the_case_material_and_the_style_contract() -> None:
    """El pase recibe el MATERIAL bruto del caso (hallazgos íntegros — donde
    viven las entidades concretas —, evidencias, veredictos MITRE), no solo la
    prosa determinista, y el contrato de estilo de la referencia (continuidad
    de sujeto, veredicto por delante). Sin eso el ejecutor no puede redactar al
    nivel del resumen de referencia (2026-07-30)."""
    report = _report()
    report["sections"].insert(2, {
        "num": narrative.SEC_CUSTODIA, "title": "Cadena de custodia", "blocks": [
            {"t": "kv", "pairs": [
                {"k": "Fichero original", "v": "memoria.raw"},
                {"k": "SO detectado", "v": "windows"},
                {"k": "SHA-256 baseline", "v": "ab" * 32},
            ]},
        ],
    })
    report["sections"].append({
        "num": narrative.SEC_HALLAZGOS, "title": "Hallazgos", "blocks": [
            {"t": "finding", "sev": "critical", "title": "Exfiltración por correo",
             "text": "El usuario IEUser envió CLIENTES.xls a insider2@dominio.org.",
             "tags": ["volatility3", "T1003"], "meta": "Run: 11111111"},
        ],
    })
    report["sections"].append({
        "num": narrative.SEC_MITRE, "title": "Correlación", "blocks": [
            {"t": "table", "headers": ["Técnica", "Veredicto"],
             "rows": [["T1003", "Confirmada"]]},
        ],
    })
    executor = _FakeExecutor(_reply(
        ["La investigación confirma T1003 con el run 11111111."],
        ["Cierre sobre T1003."],
    ))

    humanize_report("caso-1", report, executor=executor, audit=None)

    prompt = executor.prompts[0]
    # El material bruto viaja: el detalle del hallazgo (las entidades), la
    # evidencia por su fichero y el veredicto adjudicado.
    assert "IEUser" in prompt and "insider2@dominio.org" in prompt
    assert "memoria.raw" in prompt
    assert "Confirmada" in prompt
    # El hash baseline NO viaja como dato de evidencia (no es material de prosa).
    assert "ab" * 32 not in prompt
    # El contrato de estilo de la referencia.
    assert "CONTINUIDAD DE SUJETO" in prompt
    assert "veredicto por delante" in prompt
    assert "nunca se rellena" in prompt


def test_unknown_technique_rejects_the_whole_pass() -> None:
    executor = _FakeExecutor(_reply(
        ["El atacante usó T1566 para el acceso inicial."],  # no está en el informe
        ["Conclusión sobre T1003."],
    ))
    with pytest.raises(ReportHumanizeError, match="T1566"):
        humanize_report("caso-1", _report(), executor=executor, audit=None)


def test_hex_token_extending_a_known_prefix_is_rejected() -> None:
    executor = _FakeExecutor(_reply(
        ["El run 11111111beef lo demuestra."],  # extiende el prefijo real: fabricación
        ["Conclusión sobre T1003."],
    ))
    with pytest.raises(ReportHumanizeError, match="11111111beef"):
        humanize_report("caso-1", _report(), executor=executor, audit=None)


def test_unknown_uuid_is_rejected() -> None:
    executor = _FakeExecutor(_reply(
        ["Lo ancla el hallazgo 99999999-9999-4999-8999-999999999999."],
        ["Conclusión sobre T1003."],
    ))
    with pytest.raises(ReportHumanizeError, match="99999999"):
        humanize_report("caso-1", _report(), executor=executor, audit=None)


def test_non_contract_reply_fails_loud() -> None:
    executor = _FakeExecutor("Aquí tienes el informe mejorado en prosa libre.")
    with pytest.raises(ReportHumanizeError, match="JSON"):
        humanize_report("caso-1", _report(), executor=executor, audit=None)


def test_missing_section_list_fails_loud() -> None:
    executor = _FakeExecutor(json.dumps({"resumen": ["ok"]}))
    with pytest.raises(ReportHumanizeError, match="conclusiones"):
        humanize_report("caso-1", _report(), executor=executor, audit=None)
