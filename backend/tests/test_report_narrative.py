"""El hilo conductor del informe pericial (forensia.reports.narrative).

Los gates que importan (encargo 2026-07-30 — narrativa sin perder detalle):

- El resumen ejecutivo ANTICIPA la historia: secuencia de hechos fechados con
  título y fecha reales, remisión a las secciones que la desarrollan, y el
  desglose técnico intacto.
- El relato ordena los hechos fechados CRONOLÓGICAMENTE aunque lleguen
  desordenados, narra lo no fechado en su propio carril (dicho como tal), y da
  a los descartes su sitio.
- Las conclusiones cierran el arco táctico en orden kill-chain y nunca computan
  como confirmada una técnica sin dictamen.
- Un caso vacío produce narrativa HONESTA (RULE 2), no relleno.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from forensia.reports import narrative


def _case(**kw):
    base = {"name": "Intrusión Alfa", "examiner": "ramos", "os_profile": "windows"}
    base.update(kw)
    return SimpleNamespace(**base)


def _finding(**kw):
    base = {
        "id": "f0000000-0000-4000-8000-000000000000",
        "title": "Hallazgo",
        "summary": "Resumen técnico.",
        "severity": "medium",
        "evidence_id": "e1",
        "tool_id": "volatility3",
        "run_id": "11111111-1111-4111-8111-111111111111",
        "created_at": "2026-07-20T10:00:00Z",
        "mitre_hints": [],
        "confidence": None,
        "observed_at": None,
        "artifact_sha256": None,
        "finding_kind": "afirmacion",
    }
    base.update(kw)
    return SimpleNamespace(**base)


def _handle():
    return SimpleNamespace(
        evidence_id="e1",
        original_path=Path("/cases/x/disk.raw"),
        registered_at="2026-07-19T09:00:00Z",
        detected_os="windows",
        detected_kind="disk",
        sha256="ab" * 32,
    )


def _text(blocks) -> str:
    return " ".join(b.get("text", "") for b in blocks)


def test_executive_summary_reflects_the_story() -> None:
    findings = [
        _finding(
            title="Volcado de credenciales", severity="critical",
            observed_at="2026-07-01T02:00:00Z", mitre_hints=["T1003"],
        ),
        _finding(title="Canal C2 residual", severity="high"),
        _finding(title="Wipe con SDelete", finding_kind="descarte"),
    ]
    coverage = [
        {"technique_id": "T1003", "tactic_id": "TA0006", "proposed_by": ["f1"],
         "status": "confirmada"},
        {"technique_id": "T1048", "tactic_id": "TA0010", "proposed_by": ["f2"],
         "status": None},
    ]
    text = _text(narrative.executive_blocks(_case(), findings, [_handle()], coverage))

    # Encuadre del encargo con la evidencia real.
    assert "Intrusión Alfa" in text
    assert "disk.raw" in text
    # La historia anticipada: el hecho fechado con su fecha y su título.
    assert "secuencia de hechos" in text
    assert "2026-07-01" in text and "Volcado de credenciales" in text
    # El carril no fechado y el descarte también se anticipan.
    assert "Canal C2 residual" in text
    assert "descartada" in text
    # El desglose técnico no se pierde y el dictamen no funde ejes.
    assert "1 de severidad crítica" in text
    assert "a la espera de dictamen" in text
    assert "no se computa como confirmada" in text
    # El mapa remite al relato y a las conclusiones.
    assert f"§{narrative.SEC_RELATO}" in text
    assert f"§{narrative.SEC_CONCLUSIONES}" in text


def test_story_orders_dated_findings_chronologically() -> None:
    findings = [
        _finding(title="Exfiltración observada", severity="high",
                 observed_at="2026-07-03T10:00:00Z"),
        _finding(title="Acceso inicial", severity="medium",
                 observed_at="2026-07-01T08:00:00Z",
                 summary="Primer indicio de entrada."),
    ]
    section = narrative.story_section(_case(), findings, [_handle()], [], [])
    text = _text(section["blocks"])

    assert section["num"] == narrative.SEC_RELATO
    assert text.index("Acceso inicial") < text.index("Exfiltración observada")
    assert "arranca el 2026-07-01" in text
    # El detalle técnico del hallazgo viaja íntegro, con su procedencia.
    assert "Primer indicio de entrada." in text
    assert "run 11111111" in text


def test_story_gives_descartes_and_open_verdicts_their_own_lanes() -> None:
    findings = [
        _finding(title="Hipótesis de wipe", finding_kind="descarte",
                 summary="No hay firmas de SDelete."),
        _finding(title="Persistencia por Run key", severity="high"),
    ]
    coverage = [
        {"technique_id": "T1547", "tactic_id": "TA0003", "proposed_by": [],
         "status": None},
    ]
    text = _text(narrative.story_section(_case(), findings, [_handle()], coverage, [])["blocks"])

    assert "Vías exploradas y descartadas" in text
    assert "No hay firmas de SDelete." in text
    assert "fecha directa en la evidencia" in text  # el carril no fechado se dice
    assert "Queda abierto el dictamen" in text and "T1547" in text


def test_conclusions_close_the_arc_in_kill_chain_order() -> None:
    findings = [
        _finding(title="Volcado de credenciales", severity="critical"),
        _finding(title="Canal de exfiltración", severity="high"),
    ]
    coverage = [
        # Deliberadamente en orden inverso al kill-chain: exfiltración (TA0010)
        # antes que credenciales (TA0006). Las conclusiones deben re-ordenar.
        {"technique_id": "T1048", "tactic_id": "TA0010", "proposed_by": [],
         "status": "confirmada"},
        {"technique_id": "T1003", "tactic_id": "TA0006", "proposed_by": [],
         "status": "confirmada"},
        {"technique_id": "T1070", "tactic_id": "TA0005", "proposed_by": [],
         "status": None},
    ]
    blocks = narrative.conclusion_blocks(_case(), findings, coverage)
    text = _text(blocks)

    assert text.index("T1003") < text.index("T1048")  # kill-chain, no orden de llegada
    assert "patrón táctico" in text
    assert "aguarda" in text and "no se computa como confirmada" in text
    # Lo más severo se restata como conclusión con su soporte.
    assert "Volcado de credenciales" in text
    # El aviso de borrador cierra SIEMPRE.
    assert "BORRADOR" in blocks[-1]["text"]


def test_empty_case_is_honest() -> None:
    case = _case(name="Caso vacío")
    resumen = _text(narrative.executive_blocks(case, [], [], []))
    relato = _text(narrative.story_section(case, [], [], [], [])["blocks"])
    conclusiones = _text(narrative.conclusion_blocks(case, [], []))

    assert "NO se han registrado hallazgos" in resumen
    assert "no hay hechos que narrar" in relato
    assert "sin afirmar conclusiones" in conclusiones
    for text in (resumen, relato, conclusiones):
        assert "secuencia de hechos" not in text  # nada de historia fabricada


def test_summary_line_carries_the_thread() -> None:
    findings = [_finding(severity="critical")]
    coverage = [{"technique_id": "T1003", "tactic_id": "TA0006",
                 "proposed_by": [], "status": "confirmada"}]
    line = narrative.summary_line(_case(), findings, [_handle()], coverage)
    assert "Intrusión Alfa" in line
    assert "1 de severidad crítica" in line
    assert "1 confirmada" in line
