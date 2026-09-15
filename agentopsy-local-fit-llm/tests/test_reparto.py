"""Reparto invertido: el revisor planifica órdenes y el investigador las ejecuta."""

from __future__ import annotations

from runner import Corrida
from tests.conftest import MaletinFalso, ModeloGuion


def test_revisor_planifica_y_el_investigador_ejecuta(entorno):
    import os

    from configuracion import Ajustes

    cfg = Ajustes({**os.environ, "LOCALFIT_REPARTO": "revisor", "LOCALFIT_MAX_PASOS_ORDEN": "2"})
    guion = [
        {"ordenes": ["identifica el formato con la herramienta file_info", "busca Administrator con la herramienta buscar"]},
        {"accion": "file_info", "args": {}},
        {"accion": "informar", "args": {"texto": "es data"}},
        {"accion": "strings_head", "args": {"min_len": 6}},
        {"accion": "buscar", "args": {"consulta": "Administrator"}},   # 2 pasos: se agota sin informar
        {"veredicto": "aprobar", "respuesta": "WIN-TESTHOST con usuario Administrator"},
    ]
    eventos = []
    corrida = Corrida(case_id=entorno["caso"]["id"], evidence_id=entorno["evidencia"].evidence_id, sesion="rep",
                      prompt="¿qué pasó?", cfg=cfg, cs=entorno["casos"], ing=entorno["ingesta"],
                      modelo=ModeloGuion(guion), maletin=MaletinFalso(), emitir=eventos.append)
    r = corrida.ejecutar()
    assert r["reply"].startswith("WIN-TESTHOST")
    tipos = [e["type"] for e in eventos]
    assert tipos[0] == "plan" and tipos.count("orden") == 2
    assert [t["estado"] for t in r["tasks"]] == ["hecha", "hecha"]
    assert r["metrics"]["llamadas_modelo"] == 6 and r["metrics"]["pasos"] == 4
    # Cada orden fue el objetivo del investigador.
    ordenes = [e["text"] for e in eventos if e["type"] == "orden"]
    assert ordenes[0].startswith("identifica el formato")


def test_una_orden_abandonada_no_figura_como_cumplida(entorno):
    """La segunda orden se cierra con `informar` en el primer paso, sin ejecutar nada.
    Es lo que pasó el 2026-09-13: se marcó «hecha» igual que la primera y el revisor
    aprobó el turno creyendo que se habían cumplido las dos.
    """
    import json
    import os

    from configuracion import Ajustes

    cfg = Ajustes({**os.environ, "LOCALFIT_REPARTO": "revisor", "LOCALFIT_MAX_PASOS_ORDEN": "2"})
    guion = [
        {"ordenes": ["identifica el formato con la herramienta file_info",
                     "busca indicadores con la herramienta buscar"]},
        {"accion": "file_info", "args": {}},
        {"accion": "informar", "args": {"texto": "es data"}},
        # Segunda orden: la cierra de entrada, sin tocar una sola herramienta.
        {"accion": "informar", "args": {"texto": "No se requiere realizar más análisis."}},
        {"veredicto": "aprobar", "respuesta": "lo determinado"},
    ]
    eventos = []
    corrida = Corrida(case_id=entorno["caso"]["id"], evidence_id=entorno["evidencia"].evidence_id, sesion="aband",
                      prompt="¿qué pasó?", cfg=cfg, cs=entorno["casos"], ing=entorno["ingesta"],
                      modelo=ModeloGuion(guion), maletin=MaletinFalso(), emitir=eventos.append)
    r = corrida.ejecutar()

    # La primera se cumplió; la segunda NO, y la lista de tareas lo dice.
    assert [t["estado"] for t in r["tasks"]] == ["hecha", "descartada"]
    # Y el revisor lo lee así, no como un informe de una orden cumplida.
    revisiones = [e for e in eventos if e["type"] == "revision"]
    assert revisiones, "el revisor tiene que haber visto el informe"
    audit = (corrida.dir_caso / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    abandonadas = [json.loads(linea) for linea in audit if linea.strip() and "reviewer_order_abandoned" in linea]
    assert len(abandonadas) == 1
    assert abandonadas[0]["order"].startswith("busca indicadores")
