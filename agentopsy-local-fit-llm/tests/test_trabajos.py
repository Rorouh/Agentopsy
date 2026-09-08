"""Jobs en segundo plano: progreso incremental y parada cooperativa."""

from __future__ import annotations

import time

from runner import Corrida
from tests.conftest import MaletinFalso, ModeloGuion
from trabajos import Registro


class ModeloLento(ModeloGuion):
    def preguntar(self, system, user, **kw):
        time.sleep(0.05)
        return super().preguntar(system, user, **kw)


def test_cancelacion_cooperativa(entorno):
    guion = [{"accion": "ver_tareas", "args": {}}] * 8 + [{"veredicto": "aprobar", "respuesta": "parado"}]
    corrida = Corrida(case_id=entorno["caso"]["id"], evidence_id=entorno["evidencia"].evidence_id, sesion="job",
                      prompt="analiza", cfg=entorno["cfg"], cs=entorno["casos"], ing=entorno["ingesta"],
                      modelo=ModeloLento(guion), maletin=MaletinFalso(), persistir_chat=False)
    registro = Registro()
    trabajo = registro.lanzar(corrida)
    for _ in range(100):
        snap = registro.instantanea(trabajo.id, since=0)
        if snap["event_count"] >= 2:
            break
        time.sleep(0.02)
    assert registro.cancelar(trabajo.id) is True
    for _ in range(200):
        snap = registro.instantanea(trabajo.id, since=0)
        if snap["status"] != "running":
            break
        time.sleep(0.02)
    assert snap["status"] == "cancelled"
    assert snap["result"]["reply"].startswith("Parado por el operador")
    assert any(e["type"] == "final" and e.get("exhausted") for e in snap["events"])
    assert snap["result"]["metrics"]["pasos"] < 8
    assert registro.cancelar(trabajo.id) is False
    assert registro.del_caso(entorno["caso"]["id"])[0]["job_id"] == trabajo.id
    # `since` devuelve solo lo nuevo.
    assert registro.instantanea(trabajo.id, since=snap["event_count"])["events"] == []
