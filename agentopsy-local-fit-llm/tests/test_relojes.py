"""Los dos relojes: el trabajo real y lo que la máquina durmió en medio.

El caso que da sentido a esto es la traza `01a09bcb` del 2026-09-13: 1374 s de reloj de
pared para un turno que fueron ~286 s de trabajo, porque el portátil se suspendió 18m08s
a mitad. `segundos_total` ya era inmune (mide en monotónico); la traza no lo era, y ahora
lleva los dos números al lado.
"""

from __future__ import annotations

import time

import pytest

import relojes
from relojes import Cronometro


def test_el_trabajo_real_no_cuenta_el_sueno(monkeypatch):
    """La máquina duerme 1088 s en medio: el trabajo sigue siendo el que fue."""
    reloj = Cronometro(monotonic=1000.0, boottime=5000.0)
    monkeypatch.setattr(time, "monotonic", lambda: 1286.0)
    monkeypatch.setattr(relojes, "_boottime", lambda: 5000.0 + 286.0 + 1088.0)
    assert reloj.transcurrido() == pytest.approx(286.0)
    assert reloj.suspendido() == pytest.approx(1088.0)


def test_sin_suspension_el_hueco_es_cero(monkeypatch):
    reloj = Cronometro(monotonic=1000.0, boottime=5000.0)
    monkeypatch.setattr(time, "monotonic", lambda: 1286.0)
    monkeypatch.setattr(relojes, "_boottime", lambda: 5286.0)
    assert reloj.suspendido() == 0.0


def test_sin_boottime_es_none_y_no_cero(monkeypatch):
    """No saber cuánto durmió la máquina no es saber que no durmió (RULE 2). Un `0` aquí
    diría «medición limpia» de un sistema que no puede afirmarlo."""
    monkeypatch.setattr(relojes, "_boottime", lambda: None)
    reloj = Cronometro(monotonic=1000.0, boottime=None)
    assert reloj.suspendido() is None


def test_el_ruido_entre_las_dos_lecturas_no_sale_como_suspension():
    reloj = Cronometro.arrancar()
    assert reloj.suspendido() == 0.0


def test_el_turno_publica_los_dos_numeros(entorno):
    """La métrica viaja en el resultado del turno, así que llega a la ficha de medición
    (`medir.py` la vuelca con `**metricas`) sin tocar nada más."""
    from tests.test_bucle import _corrida

    corrida, _ = _corrida(entorno, [{"accion": "informar", "args": {"texto": "listo"}},
                                    {"veredicto": "aprobar", "respuesta": "ok"}])
    r = corrida.ejecutar()
    assert r["metrics"]["segundos_total"] >= 0
    assert "segundos_suspendido" in r["metrics"]
