"""Qué orden llega al investigador y qué orden se descarta.

Los dos primeros casos son literalmente las dos órdenes que el revisor emitió en la
corrida del 2026-09-13 (traza `01a09bcb`), y las dos son inejecutables: una pide a
`strings_head` un parámetro que es de `buscar`, y la otra ordena una herramienta de
contabilidad interna. Entre las dos consumieron el turno entero sin responder nada.
"""

from __future__ import annotations

import pytest

from ordenes import PARAMETROS, motivo_inejecutable


# -- las dos órdenes de la corrida medida ---------------------------------------------

def test_parametro_que_la_herramienta_nombrada_no_tiene():
    motivo = motivo_inejecutable("usa la herramienta strings_head con consulta: 'Administrator'|'WIN-'")
    assert motivo is not None
    assert "consulta" in motivo and "strings_head" in motivo and "DOS órdenes" in motivo


def test_herramienta_de_contabilidad_no_es_una_orden():
    motivo = motivo_inejecutable("usa la herramienta ver_tareas")
    assert motivo is not None and "no es una orden de investigación" in motivo


# -- el patrón de dos pasos, que es la forma CORRECTA de lo anterior -------------------

@pytest.mark.parametrize("orden", [
    "extrae las cadenas imprimibles con la herramienta strings_head",
    "busca Administrator y WIN- en ese resultado con la herramienta buscar",
    "lee el run de strings_head con la herramienta leer_artefacto",
    "revisa indicadores de ataque con la herramienta buscar (sqlmap, webshell)",
    "ejecuta la herramienta volatility3 con plugin: windows.info.Info",
])
def test_las_ordenes_ejecutables_pasan(orden):
    assert motivo_inejecutable(orden) is None


def test_el_parametro_vale_si_su_herramienta_esta_nombrada():
    """`consulta` es de `buscar`: en una orden que nombra `buscar` es legítimo, y en una
    que solo nombra `strings_head` no. Es la misma palabra decidida por el contexto."""
    assert motivo_inejecutable("busca en el run de strings_head con la herramienta buscar, consulta: sqlmap") is None
    assert motivo_inejecutable("usa la herramienta strings_head, consulta: sqlmap") is not None


# -- lo que ya se comprobaba, que sigue comprobándose ---------------------------------

def test_herramienta_inexistente():
    assert motivo_inejecutable("usa la herramienta cmd") == "herramienta inexistente: cmd"


def test_la_terminal_depende_del_interruptor():
    orden = "ejecuta la herramienta shell con comando: grep -ai algo"
    assert motivo_inejecutable(orden, permitir_shell=True) is None
    assert motivo_inejecutable(orden, permitir_shell=False) == "herramienta inexistente: shell"


def test_una_orden_sin_herramienta_nombrada_no_se_descarta():
    """El revisor no siempre nombra la herramienta, y una orden en prosa llana no es
    inválida: el investigador elige. Descartarla vaciaría el plan."""
    assert motivo_inejecutable("determina el sistema operativo de la evidencia") is None


# -- la tabla sale de las firmas, no de una lista a mano ------------------------------

def test_la_tabla_de_parametros_sale_de_las_firmas():
    assert PARAMETROS["strings_head"] == {"min_len", "radix", "encoding"}
    assert "consulta" in PARAMETROS["buscar"]
    assert "consulta" not in PARAMETROS["strings_head"]
