"""RA06: un localizador identifica posiciones que EXISTEN, en los dos extremos.

Lo que la reauditoría del 2026-09-08 reprodujo: se acepta un localizador de
líneas 1 a 999999 sobre un fichero de tres líneas, y un rango de bytes hasta
999999 sobre 141 bytes. La extracción devolvía lo disponible y el rango imposible
se conservaba en la cita como si estuviera verificado.

La semántica queda fijada, y este fichero es donde se comprueba que se cumple:

- ``lineas``: desde 1, AMBOS extremos INCLUSIVOS.
- ``bytes``: desde 0, ``desde`` inclusivo y ``hasta`` EXCLUSIVO.
- Un rango vacío no es una cita.
- Los dos extremos se comprueban contra el contenido real; no se recorta.

Y la distinción que hay que mantener: un VISOR puede devolver menos contenido al
llegar al final del fichero, porque su trabajo es enseñar lo que hay. Una CITA
persistida certifica que en esas posiciones está ese texto.
"""

from __future__ import annotations

import pytest
from _informe import montar_caso
from _procedencia import anclar_run
from agentopsy.artifacts.store import ArtifactStore
from agentopsy.evidence import EvidenceManager
from agentopsy.findings.procedencia import ProcedenciaError, verificar_referencia

#: Tres líneas, 141 bytes: el mismo material de la reproducción.
LINEAS = 3


@pytest.fixture
def caso(tmp_path):
    return montar_caso(tmp_path)


def _referencia(caso, **localizador):
    return verificar_referencia(
        caso["case"].id,
        {
            "run_id": caso["run_id"],
            "artefacto": "stdout",
            "localizador": localizador,
        },
        store=caso["artefactos"],
        evidence=EvidenceManager(caso["cases"]),
    )


def _run_con(caso, stdout: str) -> str:
    """Otra ejecución del mismo caso, con la salida que el test necesita."""
    store = ArtifactStore(caso["cases"])
    run_id, _out = store.start_run(
        caso["case"].id, "tsk_fls", ["fls"],
        evidence_id=caso["evidencia"].evidence_id,
        evidence_baseline_sha256=caso["evidencia"].sha256,
        tool_version="sleuthkit 4.12.1",
    )
    run = store.finalize_run(
        caso["case"].id, run_id, exit_code=0, stdout=stdout, stderr=""
    )
    anclar_run(caso["cases"], caso["case"].id, run)
    return run_id


def _referencia_en(caso, run_id: str, **localizador):
    return verificar_referencia(
        caso["case"].id,
        {"run_id": run_id, "artefacto": "stdout", "localizador": localizador},
        store=caso["artefactos"],
        evidence=EvidenceManager(caso["cases"]),
    )


# -- extremos fuera de rango --------------------------------------------------


@pytest.mark.parametrize(
    "localizador",
    [
        pytest.param({"tipo": "lineas", "desde": 1, "hasta": 999999}, id="lineas_fin"),
        pytest.param({"tipo": "lineas", "desde": 4, "hasta": 4}, id="lineas_inicio"),
        pytest.param({"tipo": "lineas", "desde": 3, "hasta": 4}, id="lineas_justo_pasado"),
        pytest.param({"tipo": "bytes", "desde": 0, "hasta": 999999}, id="bytes_fin"),
        pytest.param({"tipo": "bytes", "desde": 500, "hasta": 501}, id="bytes_inicio"),
    ],
)
def test_un_extremo_fuera_del_contenido_se_rechaza(caso, localizador) -> None:
    with pytest.raises(ProcedenciaError, match="fuera de|outside"):
        _referencia(caso, **localizador)


@pytest.mark.parametrize(
    "localizador",
    [
        pytest.param({"tipo": "lineas", "desde": 3, "hasta": 1}, id="lineas_invertido"),
        pytest.param({"tipo": "bytes", "desde": 10, "hasta": 4}, id="bytes_invertido"),
        pytest.param({"tipo": "bytes", "desde": 5, "hasta": 5}, id="bytes_vacio"),
    ],
)
def test_un_rango_invertido_o_vacio_no_es_una_cita(caso, localizador) -> None:
    with pytest.raises(ProcedenciaError):
        _referencia(caso, **localizador)


def test_no_se_recorta_el_rango_conservando_el_localizador_imposible(caso) -> None:
    """El fallo concreto que había: devolver lo disponible y guardar el rango
    pedido como si se hubiera comprobado."""
    with pytest.raises(ProcedenciaError):
        _referencia(caso, tipo="lineas", desde=1, hasta=999999)
    # Y el rango válido equivalente sí funciona, con SU extremo real.
    ref = _referencia(caso, tipo="lineas", desde=1, hasta=LINEAS)
    assert ref.localizador.hasta == LINEAS


# -- los extremos válidos -----------------------------------------------------


def test_la_ultima_linea_es_valida(caso) -> None:
    ref = _referencia(caso, tipo="lineas", desde=LINEAS, hasta=LINEAS)
    assert "updater.job" in ref.extracto


def test_el_ultimo_byte_es_valido(caso) -> None:
    """Con ``hasta`` exclusivo, el último rango de un fichero de n bytes es
    ``desde=n-1, hasta=n``."""
    run_id = _run_con(caso, "abc")
    ref = _referencia_en(caso, run_id, tipo="bytes", desde=2, hasta=3)
    assert ref.extracto == "c"
    with pytest.raises(ProcedenciaError):
        _referencia_en(caso, run_id, tipo="bytes", desde=3, hasta=4)


def test_omitir_el_final_cita_una_unidad_en_cada_tipo(caso) -> None:
    run_id = _run_con(caso, "abc")
    por_lineas = _referencia_en(caso, run_id, tipo="lineas", desde=1)
    assert por_lineas.localizador.hasta == 1
    por_bytes = _referencia_en(caso, run_id, tipo="bytes", desde=0)
    # Exclusivo: un byte es [0, 1).
    assert por_bytes.localizador.hasta == 1
    assert por_bytes.extracto == "a"


def test_un_fichero_vacio_no_admite_ningun_localizador(caso) -> None:
    run_id = _run_con(caso, "")
    for localizador in (
        {"tipo": "lineas", "desde": 1, "hasta": 1},
        {"tipo": "bytes", "desde": 0, "hasta": 1},
    ):
        with pytest.raises(ProcedenciaError):
            _referencia_en(caso, run_id, **localizador)


# -- codificación y finales de línea ------------------------------------------


def test_un_rango_de_bytes_es_de_bytes_aunque_parta_un_caracter(caso) -> None:
    """Un rango de bytes direcciona BYTES. Si corta un carácter UTF-8 por la
    mitad, el extracto trae el carácter de reemplazo: es lo que hay en esas
    posiciones, y mover el corte sería devolver otra cosa."""
    run_id = _run_con(caso, "año\n")  # 'ñ' ocupa dos bytes
    entero = _referencia_en(caso, run_id, tipo="bytes", desde=0, hasta=4)
    assert entero.extracto == "año"
    partido = _referencia_en(caso, run_id, tipo="bytes", desde=0, hasta=2)
    assert partido.extracto == "a�"


def test_el_localizador_de_lineas_cuenta_lineas_no_bytes(caso) -> None:
    run_id = _run_con(caso, "año\nmás\n")
    ref = _referencia_en(caso, run_id, tipo="lineas", desde=2, hasta=2)
    assert ref.extracto == "más"


def test_un_crlf_no_deja_el_retorno_pegado_al_extracto(caso) -> None:
    """El ``\\r`` de un CRLF es marca de fin de línea, no contenido: si viajara
    en el extracto, una cita comparada carácter a carácter fallaría por él."""
    run_id = _run_con(caso, "primera\r\nsegunda\r\n")
    ref = _referencia_en(caso, run_id, tipo="lineas", desde=1, hasta=2)
    assert ref.extracto == "primera\nsegunda"


def test_un_fichero_sin_salto_final_tiene_su_ultima_linea(caso) -> None:
    run_id = _run_con(caso, "una\ndos")
    ref = _referencia_en(caso, run_id, tipo="lineas", desde=2, hasta=2)
    assert ref.extracto == "dos"
    with pytest.raises(ProcedenciaError):
        _referencia_en(caso, run_id, tipo="lineas", desde=3, hasta=3)


# -- el rango válido y su contenido exacto ------------------------------------


def test_un_rango_valido_devuelve_el_contenido_exacto(caso) -> None:
    ref = _referencia(caso, tipo="lineas", desde=2, hasta=2)
    assert ref.extracto == "r/r 512-128-3: Users/jcloudy/AppData/updater.exe"
    assert ref.estado == "verificada"
    assert ref.localizador.desde == 2 and ref.localizador.hasta == 2
