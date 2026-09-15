"""La cita verificable: un hallazgo afirmativo se sostiene en una línea LEÍDA.

Reproduce el fallo medido el 2026-09-13 (traza `01a09bcb`), que es el que da sentido
a todo este módulo: un modelo de 3B registró «Usuario Administrador detectado en
memoria» citando un `strings_head` real del que solo se le habían puesto delante 25
líneas de 3.168.635, todas del sector de arranque. La afirmación era CIERTA (la
cadena estaba en la línea 14.795), pero el agente no la había leído: la copió del
ejemplo de su propio prompt. La compuerta anterior lo dejó pasar porque solo exigía
que el `run_id` existiera.

`test_cita_real_pero_no_leida_se_rechaza` es ese caso exacto, y es el test que
importa: sin él, un acierto por coincidencia vuelve a entrar en el expediente.
"""

from __future__ import annotations

import json

import pytest

from artefactos.almacen import Almacen
from estado import Estado
from hallazgos import Hallazgos
from herramientas.contexto import Contexto
from memoria.estructurada import MemoriaEstructurada


#: La salida del `strings_head` de la medición, en pequeño: una cabecera de sector de
#: arranque (lo único que el modelo llegó a ver) y, muy por debajo, la línea real.
CABECERA = "\n".join([
    "    75c8 BV092911ff8-46f527 1",
    "    7c03 NTFS    ",
    "    7d82 A disk read error occurred",
    "    7d9f BOOTMGR is missing",
])
LINEA_REAL = "  52c834 FilterAdministratorTokenT"
RELLENO = "\n".join(f"  {i:06x} fPgf" for i in range(400))
SALIDA = CABECERA + "\n" + RELLENO + "\n" + LINEA_REAL + "\n"


@pytest.fixture()
def banco(entorno, tmp_path):
    """Un caso con un run de `strings_head` ya sellado, y el contexto del agente."""
    caso, ev = entorno["caso"], entorno["evidencia"]
    dir_caso = entorno["casos"].dir_caso(caso["id"])
    almacen = Almacen(dir_caso)
    m = almacen.abrir(caso["id"], ev.evidence_id, "strings_head", ["strings", "-n", "4", "mini.mem"],
                      baseline_sha256=ev.sha256, tool_version="binutils test", agente="investigador")
    almacen.cerrar(m, exit_code=0, timed_out=False, stdout_texto=SALIDA, stderr_texto="")
    estado = Estado(tmp_path / "agente")
    hallazgos = Hallazgos(dir_caso, caso["id"])
    contexto = Contexto(estado=estado, almacen=almacen, memoria=MemoriaEstructurada(dir_caso),
                        hallazgos=hallazgos, kind="memory", evidence_id=ev.evidence_id,
                        agente="investigador")
    return {"contexto": contexto, "estado": estado, "hallazgos": hallazgos,
            "almacen": almacen, "run_id": m.run_id, "dir_caso": dir_caso}


def _args(banco, **extra):
    base = {"titulo": "Usuario Administrador detectado en memoria",
            "resumen": "La salida contiene el token de administrador.",
            "severidad": "low", "run_id": banco["run_id"]}
    base.update(extra)
    return base


# -- el fallo del 2026-09-13 -----------------------------------------------------------

def test_cita_real_pero_no_leida_se_rechaza(banco):
    """EL test. La línea existe en el artefacto sellado, pero al agente solo se le puso
    delante la cabecera: no puede sostener un hallazgo con algo que no ha mirado."""
    banco["estado"].anotar_lectura(CABECERA)
    with pytest.raises(ValueError, match="no has leído"):
        banco["contexto"].ejecutar("registrar_hallazgo", _args(banco, cita=LINEA_REAL))
    assert banco["hallazgos"].listar() == []


def test_cita_leida_se_registra_y_viaja_con_el_hallazgo(banco):
    """El mismo hallazgo, después de leer de verdad la línea: entra, y la cita queda
    pegada a él para que un tercero la compruebe de un vistazo."""
    banco["estado"].anotar_lectura(CABECERA)
    banco["estado"].anotar_lectura(f"1 coincidencias:\n{LINEA_REAL}")
    texto, detalle = banco["contexto"].ejecutar("registrar_hallazgo", _args(banco, cita=LINEA_REAL))
    assert "hallazgo registrado" in texto
    guardado = banco["hallazgos"].listar()[-1]
    assert guardado["quote"] == LINEA_REAL.strip()
    assert guardado["run_id"] == banco["run_id"]
    assert detalle["hallazgo"]["quote"] == LINEA_REAL.strip()


# -- la otra mitad: texto inventado ----------------------------------------------------

def test_cita_que_no_esta_en_el_artefacto_se_rechaza(banco):
    """El camino sucio de verdad: `buscar` sin coincidencias DEVUELVE el término buscado
    («sin coincidencias para 'X'»), así que el agente sí lo ha «leído». La segunda
    comprobación es la que lo para: el término no está en la salida que dice citar."""
    banco["estado"].anotar_lectura("sin coincidencias para 'WIN-L0ZZQ76PMUF'. Prueba otro término.")
    with pytest.raises(ValueError, match="NO aparece en la salida"):
        banco["contexto"].ejecutar("registrar_hallazgo", _args(banco, cita="WIN-L0ZZQ76PMUF"))
    assert banco["hallazgos"].listar() == []


def test_afirmacion_sin_cita_se_rechaza(banco):
    with pytest.raises(ValueError, match="necesita cita"):
        banco["contexto"].ejecutar("registrar_hallazgo", _args(banco))
    assert banco["hallazgos"].listar() == []


# -- lo que sigue siendo legítimo ------------------------------------------------------

def test_descarte_no_exige_cita(banco):
    texto, _ = banco["contexto"].ejecutar("registrar_hallazgo", _args(
        banco, tipo="descarte", titulo="Sin rastro de persistencia",
        resumen="La vía no aportó.", run_id=None))
    assert "hallazgo registrado" in texto
    assert banco["hallazgos"].listar()[-1]["quote"] is None


def test_la_cita_tolera_espacios_y_mayusculas_pero_no_el_texto(banco):
    """El modelo copia con ruido: se normaliza el espacio y la caja, nada más."""
    banco["estado"].anotar_lectura(LINEA_REAL)
    texto, _ = banco["contexto"].ejecutar("registrar_hallazgo",
                                          _args(banco, cita="  filteradministratortokent  "))
    assert "hallazgo registrado" in texto
    banco["estado"].anotar_lectura("FilterAdministrat0rToken")
    with pytest.raises(ValueError, match="NO aparece en la salida"):
        banco["contexto"].ejecutar("registrar_hallazgo", _args(banco, cita="FilterAdministrat0rToken"))


@pytest.mark.parametrize("cita, motivo", [("NT", "demasiado corta"), ("x" * 400, "demasiado larga")])
def test_la_cita_tiene_que_identificar_algo(banco, cita, motivo):
    banco["estado"].anotar_lectura(cita)
    with pytest.raises(ValueError, match=motivo):
        banco["contexto"].ejecutar("registrar_hallazgo", _args(banco, cita=cita))


# -- las lecturas son del turno --------------------------------------------------------

def test_las_lecturas_no_sobreviven_al_turno(banco):
    """Lo leído en el turno anterior ya no está delante del modelo: no sostiene una cita
    de este. Si sobrevivieran, la compuerta se relajaría sola con cada turno."""
    banco["estado"].anotar_lectura(LINEA_REAL)
    assert banco["estado"].ha_leido(LINEA_REAL)
    banco["estado"].olvidar_lecturas()
    assert not banco["estado"].ha_leido(LINEA_REAL)
    with pytest.raises(ValueError, match="no has leído"):
        banco["contexto"].ejecutar("registrar_hallazgo", _args(banco, cita=LINEA_REAL))


def test_el_hallazgo_rechazado_no_deja_rastro_en_la_auditoria(banco):
    """Un hallazgo que no pasa la compuerta no se registra NI se audita como registrado:
    lo que no entró en el expediente no puede figurar como que entró."""
    banco["estado"].anotar_lectura(CABECERA)
    with pytest.raises(ValueError):
        banco["contexto"].ejecutar("registrar_hallazgo", _args(banco, cita=LINEA_REAL))
    audit = banco["dir_caso"] / "audit.jsonl"
    acciones = [json.loads(linea)["action"] for linea in audit.read_text(encoding="utf-8").splitlines() if linea.strip()]
    assert "finding_recorded" not in acciones


# -- la cronología del incidente (checklist 3.1) ---------------------------------------

def test_sin_fecha_el_hallazgo_se_registra_pero_queda_fuera_de_la_cronologia(banco):
    """`observed_at` NO se exige: la línea citada aquí es un valor de registro y no tiene
    hora. Registrarlo es correcto; lo que no puede pasar es que entre en la cronología
    del incidente como si tuviera fecha."""
    banco["estado"].anotar_lectura(LINEA_REAL)
    banco["contexto"].ejecutar("registrar_hallazgo", _args(banco, cita=LINEA_REAL))
    assert banco["hallazgos"].listar()[-1]["observed_at"] is None


def test_una_fecha_con_zona_se_conserva(banco):
    banco["estado"].anotar_lectura(LINEA_REAL)
    banco["contexto"].ejecutar("registrar_hallazgo",
                               _args(banco, cita=LINEA_REAL, observado_en="2015-09-02T12:00:00Z"))
    assert banco["hallazgos"].listar()[-1]["observed_at"] == "2015-09-02T12:00:00Z"


def test_una_fecha_sin_zona_se_rechaza_en_vez_de_suponer_utc(banco):
    """Los artefactos de un equipo ajeno dan hora local: suponer UTC desplazaría el eje
    y lo presentaría como dato verificado."""
    banco["estado"].anotar_lectura(LINEA_REAL)
    with pytest.raises(ValueError, match="zona horaria"):
        banco["contexto"].ejecutar("registrar_hallazgo",
                                   _args(banco, cita=LINEA_REAL, observado_en="2015-09-02T12:00:00"))
