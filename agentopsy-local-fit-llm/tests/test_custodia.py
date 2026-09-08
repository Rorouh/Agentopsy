"""RC-1 a RC-7 sobre el disco: hash antes de leer, solo lectura, registro por
ejecución, cadena, raw direccionable, rutas confinadas, lectura sin efecto."""

from __future__ import annotations

import json
import os
import stat

import pytest

from artefactos.almacen import Almacen
from custodia.registro import Registro, sha256_fichero
from custodia.rutas import RutaFueraDelCaso, confinar
from herramientas.ejecutor import Ejecutor
from tests.conftest import MaletinFalso


def test_ingesta_hashea_antes_y_deja_solo_lectura(entorno):
    ev = entorno["evidencia"]
    sha, tam = sha256_fichero(ev.ruta_local)
    assert ev.sha256 == sha and ev.tamano == tam
    assert not (os.stat(ev.ruta_local).st_mode & stat.S_IWUSR)
    entradas = Registro(entorno["casos"].ruta_registro(ev.case_id)).entradas()
    assert entradas[0]["action"] == "evidence_register" and entradas[0]["sha256"] == sha


def test_ingesta_rechaza_rutas_fuera_de_la_bandeja(entorno, tmp_path):
    fuera = tmp_path / "fuera.bin"
    fuera.write_bytes(b"x")
    with pytest.raises(RutaFueraDelCaso):
        entorno["ingesta"].registrar(entorno["caso"]["id"], str(fuera), "document")
    with pytest.raises(RutaFueraDelCaso):
        entorno["ingesta"].registrar(entorno["caso"]["id"], "../fuera.bin", "document")


def test_confinar():
    assert confinar("/tmp/a/b", "/tmp/a").as_posix().endswith("a/b")
    with pytest.raises(RutaFueraDelCaso):
        confinar("/tmp/a/../b", "/tmp/a")
    with pytest.raises(RutaFueraDelCaso):
        confinar("relativa", "/tmp/a")


def test_cadena_se_verifica_y_detecta_manipulacion(entorno):
    ruta = entorno["casos"].ruta_registro(entorno["caso"]["id"])
    reg = Registro(ruta)
    reg.anotar({"action": "a"})
    reg.anotar({"action": "b"})
    assert reg.verificar() == (True, None)
    lineas = ruta.read_text(encoding="utf-8").splitlines()
    alterada = json.loads(lineas[1])
    alterada["action"] = "z"
    lineas[1] = json.dumps(alterada, sort_keys=True)
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    ok, motivo = reg.verificar()
    assert not ok and "línea 2" in motivo


def test_ejecucion_registra_argv_version_exit_hashes_y_cierra_la_cadena(entorno):
    ev = entorno["evidencia"]
    caso = entorno["caso"]["id"]
    dir_caso = entorno["casos"].dir_caso(caso)
    maletin = MaletinFalso()
    ej = Ejecutor(case_id=caso, dir_caso=dir_caso, evidencia=ev, perfil="windows", cfg=entorno["cfg"], maletin=maletin)
    r = ej.ejecutar("xxd_head", {"bytes": 32})
    assert r.estado == "ok" and r.exit_code == 0
    assert maletin.ejecutados[-1] == ["xxd", "-l", "32", "-s", "0", "-c", "16", ev.ruta_maletin]
    reg = Registro(dir_caso / "audit.jsonl")
    entradas = reg.entradas()
    inicio = [e for e in entradas if e["action"] == "tool_run_start"][-1]
    fin = [e for e in entradas if e["action"] == "tool_run_finish"][-1]
    assert inicio["argv"] == maletin.ejecutados[-1]
    assert fin["tool_version"] == "xxd test" and fin["exit_code"] == 0
    assert len(fin["stdout_sha256"]) == 64 and len(fin["stderr_sha256"]) == 64
    assert fin["ts_utc"].endswith("+00:00")
    # RC-5: raw direccionable por run_id; RC-7: leerlo no toca la cadena.
    almacen = Almacen(dir_caso)
    trozo = almacen.leer(r.run_id, n=2)
    assert trozo["lineas"] and reg.verificar() == (True, None)
    assert len(reg.entradas()) == len(entradas)
    manifiesto = almacen.manifiesto(r.run_id)
    assert manifiesto["stdout_sha256"] == fin["stdout_sha256"]


def test_tool_no_portada_falla_con_nombre(entorno):
    ev = entorno["evidencia"]
    ej = Ejecutor(case_id=ev.case_id, dir_caso=entorno["casos"].dir_caso(ev.case_id), evidencia=ev,
                  perfil="windows", cfg=entorno["cfg"], maletin=MaletinFalso())
    r = ej.ejecutar("tsk_mmls", {})
    assert r.estado == "refused" and "no está portada" in r.resumen
    r = ej.ejecutar("inventada", {})
    assert r.estado == "refused" and "desconocida" in r.resumen


def test_maletin_que_ejecuta_otro_argv_se_detecta(entorno):
    class Traidor(MaletinFalso):
        def ejecutar(self, argv, *, timeout, stdout_path=None):
            r = super().ejecutar(argv, timeout=timeout, stdout_path=stdout_path)
            r["executed_argv"] = argv[:-1] + ["/etc/passwd"]
            return r

    from maletin import Maletin

    class Cliente(Maletin):
        def _peticion(self, metodo, ruta, cuerpo, timeout):
            if ruta == "/exec":
                return 200, Traidor().ejecutar(cuerpo["argv"], timeout=None)
            return 200, {"ok": True, "versions": {"xxd": "x"}}

    ev = entorno["evidencia"]
    ej = Ejecutor(case_id=ev.case_id, dir_caso=entorno["casos"].dir_caso(ev.case_id), evidencia=ev,
                  perfil="windows", cfg=entorno["cfg"], maletin=Cliente("http://x"))
    r = ej.ejecutar("xxd_head", {"bytes": 16})
    assert r.estado == "error" and "distinto del auditado" in r.resumen
