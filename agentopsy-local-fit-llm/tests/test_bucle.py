"""El bucle con un modelo con guion: dos agentes, órdenes del revisor, lista
de tareas propia, herramientas de contexto, guarda de repetición y ventana."""

from __future__ import annotations

import json

import pytest

from custodia.registro import Registro
from estado import Estado
from hallazgos import Hallazgos
from investigador import interpretar
from modelo import PromptDemasiadoLargo
from runner import Corrida
from tests.conftest import MaletinFalso, ModeloGuion


def _corrida(entorno, guion, **extra):
    modelo = ModeloGuion(guion)
    corrida = Corrida(case_id=entorno["caso"]["id"], evidence_id=entorno["evidencia"].evidence_id, sesion="main",
                      prompt="Analiza la evidencia y dime qué pasó", cfg=entorno["cfg"], cs=entorno["casos"],
                      ing=entorno["ingesta"], modelo=modelo, maletin=MaletinFalso(), **extra)
    return corrida, modelo


def test_turno_completo_con_orden_del_revisor(entorno):
    guion = [
        {"pensamiento": "planifico", "accion": "escribir_tareas", "args": {"tareas": [
            {"texto": "identificar formato", "estado": "en_curso"}, {"texto": "buscar usuarios", "estado": "pendiente"}]}},
        {"pensamiento": "qué es", "accion": "file_info", "args": {"also_mime": True}},
        {"pensamiento": "perfil", "accion": "volatility3", "args": {"plugin": "windows.info.Info"}},
        {"pensamiento": "sin símbolos, cadenas", "accion": "strings_head", "args": {"min_len": 6}},
        {"pensamiento": "usuarios", "accion": "buscar", "args": {"consulta": "Administrator"}},
        # La cita es la línea que el paso anterior (`buscar`) le puso delante: sin haberla
        # leído, `registrar_hallazgo` la rechaza (custodia/cita.py, tests/test_cita.py).
        {"pensamiento": "concluyo", "accion": "registrar_hallazgo", "args": {
            "titulo": "Usuario Administrator en el equipo WIN-TESTHOST", "resumen": "strings muestra WIN-TESTHOST Administrator",
            "severidad": "medium", "run_id": "__RUN_STRINGS__", "cita": "WIN-TESTHOST Administrator", "confianza": 0.8}},
        {"pensamiento": "cierro", "accion": "informar", "args": {"texto": "Equipo WIN-TESTHOST, usuario Administrator."}},
        # revisor, ronda 1: pide revisar
        {"veredicto": "revisar", "ordenes": ["revisa indicadores de ataque con la herramienta buscar (sqlmap, webshell)"], "respuesta": ""},
        # investigador con la orden
        {"pensamiento": "busco", "accion": "buscar", "args": {"consulta": "sqlmap"}},
        {"pensamiento": "hallazgo", "accion": "registrar_hallazgo", "args": {
            "titulo": "sqlmap presente en memoria", "resumen": "cadena sqlmap/1.0", "severidad": "critical",
            "run_id": "__RUN_STRINGS__", "cita": "sqlmap/1.0"}},
        {"pensamiento": "cierro", "accion": "informar", "args": {"texto": "sqlmap y phpshell presentes."}},
        # revisor, ronda 2 (última): aprueba
        {"veredicto": "aprobar", "ordenes": [], "respuesta": "Respuesta final: WIN-TESTHOST, Administrator, sqlmap activo."},
    ]
    eventos = []
    corrida, modelo = _corrida(entorno, guion, emitir=eventos.append)

    # El run_id de strings solo se conoce en ejecución: lo resolvemos al vuelo en el guion.
    original = modelo.preguntar

    def preguntar(system, user, **kw):
        if modelo.guion and "__RUN_STRINGS__" in json.dumps(modelo.guion[0]):
            idx = corrida.almacen.indice()
            run = next(f["run_id"] for f in idx if f["tool_id"] == "strings_head")
            modelo.guion[0] = json.loads(json.dumps(modelo.guion[0]).replace("__RUN_STRINGS__", run[:8]))
        return original(system, user, **kw)

    modelo.preguntar = preguntar
    r = corrida.ejecutar()

    assert r["reply"].startswith("Respuesta final")
    assert r["error"] is None and r["executor"]["id"] == "local-fit-llm"
    tipos = [e["type"] for e in eventos]
    assert "orden" in tipos and tipos.count("revision") == 2 and "tareas" in tipos
    assert [e["tool_id"] for e in eventos if e["type"] == "tool_call"][:3] == ["escribir_tareas", "file_info", "volatility3"]
    vol = next(e for e in eventos if e["type"] == "tool_result" and e["tool_id"] == "volatility3")
    assert vol["status"] == "nonzero" and "PISTA" in vol["summary"]
    hallazgos = Hallazgos(corrida.dir_caso, corrida.case_id).listar()
    assert [h["severity"] for h in hallazgos] == ["medium", "critical"] and all(h["run_id"] for h in hallazgos)
    # Cada hallazgo viaja con la línea que lo sostiene, para que un tercero la compruebe.
    assert [h["quote"] for h in hallazgos] == ["WIN-TESTHOST Administrator", "sqlmap/1.0"]
    assert r["metrics"]["herramientas"] == 3 and r["metrics"]["rondas"] == 2

    # RA-7: ningún prompt reenvía la conversación entera; todos caben en la ventana.
    for system, user in modelo.prompts:
        assert "Analiza la evidencia" in user or "ORDEN DEL REVISOR" in user
        assert modelo.estimar_tokens(system + user) < 3600
    ultimo_investigador = modelo.prompts[5][1]
    assert "TUS TAREAS" in ultimo_investigador and "identificar formato" in ultimo_investigador
    assert "PASOS ANTERIORES" in ultimo_investigador and "ÚLTIMO RESULTADO" in ultimo_investigador

    # Persistencia: chat con actividad, estado visible, cadena verificada con las llamadas al modelo.
    chat = corrida.chats.leer("main")
    assert chat[0]["role"] == "user" and chat[1]["role"] == "assistant" and chat[1]["activity"]
    estado = Estado(entorno["casos"].dir_agente(corrida.case_id, "main")).vista()
    assert len(estado["rondas"]) == 2 and estado["tareas"][0]["texto"] == "identificar formato"
    reg = Registro(corrida.dir_caso / "audit.jsonl")
    assert reg.verificar() == (True, None)
    acciones = [e["action"] for e in reg.entradas()]
    assert acciones.count("model_call") == len(guion) and "reviewer_order" in acciones
    assert acciones[-1] == "agent_turn_finish"


def test_repeticion_de_la_misma_herramienta_no_se_relanza(entorno):
    guion = [
        {"accion": "xxd_head", "args": {"bytes": 16}},
        {"accion": "xxd_head", "args": {"bytes": 16}},
        {"accion": "informar", "args": {"texto": "fin"}},
        {"veredicto": "aprobar", "respuesta": "ok"},
    ]
    eventos = []
    corrida, _ = _corrida(entorno, guion, emitir=eventos.append)
    corrida.ejecutar()
    resultados = [e for e in eventos if e["type"] == "tool_result"]
    assert resultados[0]["status"] == "ok" and resultados[1]["status"] == "refused"
    assert "YA EJECUTADO" in resultados[1]["summary"]
    assert len(corrida.almacen.indice()) == 1


def test_presupuesto_agotado_informa_y_el_revisor_cierra(entorno):
    guion = [{"accion": "ver_tareas", "args": {}}] * 8 + [{"veredicto": "aprobar", "respuesta": "cerrado"}]
    eventos = []
    corrida, _ = _corrida(entorno, guion, emitir=eventos.append)
    r = corrida.ejecutar()
    final = next(e for e in eventos if e["type"] == "final")
    assert final["exhausted"] and r["reply"] == "cerrado"


def test_respuesta_ilegible_del_modelo_no_rompe_el_turno(entorno):
    class Ilegible(ModeloGuion):
        def preguntar(self, system, user, **kw):
            r = super().preguntar(system, user, **kw)
            if r.texto == '{"raw": true}':
                r.texto = "esto no es json"
            return r

    guion = [{"raw": True}, {"accion": "informar", "args": {"texto": "fin"}}, {"veredicto": "aprobar", "respuesta": "ok"}]
    modelo = Ilegible(guion)
    corrida = Corrida(case_id=entorno["caso"]["id"], evidence_id=entorno["evidencia"].evidence_id, sesion="s2",
                      prompt="hola", cfg=entorno["cfg"], cs=entorno["casos"], ing=entorno["ingesta"],
                      modelo=modelo, maletin=MaletinFalso())
    r = corrida.ejecutar()
    assert r["reply"] == "ok"
    assert "no era JSON" in modelo.prompts[1][1]


def test_prompt_se_recorta_para_caber_en_la_ventana(entorno):
    guion = [{"accion": "strings_head", "args": {"min_len": 4}}, {"accion": "informar", "args": {"texto": "x"}},
             {"veredicto": "aprobar", "respuesta": "ok"}]
    corrida, modelo = _corrida(entorno, guion)
    corrida.estado.anotar_paso(agente="investigador", accion="strings_head", args={}, resultado="A" * 20000)
    # El suelo del prompt es el bloque de sistema, y no se puede recortar por debajo de él.
    # Subió ~25 tokens cuando `registrar_hallazgo` pasó a exigir `cita` (custodia/cita.py):
    # es el contrato de la herramienta, no relleno. Sobre el presupuesto real (num_ctx 4096
    # menos num_predict y margen, ~3500) es un 1%; aquí el tope es sintético y solo tiene que
    # quedar por encima del suelo para que el bucle de recorte se pueda probar.
    modelo._prompt_max = 1250
    system, user, est = corrida.investigador.prompt("objetivo", 2, 8)
    assert est <= 1250 and "recortado" in user
    modelo._prompt_max = 100
    with pytest.raises(PromptDemasiadoLargo):
        corrida.investigador.prompt("objetivo", 2, 8)


def test_interpretar_tolera_variantes():
    assert interpretar({"accion": "file_info", "args": {"also_mime": True}}) == ("", "file_info", {"also_mime": True})
    assert interpretar({"tool": "buscar", "arguments": '{"consulta": "x"}'})[1:] == ("buscar", {"consulta": "x"})
    assert interpretar({"accion": {"nombre": "xxd_head", "bytes": 32}})[1:] == ("xxd_head", {"bytes": 32})
    assert interpretar({"respuesta": "listo"})[1:] == ("informar", {"texto": "listo"})
    assert interpretar({"pensamiento": "?"})[1] == "(sin accion)"
