"""F02: la frontera ÚNICA de lectura verificada, y las ocho comprobaciones.

Lo que la auditoría reprodujo (2026-09-07): se cerró una ejecución sintética, se
sustituyó su ``stdout.txt`` por ``TAMPERED`` y el lector devolvió ese texto sin
un solo error. La verificación de derivados EXISTÍA, pero su aplicación era
desigual: la lectura de stdout/stderr, el recurso MCP y el lector de bodyfiles
de la cronología entraban por caminos que no la cruzaban.

Este fichero fija que ya no hay más de un camino, y que todas las superficies
aplican la MISMA política. Se prueba comportamiento sobre almacenes reales en
directorios temporales, nunca inspeccionando el código fuente.
"""

from __future__ import annotations

import json

import pytest
from _procedencia import crear_run
from _symlink_support import requires_symlinks

from agentopsy.artifacts import lectura
from agentopsy.artifacts.store import ArtifactStore
from agentopsy.audit.log import AuditLog
from agentopsy.cases import CaseManager


@pytest.fixture
def caso(tmp_path):
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Frontera", examiner="ramos", os_profile="unix")
    store = ArtifactStore(cases)
    run = crear_run(
        cases,
        case.id,
        stdout="alfa\nbeta\ngamma\n",
        stderr="aviso de la herramienta\n",
        ficheros={"derivado.txt": "uno\ndos\ntres\n"},
    )
    return {"cases": cases, "case_id": case.id, "store": store, "run": run}


def _ruta(caso, nombre: str):
    return (
        caso["cases"].case_dir(caso["case_id"])
        / "artifacts" / caso["run"]["run_id"] / nombre
    )


# -- las tres clases de salida se leen, y las tres se verifican ---------------


@pytest.mark.parametrize(
    ("referencia", "esperado"),
    [("stdout", "alfa"), ("stderr", "aviso"), ("derivado.txt", "uno")],
)
def test_stdout_stderr_y_derivados_integros_se_leen(caso, referencia, esperado) -> None:
    pagina = caso["store"].read_run_output(
        caso["case_id"], caso["run"]["run_id"], fichero=referencia
    )
    assert pagina["devueltas"] >= 1
    assert esperado in pagina["lineas"][0]
    # Y la lectura viaja con su PROCEDENCIA, no solo con el texto.
    assert pagina["procedencia"]["sha256"]
    assert pagina["procedencia"]["sellado"] is True


@pytest.mark.parametrize(
    ("referencia", "fichero"),
    [
        ("stdout", "stdout.txt"),
        ("stderr", "stderr.txt"),
        ("derivado.txt", "out/derivado.txt"),
    ],
)
def test_alterar_cada_clase_produce_error_de_integridad(
    caso, referencia, fichero
) -> None:
    """El defecto de la auditoría, en las TRES clases de salida."""
    _ruta(caso, fichero).write_text("TAMPERED\n", encoding="utf-8")
    with pytest.raises(lectura.ArtefactoIntegridadError):
        caso["store"].read_run_output(
            caso["case_id"], caso["run"]["run_id"], fichero=referencia
        )


def test_la_alteracion_coordinada_de_fichero_y_manifiesto_se_detecta(caso) -> None:
    """Recalcular el hash en el manifiesto no basta: falta el ancla auditada."""
    case_id, run_id = caso["case_id"], caso["run"]["run_id"]
    # El run del ayudante no pasó por el dispatcher, así que se le pone su ancla
    # como haría un `tool_run_finish` real.
    manifiesto = json.loads(_ruta(caso, "manifest.json").read_text(encoding="utf-8"))
    AuditLog(caso["cases"].case_dir(case_id) / "audit.jsonl").append({
        "action": "tool_run_finish", "case_id": case_id, "run_id": run_id,
        "status": "finished", "exit_code": 0,
        "manifest_sha256": manifiesto["manifest_sha256"],
    })

    import hashlib

    _ruta(caso, "stdout.txt").write_text("COHERENTE\n", encoding="utf-8")
    manifiesto["stdout_sha256"] = hashlib.sha256(
        _ruta(caso, "stdout.txt").read_bytes()
    ).hexdigest()
    manifiesto["manifest_sha256"] = lectura.manifest_digest(manifiesto)
    _ruta(caso, "manifest.json").write_text(json.dumps(manifiesto), encoding="utf-8")

    with pytest.raises(lectura.ArtefactoIntegridadError, match="ancla"):
        caso["store"].read_run_output(case_id, run_id, fichero="stdout")


# -- confinamiento y pertenencia ---------------------------------------------


def test_un_fichero_no_registrado_no_se_sirve(caso) -> None:
    """Que exista en el disco no basta: tiene que estar en el manifiesto."""
    intruso = _ruta(caso, "out") / "colado.txt"
    intruso.write_text("puesto despues de cerrar\n", encoding="utf-8")
    with pytest.raises(lectura.ArtefactoInexistente, match="no produjo el artefacto"):
        caso["store"].read_run_output(
            caso["case_id"], caso["run"]["run_id"], fichero="colado.txt"
        )


@pytest.mark.parametrize(
    "ruta", ["../../etc/passwd", "/etc/passwd", "..", "out/../../manifest.json"]
)
def test_una_ruta_escapada_se_rechaza(caso, ruta) -> None:
    with pytest.raises(
        (lectura.ArtefactoFueraDeAmbito, lectura.LocalizadorInvalido,
         lectura.ArtefactoInexistente)
    ):
        caso["store"].read_run_output(
            caso["case_id"], caso["run"]["run_id"], fichero=ruta
        )


@requires_symlinks
def test_un_enlace_que_apunta_fuera_del_run_se_rechaza(caso, tmp_path) -> None:
    """El confinamiento se comprueba sobre la ruta RESUELTA, no sobre el nombre."""
    secreto = tmp_path / "fuera.txt"
    secreto.write_text("contenido de fuera del caso\n", encoding="utf-8")
    enlace = _ruta(caso, "out") / "enlace.txt"
    enlace.symlink_to(secreto)

    # Se declara en el manifiesto para pasar la comprobación de pertenencia: lo
    # que tiene que pararlo es el CONFINAMIENTO, no que falte del manifiesto.
    ruta_manifiesto = _ruta(caso, "manifest.json")
    manifiesto = json.loads(ruta_manifiesto.read_text(encoding="utf-8"))
    manifiesto["output_files"].append(
        {"relpath": "enlace.txt", "sha256": "0" * 64, "size": 1}
    )
    ruta_manifiesto.write_text(json.dumps(manifiesto), encoding="utf-8")

    with pytest.raises(lectura.ArtefactoFueraDeAmbito, match="escapa"):
        caso["store"].read_run_output(
            caso["case_id"], caso["run"]["run_id"], fichero="enlace.txt"
        )


def test_se_comprueba_el_caso_y_la_ejecucion_pedidos(caso) -> None:
    otro = caso["cases"].create(name="Otro", examiner="e", os_profile="unix")
    with pytest.raises(lectura.ArtefactoInexistente, match="no existe en el caso"):
        caso["store"].read_run_output(
            otro.id, caso["run"]["run_id"], fichero="stdout"
        )


def test_un_manifiesto_de_otro_caso_no_se_sirve_por_estar_ahi(caso) -> None:
    """Un run trasplantado declara otro `case_id`, y eso lo delata."""
    ruta = _ruta(caso, "manifest.json")
    manifiesto = json.loads(ruta.read_text(encoding="utf-8"))
    manifiesto["case_id"] = "11111111-1111-4111-8111-111111111111"
    ruta.write_text(json.dumps(manifiesto), encoding="utf-8")
    with pytest.raises(lectura.ArtefactoFueraDeAmbito, match="declara pertenecer"):
        caso["store"].read_run_output(
            caso["case_id"], caso["run"]["run_id"], fichero="stdout"
        )


# -- lo que todavía no está sellado ------------------------------------------


def test_una_salida_no_sellada_no_se_sirve_como_final(caso) -> None:
    run_id, out_dir = caso["store"].start_run(
        caso["case_id"], "tsk_fls", ["fls"],
        evidence_id=caso["run"]["evidence_id"],
        evidence_baseline_sha256="a" * 64,
        tool_version="sleuthkit 4.12.1",
    )
    (out_dir.parent / "stdout.txt").write_text("a medias\n", encoding="utf-8")

    with pytest.raises(lectura.ArtefactoNoSellado, match="sigue en curso"):
        caso["store"].read_run_output(caso["case_id"], run_id, fichero="stdout")

    # Y por la puerta EXPLÍCITA de progreso sí se sirve, marcada como lo que es.
    with lectura.abrir_parcial(
        caso["case_id"], run_id, "stdout",
        ambito=lectura.AMBITO_PROGRESO, store=caso["store"],
    ) as parcial:
        assert parcial.sellado is False
        assert parcial.sha256 == ""
        assert "a medias" in parcial.texto()

    # Ningún otro ámbito la admite: una cita no se apoya en material en vuelo.
    with pytest.raises(lectura.ArtefactoFueraDeAmbito, match="parciales"):
        with lectura.abrir_parcial(
            caso["case_id"], run_id, "stdout",
            ambito=lectura.AMBITO_PROCEDENCIA, store=caso["store"],
        ):
            pass


def test_el_ambito_de_la_superficie_se_hace_cumplir(caso) -> None:
    """La cronología solo lee derivados: stdout no entra en su ámbito."""
    with pytest.raises(lectura.ArtefactoFueraDeAmbito, match="no puede leer"):
        with lectura.abrir_verificado(
            caso["case_id"], caso["run"]["run_id"], "stdout",
            ambito=lectura.AMBITO_TIMELINE, store=caso["store"],
        ):
            pass


# -- directorios derivados: el CONJUNTO de miembros --------------------------


def test_un_fichero_de_mas_en_un_directorio_derivado_rompe_la_verificacion(
    tmp_path,
) -> None:
    """No basta con comprobar los conocidos: la herramienta leerá lo que HAYA."""
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Arbol", examiner="e", os_profile="unix")
    run = crear_run(
        cases, case.id, tool_id="tsk_recover",
        ficheros={"recuperado/a.txt": "a\n", "recuperado/b.txt": "b\n"},
    )
    store = ArtifactStore(cases)

    # Íntegro: el subárbol verifica y da su digest.
    _ruta_dir, digest, total = store.resolve_output_dir(
        case.id, run["run_id"], "recuperado"
    )
    assert len(digest) == 64 and total > 0

    intruso = (
        cases.case_dir(case.id) / "artifacts" / run["run_id"]
        / "out" / "recuperado" / "c.txt"
    )
    intruso.write_text("colado despues de cerrar\n", encoding="utf-8")
    with pytest.raises(lectura.ArtefactoIntegridadError, match="no declara"):
        store.resolve_output_dir(case.id, run["run_id"], "recuperado")


# -- paginación: el cursor SIEMPRE progresa ----------------------------------


def test_una_linea_de_mas_de_12000_caracteres_no_bloquea_la_paginacion(
    tmp_path,
) -> None:
    """El bloqueo reproducido: cero líneas y el mismo cursor, indefinidamente."""
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Cursor", examiner="e", os_profile="unix")
    run = crear_run(cases, case.id, stdout=("X" * 20000) + "\n")
    store = ArtifactStore(cases)

    pagina = store.read_run_output(case.id, run["run_id"], fichero="stdout")
    # Progresa: se sirve la línea FRAGMENTADA y el recorrido termina.
    assert pagina["devueltas"] == 1
    assert pagina["hay_mas"] is False
    assert pagina["siguiente_desde"] is None
    # Y el recorte se DECLARA, con cuánto había y cuánto va.
    assert pagina["truncado_por_tamano"] is True
    assert pagina["fragmentadas"] == [
        {"linea": 1, "chars_totales": 20000, "chars_incluidos": 12000}
    ]
    assert len(pagina["lineas"][0]) == 12000


def test_el_cursor_apunta_a_la_primera_linea_no_devuelta(tmp_path) -> None:
    """Una línea larga que no cabe en ESTA página no se salta: abre la siguiente."""
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Cursor2", examiner="e", os_profile="unix")
    run = crear_run(
        cases, case.id, stdout="corta\n" + ("Y" * 12500) + "\n" + "final\n"
    )
    store = ArtifactStore(cases)

    primera = store.read_run_output(case.id, run["run_id"], fichero="stdout")
    assert primera["lineas"] == ["corta"]
    assert primera["hay_mas"] is True
    assert primera["siguiente_desde"] == 2

    # Y la siguiente página empieza EXACTAMENTE en la línea que no cabía.
    segunda = store.read_run_output(
        case.id, run["run_id"], fichero="stdout", desde=primera["siguiente_desde"]
    )
    assert segunda["lineas"][0].startswith("Y")
    assert segunda["fragmentadas"] == [
        {"linea": 2, "chars_totales": 12500, "chars_incluidos": 12000}
    ]
    assert len(segunda["lineas"][0]) == 12000  # fragmentada y declarada

    # El recorrido entero termina y no repite ni se salta ninguna línea.
    vistas: list[str] = []
    desde = 1
    for _ in range(10):
        p = store.read_run_output(
            case.id, run["run_id"], fichero="stdout", desde=desde
        )
        vistas.extend(p["lineas"])
        if not p["hay_mas"]:
            break
        assert p["siguiente_desde"] != desde, "el cursor no avanzó"
        desde = p["siguiente_desde"]
    assert [v[:5] for v in vistas] == ["corta", "YYYYY", "final"]


# -- todas las superficies aplican la misma política -------------------------


def test_el_recurso_mcp_aplica_la_misma_politica(caso, monkeypatch) -> None:
    mcp_resources = pytest.importorskip("agentopsy.mcp.resources")
    monkeypatch.setattr(lectura, "artifact_store", caso["store"])

    uri = f"artifact://{caso['case_id']}/{caso['run']['run_id']}/stdout.txt"
    contenido = mcp_resources.read_artifact(uri)
    assert "alfa" in contenido[0].content
    # La meta declara la procedencia VERIFICADA, no solo el tamaño.
    assert contenido[0].meta["verified"] is True
    assert contenido[0].meta["sha256"] == caso["run"]["stdout_sha256"]

    _ruta(caso, "stdout.txt").write_text("TAMPERED\n", encoding="utf-8")
    with pytest.raises(lectura.ArtefactoIntegridadError):
        mcp_resources.read_artifact(uri)


def test_el_recurso_mcp_no_sirve_el_manifiesto(caso, monkeypatch) -> None:
    """El manifiesto es metadato de custodia, no contenido que se sirva."""
    mcp_resources = pytest.importorskip("agentopsy.mcp.resources")
    monkeypatch.setattr(lectura, "artifact_store", caso["store"])
    with pytest.raises(ValueError, match="does not name an artifact"):
        mcp_resources.read_artifact(
            f"artifact://{caso['case_id']}/{caso['run']['run_id']}/manifest.json"
        )


def test_la_cronologia_no_pinta_un_bodyfile_alterado(tmp_path, monkeypatch) -> None:
    """Una cronología sobre bytes rotos sería peor que ninguna cronología."""
    from agentopsy.timeline import builder

    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Cronologia", examiner="e", os_profile="unix")
    run = crear_run(
        cases, case.id, tool_id="tsk_fls",
        ficheros={"stdout.bin": "0|/etc/passwd|5|r/r|0|0|4096|100|100|100|100\n"},
    )
    monkeypatch.setattr(builder, "case_manager", cases)

    # Íntegro: se lee.
    assert "/etc/passwd" in builder._read_run_stdout(case.id, run["run_id"])

    ruta = (
        cases.case_dir(case.id) / "artifacts" / run["run_id"] / "out" / "stdout.bin"
    )
    ruta.write_text("0|/inventado|1|r/r|0|0|1|1|1|1|1\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="integridad"):
        builder._read_run_stdout(case.id, run["run_id"])


def test_una_pagina_llena_de_lineas_no_se_declara_recortada_por_tamano(
    tmp_path,
) -> None:
    """Llenarse por el número de líneas pedidas es paginación, no un recorte.

    Confundir los dos motivos haría que TODA página completa pareciese haber
    perdido contenido por el tope de tamaño, que es justo lo contrario de lo que
    ese campo tiene que decir.
    """
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Paginas", examiner="e", os_profile="unix")
    run = crear_run(cases, case.id, stdout="".join(f"linea {i}\n" for i in range(50)))
    store = ArtifactStore(cases)

    pagina = store.read_run_output(
        case.id, run["run_id"], fichero="stdout", lineas=10
    )
    assert pagina["devueltas"] == 10
    assert pagina["hay_mas"] is True
    assert pagina["siguiente_desde"] == 11
    assert pagina["truncado_por_tamano"] is False
    assert pagina["fragmentadas"] == []
