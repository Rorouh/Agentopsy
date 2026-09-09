"""RA07: cada conclusión del informe permite abrir su respaldo concreto.

Lo que la reauditoría del 2026-09-08 confirmó por código: la pantalla de
aprobación enseñaba identificadores y estados, pero desde una conclusión no se
podía llegar a la línea que la sostiene. Y los bloques narrativos no tenían
ninguna asociación OBLIGATORIA con citas estructuradas: el manifiesto agrupaba
fuentes a nivel de documento, no de afirmación.

Los gates de este fichero:

- Una conclusión forense sin respaldo BLOQUEA la aprobación, y el motivo dice
  qué bloque de qué apartado.
- El texto metodológico NO está obligado a citar: exigírselo produciría citas de
  adorno.
- Una limitación se declara con su CÓDIGO y no necesita cita.
- Desde una conclusión válida se abre el fragmento correcto, con su localizador.
- Una cita a un hallazgo inexistente, de otro caso o fuera del manifiesto se
  detecta y se dice.
- Si la fuente se altera, se dice el motivo y NO se presenta como verificada.
- El redactor no puede publicar un informe que incumpla esto (quinta puerta).
- Las limitaciones exigidas intervienen en la revisión.

La distinción que se mantiene explícita: que la fuente exista y su hash case es
INTEGRIDAD TÉCNICA. Que respalde lo que la conclusión afirma es REVISIÓN HUMANA,
y ninguna comprobación de este fichero la sustituye.
"""

from __future__ import annotations

import pytest
from _informe import (
    ARGV,
    aprobar,
    hallazgo,
    informe,
    material_de,
    montar_caso,
    secciones,
)
from agentopsy.reports.aprobacion import comprobar
from agentopsy.reports.citas import abrir_cita
from agentopsy.reports.works import render_argv


@pytest.fixture
def caso(tmp_path):
    entorno = montar_caso(tmp_path)
    h = hallazgo(entorno)
    return entorno, h, informe(entorno, h)


def _checks(entorno, doc):
    return comprobar(
        entorno["case"].id, doc.id,
        documents=entorno["documents"], cases=entorno["cases"],
    )


def _abrir(entorno, doc, finding_id: str, revision: int = 1):
    return abrir_cita(
        entorno["case"].id, doc.id, finding_id,
        revision=revision,
        documents=entorno["documents"],
        cases=entorno["cases"],
        findings=entorno["findings"],
        artifacts=entorno["artefactos"],
    )


# -- la asociación obligatoria ------------------------------------------------


def test_una_conclusion_forense_sin_respaldo_bloquea(tmp_path) -> None:
    entorno = montar_caso(tmp_path)
    h = hallazgo(entorno)
    cuerpo = secciones(h)
    # Se le quita la cita a la conclusión del apartado 9.
    cuerpo[2]["blocks"][0].pop("refs")
    doc = informe(entorno, h, sections=cuerpo)

    comprobacion = _checks(entorno, doc)
    assert not comprobacion.aprobable
    bloqueo = next(
        b for b in comprobacion.bloqueos if b.codigo == "conclusion_sin_respaldo"
    )
    # El motivo señala el bloque concreto, no «hay un problema en el informe».
    assert "9#0" in bloqueo.detalle


def test_el_texto_metodologico_no_esta_obligado_a_citar(caso) -> None:
    """RA07 c: obligar a citar un título o un comando produciría citas de adorno."""
    entorno, _h, doc = caso
    # El apartado 1 lleva prosa y un bloque de comando, sin una sola cita.
    apartado_1 = doc.sections[0]
    assert apartado_1["num"] == "1"
    assert all("refs" not in b for b in apartado_1["blocks"])
    assert _checks(entorno, doc).aprobable


def test_una_limitacion_se_declara_por_codigo_y_no_necesita_cita(caso) -> None:
    entorno, _h, doc = caso
    limitacion = next(
        b for b in doc.sections[2]["blocks"] if b.get("limitacion")
    )
    assert "refs" not in limitacion
    assert _checks(entorno, doc).aprobable


def test_una_cita_fuera_del_manifiesto_se_detecta(tmp_path) -> None:
    """Un hallazgo de otro caso, o uno que el informe no tenía delante: lo que
    esa conclusión enseñaría no es lo que la sostuvo."""
    entorno = montar_caso(tmp_path)
    h = hallazgo(entorno)
    ajeno = hallazgo(entorno)  # existe, pero no entra en el manifiesto
    cuerpo = secciones(h)
    cuerpo[2]["blocks"][0]["refs"] = [
        {"finding_id": ajeno.id, "revision": ajeno.revision}
    ]
    doc = informe(entorno, h, material=material_de(entorno, h), sections=cuerpo)

    comprobacion = _checks(entorno, doc)
    assert "cita_fuera_del_manifiesto" in {b.codigo for b in comprobacion.bloqueos}
    cita = next(c for c in comprobacion.citas if c["finding_id"] == ajeno.id)
    assert cita["en_manifiesto"] is False


def test_una_cita_a_un_hallazgo_inexistente_se_rechaza_al_abrirla(caso) -> None:
    entorno, _h, doc = caso
    with pytest.raises(KeyError):
        _abrir(entorno, doc, "11111111-1111-4111-8111-111111111111")


def test_el_documento_no_es_una_puerta_a_cualquier_hallazgo(tmp_path) -> None:
    """La ruta del informe abre las fuentes de SUS conclusiones. Un hallazgo del
    caso que este informe no cita no se sirve por ahí."""
    entorno = montar_caso(tmp_path)
    h = hallazgo(entorno)
    otro = hallazgo(entorno)
    doc = informe(entorno, h)
    with pytest.raises(KeyError, match="no cita|does not cite"):
        _abrir(entorno, doc, otro.id)


# -- abrir la fuente ----------------------------------------------------------


def test_desde_una_conclusion_valida_se_abre_el_fragmento_correcto(caso) -> None:
    entorno, h, doc = caso
    cita = _abrir(entorno, doc, h.id, h.revision)

    # Dónde se cita: la conclusión concreta cuya fuente se está enseñando.
    assert [c["num"] for c in cita["conclusiones"]] == ["6", "9"]
    assert cita["en_manifiesto"] is True
    assert cita["integridad_ok"] is True

    fuente = cita["fuentes"][0]
    assert fuente["estado"] == "verificada"
    assert fuente["run_id"] == entorno["run_id"]
    assert fuente["localizador"] == {"tipo": "lineas", "desde": 2, "hasta": 2}
    # El EXTRACTO que hay en esa posición, recomputado ahora sobre los bytes.
    assert fuente["extracto"] == "r/r 512-128-3: Users/jcloudy/AppData/updater.exe"
    assert fuente["anclaje"] == "anclado"


def test_si_la_fuente_se_altera_se_dice_el_motivo_y_no_se_da_por_verificada(
    caso,
) -> None:
    entorno, h, doc = caso
    (
        entorno["cases"].case_dir(entorno["case"].id)
        / "artifacts" / entorno["run_id"] / "stdout.txt"
    ).write_text("MANIPULADO\n", encoding="utf-8")

    cita = _abrir(entorno, doc, h.id, h.revision)
    fuente = cita["fuentes"][0]
    assert fuente["estado"] != "verificada"
    assert fuente.get("motivo")
    # Y sin extracto: enseñarlo sería presentarlo como comprobado.
    assert not fuente.get("extracto")


def test_un_localizador_imposible_no_se_confunde_con_una_fuente_alterada(
    tmp_path,
) -> None:
    """Los bytes casan con su hash; lo que no existe es la posición citada.
    Decir «alterada» mandaría a mirar donde no está el problema (RA06)."""
    import json

    entorno = montar_caso(tmp_path)
    h = hallazgo(entorno)
    doc = informe(entorno, h)

    ruta = entorno["cases"].case_dir(entorno["case"].id) / "findings.jsonl"
    registro = json.loads(ruta.read_text(encoding="utf-8").strip())
    registro["references"][0]["localizador"] = {
        "tipo": "lineas", "desde": 1, "hasta": 999999,
    }
    ruta.write_text(json.dumps(registro) + "\n", encoding="utf-8")

    cita = _abrir(entorno, doc, h.id, h.revision)
    assert cita["fuentes"][0]["estado"] == "localizador_invalido"


def test_un_hallazgo_reescrito_se_marca_al_abrir_su_cita(caso) -> None:
    import json

    entorno, h, doc = caso
    ruta = entorno["cases"].case_dir(entorno["case"].id) / "findings.jsonl"
    registro = json.loads(ruta.read_text(encoding="utf-8").strip())
    registro["summary"] = "RESUMEN REESCRITO"
    ruta.write_text(json.dumps(registro) + "\n", encoding="utf-8")

    cita = _abrir(entorno, doc, h.id, h.revision)
    assert cita["integridad_ok"] is False
    assert cita["content_sha256_recomputado"] != cita["content_sha256"]


# -- la quinta puerta del redactor --------------------------------------------


def test_el_redactor_rechaza_una_conclusion_sin_respaldo(tmp_path) -> None:
    """RA07 d: la validación no depende de lo que produzca el modelo. Si su
    redacción no trae el respaldo, no se publica."""
    from agentopsy.reports.writer import ReportWriteError, _validar_respaldo

    entorno = montar_caso(tmp_path)
    h = hallazgo(entorno)
    material = material_de(entorno, h)
    snapshot = {"limitaciones_exigidas": []}

    cuerpo = secciones(h)
    _validar_respaldo(cuerpo, material, snapshot)  # el válido pasa

    cuerpo[1]["blocks"][0].pop("refs")
    with pytest.raises(ReportWriteError, match="refs"):
        _validar_respaldo(cuerpo, material, snapshot)


def test_el_redactor_rechaza_una_cita_que_no_esta_en_el_material(tmp_path) -> None:
    from agentopsy.reports.writer import ReportWriteError, _validar_respaldo

    entorno = montar_caso(tmp_path)
    h = hallazgo(entorno)
    cuerpo = secciones(h)
    cuerpo[1]["blocks"][0]["refs"] = [
        {"finding_id": "11111111-1111-4111-8111-111111111111", "revision": 1}
    ]
    with pytest.raises(ReportWriteError, match="material"):
        _validar_respaldo(cuerpo, material_de(entorno, h), {"limitaciones_exigidas": []})


def test_el_redactor_exige_declarar_las_limitaciones_por_codigo(tmp_path) -> None:
    from agentopsy.reports.writer import ReportWriteError, _validar_respaldo

    entorno = montar_caso(tmp_path)
    h = hallazgo(entorno)
    snapshot = {"limitaciones_exigidas": ["ejecuciones_fallidas"]}
    with pytest.raises(ReportWriteError, match="ejecuciones_fallidas"):
        _validar_respaldo(secciones(h), material_de(entorno, h), snapshot)

    # Declarada por su código, pasa.
    _validar_respaldo(
        secciones(h, limitaciones=("ejecuciones_fallidas",)),
        material_de(entorno, h),
        snapshot,
    )


# -- las limitaciones exigidas intervienen en la revisión ---------------------


def test_una_limitacion_exigida_y_no_declarada_bloquea(tmp_path) -> None:
    entorno = montar_caso(tmp_path)
    h = hallazgo(entorno)
    material = material_de(entorno, h)
    material["truncado"] = {"hallazgos": {"total": 500, "incluidos": 400}}
    # El apartado 9 tiene texto, pero no declara el CÓDIGO exigido.
    doc = informe(entorno, h, material=material, sections=secciones(h))

    comprobacion = _checks(entorno, doc)
    bloqueo = next(
        b for b in comprobacion.bloqueos if b.codigo == "limitaciones_ausentes"
    )
    assert "material_truncado:hallazgos" in bloqueo.detalle


def test_el_mismo_informe_declarandola_por_codigo_se_aprueba(tmp_path) -> None:
    entorno = montar_caso(tmp_path)
    h = hallazgo(entorno)
    material = material_de(entorno, h)
    material["truncado"] = {"hallazgos": {"total": 500, "incluidos": 400}}
    doc = informe(
        entorno, h,
        material=material,
        sections=secciones(h, limitaciones=("material_truncado:hallazgos",)),
    )
    comprobacion = _checks(entorno, doc)
    assert comprobacion.aprobable, [b.mensaje for b in comprobacion.bloqueos]


# -- el recorrido válido, de la evidencia al PDF ------------------------------


def test_el_recorrido_completo_con_su_respaldo(caso) -> None:
    entorno, h, doc = caso
    comprobacion = _checks(entorno, doc)
    assert comprobacion.aprobable, [b.mensaje for b in comprobacion.bloqueos]

    # Cada cita del contenido está en el manifiesto y su hallazgo verifica.
    assert comprobacion.citas
    assert all(c["en_manifiesto"] for c in comprobacion.citas)
    assert all(c["estado"] == "verificada" for c in comprobacion.citas)

    # Y el comando auditado sigue siendo el que se ejecutó, carácter a carácter.
    codigo = next(b for b in doc.sections[0]["blocks"] if b["t"] == "code")
    assert codigo["text"] == render_argv(ARGV)

    assert aprobar(entorno, doc).status == "final"
