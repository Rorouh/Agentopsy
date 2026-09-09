"""RA05: una cadena inválida no produce lecturas marcadas como ancladas.

Lo que la reauditoría del 2026-09-08 reprodujo: se alteran ``stdout.txt``, su
entrada en el manifiesto y el ``manifest_sha256`` de un único evento del audit.
No se recalcula ningún ``entry_hash``, así que ``AuditLog.verify`` devuelve
falso. Y aun así el lector devolvía el texto alterado marcándolo ``anclado``,
porque ``_ancla_auditada`` leía el digest sin mirar la cadena que lo contiene.

No hace falta reescribir la cadena entera (ese es el límite externo que la
herramienta reconoce y documenta). Era una comprobación interna que faltaba.

Los gates de este fichero:

- Artefacto, manifiesto y un evento alterados sin reparar la cadena: la lectura
  se RECHAZA, no se degrada ni se sirve marcada como anclada.
- El ancla de una ejecución MODERNA que falta no se degrada a histórica.
- Una entrada corrupta del log rompe la cadena en vez de reventar el parseo.
- No hay caché: leer bien una vez no hace que la siguiente lectura mienta.
- Un registro HISTÓRICO (manifiesto sin digest propio) se lee declarando que no
  tiene ancla.
- Una ejecución moderna e íntegra se lee marcada como anclada.
- El error se propaga a los consumidores del lector común.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from _informe import hallazgo, montar_caso
from agentopsy.artifacts import lectura
from agentopsy.artifacts.store import ArtifactStore
from agentopsy.audit.log import AuditLog
from agentopsy.findings.procedencia import ProcedenciaError, verificar_referencia
from agentopsy.reports.aprobacion import comprobar


@pytest.fixture
def caso(tmp_path):
    return montar_caso(tmp_path)


def _abrir(caso, ambito=lectura.AMBITO_AGENTE):
    return lectura.abrir_verificado(
        caso["case"].id, caso["run_id"], "stdout",
        ambito=ambito, store=caso["artefactos"],
    )


def _dir_run(caso):
    return caso["cases"].case_dir(caso["case"].id) / "artifacts" / caso["run_id"]


def _reescribir_coherente(caso) -> None:
    """Altera la salida y su manifiesto de forma coherente, y actualiza el
    evento del audit SIN recalcular los ``entry_hash``: la cadena queda rota."""
    ruta = _dir_run(caso)
    (ruta / "stdout.txt").write_text("CONTENIDO SINTETICO CAMBIADO\n", encoding="utf-8")
    manifiesto = json.loads((ruta / "manifest.json").read_text(encoding="utf-8"))
    manifiesto["stdout_sha256"] = hashlib.sha256(
        (ruta / "stdout.txt").read_bytes()
    ).hexdigest()
    manifiesto["manifest_sha256"] = lectura.manifest_digest(manifiesto)
    (ruta / "manifest.json").write_text(json.dumps(manifiesto), encoding="utf-8")

    eventos = caso["audit"].entries()
    for evento in eventos:
        if evento.get("action") == "tool_run_finish":
            evento["manifest_sha256"] = manifiesto["manifest_sha256"]
    caso["audit"].path.write_text(
        "\n".join(json.dumps(e) for e in eventos) + "\n", encoding="utf-8"
    )


# -- la reproducción ----------------------------------------------------------


def test_una_cadena_rota_no_produce_una_lectura_anclada(caso) -> None:
    _reescribir_coherente(caso)
    assert caso["audit"].verify() is False

    with pytest.raises(lectura.CadenaRotaError):
        with _abrir(caso):
            pass


def test_la_cadena_rota_no_se_convierte_en_una_lectura_vacia(caso) -> None:
    """RA05 c: un fallo de integridad no se degrada a «no hay resultados»."""
    _reescribir_coherente(caso)
    try:
        with _abrir(caso) as abierta:
            abierta.texto()
        pytest.fail("la lectura no debería haber devuelto contenido")
    except lectura.CadenaRotaError as exc:
        # El motivo dice qué caso y qué entrada, para poder ir a mirarla.
        assert caso["case"].id in str(exc)


def test_un_ancla_ausente_de_una_ejecucion_moderna_no_pasa_por_historica(
    tmp_path,
) -> None:
    """El manifiesto declara su propio digest, así que ese run se cerró con el
    anclaje implantado. Que su ancla no esté en el log no lo convierte en
    antiguo: lo convierte en roto."""
    caso = montar_caso(tmp_path)
    store = ArtifactStore(caso["cases"])
    run_id, _out = store.start_run(
        caso["case"].id, "tsk_fls", ["fls"],
        evidence_id=caso["evidencia"].evidence_id,
        evidence_baseline_sha256=caso["evidencia"].sha256,
        tool_version="sleuthkit 4.12.1",
    )
    # Se cierra la ejecución y NO se ancla: la cadena sigue siendo válida.
    store.finalize_run(caso["case"].id, run_id, exit_code=0, stdout="x\n", stderr="")
    assert caso["audit"].verify() is True

    with pytest.raises(lectura.AnclaAusenteError):
        with lectura.abrir_verificado(
            caso["case"].id, run_id, "stdout",
            ambito=lectura.AMBITO_AGENTE, store=store,
        ):
            pass


def test_un_registro_historico_sin_ancla_se_lee_declarandolo(tmp_path) -> None:
    """Compatibilidad honesta: un run anterior al anclaje no tiene digest propio
    en su manifiesto, se sirve, y se DICE que su garantía es menor."""
    caso = montar_caso(tmp_path)
    ruta = _dir_run(caso) / "manifest.json"
    manifiesto = json.loads(ruta.read_text(encoding="utf-8"))
    manifiesto.pop("manifest_sha256", None)
    ruta.write_text(json.dumps(manifiesto), encoding="utf-8")

    # Y su ancla se retira del log, escribiéndolo entero de nuevo con `append`
    # para que la cadena siga siendo válida.
    eventos = [
        e for e in caso["audit"].entries() if e.get("action") != "tool_run_finish"
    ]
    caso["audit"].path.unlink()
    log = AuditLog(caso["audit"].path)
    for evento in eventos:
        log.append({k: v for k, v in evento.items()
                    if k not in ("entry_hash", "prev_hash", "ts_utc")})
    assert log.verify() is True

    with _abrir(caso) as abierta:
        assert abierta.anclaje == "sin_ancla"
        assert "updater.exe" in abierta.texto()


def test_una_entrada_corrupta_rompe_la_cadena_sin_reventar(caso) -> None:
    """Una línea que no es JSON válido es una rotura como cualquier otra: se
    informa, no se lanza un error de parseo desde las tripas."""
    with caso["audit"].path.open("a", encoding="utf-8") as fh:
        fh.write("{esto no es json}\n")

    estado = caso["audit"].estado()
    assert estado.valida is False
    assert estado.indice_roto is not None
    assert caso["audit"].verify() is False
    with pytest.raises(lectura.CadenaRotaError):
        with _abrir(caso):
            pass


def test_no_hay_cache_que_oculte_una_alteracion_posterior(caso) -> None:
    """Leer bien una vez no hace que la siguiente lectura mienta: cada lectura
    revalida la cadena y rehashea los bytes."""
    with _abrir(caso) as abierta:
        assert abierta.anclaje == "anclado"

    _reescribir_coherente(caso)
    with pytest.raises(lectura.CadenaRotaError):
        with _abrir(caso):
            pass


# -- propagación a los consumidores del lector común --------------------------


def test_el_error_llega_a_la_procedencia_de_un_hallazgo(caso) -> None:
    _reescribir_coherente(caso)
    with pytest.raises(ProcedenciaError):
        verificar_referencia(
            caso["case"].id,
            {"run_id": caso["run_id"], "artefacto": "stdout"},
            store=caso["artefactos"],
        )


def test_el_error_llega_a_la_comprobacion_de_aprobacion(tmp_path) -> None:
    from _informe import informe

    caso = montar_caso(tmp_path)
    h = hallazgo(caso)
    doc = informe(caso, h)
    _reescribir_coherente(caso)

    comprobacion = comprobar(
        caso["case"].id, doc.id,
        documents=caso["documents"], cases=caso["cases"],
    )
    codigos = {b.codigo for b in comprobacion.bloqueos}
    assert "cadena_rota" in codigos
    assert not comprobacion.aprobable


def test_la_familia_de_errores_es_una_sola(caso) -> None:
    """Un consumidor que capture ``ArtefactoError`` para decir «no puedo leer
    esto, este es el motivo» tiene que enterarse también cuando el motivo es que
    está alterado. Con dos ramas sueltas, el fallo que más importa se escapaba."""
    assert issubclass(lectura.CadenaRotaError, lectura.ArtefactoError)
    assert issubclass(lectura.AnclaAusenteError, lectura.ArtefactoError)
    assert issubclass(lectura.ArtefactoIntegridadError, lectura.ArtefactoError)


# -- el recorrido válido ------------------------------------------------------


def test_una_ejecucion_moderna_integra_se_lee_anclada(caso) -> None:
    assert caso["audit"].verify() is True
    with _abrir(caso) as abierta:
        assert abierta.anclaje == "anclado"
        assert abierta.sellado is True
        assert "updater.exe" in abierta.texto()
