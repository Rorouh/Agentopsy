"""Ronda de corrección del contrato de respuesta (2026-08-16).

La corrida medida murió en la iteración 2 con «acción desconocida
'record_finding'»: el modelo puso el NOMBRE de la herramienta en `action` en vez
de en `tool_id`, algo que el propio prompt invitaba al enseñar las tools internas
en notación de firma (`record_finding(title, summary, ...)`). Un envoltorio mal
formado se llevaba por delante el resto de la corrida y sus iteraciones ya
pagadas.

Lo que se fija aquí:

1. el contrato distingue el defecto de FORMATO (``ResponseContractError``) de un
   fallo de EJECUCIÓN, y nombra la confusión concreta en el mensaje;
2. el loop concede DOS correcciones seguidas, con el motivo exacto devuelto al
   modelo (una hasta la corrida del 2026-09-15: respuesta final en prosa y, en
   la corrección, un tool_call con una comilla sin cerrar, dos deslices
   distintos al cierre de una investigación ya hecha);
3. tres incumplimientos SEGUIDOS abortan;
4. el contador se reinicia con cada envoltorio válido: lo acotado son los
   incumplimientos consecutivos, no uno por corrida;
5. un fallo que NO es de contrato (timeout, CLI caído) no se reintenta: eso sería
   adivinar que la segunda vez sale mejor (RULE 2);
6. una respuesta SIN JSON recibe la reparación que le corresponde: envolver ese
   texto en ``final``, no «continúa donde estabas».
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from _agent_pkg import make_package
from agentopsy.i18n import t
from agentopsy.agent.agent import MAX_REPARACIONES_CONTRATO, ForensicAgent


from agentopsy.models.base import (
    Action,
    ExecutorBackend,
    FinalAnswer,
    ModelBackend,
    ModelCapabilities,
    ResponseContractError,
    ToolCall,
)


def _marca(clave: str) -> str:
    """El marcador distintivo de un bloque del prompt, EN EL IDIOMA EN CURSO.

    Los bloques del prompt se rotulan desde el catálogo, así que un test los
    nombra por su CLAVE y no por su texto castellano: lo que fija es que el
    marcador está, no con qué palabra se escribe. Para los que abren con una
    etiqueta entre corchetes (`[Presupuesto]`, `[Reminder]`) devuelve esa
    etiqueta; para el resto, el primer trozo de la primera línea.
    """
    texto = t(clave).strip()
    if texto.startswith("["):
        return texto[: texto.index("]") + 1]
    return texto.split("\n")[0].split(",")[0].strip()


class _FakeEvidence:
    def __init__(self, evidence_id: str = "e") -> None:
        # El caso de prueba tiene UNA evidencia. La investigación abarca TODAS las
        # del caso (`list`), y con una sola esa es el alcance entero.
        self._evidence_id = evidence_id

    def list(self, case_id: str) -> list[SimpleNamespace]:
        return [self.get(case_id, self._evidence_id)]

    def get(self, case_id: str, evidence_id: str) -> SimpleNamespace:
        return SimpleNamespace(
            evidence_id=evidence_id,
            original_path=Path("/cases/x/original.raw"),
            detected_os="unix",
            detected_kind="disk",
            sha256="0" * 64,
        )


class _Scripted(ModelBackend):
    """Modelo que reproduce una secuencia fija de respuestas.

    Cada elemento es o una excepción a lanzar o una ``Action`` a devolver. Guarda
    los mensajes que recibió en cada turno para poder comprobar qué se le dijo.
    """

    name = "fake"
    model_name = "fake-model"

    def __init__(self, guion: list[Any]) -> None:
        self.guion = list(guion)
        self.vistos: list[list[dict[str, Any]]] = []

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            supports_native_tools=False, json_mode=True, max_context=0, is_local=True
        )

    def next_action(self, state: dict[str, Any], tools: list[dict[str, Any]]) -> Action:
        self.vistos.append([dict(m) for m in state.get("messages", [])])
        if not self.guion:
            return FinalAnswer(text="fin del guion")
        siguiente = self.guion.pop(0)
        if isinstance(siguiente, BaseException):
            raise siguiente
        return siguiente


def _violacion(raw: str = '{"action": "record_finding", "title": "x"}') -> ResponseContractError:
    """El defecto exacto que se midió, construido por el parser real."""
    with pytest.raises(ResponseContractError) as exc:
        ExecutorBackend._parse_action(raw)
    return exc.value


def _correccion_en(mensajes: list[dict[str, Any]]) -> list[str]:
    return [
        str(m.get("content", ""))
        for m in mensajes
        if _marca("agentLoop.repairHead") in str(m.get("content", ""))
    ]


# ---- 1. el parser -----------------------------------------------------------


def test_tool_name_as_action_is_a_contract_error_that_names_the_fix() -> None:
    """El fallo medido. El mensaje tiene que decir DÓNDE va el nombre de la
    herramienta, porque es lo único que la corrección tiene que deshacer."""
    exc = _violacion()

    assert isinstance(exc, ValueError)  # sigue siendo un ValueError: nada que romper
    texto = str(exc)
    assert "record_finding" in texto
    assert "tool_id" in texto
    assert "action" in texto


def test_contract_error_carries_a_bounded_sample_of_the_reply() -> None:
    """La corrección cita lo que el modelo emitió, acotado: una respuesta
    desbocada no puede volver a entrar entera en el prompt."""
    exc = _violacion('{"action": "record_finding", "title": "' + "x" * 5000 + '"}')

    assert exc.raw_text
    assert len(exc.raw_text) <= 600


@pytest.mark.parametrize(
    "raw",
    [
        "no hay ningun json aqui",
        '{"action": "final"}',  # sin "text"
        '{"action": "tool_call"}',  # sin "tool_id"
        '{"action": "tool_batch", "calls": []}',  # lote vacio
        "[1, 2, 3]",  # no es un objeto
    ],
)
def test_every_envelope_defect_is_a_contract_error(raw: str) -> None:
    """Todas las puertas del parser son del MISMO tipo: cualquiera de ellas se
    puede nombrar al modelo y merece la misma ronda."""
    with pytest.raises(ResponseContractError):
        ExecutorBackend._parse_action(raw)


# ---- 2. el bucle ------------------------------------------------------------


def test_one_violation_gets_a_correction_and_the_run_continues() -> None:
    modelo = _Scripted([_violacion(), FinalAnswer(text="ya lo tengo")])
    agent = ForensicAgent(make_package("unix"), modelo, _FakeEvidence())

    result = agent.run("analiza", case_id="c")

    assert result["reply"] == "ya lo tengo"
    # Al modelo se le devolvió el motivo EXACTO, no un «formato incorrecto» seco.
    correcciones = _correccion_en(modelo.vistos[-1])
    assert len(correcciones) == 1
    assert "record_finding" in correcciones[0]
    assert "tool_id" in correcciones[0]


def test_two_consecutive_violations_still_get_corrected() -> None:
    """La corrida medida: prosa en la iteración 7, comilla sin cerrar en la
    corrección. Con una sola ronda se perdía la respuesta final de una
    investigación terminada; con dos, la tercera emisión cierra la corrida."""
    modelo = _Scripted(
        [
            _violacion("La evidencia confirma un indicador de compromiso."),
            _violacion('{"action":"tool_call","tool_id":"aff4imager","params":{"evidence_id":"e0}}'),
            FinalAnswer(text="ya lo tengo"),
        ]
    )
    agent = ForensicAgent(make_package("unix"), modelo, _FakeEvidence())

    result = agent.run("analiza", case_id="c")

    assert result["reply"] == "ya lo tengo"
    assert len(_correccion_en(modelo.vistos[-1])) == 2


def test_three_consecutive_violations_abort_the_run() -> None:
    modelo = _Scripted(
        [_violacion(), _violacion(), _violacion(), FinalAnswer(text="tarde")]
    )
    agent = ForensicAgent(make_package("unix"), modelo, _FakeEvidence())

    result = agent.run("analiza", case_id="c")

    assert "tarde" not in result["reply"]
    # El aviso al perito sale en el idioma en curso, así que se fija por la
    # entrada del catálogo: dice que el contrato se incumplió y que lo ya
    # persistido en caliente se conserva. No se relaja nada.
    # Se comprueba contra la PLANTILLA del catálogo, trozo fijo a trozo fijo,
    # en vez de contra una frase castellana.
    plantilla = t("agent.contractBroken", None, model="\x00", iteration="\x00", error="\x00")
    for trozo in (parte for parte in plantilla.split("\x00") if parte.strip()):
        assert trozo in result["reply"]


def test_the_allowance_is_consecutive_not_per_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Un desliz aislado en la iteración 2 no debe condenar a la 15."""

    def fake_execute(
        tool_id,
        params,
        *,
        case_id=None,
        os_profile=None,
        timeout=None,
        evidence_context=None,
    ):
        return {
            "tool_id": tool_id,
            "argv": ["fls", "/cases/x/original.raw"],
            "exit_code": 0,
            "stdout_sample": "d/d 13:\tbin",
            "stderr_sample": "",
            "parsed": {"format": "list", "entries_count": 1, "entries": []},
            "run_id": "r",
        }

    monkeypatch.setattr("agentopsy.toolkit.dispatcher.execute", fake_execute)

    valida = ToolCall(
        tool_id="tsk_fls",
        params={},
        call_id="x",
        assistant_message={"role": "assistant", "content": "{}"},
    )
    modelo = _Scripted(
        [_violacion(), valida, _violacion(), FinalAnswer(text="cerrado")]
    )
    agent = ForensicAgent(make_package("unix"), modelo, _FakeEvidence())

    result = agent.run("analiza", case_id="c")

    assert result["reply"] == "cerrado"
    # Dos correcciones a lo largo de la corrida, ninguna seguida de otra.
    assert len(_correccion_en(modelo.vistos[-1])) == 2


def test_an_execution_failure_is_not_retried() -> None:
    """Un timeout o un CLI caído NO es un defecto que se pueda nombrar: reintentar
    sería adivinar que la segunda vez sale mejor (RULE 2)."""
    modelo = _Scripted([RuntimeError("executor timeout"), FinalAnswer(text="nunca")])
    agent = ForensicAgent(make_package("unix"), modelo, _FakeEvidence())

    result = agent.run("analiza", case_id="c")

    assert "nunca" not in result["reply"]
    assert "RuntimeError" in result["reply"]
    assert not _correccion_en(modelo.vistos[-1])


def test_two_correction_rounds_are_granted() -> None:
    assert MAX_REPARACIONES_CONTRATO == 2


# ---- 3. la reparación nombra el arreglo real ---------------------------------


def test_a_reply_without_json_is_told_to_wrap_it_in_final() -> None:
    """Iteración 7 de la corrida medida: la respuesta final, en prosa. La
    corrección tiene que decir que ese texto se envuelve en `final`, no
    «continúa donde estabas», que a un modelo que ya había terminado lo mandó a
    inventarse un tool_call."""
    exc = _violacion("La evidencia confirma un indicador de compromiso.")
    assert exc.no_json is True

    modelo = _Scripted([exc, FinalAnswer(text="ya lo tengo")])
    agent = ForensicAgent(make_package("unix"), modelo, _FakeEvidence())
    agent.run("analiza", case_id="c")

    (correccion,) = _correccion_en(modelo.vistos[-1])
    assert '{"action": "final", "text":' in correccion
    assert t("agentLoop.repairTailNoJson") in correccion
    assert t("agentLoop.repairTail") not in correccion
    # Lo que emitió viaja citado, para que reconozca su propio texto.
    assert "La evidencia confirma" in correccion


def test_a_broken_envelope_keeps_the_generic_repair() -> None:
    """Una comilla sin cerrar o una clave mal puesta se corrige reemitiendo lo
    mismo bien formado: ahí no hay nada que envolver en `final`."""
    exc = _violacion('{"action":"tool_call","tool_id":"aff4imager","params":{"evidence_id":"e0}}')
    assert exc.no_json is False

    modelo = _Scripted([exc, FinalAnswer(text="ya lo tengo")])
    agent = ForensicAgent(make_package("unix"), modelo, _FakeEvidence())
    agent.run("analiza", case_id="c")

    (correccion,) = _correccion_en(modelo.vistos[-1])
    assert t("agentLoop.repairTail") in correccion
    assert t("agentLoop.repairTailNoJson") not in correccion
    assert "Unterminated string" in correccion


def test_the_contract_shown_to_the_model_has_single_braces() -> None:
    """El catálogo escapaba las llaves para `str.format`, pero `t()` no formatea
    una entrada sin parámetros: el modelo leía `{{"action": "final", ...}}` como
    formato OBLIGATORIO. Los tres ejemplos tienen que ser JSON de una llave."""
    from agentopsy.models.base import _response_contract

    for lang in ("es", "en"):
        contrato = t("agentContract.format", lang)
        assert "{{" not in contrato and "}}}}" not in contrato
        assert '{"action": "final", "text":' in contrato
        assert '{"action": "tool_call", "tool_id":' in contrato
        assert '{"action": "tool_batch", "calls": [{"tool_id":' in contrato
    assert "{{" not in _response_contract()


# ---- 4. quién escribió la respuesta -----------------------------------------


def test_the_result_declares_whether_the_reply_is_the_models_or_a_notice() -> None:
    """`notice` viaja con el resultado y de ahí al mensaje persistido: el aviso
    de contrato roto, replicado como turno del asistente, fue el ejemplo que el
    modelo copió byte a byte tres corridas seguidas (2026-09-15)."""
    modelo = _Scripted([FinalAnswer(text="ya lo tengo")])
    agent = ForensicAgent(make_package("unix"), modelo, _FakeEvidence())
    assert agent.run("analiza", case_id="c")["notice"] is False

    modelo = _Scripted([_violacion(), _violacion(), _violacion(), FinalAnswer(text="tarde")])
    agent = ForensicAgent(make_package("unix"), modelo, _FakeEvidence())
    assert agent.run("analiza", case_id="c")["notice"] is True

    modelo = _Scripted([RuntimeError("executor timeout")])
    agent = ForensicAgent(make_package("unix"), modelo, _FakeEvidence())
    assert agent.run("analiza", case_id="c")["notice"] is True
