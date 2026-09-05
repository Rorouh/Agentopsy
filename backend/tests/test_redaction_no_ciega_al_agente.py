"""La redacción de egress NO puede cegar al agente (regresión, 2026-07-28).

**El bug.** `policy/redaction.yaml` del paquete Windows declara un patrón `guid`
para tapar el `MachineGuid` que aparezca DENTRO de la evidencia. Pero
`redact_messages` lo aplicaba como un `re.sub` ciego sobre TODO el contenido de
TODOS los mensajes, incluidos los identificadores que la propia Agentopsy inyecta.
El agente veía:

    run_id: <GUID>

…y a la vez se le exigía citar el `run_id` para encadenar `tsk_mactime`, para leer
un artefacto y para registrar un hallazgo. Era **imposible**: copiaba literalmente
lo único que se le enseñaba y la llamada se rechazaba por UUID4 inválido.

Coste real medido antes del arreglo: dos corridas completas ($4,13 y $3,30) sin un
solo hallazgo persistido, atribuidas a fallo del modelo y de los prompts.

Solo afectaba a ejecutores CLOUD: con un backend local la redacción ni se aplica.

**La frontera.** Un `run_id`/`case_id`/`evidence_id`/`finding_id` lo genera
Agentopsy, no sale de la evidencia y no contiene dato personal: no hay nada que
minimizar. Un GUID que venga del CONTENIDO de la evidencia se sigue tapando.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from _agent_pkg import make_package

from agentopsy.agent.agent import ForensicAgent
from agentopsy.agent.package import RedactionPattern
from agentopsy.agent.redaction import apply_redaction, redact_messages
from agentopsy.models.base import FinalAnswer, ModelBackend, ModelCapabilities, ToolCall

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENTES_DIR = REPO_ROOT / "agentes"

RUN_ID = "a91ad448-1bd0-4c79-8645-e7fe24d333bc"
OTRO_GUID = "11111111-2222-3333-4444-555555555555"

GUID_PATTERN = RedactionPattern(
    name="guid",
    regex=r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b",
    replacement="<GUID>",
    apply_in=("strict",),
)


# ── el bug, en su forma mínima ──────────────────────────────────────────────


def test_sin_proteccion_el_run_id_se_convierte_en_guid() -> None:
    """Pinea el comportamiento ANTIGUO para que quede claro qué se arregló."""
    texto = f"run_id: {RUN_ID}"
    assert apply_redaction(texto, [GUID_PATTERN]) == "run_id: <GUID>"


def test_un_run_id_protegido_sobrevive_intacto() -> None:
    texto = f"run_id: {RUN_ID}"
    out = apply_redaction(texto, [GUID_PATTERN], protected=[RUN_ID])
    assert out == texto
    assert "<GUID>" not in out


def test_el_guid_de_la_evidencia_se_sigue_tapando() -> None:
    """Lo que el patrón existe para hacer NO se toca: solo se exceptúan los ids
    del plano de control."""
    texto = f"run_id: {RUN_ID} · MachineGuid del registro: {OTRO_GUID}"
    out = apply_redaction(texto, [GUID_PATTERN], protected=[RUN_ID])
    assert RUN_ID in out
    assert OTRO_GUID not in out
    assert "<GUID>" in out


def test_varios_ids_protegidos_a_la_vez() -> None:
    case_id = "6a1375d3-3005-442a-874a-18fc17f062ed"
    ev_id = "9bc48a90-0a8d-441e-bd1a-146d9170636a"
    texto = f"caso {case_id}, evidencia {ev_id}, run {RUN_ID}, ajeno {OTRO_GUID}"
    out = apply_redaction(texto, [GUID_PATTERN], protected=[case_id, ev_id, RUN_ID])
    for protegido in (case_id, ev_id, RUN_ID):
        assert protegido in out
    assert OTRO_GUID not in out


def test_proteger_no_desactiva_los_demas_patrones() -> None:
    email = RedactionPattern(
        name="email", regex=r"\b[\w.]+@[\w.]+\b", replacement="<EMAIL>"
    )
    texto = f"run {RUN_ID} lo vio perito@ejemplo.com"
    out = apply_redaction(texto, [GUID_PATTERN, email], protected=[RUN_ID])
    assert RUN_ID in out
    assert "perito@ejemplo.com" not in out


def test_protegidos_vacios_se_comporta_como_antes() -> None:
    texto = f"run {RUN_ID}"
    assert apply_redaction(texto, [GUID_PATTERN], protected=[]) == "run <GUID>"
    assert apply_redaction(texto, [GUID_PATTERN], protected=[""]) == "run <GUID>"


def test_redact_messages_protege_en_todos_los_mensajes() -> None:
    msgs = [
        {"role": "system", "content": f"caso con run {RUN_ID}"},
        {"role": "tool", "content": f"resultado run_id={RUN_ID} guid={OTRO_GUID}"},
    ]
    out = redact_messages(msgs, [GUID_PATTERN], protected=[RUN_ID])
    assert all(RUN_ID in m["content"] for m in out)
    assert OTRO_GUID not in out[1]["content"]
    # Y no muta la conversación canónica.
    assert msgs[1]["content"] == f"resultado run_id={RUN_ID} guid={OTRO_GUID}"


# ── apply_in deja de ignorarse ──────────────────────────────────────────────


def test_un_patron_que_no_aplica_al_modo_no_se_ejecuta() -> None:
    solo_relaxed = RedactionPattern(
        name="x", regex=r"SECRETO", replacement="<X>", apply_in=("relaxed",)
    )
    assert apply_redaction("SECRETO", [solo_relaxed], mode="strict") == "SECRETO"
    assert apply_redaction("SECRETO", [solo_relaxed], mode="relaxed") == "<X>"


def test_el_modo_por_defecto_conserva_el_comportamiento_historico() -> None:
    """Los patrones de redacción por defecto declaran `strict`, así que el default
    no cambia nada de lo que ya se redactaba en egress."""
    for prof in ("unix", "windows"):
        pkg = make_package(prof)
        assert pkg.policy.redaction_patterns
        assert all("strict" in p.apply_in for p in pkg.policy.redaction_patterns)


# ── el loop real, con el paquete real ───────────────────────────────────────


class _Capturador(ModelBackend):
    """Modelo cloud falso: guarda EXACTAMENTE lo que se le manda por el wire."""

    name = "claude-code"

    def __init__(self, acciones: list[Any]) -> None:
        self._acciones = list(acciones)
        self.visto: list[list[dict[str, Any]]] = []

    def capabilities(self) -> ModelCapabilities:
        # is_local=False → el loop redacta. Es la condición del bug.
        return ModelCapabilities(
            supports_native_tools=False, json_mode=True, max_context=0, is_local=False
        )

    def next_action(self, state, tools):
        self.visto.append(list(state.get("messages") or []))
        return self._acciones.pop(0) if self._acciones else FinalAnswer(text="fin")


class _FakeEvidence:
    def get(self, case_id: str, evidence_id: str) -> SimpleNamespace:
        return SimpleNamespace(
            evidence_id=evidence_id,
            original_path=Path("/cases/x/original.raw"),
            detected_os="windows",
            detected_kind="disk",
            sha256="0" * 64,
        )


def test_el_agente_cloud_VE_el_run_id_real_de_la_herramienta(monkeypatch) -> None:
    """El gate que cierra el bug de punta a punta, con el paquete Windows real y
    su patrón `guid`: tras ejecutar una herramienta, el run_id que llega al modelo
    en la SIGUIENTE iteración es el UUID4 de verdad, no `<GUID>`."""

    def fake_execute(tool_id, params, **kwargs):
        return {
            "tool_id": tool_id,
            "argv": [tool_id],
            "exit_code": 0,
            "stdout_sample": "ok",
            "stderr_sample": "",
            "parsed": None,
            "run_id": RUN_ID,
        }

    monkeypatch.setattr("agentopsy.toolkit.dispatcher.execute", fake_execute)
    pkg = make_package("windows", redaction_patterns=(GUID_PATTERN,))
    model = _Capturador([
        ToolCall(tool_id="tsk_mmls", params={}, call_id="x"),
    ])
    agent = ForensicAgent(pkg, model, _FakeEvidence())
    agent.run("analiza", case_id="c", evidence_id="e")

    # La segunda vez que habla el modelo ya lleva el resultado de la herramienta.
    assert len(model.visto) >= 2
    ultimo = "\n".join(
        str(m.get("content") or "") for m in model.visto[-1] if m.get("role") == "tool"
    )
    assert RUN_ID in ultimo, "el agente NO puede citar un run_id que no ve"
    assert "<GUID>" not in ultimo


def test_el_case_id_y_el_evidence_id_tambien_sobreviven(monkeypatch) -> None:
    case_id = "6a1375d3-3005-442a-874a-18fc17f062ed"
    ev_id = "9bc48a90-0a8d-441e-bd1a-146d9170636a"
    pkg = make_package("windows", redaction_patterns=(GUID_PATTERN,))
    model = _Capturador([])
    ForensicAgent(pkg, model, _FakeEvidence()).run(
        "hola", case_id=case_id, evidence_id=ev_id
    )
    system = "\n".join(
        str(m.get("content") or "")
        for m in model.visto[0]
        if m.get("role") == "system"
    )
    assert case_id in system


@pytest.mark.parametrize("es_local", [True, False])
def test_un_backend_local_nunca_redacta(monkeypatch, es_local) -> None:
    """Con Ollama la evidencia no sale del host, así que no se redacta — por eso
    este bug SOLO se manifestaba con ejecutores cloud."""

    class _M(_Capturador):
        def capabilities(self):
            return ModelCapabilities(
                supports_native_tools=False, json_mode=True, max_context=0,
                is_local=es_local,
            )

    def fake_execute(tool_id, params, **kwargs):
        return {
            "tool_id": tool_id, "argv": [tool_id], "exit_code": 0,
            "stdout_sample": f"MachineGuid={OTRO_GUID}", "stderr_sample": "",
            "parsed": None, "run_id": RUN_ID,
        }

    monkeypatch.setattr("agentopsy.toolkit.dispatcher.execute", fake_execute)
    pkg = make_package("windows", redaction_patterns=(GUID_PATTERN,))
    model = _M([ToolCall(tool_id="tsk_mmls", params={}, call_id="x")])
    ForensicAgent(pkg, model, _FakeEvidence()).run("x", case_id="c", evidence_id="e")

    ultimo = "\n".join(
        str(m.get("content") or "") for m in model.visto[-1] if m.get("role") == "tool"
    )
    # El run_id se ve SIEMPRE; el GUID de la evidencia solo si es local.
    assert RUN_ID in ultimo
    assert (OTRO_GUID in ultimo) is es_local
