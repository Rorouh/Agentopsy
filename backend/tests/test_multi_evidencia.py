"""El agente investiga TODAS las evidencias del caso, por igual y sin primaria.

Historia del bug:

- 2026-07-28: la investigación mandaba una única `evidence_id` (la primera), así
  que en un caso con memoria + disco el agente quedaba encajonado en un soporte.
  Se le enseñaron todas y un selector `evidence_id` por herramienta, pero seguía
  existiendo una evidencia «primaria» (la primera de la lista de la interfaz, es
  decir, la última registrada) que se usaba por defecto.
- 2026-09-15 (TestCase6): esa primaria se colaba en la custodia. Los 14 hallazgos
  del caso quedaron atribuidos a la RAM, 7 de ellos sostenidos por ejecuciones
  sobre el disco; `consultar_actividad` solo podía consultar la super-timeline de
  la primaria; y la primaria cambiaba sola entre dos corridas del mismo caso.

Ahora:

- la corrida abarca todas las evidencias del caso (`EvidenceManager.list`), y un
  caso sin evidencias falla en alto;
- el system prompt las enumera por igual y lleva la regla de alcance (todas, salvo
  que el perito pida centrarse en alguna en el propio mensaje);
- con varias evidencias, cada herramienta y `consultar_actividad` EXIGEN
  `evidence_id` (no hay evidencia por defecto);
- un hallazgo toma la evidencia de la ejecución que lo sostiene, y el audit
  registra esa evidencia real y cómo se determinó;
- `agent_run_start` ancla la corrida a todas las evidencias con su hash.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from _agent_pkg import make_package

from agentopsy.agent.agent import ForensicAgent
from agentopsy.agent.history import _findings_ledger, _tool_runs_ledger
from agentopsy.agent.tool_schemas import internal_tool_specs, tool_spec
from agentopsy.chats.store import ChatMessage
from agentopsy.i18n import t
from agentopsy.models.base import FinalAnswer, ModelBackend, ModelCapabilities, ToolCall

RAM_ID = "11111111-1111-4111-8111-111111111111"
DISK_ID = "22222222-2222-4222-8222-222222222222"
RUN_RAM = "33333333-3333-4333-8333-333333333333"
RUN_DISK = "44444444-4444-4444-8444-444444444444"


def _handle(eid: str, name: str, kind: str, os_: str = "windows") -> SimpleNamespace:
    return SimpleNamespace(
        evidence_id=eid,
        original_path=Path(f"/cases/x/{name}"),
        detected_os=os_,
        detected_kind=kind,
        sha256=("a" if eid == RAM_ID else "b") * 64,
    )


class _MultiEvidence:
    """Doble con DOS evidencias: memoria y disco (el caso TestCase6)."""

    def __init__(self, disk_os: str = "windows") -> None:
        self._h = {
            RAM_ID: _handle(RAM_ID, "original.raw", "memory"),
            DISK_ID: _handle(DISK_ID, "original.vmdk", "container_disk", disk_os),
        }

    def get(self, case_id: str, evidence_id: str) -> SimpleNamespace:
        return self._h[evidence_id]

    def list(self, case_id: str) -> list[SimpleNamespace]:
        return list(self._h.values())


class _SingleEvidence:
    def get(self, case_id: str, evidence_id: str) -> SimpleNamespace:
        return _handle(DISK_ID, "original.vmdk", "container_disk")

    def list(self, case_id: str) -> list[SimpleNamespace]:
        return [_handle(DISK_ID, "original.vmdk", "container_disk")]


class _NoEvidence:
    def get(self, case_id: str, evidence_id: str) -> SimpleNamespace:  # pragma: no cover
        raise KeyError(evidence_id)

    def list(self, case_id: str) -> list[SimpleNamespace]:
        return []


class _ScriptedModel(ModelBackend):
    name = "fake"

    def __init__(self, actions: list[Any]) -> None:
        self._actions = list(actions)
        self.offered_specs: list[dict[str, Any]] = []
        self.seen_system = ""

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            supports_native_tools=False, json_mode=True, max_context=0, is_local=True
        )

    def next_action(self, state, tools):
        self.offered_specs = tools
        for m in state.get("messages", []):
            if m.get("role") == "system":
                self.seen_system = m["content"]
                break
        return self._actions.pop(0) if self._actions else FinalAnswer(text="fin")


class _Audit:
    """Audit en memoria: lo que el bucle encadenaría en `audit.jsonl`."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def append(self, entry: dict[str, Any]) -> None:
        self.events.append(dict(entry))

    def of(self, kind: str) -> list[dict[str, Any]]:
        return [e for e in self.events if e.get("event") == kind]


class _Runs:
    """Registro de ejecuciones: cada run declara la evidencia sobre la que corrió."""

    def __init__(self, runs: dict[str, str | None]) -> None:
        self._runs = runs

    def get_run(self, case_id: str, run_id: str) -> SimpleNamespace:
        if run_id not in self._runs:
            raise KeyError(f"unknown run_id for case {case_id}: {run_id}")
        return SimpleNamespace(run_id=run_id, evidence_id=self._runs[run_id])


class _Findings:
    """Almacén de hallazgos que guarda lo que recibe (sin disco)."""

    def __init__(self) -> None:
        self.appended: list[dict[str, Any]] = []

    def append(self, case_id: str, data: dict[str, Any]) -> SimpleNamespace:
        self.appended.append(dict(data))
        return SimpleNamespace(
            id=f"f{len(self.appended)}",
            title=data["title"],
            severity=data["severity"],
            evidence_id=data.get("evidence_id"),
            run_id=data.get("run_id"),
        )


def _no_dispatch(tool_id, params, **kwargs):  # pragma: no cover — no debe llamarse
    raise AssertionError(f"no debería ejecutar {tool_id}")


def _ok_dispatch(seen: dict[str, Any]):
    def fake_execute(tool_id, params, **kwargs):
        seen.setdefault("calls", []).append(
            {
                "tool_id": tool_id,
                "ctx_evidence_id": kwargs["evidence_context"].evidence_id,
                "params": dict(params),
            }
        )
        return {
            "tool_id": tool_id, "argv": [tool_id], "exit_code": 0,
            "stdout_sample": "ok", "stderr_sample": "", "parsed": None, "run_id": RUN_DISK,
        }

    return fake_execute


# --------------------------------------------------------------------------- #
# El system prompt: todas las evidencias, ninguna primaria, regla de alcance
# --------------------------------------------------------------------------- #
def test_system_prompt_lists_every_evidence_and_no_primary() -> None:
    pkg = make_package("windows")
    agent = ForensicAgent(pkg, _ScriptedModel([]), _MultiEvidence())
    text = agent._system_prompt(
        "c", ("tsk_fls", "volatility3"), _MultiEvidence().list("c")
    )
    # Las dos evidencias, con su id, fichero y triage.
    assert RAM_ID in text and DISK_ID in text
    assert "original.raw" in text and "original.vmdk" in text
    assert "memory" in text and "container_disk" in text
    # La cabecera de evidencias y la regla de alcance viajan, en el idioma del agente.
    assert t("agentCtx.evidenceHeader", count=2).splitlines()[0] in text
    assert t("agentCtx.multiEvidence").strip().splitlines()[0] in text
    # Ya no hay evidencia primaria en ningún idioma.
    for lang in ("es", "en"):
        assert "primaria" not in t("agentCtx.caseHeader", lang, case="c", profile="p")
        assert "Primary" not in t("agentCtx.caseHeader", lang, case="c", profile="p")
    assert "Evidencia primaria" not in text and "Primary evidence" not in text


def test_system_prompt_of_a_single_evidence_keeps_the_support_routing() -> None:
    pkg = make_package("windows")
    agent = ForensicAgent(pkg, _ScriptedModel([]), _SingleEvidence())
    text = agent._system_prompt("c", ("tsk_fls",), _SingleEvidence().list("c"))
    assert DISK_ID in text
    # Con una sola evidencia no hay regla de alcance que dar...
    assert t("agentCtx.multiEvidence").strip().splitlines()[0] not in text
    # ...y sí la guía del soporte de ESA evidencia.
    assert t("agentCtx.kindDisk", kind="container_disk", container="").splitlines()[1] in text


def test_profile_mismatch_names_only_the_evidence_that_disagrees() -> None:
    pkg = make_package("windows")
    evidence = _MultiEvidence(disk_os="unix")
    text = ForensicAgent(pkg, _ScriptedModel([]), evidence)._system_prompt(
        "c", ("tsk_fls",), evidence.list("c")
    )
    # Solo el disco desentona con el perfil `windows`: el bloque lo nombra a él y
    # a nadie más, y la memoria se sigue analizando con normalidad.
    esperado = t(
        "agentCtx.mismatchMulti",
        profile="windows",
        evidences=f"`{DISK_ID}` (`original.vmdk`, detected_os `unix`)",
    )
    assert esperado in text


def test_the_run_sees_every_evidence_of_the_case() -> None:
    model = _ScriptedModel([])
    ForensicAgent(make_package("windows"), model, _MultiEvidence()).run("hola", case_id="c")
    assert RAM_ID in model.seen_system and DISK_ID in model.seen_system


def test_a_case_without_evidence_fails_loud() -> None:
    with pytest.raises(ValueError, match="no tiene evidencias registradas"):
        ForensicAgent(make_package("windows"), _ScriptedModel([]), _NoEvidence()).run(
            "hola", case_id="c"
        )


def test_run_start_is_anchored_to_every_evidence_with_its_hash() -> None:
    audit = _Audit()
    ForensicAgent(
        make_package("windows"), _ScriptedModel([]), _MultiEvidence(), audit=audit
    ).run("hola", case_id="c")
    (start,) = audit.of("agent_run_start")
    assert start["evidences"] == [
        {"evidence_id": RAM_ID, "baseline_sha256": "a" * 64},
        {"evidence_id": DISK_ID, "baseline_sha256": "b" * 64},
    ]
    assert "evidence_id" not in start


# --------------------------------------------------------------------------- #
# Herramientas del maletín: evidencia obligatoria con varias, sin defecto
# --------------------------------------------------------------------------- #
def test_tool_targets_the_chosen_evidence(monkeypatch) -> None:
    """`evidence_id` en la tool call resuelve el path y la custodia de ESA evidencia."""
    seen: dict[str, Any] = {}
    monkeypatch.setattr("agentopsy.toolkit.dispatcher.execute", _ok_dispatch(seen))
    model = _ScriptedModel([
        ToolCall(tool_id="volatility3", params={"evidence_id": RAM_ID, "plugin": "windows.info"}, call_id="x"),
    ])
    result = ForensicAgent(make_package("windows"), model, _MultiEvidence()).run(
        "perfila la memoria", case_id="c"
    )
    (call,) = seen["calls"]
    assert call["ctx_evidence_id"] == RAM_ID  # el audit se ata a la RAM
    injected = call["params"].get("dump_path") or call["params"].get("image_path")
    assert "original.raw" in str(injected)  # corrió sobre el volcado de RAM
    assert "evidence_id" not in call["params"]  # el selector no llega al argv
    (logged,) = [c for c in result["tool_calls"] if c.get("tool_id") == "volatility3"]
    assert logged["evidence_id"] == RAM_ID


def test_tool_call_without_evidence_id_is_rejected_when_the_case_has_several(monkeypatch) -> None:
    monkeypatch.setattr("agentopsy.toolkit.dispatcher.execute", _no_dispatch)
    events: list[dict[str, Any]] = []
    model = _ScriptedModel([ToolCall(tool_id="tsk_fls", params={}, call_id="x")])
    result = ForensicAgent(make_package("windows"), model, _MultiEvidence()).run(
        "lista", case_id="c", on_event=events.append
    )
    (logged,) = [c for c in result["tool_calls"] if c.get("tool_id") == "tsk_fls"]
    assert "necesita `evidence_id`" in logged["error"]
    # El error enumera las evidencias válidas para que el modelo corrija.
    assert RAM_ID in logged["error"] and DISK_ID in logged["error"]
    assert any(e.get("type") == "tool_result" and e.get("status") == "error" for e in events)


def test_a_single_evidence_is_the_whole_scope_and_needs_no_selector(monkeypatch) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr("agentopsy.toolkit.dispatcher.execute", _ok_dispatch(seen))
    model = _ScriptedModel([ToolCall(tool_id="tsk_fls", params={}, call_id="x")])
    ForensicAgent(make_package("windows"), model, _SingleEvidence()).run("lista", case_id="c")
    (call,) = seen["calls"]
    assert call["ctx_evidence_id"] == DISK_ID


def test_unknown_evidence_id_is_rejected(monkeypatch) -> None:
    monkeypatch.setattr("agentopsy.toolkit.dispatcher.execute", _no_dispatch)
    model = _ScriptedModel([
        ToolCall(tool_id="tsk_fls", params={"evidence_id": "99999999-9999-4999-8999-999999999999"}, call_id="x"),
    ])
    result = ForensicAgent(make_package("windows"), model, _MultiEvidence()).run("x", case_id="c")
    # El run no crashea: el error se le devuelve al modelo como resultado de tool.
    errs = [c for c in result["tool_calls"] if c.get("error")]
    assert any("no es una evidencia de este caso" in (c.get("error") or "") for c in errs)


def test_tool_schema_requires_the_evidence_selector_only_when_several() -> None:
    choices = [(RAM_ID, "original.raw · memory"), (DISK_ID, "original.vmdk · container_disk")]
    params = tool_spec("tsk_fls", choices)["function"]["parameters"]
    assert set(params["properties"]["evidence_id"]["enum"]) == {RAM_ID, DISK_ID}
    assert "evidence_id" in params["required"]
    # Con una sola evidencia NO se añade el selector (esa evidencia es el alcance).
    one = tool_spec("tsk_fls", [(RAM_ID, "original.raw · memory")])["function"]["parameters"]
    assert "evidence_id" not in one["properties"]
    assert "evidence_id" not in one.get("required", [])
    # Sin choices tampoco.
    assert "evidence_id" not in tool_spec("tsk_fls")["function"]["parameters"]["properties"]


def test_internal_tools_expose_the_selector_where_it_applies() -> None:
    choices = [(RAM_ID, "original.raw · memory"), (DISK_ID, "original.vmdk · container_disk")]
    specs = {s["function"]["name"]: s["function"]["parameters"] for s in internal_tool_specs(choices)}
    # consultar_actividad: obligatorio.
    assert set(specs["consultar_actividad"]["properties"]["evidence_id"]["enum"]) == {RAM_ID, DISK_ID}
    assert "evidence_id" in specs["consultar_actividad"]["required"]
    # record_finding: opcional (con run_id, la evidencia sale de la ejecución).
    assert "evidence_id" in specs["record_finding"]["properties"]
    assert "evidence_id" not in specs["record_finding"]["required"]
    # Sin varias evidencias, ninguna tool interna gana el selector.
    for params in (s["function"]["parameters"] for s in internal_tool_specs()):
        assert "evidence_id" not in params.get("properties", {})


# --------------------------------------------------------------------------- #
# consultar_actividad: la evidencia la elige el agente
# --------------------------------------------------------------------------- #
def test_consultar_actividad_queries_the_chosen_evidence(monkeypatch) -> None:
    asked: list[str] = []

    def fake_query(case_id, evidence_id, **kwargs):
        asked.append(evidence_id)
        return {"status": "ok", "evidence_id": evidence_id, "matched": 0, "total_events": 0, "events": []}

    monkeypatch.setattr("agentopsy.agent.agent.query_filesystem_timeline", fake_query)
    model = _ScriptedModel([
        ToolCall(tool_id="consultar_actividad", params={"evidence_id": DISK_ID, "date_from": "2021-03-23"}, call_id="x"),
    ])
    result = ForensicAgent(make_package("windows"), model, _MultiEvidence()).run("x", case_id="c")
    assert asked == [DISK_ID]
    (logged,) = [c for c in result["tool_calls"] if c.get("tool_id") == "consultar_actividad"]
    assert logged["evidence_id"] == DISK_ID
    assert not logged.get("error")


def test_consultar_actividad_without_evidence_id_is_rejected_when_several(monkeypatch) -> None:
    def fake_query(*args, **kwargs):  # pragma: no cover — no debe llamarse
        raise AssertionError("no debería consultar ninguna timeline")

    monkeypatch.setattr("agentopsy.agent.agent.query_filesystem_timeline", fake_query)
    model = _ScriptedModel([ToolCall(tool_id="consultar_actividad", params={}, call_id="x")])
    result = ForensicAgent(make_package("windows"), model, _MultiEvidence()).run("x", case_id="c")
    (logged,) = [c for c in result["tool_calls"] if c.get("tool_id") == "consultar_actividad"]
    assert "necesita `evidence_id`" in (logged.get("error") or "")


def test_consultar_actividad_of_a_single_evidence_needs_no_selector(monkeypatch) -> None:
    asked: list[str] = []

    def fake_query(case_id, evidence_id, **kwargs):
        asked.append(evidence_id)
        return {"status": "no_timeline", "evidence_id": evidence_id}

    monkeypatch.setattr("agentopsy.agent.agent.query_filesystem_timeline", fake_query)
    model = _ScriptedModel([ToolCall(tool_id="consultar_actividad", params={}, call_id="x")])
    ForensicAgent(make_package("windows"), model, _SingleEvidence()).run("x", case_id="c")
    assert asked == [DISK_ID]


# --------------------------------------------------------------------------- #
# Hallazgos: la evidencia de la ejecución que los sostiene, y así en el audit
# --------------------------------------------------------------------------- #
def _finding(**extra: Any) -> ToolCall:
    params = {"title": "Binario recuperado", "summary": "key.exe en el Escritorio", "severity": "high"}
    params.update(extra)
    return ToolCall(tool_id="record_finding", params=params, call_id="f")


@pytest.fixture
def stores(monkeypatch):
    runs = _Runs({RUN_RAM: RAM_ID, RUN_DISK: DISK_ID})
    findings = _Findings()
    monkeypatch.setattr("agentopsy.agent.agent.artifact_store", runs)
    monkeypatch.setattr("agentopsy.agent.agent.finding_store", findings)
    return SimpleNamespace(runs=runs, findings=findings)


def test_a_finding_takes_the_evidence_of_its_run_not_a_primary(stores) -> None:
    audit = _Audit()
    model = _ScriptedModel([_finding(run_id=RUN_DISK, tool_id="tsk_icat")])
    ForensicAgent(make_package("windows"), model, _MultiEvidence(), audit=audit).run(
        "analiza", case_id="c"
    )
    (stored,) = stores.findings.appended
    assert stored["evidence_id"] == DISK_ID  # la del run, no la RAM
    (event,) = audit.of("agent_finding")
    assert event["evidence_id"] == DISK_ID
    assert event["evidence_source"] == "run"
    assert event["run_id"] == RUN_DISK


def test_a_finding_declaring_another_evidence_than_its_run_is_rejected(stores) -> None:
    audit = _Audit()
    model = _ScriptedModel([_finding(run_id=RUN_DISK, evidence_id=RAM_ID)])
    result = ForensicAgent(make_package("windows"), model, _MultiEvidence(), audit=audit).run(
        "analiza", case_id="c"
    )
    assert stores.findings.appended == []
    assert audit.of("agent_finding") == []
    (logged,) = [c for c in result["tool_calls"] if c.get("tool_id") == "record_finding"]
    assert RUN_DISK in logged["error"] and DISK_ID in logged["error"]


def test_a_finding_citing_a_run_that_does_not_exist_is_rejected(stores) -> None:
    model = _ScriptedModel([_finding(run_id="55555555-5555-4555-8555-555555555555")])
    result = ForensicAgent(make_package("windows"), model, _MultiEvidence()).run(
        "analiza", case_id="c"
    )
    assert stores.findings.appended == []
    (logged,) = [c for c in result["tool_calls"] if c.get("tool_id") == "record_finding"]
    assert "no corresponde a ninguna ejecución" in logged["error"]


def test_a_ruled_out_finding_without_run_belongs_to_the_case_when_several(stores) -> None:
    audit = _Audit()
    model = _ScriptedModel([_finding(finding_kind="descarte")])
    ForensicAgent(make_package("windows"), model, _MultiEvidence(), audit=audit).run(
        "analiza", case_id="c"
    )
    (stored,) = stores.findings.appended
    assert stored["evidence_id"] is None
    (event,) = audit.of("agent_finding")
    assert event["evidence_id"] is None and event["evidence_source"] == "case"


def test_a_ruled_out_finding_can_declare_its_evidence(stores) -> None:
    audit = _Audit()
    model = _ScriptedModel([_finding(finding_kind="descarte", evidence_id=RAM_ID)])
    ForensicAgent(make_package("windows"), model, _MultiEvidence(), audit=audit).run(
        "analiza", case_id="c"
    )
    (stored,) = stores.findings.appended
    assert stored["evidence_id"] == RAM_ID
    assert audit.of("agent_finding")[0]["evidence_source"] == "declared"


def test_pivot_events_are_anchored_to_the_whole_scope() -> None:
    audit = _Audit()
    model = _ScriptedModel([
        ToolCall(
            tool_id="declarar_pivote",
            params={"via_cerrada": "tsk_fls", "motivo": "exit 1", "via_alternativa": "hives desde la RAM"},
            call_id="p",
        ),
    ])
    ForensicAgent(make_package("windows"), model, _MultiEvidence(), audit=audit).run(
        "analiza", case_id="c"
    )
    (pivot,) = audit.of("agent_pivot")
    assert pivot["evidence_ids"] == [RAM_ID, DISK_ID]
    assert "evidence_id" not in pivot


# --------------------------------------------------------------------------- #
# Entre turnos: el ledger dice qué evidencia leyó cada ejecución
# --------------------------------------------------------------------------- #
def test_the_replay_ledgers_carry_the_evidence_of_each_run_and_finding(monkeypatch) -> None:
    turno = ChatMessage(
        role="assistant",
        content="hecho",
        ts="2026-09-15T12:00:00+00:00",
        tool_calls=[
            {"tool_id": "tsk_icat", "run_id": RUN_DISK, "exit_code": 0, "evidence_id": DISK_ID},
            {"tool_id": "volatility3", "error": "boom", "evidence_id": RAM_ID},
        ],
    )
    ledger = _tool_runs_ledger([turno])
    assert f"tsk_icat exit=0 run={RUN_DISK} evidence={DISK_ID}" in ledger
    assert f"volatility3 evidence={RAM_ID} ERROR" in ledger

    fake = SimpleNamespace(
        id="f1", severity="high", title="Binario", tool_id="tsk_icat", evidence_id=DISK_ID
    )
    monkeypatch.setattr(
        "agentopsy.agent.history.finding_store", SimpleNamespace(list=lambda case_id: [fake])
    )
    assert f"(evidence={DISK_ID})" in _findings_ledger("c")
