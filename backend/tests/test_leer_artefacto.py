"""CP1 — El agente puede LEER sus propias salidas.

El agujero que cierra: hasta ahora el agente solo veía un `stdout_sample` de 2000
chars, así que una salida de `regripper` (400 líneas) o un árbol de `fls` (52 MB)
eran opacos. Acababa re-ejecutando la herramienta o infiriendo sin sostén — es la
mitad de la distancia con el flujo manual de `prueba-agentes`, donde el analista
hacía `grep`/`head` sobre `output/`.

Gates:
- Lee stdout/stderr completos y ficheros de salida declarados.
- `buscar` filtra por SUBCADENA literal (nunca una regex del modelo), sin
  distinguir mayúsculas.
- Pagina de verdad: `hay_mas`/`siguiente_desde` y nada de truncados silenciosos.
- Confinamiento: no se puede leer un run de OTRO caso ni una ruta arbitraria.
- Un binario NO se sirve como texto: error accionable que nombra la alternativa.
- Lo que vuelve al modelo va marcado NO CONFIABLE (son bytes derivados de
  evidencia hostil).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from forensia.agent.agent import ForensicAgent
from _agent_pkg import make_package
from forensia.agent.tool_schemas import internal_tool_specs
from forensia.artifacts.store import ArtifactStore
from forensia.cases.manager import CaseManager
from forensia.models.base import FinalAnswer, ModelBackend, ModelCapabilities, ToolCall

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENTES_DIR = REPO_ROOT / "agentes"

_PROV = {
    "evidence_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "evidence_baseline_sha256": "a" * 64,
    "tool_version": "regripper 3.0",
}


@pytest.fixture
def store_run(tmp_path):
    """Un run cerrado con una salida realista de regripper."""
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Caso", examiner="ramos", os_profile="windows")
    store = ArtifactStore(cases)

    stdout = "\n".join(
        [
            "samparse v.20200825",
            "User Information",
            "-------------------------",
            "Username        : IEUser [1000]",
            "Full Name       :",
            "Last Login Date : 2021-03-23 17:15:22Z",
            "Username        : sshd_server [1002]",
            "Last Login Date : 2021-03-23 17:15:46Z",
            "Username        : testuser [1003]",
            "Account Created : 2021-03-23 19:07:38Z",
            "Group Membership: Administrators",
        ]
    )
    run_id, _out = store.start_run(
        case.id, "regripper", ["rip.pl", "-r", "SAM", "-p", "samparse"], **_PROV
    )
    store.finalize_run(case.id, run_id, exit_code=0, stdout=stdout, stderr="")
    return store, cases, case.id, run_id


# ── lectura básica ──────────────────────────────────────────────────────────


def test_lee_el_stdout_entero_no_una_muestra(store_run) -> None:
    store, _cases, case_id, run_id = store_run
    body = store.read_run_output(case_id, run_id)
    assert body["total_lineas"] == 11
    assert body["devueltas"] == 11
    assert body["hay_mas"] is False
    assert any("testuser" in line for line in body["lineas"])
    assert body["tool_id"] == "regripper"


def test_buscar_filtra_como_un_grep(store_run) -> None:
    store, _cases, case_id, run_id = store_run
    body = store.read_run_output(case_id, run_id, buscar="Username")
    assert body["lineas_relevantes"] == 3
    assert body["devueltas"] == 3
    assert all("Username" in line for line in body["lineas"])


def test_buscar_no_distingue_mayusculas(store_run) -> None:
    store, _cases, case_id, run_id = store_run
    assert store.read_run_output(case_id, run_id, buscar="TESTUSER")["devueltas"] == 1


def test_buscar_es_subcadena_literal_no_regex(store_run) -> None:
    """Una regex del modelo seria un vector (ReDoS) y una fuente de sorpresas: los
    metacaracteres se tratan como texto."""
    store, _cases, case_id, run_id = store_run
    body = store.read_run_output(case_id, run_id, buscar="User.*")
    assert body["devueltas"] == 0


def test_lee_stderr(store_run) -> None:
    store, cases, case_id, _run_id = store_run
    run_id, _out = store.start_run(case_id, "tsk_fls", ["fls"], **_PROV)
    store.finalize_run(
        case_id, run_id, exit_code=1, stdout="", stderr="Cannot determine fs type"
    )
    body = store.read_run_output(case_id, run_id, fichero="stderr")
    assert "Cannot determine" in body["lineas"][0]


# ── paginación ──────────────────────────────────────────────────────────────


def test_pagina_y_declara_lo_que_queda(store_run) -> None:
    store, _cases, case_id, run_id = store_run
    p1 = store.read_run_output(case_id, run_id, lineas=4)
    assert p1["devueltas"] == 4
    assert p1["hay_mas"] is True
    assert p1["siguiente_desde"] == 5

    p2 = store.read_run_output(case_id, run_id, desde=p1["siguiente_desde"], lineas=4)
    assert p2["lineas"][0] == "Full Name       :"
    assert p2["hay_mas"] is True


def test_la_ultima_pagina_cierra(store_run) -> None:
    store, _cases, case_id, run_id = store_run
    last = store.read_run_output(case_id, run_id, desde=9, lineas=50)
    assert last["hay_mas"] is False
    assert last["siguiente_desde"] is None


def test_desde_cuenta_sobre_las_lineas_relevantes(store_run) -> None:
    """Al paginar una BÚSQUEDA, `desde` numera las coincidencias, no el fichero."""
    store, _cases, case_id, run_id = store_run
    body = store.read_run_output(case_id, run_id, buscar="Username", desde=2, lineas=1)
    assert body["lineas"] == ["Username        : sshd_server [1002]"]


def test_el_tope_de_lineas_se_acota_sin_reventar(store_run) -> None:
    store, _cases, case_id, run_id = store_run
    assert store.read_run_output(case_id, run_id, lineas=99_999)["devueltas"] == 11


# ── ficheros de salida declarados ───────────────────────────────────────────


def test_lee_un_fichero_de_out_declarado_en_el_manifiesto(tmp_path) -> None:
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="c", examiner="e", os_profile="windows")
    store = ArtifactStore(cases)
    run_id, out = store.start_run(case.id, "mftecmd", ["MFTECmd.exe"], **_PROV)
    (out / "mft.csv").write_text("ruta,fecha\n/Confidential.xls,2021-03-23\n", "utf-8")
    store.finalize_run(case.id, run_id, exit_code=0, stdout="", stderr="")

    body = store.read_run_output(case.id, run_id, fichero="mft.csv", buscar="Confidential")
    assert body["devueltas"] == 1
    assert "Confidential.xls" in body["lineas"][0]


def test_fichero_de_out_inexistente_falla(store_run) -> None:
    store, _cases, case_id, run_id = store_run
    with pytest.raises(KeyError):
        store.read_run_output(case_id, run_id, fichero="no-existe.csv")


# ── confinamiento y binarios ────────────────────────────────────────────────


def test_no_se_puede_leer_un_run_de_otro_caso(store_run) -> None:
    store, cases, _case_id, run_id = store_run
    otro = cases.create(name="otro", examiner="e", os_profile="windows")
    with pytest.raises(KeyError):
        store.read_run_output(otro.id, run_id)


@pytest.mark.parametrize("bad", ["../../etc/passwd", "/etc/passwd", "..", ""])
def test_relpath_que_intenta_escapar_se_rechaza(store_run, bad) -> None:
    store, _cases, case_id, run_id = store_run
    with pytest.raises((ValueError, KeyError)):
        store.read_run_output(case_id, run_id, fichero=bad)


def test_run_id_invalido_se_rechaza(store_run) -> None:
    store, _cases, case_id, _run_id = store_run
    with pytest.raises(ValueError, match="run_id"):
        store.read_run_output(case_id, "no-es-un-uuid")


def test_un_binario_no_se_sirve_como_texto(tmp_path) -> None:
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="c", examiner="e", os_profile="windows")
    store = ArtifactStore(cases)
    run_id, out = store.start_run(case.id, "tsk_icat", ["icat"], **_PROV)
    (out / "stdout.bin").write_bytes(b"MZ\x00\x90\x00\x03" + b"\x00" * 100)
    store.finalize_run(case.id, run_id, exit_code=0, stdout="", stderr="")

    with pytest.raises(ValueError, match="BINARIO"):
        store.read_run_output(case.id, run_id, fichero="stdout.bin")


# ── cableado en el loop ─────────────────────────────────────────────────────


class _Scripted(ModelBackend):
    name = "fake"

    def __init__(self, actions: list[Any]) -> None:
        self._actions = list(actions)
        self.seen: list[list[dict[str, Any]]] = []

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            supports_native_tools=False, json_mode=True, max_context=0, is_local=True
        )

    def next_action(self, state, tools):
        self.seen.append(list(state.get("messages") or []))
        self.offered = [t["function"]["name"] for t in tools]
        return self._actions.pop(0) if self._actions else FinalAnswer(text="fin")


class _FakeEvidence:
    def get(self, case_id: str, evidence_id: str) -> SimpleNamespace:
        return SimpleNamespace(
            evidence_id=evidence_id,
            original_path=Path("/cases/x/original.raw"),
            detected_os="windows",
            detected_kind="disk",
            sha256="0" * 64,
        )


def test_el_agente_lee_su_salida_y_le_vuelve_marcada_no_confiable(
    store_run, monkeypatch
) -> None:
    store, _cases, case_id, run_id = store_run
    monkeypatch.setattr("forensia.agent.agent.artifact_store", store)
    pkg = make_package("windows")
    model = _Scripted([
        ToolCall(
            tool_id="leer_artefacto",
            params={"run_id": run_id, "buscar": "testuser"},
            call_id="x",
            assistant_message={"role": "assistant", "content": "{}"},
        )
    ])
    agent = ForensicAgent(pkg, model, _FakeEvidence())
    result = agent.run("lee", case_id=case_id, evidence_id="e")

    call = result["tool_calls"][0]
    assert call["tool_id"] == "leer_artefacto"
    assert call["error"] is None

    served = "\n".join(
        str(m.get("content") or "") for m in model.seen[-1] if m.get("role") == "tool"
    )
    assert "testuser" in served
    # Son bytes derivados de la evidencia: DATO, nunca instrucción.
    assert "EVIDENCIA_NO_CONFIABLE" in served


def test_un_run_id_inventado_no_tumba_el_run(store_run, monkeypatch) -> None:
    store, _cases, case_id, _run_id = store_run
    monkeypatch.setattr("forensia.agent.agent.artifact_store", store)
    pkg = make_package("windows")
    model = _Scripted([
        ToolCall(
            tool_id="leer_artefacto",
            params={"run_id": "dict"},
            call_id="x",
            assistant_message={"role": "assistant", "content": "{}"},
        )
    ])
    result = ForensicAgent(pkg, model, _FakeEvidence()).run(
        "lee", case_id=case_id, evidence_id="e"
    )
    assert "run_id" in (result["tool_calls"][0]["error"] or "")


def test_la_tool_se_ofrece_al_modelo() -> None:
    specs = {s["function"]["name"]: s["function"] for s in internal_tool_specs()}
    assert "leer_artefacto" in specs
    params = specs["leer_artefacto"]["parameters"]
    assert params["required"] == ["run_id"]
    assert params["additionalProperties"] is False
    assert params["properties"]["lineas"]["maximum"] == 400
