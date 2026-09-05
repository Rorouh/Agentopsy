"""El pulso de un caso: la señal con la que la interfaz se refresca sola.

Lo que se fija aquí es lo que hace que el perito deje de pulsar F5, y también lo
que impide que el arreglo mienta:

- una firma CAMBIA cuando el flujo cambia (una línea nueva en `findings.jsonl`, un
  documento nuevo, una evidencia registrada) y NO cambia cuando no pasa nada, que
  es lo que evita que la SPA recargue en bucle;
- «todavía no existe» tiene su propia firma, distinta de cualquier firma real, de
  modo que el primer hallazgo de un caso se nota igual que el décimo;
- un caso que no existe es un 404, nunca un pulso plano que se leería como «no ha
  cambiado nada» (RULE 2);
- los trabajos en curso se cuentan por tipo, que es lo que permite sondear deprisa
  mientras algo corre y calmarse cuando no.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agentopsy.cases import CaseManager
from agentopsy.pulse import AUSENTE, FLUJOS, case_pulse
from agentopsy.server import create_app

PORT = 51044


class _RegistroFalso:
    """Un registro de jobs en memoria, con la forma que publica el de verdad."""

    def __init__(self, jobs: list[dict[str, Any]] | None = None) -> None:
        self._jobs = jobs or []

    def list_for_case(self, case_id: str) -> list[dict[str, Any]]:
        return [j for j in self._jobs if j.get("case_id") == case_id]


@pytest.fixture
def cases(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


@pytest.fixture
def case_id(cases) -> str:
    return cases.create(name="Caso pulso", examiner="perito", os_profile="windows").id


def _pulso(cases: CaseManager, case_id: str, **kw) -> dict[str, Any]:
    return case_pulse(
        case_id,
        cases=cases,
        jobs=kw.get("jobs") or _RegistroFalso(),
        evidence_jobs=kw.get("evidence_jobs") or _RegistroFalso(),
    )


def test_a_case_that_never_changed_keeps_the_same_signatures(cases, case_id) -> None:
    """Sin actividad, dos pulsos consecutivos son idénticos. Si no, la interfaz
    recargaría en bucle y el sondeo sería peor que no tenerlo."""
    assert _pulso(cases, case_id)["streams"] == _pulso(cases, case_id)["streams"]


def test_every_stream_the_spa_paints_has_a_signature(cases, case_id) -> None:
    """El contrato de los flujos: si una vista pinta un flujo, el pulso lo trae."""
    streams = _pulso(cases, case_id)["streams"]
    assert set(streams) == set(FLUJOS)
    for nombre in ("findings", "audit", "evidence", "documents", "graphs"):
        assert nombre in streams


def test_a_stream_with_nothing_behind_it_says_so(cases, case_id) -> None:
    """Un caso recién creado no tiene hallazgos: la firma es AUSENTE, que es un
    valor propio y no se confunde con una firma real."""
    streams = _pulso(cases, case_id)["streams"]
    assert streams["findings"] == AUSENTE
    assert streams["case"] != AUSENTE  # case.json sí existe desde el minuto uno


def test_the_first_finding_changes_the_signature(cases, case_id) -> None:
    """De AUSENTE a una firma real: aparecer es un cambio como cualquier otro."""
    antes = _pulso(cases, case_id)["streams"]["findings"]
    ruta = cases.case_dir(case_id) / "findings.jsonl"
    ruta.write_text(json.dumps({"id": "f1"}) + "\n", encoding="utf-8")

    despues = _pulso(cases, case_id)["streams"]["findings"]
    assert antes == AUSENTE
    assert despues != antes


def test_appending_a_finding_changes_the_signature(cases, case_id) -> None:
    """El caso que importa de verdad: el agente añade un hallazgo mientras el
    perito mira otra sección, y al volver tiene que estar."""
    ruta = cases.case_dir(case_id) / "findings.jsonl"
    ruta.write_text(json.dumps({"id": "f1"}) + "\n", encoding="utf-8")
    antes = _pulso(cases, case_id)["streams"]["findings"]

    with ruta.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"id": "f2"}) + "\n")

    assert _pulso(cases, case_id)["streams"]["findings"] != antes


def test_a_new_entry_in_a_directory_changes_its_signature(cases, case_id) -> None:
    """Los flujos que son un directorio (evidencias, informes, grafos) se notan
    por sus entradas, no por su contenido."""
    documentos = cases.case_dir(case_id) / "documents"
    documentos.mkdir(exist_ok=True)
    antes = _pulso(cases, case_id)["streams"]["documents"]

    (documentos / "doc1.json").write_text("{}", encoding="utf-8")

    assert _pulso(cases, case_id)["streams"]["documents"] != antes


def test_one_stream_changing_leaves_the_others_alone(cases, case_id) -> None:
    """Cada vista recarga SOLO lo suyo: un hallazgo nuevo no puede hacer que la
    matriz ATT&CK y los informes se recarguen también."""
    antes = _pulso(cases, case_id)["streams"]
    (cases.case_dir(case_id) / "findings.jsonl").write_text("{}\n", encoding="utf-8")

    despues = _pulso(cases, case_id)["streams"]
    cambiados = {k for k in antes if antes[k] != despues[k]}
    assert cambiados == {"findings"}


def test_running_jobs_are_counted_by_kind(cases, case_id) -> None:
    """La cadencia del sondeo sale de aquí: deprisa mientras algo corre."""
    jobs = _RegistroFalso([
        {"case_id": case_id, "kind": "analyze", "status": "running"},
        {"case_id": case_id, "kind": "report", "status": "running"},
        {"case_id": case_id, "kind": "analyze", "status": "done"},
        {"case_id": "otro-caso", "kind": "analyze", "status": "running"},
    ])
    evidencia = _RegistroFalso([{"case_id": case_id, "state": "running"}])

    pulso = _pulso(cases, case_id, jobs=jobs, evidence_jobs=evidencia)

    assert pulso["jobs"]["running"] == 3  # el 'done' y el de otro caso no cuentan
    assert pulso["jobs"]["by_kind"] == {
        "analyze": 1, "report": 1, "evidence_register": 1,
    }


def test_a_quiet_case_reports_no_running_jobs(cases, case_id) -> None:
    pulso = _pulso(cases, case_id)
    assert pulso["jobs"] == {"running": 0, "by_kind": {}}


def test_a_case_that_does_not_exist_raises(cases) -> None:
    """RULE 2: un caso borrado tiene que notarse, no devolver un pulso plano."""
    with pytest.raises(KeyError):
        _pulso(cases, "00000000-0000-4000-8000-000000000000")


# ── la superficie HTTP ───────────────────────────────────────────────────────


@pytest.fixture
def client(cases, monkeypatch) -> TestClient:
    import agentopsy.pulse as pulse_mod
    import agentopsy.routers.cases as cases_router

    monkeypatch.setattr(cases_router, "case_manager", cases)
    monkeypatch.setattr(pulse_mod, "case_manager", cases)
    return TestClient(create_app(PORT), base_url=f"http://127.0.0.1:{PORT}")


def test_the_endpoint_serves_the_pulse(client, case_id) -> None:
    auth = {"X-Agentopsy-Token": client.app.state.token}

    res = client.get(f"/api/cases/{case_id}/pulse", headers=auth)

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["case_id"] == case_id
    assert set(body["streams"]) == set(FLUJOS)
    assert body["jobs"]["running"] == 0


def test_the_endpoint_404s_on_a_case_that_does_not_exist(client) -> None:
    auth = {"X-Agentopsy-Token": client.app.state.token}
    res = client.get(
        "/api/cases/00000000-0000-4000-8000-000000000000/pulse", headers=auth
    )
    assert res.status_code == 404


def test_the_endpoint_requires_the_session_token(client, case_id) -> None:
    assert client.get(f"/api/cases/{case_id}/pulse").status_code == 401
