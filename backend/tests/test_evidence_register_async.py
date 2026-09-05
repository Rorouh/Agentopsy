"""Registro de evidencia ASÍNCRONO y ATÓMICO (2026-07-27).

Dos problemas reales de una imagen grande (EWF multi-segmento de decenas de GB):

1. el registro era SÍNCRONO dentro de la petición HTTP y tarda minutos (hash del
   origen + copia + re-hash ≈ 3 pasadas sobre todos los bytes) → el proxy corta
   con 504 y, al morir la petición a mitad de copia, quedaban directorios de
   evidencia TRUNCADOS y huérfanos (sin ``baseline.json``);
2. no había forma de ver el avance.

Aquí se fija el contrato de la solución:

- ``register(..., on_progress=cb)`` reporta progreso OBSERVACIONAL — monótono
  hasta ``3 × tamaño`` del conjunto, con las tres fases — y el RESULTADO es
  idéntico al de un registro sin callback (mismo baseline, mismos segmentos,
  mismo audit). El hash-gate no cambia (FORENSIC INVARIANT 2).
- el registro es ATÓMICO: se construye en un directorio temporal OCULTO y se
  publica con un único ``rename``; un fallo a mitad no deja NADA bajo
  ``evidence/`` (ni ``<uuid>`` ni temporal).
- ``agentopsy.evidence_jobs`` corre ese registro en un hilo y expone su estado;
  el router lo arranca (``POST …/evidence/async``) y lo sondea
  (``GET …/evidence/jobs/{job_id}``), con 404 para caso/job inexistente.

Los tests de evidencia previos (``test_evidence_ewf_segments.py``, hash-gate) NO
se tocan y siguen verdes: el parámetro es opcional y por defecto ``None``.
"""

from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from agentopsy.cases.manager import CaseManager
from agentopsy.evidence import PROGRESS_PHASES, EvidenceManager
from agentopsy.evidence_jobs import RegisterJobRegistry
from agentopsy.server import create_app

PORT = 51011


@pytest.fixture
def cases(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


@pytest.fixture
def manager(cases) -> EvidenceManager:
    return EvidenceManager(cases)


@pytest.fixture
def case(cases):
    return cases.create(name="op", examiner="alice", os_profile="unix")


def _write_ewf_set(directory, stem: str, count: int, *, payload: int = 3000):
    """``stem.E01`` … ``stem.E0<count>`` con contenido DISTINTO por segmento."""
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for i in range(1, count + 1):
        seg = directory / f"{stem}.E{i:02d}"
        seg.write_bytes(f"seg{i:02d}-".encode() * payload)
        paths.append(seg)
    return paths


def _evidence_root(cases: CaseManager, case_id: str):
    return cases.root / case_id / "evidence"


def _evidence_entries(cases: CaseManager, case_id: str) -> set:
    root = _evidence_root(cases, case_id)
    return set(root.iterdir()) if root.is_dir() else set()


def _baseline(cases: CaseManager, case_id: str, evidence_id: str) -> dict:
    path = _evidence_root(cases, case_id) / evidence_id / "baseline.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _audit_events(cases: CaseManager, case_id: str, action: str) -> list[dict]:
    log = cases.root / case_id / "audit.jsonl"
    if not log.is_file():
        return []
    return [
        json.loads(line)
        for line in log.read_text(encoding="utf-8").splitlines()
        if line.strip() and json.loads(line).get("action") == action
    ]


# ── progreso observacional ───────────────────────────────────────────────────


class TestProgress:
    def test_progress_is_monotonic_up_to_three_times_the_set_size(
        self, manager, case, tmp_path
    ) -> None:
        segments = _write_ewf_set(tmp_path / "src", "caso", 3)
        total = sum(s.stat().st_size for s in segments)
        seen: list[tuple[int, int, str, int, int]] = []

        manager.register(case.id, str(segments[0]), on_progress=lambda *a: seen.append(a))

        assert seen, "con callback DEBE haber progreso"
        done = [ev[0] for ev in seen]
        assert done == sorted(done), "bytes_done nunca retrocede"
        assert done[-1] == 3 * total, "el trabajo total son las 3 pasadas sobre el set"
        # total_work y seg_count son constantes durante todo el registro.
        assert {ev[1] for ev in seen} == {3 * total}
        assert {ev[4] for ev in seen} == {3}
        # Las tres fases, y en orden por segmento (1 → 2 → 3).
        assert {ev[2] for ev in seen} == set(PROGRESS_PHASES)
        assert [ev[3] for ev in seen] == sorted(ev[3] for ev in seen)
        assert {ev[3] for ev in seen} == {1, 2, 3}
        for phase in PROGRESS_PHASES:
            assert {ev[3] for ev in seen if ev[2] == phase} == {1, 2, 3}

    def test_single_file_evidence_reports_one_segment(self, manager, case, tmp_path) -> None:
        src = tmp_path / "disco.raw"
        src.write_bytes(b"raw-payload" * 500)
        seen: list[tuple] = []

        manager.register(case.id, str(src), on_progress=lambda *a: seen.append(a))

        assert {ev[4] for ev in seen} == {1}
        assert {ev[3] for ev in seen} == {1}
        assert seen[-1][0] == 3 * src.stat().st_size

    def test_progress_does_not_change_the_result(self, manager, cases, case, tmp_path) -> None:
        """Mismo origen, con y sin callback → baseline, segmentos y audit idénticos
        (el progreso es OBSERVACIONAL: no toca el hash-gate)."""
        segments = _write_ewf_set(tmp_path / "src", "caso", 2)
        seen: list[tuple] = []

        plain = manager.register(case.id, str(segments[0]))
        observed = manager.register(case.id, str(segments[0]), on_progress=lambda *a: seen.append(a))

        assert seen  # el segundo sí reportó
        assert plain.sha256 == observed.sha256
        assert plain.size == observed.size
        assert [(s.name, s.sha256, s.size) for s in plain.segments] == [
            (s.name, s.sha256, s.size) for s in observed.segments
        ]

        a = _baseline(cases, case.id, plain.evidence_id)
        b = _baseline(cases, case.id, observed.evidence_id)
        a.pop("registered_at")
        b.pop("registered_at")
        assert a == b

        events = _audit_events(cases, case.id, "evidence_register")
        assert len(events) == 2
        for ev in events:
            assert ev["sha256"] == plain.sha256
            assert [s["name"] for s in ev["segments"]] == ["original.E01", "original.E02"]

    def test_without_callback_nothing_is_reported(self, manager, case, tmp_path) -> None:
        src = tmp_path / "disco.raw"
        src.write_bytes(b"x" * 1024)
        handle = manager.register(case.id, str(src))  # el camino de siempre
        assert handle.sha256

    def test_a_non_callable_on_progress_fails_loud(self, manager, case, tmp_path) -> None:
        src = tmp_path / "disco.raw"
        src.write_bytes(b"x" * 16)
        with pytest.raises(ValueError, match="on_progress"):
            manager.register(case.id, str(src), on_progress="cada rato")  # type: ignore[arg-type]


# ── atomicidad del registro ──────────────────────────────────────────────────


class TestAtomicity:
    def test_a_failed_copy_leaves_no_directory_at_all(
        self, manager, cases, case, tmp_path, monkeypatch
    ) -> None:
        """Corte a mitad de copia del 3er segmento (los dos primeros ya están
        congelados a 0444): ni evidencia truncada ni temporal huérfano."""
        segments = _write_ewf_set(tmp_path / "src", "caso", 3)
        good = manager.register(case.id, str(segments[0]))
        before = _evidence_entries(cases, case.id)

        import agentopsy.evidence as ev_mod

        real_copy = ev_mod._copy_file
        calls = {"n": 0}

        def flaky_copy(src, dest, on_chunk=None):
            calls["n"] += 1
            if calls["n"] == 3:
                dest.write_bytes(b"copia-a-medias")  # justo lo que NO debe sobrevivir
                raise OSError("no space left on device")
            real_copy(src, dest, on_chunk)

        monkeypatch.setattr(ev_mod, "_copy_file", flaky_copy)

        with pytest.raises(OSError, match="no space left"):
            manager.register(case.id, str(segments[0]))

        assert _evidence_entries(cases, case.id) == before
        assert [h.evidence_id for h in manager.list(case.id)] == [good.evidence_id]

    def test_a_hash_mismatch_leaves_no_directory_at_all(
        self, manager, cases, case, tmp_path, monkeypatch
    ) -> None:
        segments = _write_ewf_set(tmp_path / "src", "caso", 2)
        before = _evidence_entries(cases, case.id)

        import agentopsy.evidence as ev_mod

        def corrupting_copy(src, dest, on_chunk=None):
            dest.write_bytes(b"bytes que no son los del origen")

        monkeypatch.setattr(ev_mod, "_copy_file", corrupting_copy)

        with pytest.raises(OSError, match="hash mismatch"):
            manager.register(case.id, str(segments[0]))

        assert _evidence_entries(cases, case.id) == before
        assert manager.list(case.id) == []

    def test_a_failure_after_the_copy_leaves_no_directory_either(
        self, manager, cases, case, tmp_path, monkeypatch
    ) -> None:
        """El fallo tras la copia (aquí: escribir baseline.json) también revierte:
        una evidencia sin baseline no es evidencia."""
        src = tmp_path / "disco.raw"
        src.write_bytes(b"payload" * 100)
        before = _evidence_entries(cases, case.id)

        def boom(self, evidence_dir, baseline):
            raise OSError("disk full writing baseline.json")

        monkeypatch.setattr(EvidenceManager, "_write_baseline", boom)

        with pytest.raises(OSError, match="baseline"):
            manager.register(case.id, str(src))

        assert _evidence_entries(cases, case.id) == before

    def test_list_ignores_a_leftover_staging_dir(self, manager, cases, case, tmp_path) -> None:
        """Si el proceso muere entre la copia y la limpieza, el temporal que quede
        NUNCA se confunde con evidencia (su nombre no es un UUID4)."""
        src = tmp_path / "disco.raw"
        src.write_bytes(b"payload" * 100)
        handle = manager.register(case.id, str(src))

        stray = _evidence_root(cases, case.id) / ".registrando-a-medio-hacer"
        stray.mkdir()
        (stray / "original.raw").write_bytes(b"a medias")

        assert [h.evidence_id for h in manager.list(case.id)] == [handle.evidence_id]


# ── jobs en segundo plano ────────────────────────────────────────────────────


def _wait(registry: RegisterJobRegistry, job_id: str, timeout: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        snap = registry.snapshot(job_id)
        assert snap is not None
        if snap["state"] in {"done", "error"}:
            return snap
        time.sleep(0.02)
    raise AssertionError(f"el job {job_id} no terminó en {timeout}s")


class TestJobs:
    def test_submit_poll_done(self, manager, cases, case, tmp_path) -> None:
        segments = _write_ewf_set(tmp_path / "src", "caso", 2)
        total = sum(s.stat().st_size for s in segments)
        registry = RegisterJobRegistry()

        job = registry.submit(case.id, str(segments[0]), manager=manager)
        assert job.state in {"pending", "running"}
        assert job.evidence_id is None

        snap = _wait(registry, job.id)
        assert snap["state"] == "done"
        assert snap["error"] is None
        assert snap["bytes_total"] == 3 * total
        assert snap["bytes_done"] == snap["bytes_total"]
        assert snap["seg_count"] == 2
        assert snap["phase"] in PROGRESS_PHASES
        assert snap["finished_at"]

        registered = manager.get(case.id, snap["evidence_id"])
        assert [s.name for s in registered.segments] == ["original.E01", "original.E02"]

    def test_a_failed_registration_ends_in_error_with_an_actionable_message(
        self, manager, cases, case, tmp_path
    ) -> None:
        registry = RegisterJobRegistry()
        job = registry.submit(case.id, str(tmp_path / "no-existe.raw"), manager=manager)

        snap = _wait(registry, job.id)
        assert snap["state"] == "error"
        assert snap["evidence_id"] is None
        assert "no-existe.raw" in snap["error"]
        assert manager.list(case.id) == []

    def test_a_middle_ewf_segment_is_refused_by_the_job_too(
        self, manager, cases, case, tmp_path
    ) -> None:
        segments = _write_ewf_set(tmp_path / "src", "caso", 2)
        registry = RegisterJobRegistry()

        snap = _wait(registry, registry.submit(case.id, str(segments[1]), manager=manager).id)

        assert snap["state"] == "error"
        assert "E01" in snap["error"]  # dice cuál es el punto de entrada
        assert manager.list(case.id) == []

    def test_unknown_job_snapshot_is_none(self) -> None:
        assert RegisterJobRegistry().snapshot("no-existe") is None

    def test_list_for_case_only_returns_that_case(self, manager, cases, tmp_path) -> None:
        a = cases.create(name="a", examiner="alice", os_profile="unix")
        b = cases.create(name="b", examiner="alice", os_profile="unix")
        src = tmp_path / "disco.raw"
        src.write_bytes(b"payload" * 50)
        registry = RegisterJobRegistry()

        job_a = registry.submit(a.id, str(src), manager=manager)
        job_b = registry.submit(b.id, str(src), manager=manager)
        _wait(registry, job_a.id)
        _wait(registry, job_b.id)

        assert [j["job_id"] for j in registry.list_for_case(a.id)] == [job_a.id]
        assert [j["job_id"] for j in registry.list_for_case(b.id)] == [job_b.id]


# ── superficie HTTP ──────────────────────────────────────────────────────────


@pytest.fixture
def isolated_cases(tmp_path, monkeypatch) -> CaseManager:
    cases = CaseManager(root=tmp_path / "cases")

    import agentopsy.routers.cases as cases_router

    monkeypatch.setattr(cases_router, "case_manager", cases)
    monkeypatch.setattr(cases_router, "evidence_manager", EvidenceManager(cases))
    return cases


@pytest.fixture
def client(isolated_cases) -> TestClient:
    return TestClient(create_app(PORT), base_url=f"http://127.0.0.1:{PORT}")


@pytest.fixture
def auth(client) -> dict[str, str]:
    return {"X-Agentopsy-Token": client.app.state.token}


def _poll_http(client: TestClient, auth: dict, case_id: str, job_id: str, timeout=20.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = client.get(f"/api/cases/{case_id}/evidence/jobs/{job_id}", headers=auth)
        assert r.status_code == 200, r.text
        body = r.json()
        if body["state"] in {"done", "error"}:
            return body
        time.sleep(0.02)
    raise AssertionError("el job no terminó a tiempo")


class TestAsyncRoute:
    def test_start_returns_a_job_id_immediately_and_completes(
        self, client, auth, isolated_cases, tmp_path
    ) -> None:
        case = isolated_cases.create(name="op", examiner="alice", os_profile="unix")
        segments = _write_ewf_set(tmp_path / "src", "caso", 2)

        r = client.post(
            f"/api/cases/{case.id}/evidence/async",
            json={"source_path": str(segments[0])},
            headers=auth,
        )
        assert r.status_code == 200, r.text
        started = r.json()
        assert started["job_id"]
        assert started["state"] in {"pending", "running"}
        assert started["case_id"] == case.id

        done = _poll_http(client, auth, case.id, started["job_id"])
        assert done["state"] == "done", done
        assert done["evidence_id"]
        assert done["bytes_done"] == done["bytes_total"] > 0

        listed = client.get(f"/api/cases/{case.id}/evidence", headers=auth).json()
        assert [e["evidence_id"] for e in listed] == [done["evidence_id"]]

    def test_running_jobs_of_the_case_are_listed_for_reattachment(
        self, client, auth, isolated_cases, tmp_path
    ) -> None:
        case = isolated_cases.create(name="op", examiner="alice", os_profile="unix")
        src = tmp_path / "disco.raw"
        src.write_bytes(b"payload" * 100)

        started = client.post(
            f"/api/cases/{case.id}/evidence/async",
            json={"source_path": str(src)},
            headers=auth,
        ).json()
        _poll_http(client, auth, case.id, started["job_id"])

        r = client.get(f"/api/cases/{case.id}/evidence/jobs", headers=auth)
        assert r.status_code == 200
        assert started["job_id"] in [j["job_id"] for j in r.json()]

    def test_a_bad_source_path_ends_as_an_error_job_not_a_partial_evidence(
        self, client, auth, isolated_cases, tmp_path
    ) -> None:
        case = isolated_cases.create(name="op", examiner="alice", os_profile="unix")
        started = client.post(
            f"/api/cases/{case.id}/evidence/async",
            json={"source_path": str(tmp_path / "fantasma.raw")},
            headers=auth,
        ).json()

        done = _poll_http(client, auth, case.id, started["job_id"])
        assert done["state"] == "error"
        assert "fantasma.raw" in done["error"]
        assert client.get(f"/api/cases/{case.id}/evidence", headers=auth).json() == []

    def test_unknown_case_is_404(self, client, auth) -> None:
        r = client.post(
            "/api/cases/8a2b7c1e-0000-4000-8000-000000000000/evidence/async",
            json={"source_path": "/evidence/disco.raw"},
            headers=auth,
        )
        assert r.status_code == 404

    def test_empty_source_path_is_422(self, client, auth, isolated_cases) -> None:
        case = isolated_cases.create(name="op", examiner="alice", os_profile="unix")
        r = client.post(
            f"/api/cases/{case.id}/evidence/async",
            json={"source_path": "   "},
            headers=auth,
        )
        assert r.status_code == 422
        assert "source_path" in r.json()["detail"]

    def test_unknown_job_is_404(self, client, auth, isolated_cases) -> None:
        case = isolated_cases.create(name="op", examiner="alice", os_profile="unix")
        r = client.get(f"/api/cases/{case.id}/evidence/jobs/no-existe", headers=auth)
        assert r.status_code == 404

    def test_a_job_of_another_case_is_404(self, client, auth, isolated_cases, tmp_path) -> None:
        a = isolated_cases.create(name="a", examiner="alice", os_profile="unix")
        b = isolated_cases.create(name="b", examiner="alice", os_profile="unix")
        src = tmp_path / "disco.raw"
        src.write_bytes(b"payload" * 50)

        started = client.post(
            f"/api/cases/{a.id}/evidence/async",
            json={"source_path": str(src)},
            headers=auth,
        ).json()
        _poll_http(client, auth, a.id, started["job_id"])

        r = client.get(f"/api/cases/{b.id}/evidence/jobs/{started['job_id']}", headers=auth)
        assert r.status_code == 404

    def test_token_is_required(self, client, isolated_cases, tmp_path) -> None:
        case = isolated_cases.create(name="op", examiner="alice", os_profile="unix")
        assert (
            client.post(
                f"/api/cases/{case.id}/evidence/async",
                json={"source_path": str(tmp_path / "x.raw")},
            ).status_code
            == 401
        )
        assert client.get(f"/api/cases/{case.id}/evidence/jobs").status_code == 401
        assert client.get(f"/api/cases/{case.id}/evidence/jobs/algo").status_code == 401

    def test_the_synchronous_endpoint_still_works(
        self, client, auth, isolated_cases, tmp_path
    ) -> None:
        """El registro síncrono no se retira (MCP / tests / scripts lo usan)."""
        case = isolated_cases.create(name="op", examiner="alice", os_profile="unix")
        src = tmp_path / "disco.raw"
        src.write_bytes(b"payload" * 100)

        r = client.post(
            f"/api/cases/{case.id}/evidence",
            json={"source_path": str(src)},
            headers=auth,
        )
        assert r.status_code == 200, r.text
        assert r.json()["sha256"]
