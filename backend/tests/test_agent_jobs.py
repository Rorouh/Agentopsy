"""Ejecución asíncrona del análisis: el job corre en segundo plano, desacoplado
de la petición, y su estado se consulta por id (running / done / error)."""

from __future__ import annotations

import threading
import time

from agentopsy.agent.jobs import JobRegistry


def _wait(reg: JobRegistry, job_id: str, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        j = reg.get(job_id)
        if j and j.status != "running":
            return
        time.sleep(0.02)


def test_job_runs_in_background_and_reports_done() -> None:
    reg = JobRegistry()
    gate = threading.Event()  # el trabajo se bloquea hasta que lo soltemos

    def work(emit, should_cancel) -> dict:
        gate.wait(timeout=3)
        return {"reply": "ok", "iterations": 2}

    job = reg.submit("c1", "analyze", work, prompt_chars=10)
    # submit devuelve YA, sin bloquear: el trabajo sigue en curso (gate cerrada).
    assert reg.get(job.id).status == "running"
    gate.set()  # suelta el trabajo
    _wait(reg, job.id)
    done = reg.get(job.id)
    assert done.status == "done"
    assert done.result == {"reply": "ok", "iterations": 2}
    assert done.finished_at
    pub = done.public()
    assert pub["job_id"] == job.id and pub["status"] == "done"


def test_job_captures_error_without_crashing() -> None:
    reg = JobRegistry()

    def boom(emit, should_cancel) -> dict:
        raise ValueError("evidencia no verificada")

    job = reg.submit("c1", "analyze", boom)
    _wait(reg, job.id)
    j = reg.get(job.id)
    assert j.status == "error"
    assert "evidencia no verificada" in j.error


def test_list_for_case_filters_and_orders() -> None:
    reg = JobRegistry()
    a = reg.submit("caseA", "analyze", lambda emit, should_cancel: {})
    reg.submit("caseB", "analyze", lambda emit, should_cancel: {})
    b2 = reg.submit("caseA", "analyze", lambda emit, should_cancel: {})
    _wait(reg, a.id)
    _wait(reg, b2.id)
    jobs = reg.list_for_case("caseA")
    assert [j["job_id"] for j in jobs] == [b2.id, a.id]  # más recientes primero
    assert "events" not in jobs[0]  # la lista es ligera (sin eventos)


def test_missing_job_is_none() -> None:
    assert JobRegistry().get("nope") is None


def test_cancel_signals_running_job_and_marks_cancelled() -> None:
    """El botón «Parar»: la señal llega al trabajo (should_cancel pasa a True) y,
    cuando el trabajo termina cooperativamente, el job queda en `cancelled` con su
    result parcial conservado (no se pierde lo persistido en caliente)."""
    reg = JobRegistry()
    seen_cancel = threading.Event()

    def work(emit, should_cancel) -> dict:
        # Espera activa a que el operador pida parar (simula el loop del agente
        # comprobando should_cancel entre iteraciones).
        for _ in range(300):
            if should_cancel():
                seen_cancel.set()
                return {"reply": "parado", "partial": True}
            time.sleep(0.01)
        return {"reply": "terminó solo"}

    job = reg.submit("c1", "analyze", work)
    assert reg.get(job.id).status == "running"
    assert reg.cancel(job.id) is True  # se señalizó
    assert seen_cancel.wait(timeout=3)  # el trabajo VIO la señal
    _wait(reg, job.id)
    done = reg.get(job.id)
    assert done.status == "cancelled"
    assert done.result == {"reply": "parado", "partial": True}


def test_cancel_unknown_or_finished_job_returns_false() -> None:
    reg = JobRegistry()
    assert reg.cancel("nope") is False  # no existe
    job = reg.submit("c1", "analyze", lambda emit, should_cancel: {"reply": "ya"})
    _wait(reg, job.id)
    assert reg.get(job.id).status == "done"
    assert reg.cancel(job.id) is False  # ya terminó: no se puede parar


def test_job_accumulates_progress_events() -> None:
    reg = JobRegistry()
    gate = threading.Event()

    def work(emit, should_cancel) -> dict:
        emit({"type": "tool_call", "tool_id": "tsk_fls"})
        emit({"type": "tool_result", "tool_id": "tsk_fls", "status": "ok", "argv": ["fls", "-o", "0"]})
        emit({"type": "finding", "severity": "low", "title": "raíz ext"})
        gate.wait(timeout=3)
        return {"reply": "hecho"}

    job = reg.submit("c1", "analyze", work)
    # Antes de terminar, el snapshot ya trae los eventos acumulados.
    for _ in range(100):
        snap = reg.snapshot(job.id)
        if snap and len(snap["events"]) >= 3:
            break
        time.sleep(0.02)
    snap = reg.snapshot(job.id)
    assert [e["type"] for e in snap["events"]] == ["tool_call", "tool_result", "finding"]
    # `since` devuelve sólo los nuevos.
    assert reg.snapshot(job.id, since=2)["events"][0]["type"] == "finding"
    assert reg.snapshot(job.id, since=99)["events"] == []
    gate.set()
