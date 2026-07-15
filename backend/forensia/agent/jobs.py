"""Ejecución ASÍNCRONA del análisis del agente — desacoplada de la petición HTTP.

Un análisis forense real es largo (minutos): atarlo a la conexión del cliente lo
mata si el navegador se cierra o hay timeout. Aquí el análisis corre en un hilo
de fondo y el cliente consulta su estado con un `job_id` — puede cerrar la
pestaña y volver luego. Los hallazgos se persisten en caliente durante el run
(ver el nudge del loop), así que aunque nadie consulte el job, el análisis termina
y los hallazgos quedan.

El job ACUMULA los eventos de progreso (tool_call con su argv, tool_result,
finding, reasoning) para que el cliente los pinte en el chat aunque sondee en vez
de recibir un stream — así se ve "qué está pasando" (el comando lanzado, el
hallazgo registrado) sin depender de una conexión persistente.

Registro en memoria del proceso `api` (no sobrevive a un reinicio; los hallazgos
sí, porque van a disco). Acotado para no crecer sin límite.
"""

from __future__ import annotations

import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

_MAX_JOBS = 200      # cota del registro de jobs
_MAX_EVENTS = 800    # cota de eventos por job

# fn recibe un `emit(event)` para reportar progreso y devuelve el result final.
JobFn = Callable[[Callable[[dict[str, Any]], None]], dict[str, Any]]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class Job:
    id: str
    case_id: str
    kind: str
    status: str  # "running" | "done" | "error"
    created_at: str
    prompt_chars: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)
    result: dict[str, Any] | None = None
    error: str | None = None
    finished_at: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    def public(self, since: int = 0, with_events: bool = True) -> dict[str, Any]:
        out: dict[str, Any] = {
            "job_id": self.id,
            "case_id": self.case_id,
            "kind": self.kind,
            "status": self.status,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "result": self.result,
            "error": self.error,
            "event_count": len(self.events),
            **self.meta,
        }
        if with_events:
            out["events"] = self.events[since:]
        return out


class JobRegistry:
    def __init__(self) -> None:
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._lock = threading.Lock()

    def submit(
        self, case_id: str, kind: str, fn: JobFn,
        *, prompt_chars: int = 0, meta: dict[str, Any] | None = None,
    ) -> Job:
        """Encola `fn(emit)` en un hilo de fondo y devuelve el Job (status=running)."""
        job = Job(
            id=str(uuid.uuid4()), case_id=case_id, kind=kind, status="running",
            created_at=_utc_now_iso(), prompt_chars=prompt_chars, meta=meta or {},
        )
        with self._lock:
            self._jobs[job.id] = job
            while len(self._jobs) > _MAX_JOBS:
                self._jobs.popitem(last=False)  # descarta el más antiguo

        def emit(event: dict[str, Any]) -> None:
            with self._lock:
                job.events.append(event)
                if len(job.events) > _MAX_EVENTS:
                    del job.events[: len(job.events) - _MAX_EVENTS]

        def _run() -> None:
            try:
                result = fn(emit)
                with self._lock:
                    job.status = "done"
                    job.result = result
                    job.finished_at = _utc_now_iso()
            except Exception as exc:  # noqa: BLE001 — el job captura, nunca crashea el hilo
                with self._lock:
                    job.status = "error"
                    job.error = f"{type(exc).__name__}: {exc}"
                    job.finished_at = _utc_now_iso()

        threading.Thread(target=_run, name=f"job-{job.id[:8]}", daemon=True).start()
        return job

    def snapshot(self, job_id: str, since: int = 0) -> dict[str, Any] | None:
        """Vista pública del job (estado + eventos desde `since`), bajo lock."""
        with self._lock:
            job = self._jobs.get(job_id)
            return job.public(since=since, with_events=True) if job else None

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list_for_case(self, case_id: str) -> list[dict[str, Any]]:
        """Fichas de los jobs de un caso (sin eventos), más recientes primero."""
        with self._lock:
            return [
                j.public(with_events=False)
                for j in reversed(self._jobs.values())
                if j.case_id == case_id
            ]


job_registry = JobRegistry()
