"""Análisis en segundo plano: el mismo contrato de jobs que usa la web con el
api (`analyze` → job_id, `jobs/{id}?since=N` → eventos incrementales, `cancel`
cooperativo). El turno corre en un hilo; cerrar la pestaña no lo aborta.

Registro en memoria del proceso: un job no sobrevive a un reinicio del
servicio, igual que en el api.
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from runner import Corrida


def _ahora() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Trabajo:
    def __init__(self, case_id: str, kind: str = "analysis") -> None:
        self.id = str(uuid.uuid4())
        self.case_id = case_id
        self.kind = kind
        self.status = "running"
        self.created_at = _ahora()
        self.finished_at: str | None = None
        self.result: dict[str, Any] | None = None
        self.error: str | None = None
        self.events: list[dict[str, Any]] = []
        self.cancel_requested = False

    def instantanea(self, since: int = 0) -> dict[str, Any]:
        return {
            "job_id": self.id,
            "case_id": self.case_id,
            "kind": self.kind,
            "status": self.status,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "result": self.result,
            "error": self.error,
            "events": self.events[since:],
            "event_count": len(self.events),
            "engine": "local-fit-llm",
        }


class Registro:
    def __init__(self) -> None:
        self._trabajos: dict[str, Trabajo] = {}
        self._cerrojo = threading.Lock()

    def lanzar(self, corrida: Corrida) -> Trabajo:
        trabajo = Trabajo(corrida.case_id)
        with self._cerrojo:
            self._trabajos[trabajo.id] = trabajo

        def emitir(evento: dict[str, Any]) -> None:
            with self._cerrojo:
                trabajo.events.append(evento)

        corrida.emitir = emitir
        corrida.cancelado = lambda: trabajo.cancel_requested

        def correr() -> None:
            try:
                resultado = corrida.ejecutar()
                with self._cerrojo:
                    trabajo.result = {"reply": resultado["reply"], "iterations": resultado["iterations"],
                                      "tool_calls": resultado["tool_calls"], "metrics": resultado["metrics"],
                                      "tasks": resultado["tasks"]}
                    trabajo.status = "cancelled" if trabajo.cancel_requested and resultado.get("cancelled") else "done"
                    if resultado.get("error") and trabajo.status == "done":
                        trabajo.error = resultado["error"]
            except Exception as exc:  # noqa: BLE001 — el job se cierra con la razón, nunca se cuelga
                with self._cerrojo:
                    trabajo.status = "error"
                    trabajo.error = f"{type(exc).__name__}: {exc}"
            finally:
                with self._cerrojo:
                    trabajo.finished_at = _ahora()

        threading.Thread(target=correr, name=f"local-fit-job-{trabajo.id[:8]}", daemon=True).start()
        return trabajo

    def instantanea(self, job_id: str, since: int = 0) -> dict[str, Any] | None:
        with self._cerrojo:
            t = self._trabajos.get(job_id)
            return t.instantanea(since) if t else None

    def cancelar(self, job_id: str) -> bool:
        with self._cerrojo:
            t = self._trabajos.get(job_id)
            if t is None or t.status != "running":
                return False
            t.cancel_requested = True
            return True

    def del_caso(self, case_id: str) -> list[dict[str, Any]]:
        with self._cerrojo:
            return [t.instantanea(0) | {"events": []} for t in self._trabajos.values() if t.case_id == case_id]


registro_trabajos = Registro()
