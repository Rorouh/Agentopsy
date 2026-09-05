"""Registro ASÍNCRONO de evidencia — desacoplado de la petición HTTP.

Espejo de ``agentopsy.agent.jobs`` para el otro proceso largo del producto: el
hash-gate de ``EvidenceManager.register``. Registrar una imagen grande (un EWF
multi-segmento de decenas de GB) recorre TODOS los bytes tres veces (hash del
origen → copia inmutable → re-hash de la copia), o sea minutos. Atado a la
petición HTTP eso muere en el proxy (504) y, peor, la petición se corta a mitad
de copia. Aquí el registro corre en un hilo de fondo y el cliente sondea su
estado con un ``job_id``: puede cerrar la pestaña y volver luego.

La ATOMICIDAD del registro la garantiza ``register`` (construye en un directorio
temporal oculto y publica con un único ``rename``); este módulo solo observa. El
progreso que expone es el callback OBSERVACIONAL de ``register``: no altera el
hash-gate, ni el baseline, ni la copia, ni el audit (FORENSIC INVARIANT 2).

Registro en memoria del proceso ``api``: NO sobrevive a un reinicio del api (la
evidencia registrada sí — está en disco). Acotado para no crecer sin límite.
"""

from __future__ import annotations

import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from agentopsy.i18n import Mensaje, current_lang, set_current_lang, traducir_excepcion
from agentopsy.evidence import EvidenceManager, evidence_manager

_MAX_JOBS = 200  # cota del registro de jobs


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _error_text(exc: BaseException) -> str:
    """Mensaje ACCIONABLE del fallo (RULE 2): el texto que ``register`` lanzó,
    prefijado con el tipo. ``KeyError`` se desenvuelve porque su ``str()`` mete
    comillas alrededor del mensaje y lo vuelve ilegible en la UI."""
    # El texto se re-renderiza por CÓDIGO en el idioma del hilo (el de la
    # petición que lanzó el registro): este `error` lo pinta la interfaz.
    detail = traducir_excepcion(exc)
    if isinstance(exc, KeyError) and exc.args:
        arg = exc.args[0]
        detail = traducir_excepcion(exc) if isinstance(arg, Mensaje) else str(arg)
    return f"{type(exc).__name__}: {detail}"


@dataclass
class RegisterJob:
    """Estado observable de un registro en curso.

    ``bytes_total`` es el trabajo TOTAL (3 × el tamaño del conjunto), no el
    tamaño de la evidencia: el perito ve avanzar las tres pasadas reales, no una
    barra inventada. Vale 0 hasta que ``register`` valida y descubre el conjunto
    (un fallo temprano —caso cerrado, ruta inexistente— termina el job en
    ``error`` sin haber movido un byte).
    """

    id: str
    case_id: str
    source_path: str
    state: str  # "pending" | "running" | "done" | "error"
    created_at: str
    phase: str | None = None  # "hashing" | "copying" | "verifying"
    seg_index: int = 0
    seg_count: int = 0
    bytes_done: int = 0
    bytes_total: int = 0
    evidence_id: str | None = None
    error: str | None = None
    finished_at: str | None = None

    def public(self) -> dict[str, Any]:
        return {
            "job_id": self.id,
            "case_id": self.case_id,
            "source_path": self.source_path,
            "state": self.state,
            "phase": self.phase,
            "seg_index": self.seg_index,
            "seg_count": self.seg_count,
            "bytes_done": self.bytes_done,
            "bytes_total": self.bytes_total,
            "evidence_id": self.evidence_id,
            "error": self.error,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
        }


class RegisterJobRegistry:
    def __init__(self) -> None:
        self._jobs: OrderedDict[str, RegisterJob] = OrderedDict()
        self._lock = threading.Lock()

    def submit(
        self,
        case_id: str,
        source_path: str,
        *,
        manager: EvidenceManager | None = None,
    ) -> RegisterJob:
        """Lanza ``register(case_id, source_path)`` en un hilo daemon y devuelve el
        job (``state="pending"``, ya encolado). ``manager`` permite inyectar un
        ``EvidenceManager`` atado a otra raíz de casos (tests / router aislado);
        por defecto se usa el singleton del proceso."""
        mgr = manager if manager is not None else evidence_manager
        job = RegisterJob(
            id=str(uuid.uuid4()),
            case_id=case_id,
            source_path=source_path,
            state="pending",
            created_at=_utc_now_iso(),
        )
        with self._lock:
            self._jobs[job.id] = job
            while len(self._jobs) > _MAX_JOBS:
                self._jobs.popitem(last=False)  # descarta el más antiguo

        def _on_progress(
            done: int, total: int, phase: str, seg_index: int, seg_count: int
        ) -> None:
            with self._lock:
                job.bytes_done = done
                job.bytes_total = total
                job.phase = phase
                job.seg_index = seg_index
                job.seg_count = seg_count

        idioma = current_lang()

        def _run() -> None:
            # El idioma de la PETICIÓN que lanzó el job, fijado dentro del
            # hilo. Un `ContextVar` no se hereda al crear un hilo (empieza con
            # su valor por defecto), así que sin esto un trabajo de fondo
            # redactaría sus mensajes en el idioma de partida y no en el que
            # tenía la interfaz cuando el perito pulsó el botón. Se captura
            # FUERA (al crear el job) y se aplica DENTRO.
            set_current_lang(idioma)
            with self._lock:
                job.state = "running"
            try:
                handle = mgr.register(case_id, source_path, on_progress=_on_progress)
            except Exception as exc:  # noqa: BLE001 — el job captura; el hilo nunca crashea
                with self._lock:
                    job.state = "error"
                    job.error = _error_text(exc)
                    job.finished_at = _utc_now_iso()
                return
            with self._lock:
                job.state = "done"
                job.evidence_id = handle.evidence_id
                # El trabajo terminó de verdad: la barra llega al 100 % porque las
                # tres pasadas se completaron, no porque lo pintemos así.
                job.bytes_done = job.bytes_total
                job.finished_at = _utc_now_iso()

        threading.Thread(
            target=_run, name=f"evidence-register-{job.id[:8]}", daemon=True
        ).start()
        return job

    def snapshot(self, job_id: str) -> dict[str, Any] | None:
        """Vista pública del job, bajo lock. ``None`` si no existe."""
        with self._lock:
            job = self._jobs.get(job_id)
            return job.public() if job else None

    def list_for_case(self, case_id: str) -> list[dict[str, Any]]:
        """Jobs de registro de un caso, más recientes primero. La usa la web al
        montar para RE-ENGANCHAR el sondeo de un registro que sigue vivo (cerrar
        la pestaña no aborta nada)."""
        with self._lock:
            return [j.public() for j in reversed(self._jobs.values()) if j.case_id == case_id]


register_job_registry = RegisterJobRegistry()
