"""Los dos relojes de un turno, y por qué hacen falta los dos.

`time.monotonic()` (CLOCK_MONOTONIC) **no avanza mientras la máquina está suspendida**;
`CLOCK_BOOTTIME` sí. La diferencia entre lo que han avanzado los dos durante un turno ES
el tiempo que el portátil ha pasado dormido en mitad de ese turno.

Para qué. El 2026-09-13 una traza de LangSmith marcó 1374 s para un turno que en realidad
fueron ~286 s: el portátil se suspendió 18m08s a mitad, y LangSmith mide reloj de pared
(`start_time`/`end_time`), que sí cuenta el sueño. Los 1088 s de diferencia parecían una
llamada lentísima al modelo y no lo eran. Se descubrió a mano, cruzando la traza con
`journalctl -g 'PM: suspend'` y con el `print_timing` de llama.cpp.

Esto lo convierte en un dato del turno en vez de una comprobación que alguien tiene que
acordarse de hacer. Las métricas del motor ya eran inmunes, porque miden con
`time.monotonic()`; lo que no era inmune es la traza, y ahora la traza lleva al lado
cuánto se durmió para poder restarlo.

Fuera de Linux `CLOCK_BOOTTIME` no existe. Ahí se devuelve `None`, no `0`: no saber
cuánto se ha dormido la máquina no es lo mismo que saber que no se ha dormido (RULE 2).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

_HAY_BOOTTIME = hasattr(time, "CLOCK_BOOTTIME")


def _boottime() -> float | None:
    if not _HAY_BOOTTIME:
        return None
    return time.clock_gettime(time.CLOCK_BOOTTIME)


@dataclass(frozen=True)
class Cronometro:
    """Arrancado al empezar el turno; se le pregunta al terminar."""

    monotonic: float
    boottime: float | None

    @classmethod
    def arrancar(cls) -> "Cronometro":
        return cls(monotonic=time.monotonic(), boottime=_boottime())

    def transcurrido(self) -> float:
        """Segundos de trabajo real: el sueño de la máquina NO cuenta."""
        return time.monotonic() - self.monotonic

    def suspendido(self) -> float | None:
        """Segundos que la máquina ha pasado dormida desde `arrancar()`, o `None` si
        este sistema no sabe decirlo."""
        ahora = _boottime()
        if ahora is None or self.boottime is None:
            return None
        # El redondeo evita que el ruido de microsegundos entre las dos lecturas salga
        # como una suspensión de 0,0001 s.
        return max(0.0, round((ahora - self.boottime) - self.transcurrido(), 1))
