"""La interfaz común de los dos caminos de memoria (RA-8, RA-9).

Ambos sostienen lo mismo: que el agente encuentre lo que hay en los artefactos
sin traérselos enteros. Difieren en cómo `buscar` localiza:

- `estructurada` (camino A): coincidencia literal sobre las salidas crudas.
- `embeddings` (camino B): lo anterior más recuperación por significado.

El estado estructurado (tareas, pasos, hallazgos, índice de artefactos) vive en
`estado.py` y en los almacenes; no forma parte de esta interfaz porque lo
comparten los dos caminos.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

TOPE_HITS = 12
TOPE_CHARS_HIT = 180


@dataclass(frozen=True)
class Hit:
    run_id: str
    fichero: str
    linea: int | None
    texto: str
    puntuacion: float
    origen: str  # literal | semantico

    def a_texto(self) -> str:
        donde = f"{self.run_id[:8]}:{self.fichero}"
        if self.linea:
            donde += f":{self.linea}"
        return f"[{donde}] {self.texto}"


class Memoria(Protocol):
    nombre: str

    def indexar_run(self, run_id: str, tool_id: str, ficheros: list[Path]) -> dict[str, Any]:
        """Se llama cuando un run cierra. Devuelve un pequeño informe (chunks, tiempo)."""

    def indexar_texto(self, origen: str, texto: str) -> None:
        """Mensajes del perito e informes de los agentes."""

    def buscar(self, consulta: str, *, k: int = TOPE_HITS, run_id: str | None = None) -> list[Hit]:
        ...

    def estadisticas(self) -> dict[str, Any]:
        ...
