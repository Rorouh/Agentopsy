"""Chat por sesión: `chats/<sesion>.jsonl`, mismo formato que el api (role, content,
ts, tool_calls, activity), para que la web repinte la conversación igual.

La conversación NO se reenvía al modelo (RA-7): lo que el agente sabe entre
turnos vive en `estado.py` y en los hallazgos; aquí solo se persiste lo que ve
el perito.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from casos import validar_sesion


def _ahora() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Chats:
    def __init__(self, dir_caso: Path) -> None:
        self.dir = Path(dir_caso) / "chats"

    def _ruta(self, sesion: str) -> Path:
        return self.dir / f"{validar_sesion(sesion)}.jsonl"

    def anadir(self, sesion: str, rol: str, contenido: str, *, tool_calls: list | None = None,
               actividad: list | None = None) -> dict[str, Any]:
        if rol not in {"user", "assistant", "system", "tool"}:
            raise ValueError(f"rol inválido: {rol!r}")
        self.dir.mkdir(parents=True, exist_ok=True)
        mensaje = {"role": rol, "content": contenido, "ts": _ahora(),
                   "tool_calls": tool_calls, "activity": actividad}
        with self._ruta(sesion).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(mensaje, sort_keys=True, ensure_ascii=False) + "\n")
        return mensaje

    def leer(self, sesion: str) -> list[dict[str, Any]]:
        ruta = self._ruta(sesion)
        if not ruta.is_file():
            return []
        salida = []
        for linea in ruta.read_text(encoding="utf-8").splitlines():
            if linea.strip():
                try:
                    salida.append(json.loads(linea))
                except ValueError:
                    continue
        return salida

    def sesiones(self) -> list[str]:
        if not self.dir.is_dir():
            return []
        return sorted(p.stem for p in self.dir.glob("*.jsonl"))

    def ultimos_turnos_texto(self, sesion: str, n: int = 2, tope: int = 160) -> str:
        """Dos últimos intercambios, recortados: contexto conversacional mínimo (RF-4)."""
        mensajes = [m for m in self.leer(sesion) if m["role"] in {"user", "assistant"}][-(2 * n):]
        if not mensajes:
            return "(primer turno)"
        lineas = []
        for m in mensajes:
            quien = "perito" if m["role"] == "user" else "tú"
            texto = m["content"].replace("\n", " ")
            lineas.append(f"{quien}: {texto[:tope]}{'…' if len(texto) > tope else ''}")
        return "\n".join(lineas)
