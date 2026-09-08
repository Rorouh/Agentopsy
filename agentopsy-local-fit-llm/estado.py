"""Estado del agente entre llamadas (RA-6, RA-7): la lista de tareas que el propio
modelo escribe, el resumen de cada paso y las rondas de revisión.

Persistido en `agente/<sesion>/estado.json` y visible para el operador. Es la
columna vertebral de la memoria: lo que sobrevive entre llamadas y lo que hace
que el agente sepa en qué paso va sin releer la conversación entera.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ESTADOS_TAREA = ("pendiente", "en_curso", "hecha", "descartada")
TOPE_TAREAS = 12
TOPE_PASOS_RESUMEN = 6
TOPE_CHARS_TAREA = 120


def _ahora() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Estado:
    def __init__(self, ruta_dir: Path) -> None:
        self.ruta = Path(ruta_dir) / "estado.json"
        self.datos: dict[str, Any] = {
            "tareas": [],
            "pasos": [],
            "rondas": [],
            "ultimo_resultado": None,
            "objetivo": None,
            "actualizado": None,
        }
        if self.ruta.is_file():
            try:
                self.datos.update(json.loads(self.ruta.read_text(encoding="utf-8")))
            except ValueError:
                pass

    def guardar(self) -> None:
        self.datos["actualizado"] = _ahora()
        self.ruta.parent.mkdir(parents=True, exist_ok=True)
        self.ruta.write_text(json.dumps(self.datos, indent=2, ensure_ascii=False), encoding="utf-8")

    # -- tareas ----------------------------------------------------------------------
    @property
    def tareas(self) -> list[dict[str, Any]]:
        return self.datos["tareas"]

    def escribir_tareas(self, tareas: Any) -> list[dict[str, Any]]:
        """Reescritura completa por el modelo. Se valida forma y tope; se conservan ids."""
        if isinstance(tareas, dict) and "tareas" in tareas:
            tareas = tareas["tareas"]
        if isinstance(tareas, str):
            tareas = [t for t in tareas.splitlines() if t.strip()]
        if not isinstance(tareas, list):
            raise ValueError("tareas debe ser una lista de {texto, estado}")
        nuevas: list[dict[str, Any]] = []
        for i, t in enumerate(tareas[:TOPE_TAREAS], start=1):
            if isinstance(t, str):
                texto, estado = t, "pendiente"
                marcado = texto.strip()
                if marcado[:3].lower() in {"[x]", "[v]"}:
                    texto, estado = marcado[3:], "hecha"
                elif marcado[:3] == "[ ]":
                    texto = marcado[3:]
            elif isinstance(t, dict):
                texto = str(t.get("texto") or t.get("tarea") or t.get("text") or t.get("task") or "").strip()
                estado = str(t.get("estado") or t.get("status") or "pendiente").strip().lower()
            else:
                raise ValueError(f"tarea {i} inválida: {t!r}")
            texto = texto.strip()[:TOPE_CHARS_TAREA]
            if not texto:
                continue
            estado = {"done": "hecha", "completed": "hecha", "pending": "pendiente", "in_progress": "en_curso",
                      "skipped": "descartada", "completada": "hecha", "terminada": "hecha"}.get(estado, estado)
            if estado not in ESTADOS_TAREA:
                raise ValueError(f"estado de tarea inválido {estado!r}; usa {list(ESTADOS_TAREA)}")
            nuevas.append({"id": i, "texto": texto, "estado": estado})
        self.datos["tareas"] = nuevas
        self.guardar()
        return nuevas

    def tareas_texto(self) -> str:
        if not self.tareas:
            return "(sin tareas todavía: escribe tu lista con escribir_tareas)"
        marca = {"pendiente": "[ ]", "en_curso": "[>]", "hecha": "[x]", "descartada": "[-]"}
        return "\n".join(f"{t['id']}. {marca[t['estado']]} {t['texto']}" for t in self.tareas)

    def tareas_abiertas(self) -> int:
        return sum(1 for t in self.tareas if t["estado"] in {"pendiente", "en_curso"})

    # -- pasos ---------------------------------------------------------------------
    def anotar_paso(self, *, agente: str, accion: str, args: dict[str, Any] | None,
                    resultado: str, run_id: str | None = None, estado: str = "ok") -> dict[str, Any]:
        paso = {
            "n": len(self.datos["pasos"]) + 1,
            "ts": _ahora(),
            "agente": agente,
            "accion": accion,
            "args": _resumen_args(args),
            "resultado": resultado[:200],
            "run_id": run_id,
            "estado": estado,
        }
        self.datos["pasos"].append(paso)
        self.datos["ultimo_resultado"] = {"accion": accion, "args": paso["args"], "texto": resultado}
        self.guardar()
        return paso

    def pasos_texto(self, n: int = TOPE_PASOS_RESUMEN) -> str:
        ultimos = self.datos["pasos"][-n:]
        if not ultimos:
            return "(ninguno)"
        return "\n".join(
            f"{p['n']}. {p['accion']}({p['args'][:60]}) → {p['resultado'][:80].replace(chr(10), ' ')}" for p in ultimos
        )

    def ultimo_resultado(self) -> dict[str, Any] | None:
        return self.datos.get("ultimo_resultado")

    def limpiar_ultimo(self) -> None:
        self.datos["ultimo_resultado"] = None
        self.guardar()

    # -- rondas de revisión -----------------------------------------------------------
    def anotar_ronda(self, ronda: dict[str, Any]) -> None:
        self.datos["rondas"].append({"ts": _ahora(), **ronda})
        self.guardar()

    def fijar_objetivo(self, objetivo: str | None) -> None:
        self.datos["objetivo"] = objetivo
        self.guardar()

    def vista(self) -> dict[str, Any]:
        return dict(self.datos)


def _resumen_args(args: dict[str, Any] | None) -> str:
    if not args:
        return ""
    try:
        texto = json.dumps(args, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        texto = str(args)
    return texto if len(texto) <= 120 else texto[:120] + "…"
