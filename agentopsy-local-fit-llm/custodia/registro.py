"""Registro de auditoría encadenado por hash (RC-3, RC-4, RC-5, RC-7).

Mismo formato que `backend/agentopsy/audit/log.py`, a propósito: el api, su
timeline y su verificación leen `audit.jsonl` tal cual, y un caso puede pasar de
un motor a otro sin romper la cadena. Cada línea es un objeto JSON con
`ts_utc`, `prev_hash`, los campos del evento y `entry_hash` = SHA-256 del objeto
canónico (claves ordenadas, sin espacios) sin `entry_hash`.

La cadena se cierra cuando la herramienta termina (`tool_run_finish`). Leer la
salida después no escribe nada aquí (RC-7).
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from filelock import FileLock

GENESIS = "0" * 64


def canonico(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def ahora_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


class Registro:
    def __init__(self, ruta: Path) -> None:
        self.ruta = Path(ruta)
        self.ruta.parent.mkdir(parents=True, exist_ok=True)
        self._cerrojo = self.ruta.with_suffix(self.ruta.suffix + ".lock")

    def _ultimo_hash(self) -> str:
        if not self.ruta.exists():
            return GENESIS
        ultimo = GENESIS
        with self.ruta.open("rb") as fh:
            for linea in fh:
                linea = linea.strip()
                if linea:
                    ultimo = json.loads(linea)["entry_hash"]
        return ultimo

    def anotar(self, evento: dict[str, Any]) -> dict[str, Any]:
        """Añade un evento encadenado. Sección crítica bajo cerrojo entre procesos:
        leer el último hash y escribir deben ver el mismo `prev_hash`."""
        if "action" not in evento:
            raise ValueError("todo evento del registro lleva 'action'")
        with FileLock(str(self._cerrojo)):
            cuerpo: dict[str, Any] = {
                "ts_utc": ahora_utc(),
                "prev_hash": self._ultimo_hash(),
                **evento,
            }
            cuerpo["entry_hash"] = hashlib.sha256(canonico(cuerpo)).hexdigest()
            with self.ruta.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(cuerpo, sort_keys=True, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        return cuerpo

    def entradas(self) -> list[dict[str, Any]]:
        if not self.ruta.exists():
            return []
        salida: list[dict[str, Any]] = []
        with self.ruta.open("r", encoding="utf-8") as fh:
            for linea in fh:
                if linea.strip():
                    salida.append(json.loads(linea))
        return salida

    def verificar(self) -> tuple[bool, str | None]:
        """Recorre la cadena entera. Devuelve (ok, motivo del primer fallo)."""
        prev = GENESIS
        for numero, entrada in enumerate(self.entradas(), start=1):
            registrado = entrada.pop("entry_hash", None)
            if entrada.get("prev_hash") != prev:
                return False, f"línea {numero}: prev_hash no enlaza con la anterior"
            if hashlib.sha256(canonico(entrada)).hexdigest() != registrado:
                return False, f"línea {numero}: entry_hash no coincide con el contenido"
            prev = registrado
        return True, None


def sha256_fichero(ruta: Path, bloque: int = 1024 * 1024) -> tuple[str, int]:
    """SHA-256 y tamaño leyendo por bloques (nunca el fichero entero en RAM)."""
    resumen = hashlib.sha256()
    tamano = 0
    with Path(ruta).open("rb") as fh:
        while True:
            trozo = fh.read(bloque)
            if not trozo:
                break
            resumen.update(trozo)
            tamano += len(trozo)
    return resumen.hexdigest(), tamano


def sha256_texto(texto: str) -> str:
    return hashlib.sha256(texto.encode("utf-8", errors="replace")).hexdigest()
