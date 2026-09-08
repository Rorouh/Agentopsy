"""Camino A: estado estructurado, búsqueda literal sobre las salidas crudas.

No añade ningún modelo en RAM ni latencia por consulta. `buscar` recorre los
ficheros de los artefactos (stdout y `out/*.txt`) por bloques, en bytes, con
una expresión escapada e insensible a mayúsculas, y devuelve como mucho
`TOPE_HITS` líneas recortadas con su run_id, fichero y número de línea.

Una consulta con varias palabras primero se prueba como frase; si no hay
nada, se buscan las palabras por separado y se puntúa por cuántas aparecen en
la misma línea.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from artefactos.almacen import Almacen
from memoria.base import TOPE_CHARS_HIT, TOPE_HITS, Hit

BLOQUE = 8 * 1024 * 1024
SOLAPE = 4096
TOPE_HITS_CRUDOS = 400
EXTENSIONES_TEXTO = {".txt", ".csv", ".json", ".log", ".xml", ".tsv", ""}


class MemoriaEstructurada:
    nombre = "estructurada"

    def __init__(self, dir_caso: Path) -> None:
        self.almacen = Almacen(dir_caso)
        self._indexados: dict[str, int] = {}

    def indexar_run(self, run_id: str, tool_id: str, ficheros: list[Path]) -> dict[str, Any]:
        self._indexados[run_id] = len(ficheros)
        return {"run_id": run_id, "ficheros": len(ficheros), "camino": self.nombre}

    def indexar_texto(self, origen: str, texto: str) -> None:
        return None

    def estadisticas(self) -> dict[str, Any]:
        return {"camino": self.nombre, "runs_indexados": len(self._indexados)}

    # -- búsqueda -----------------------------------------------------------------
    def ficheros_buscables(self, run_id: str | None = None) -> list[tuple[str, str, Path]]:
        salida = []
        for fila in self.almacen.indice():
            rid = fila["run_id"]
            if run_id and rid != run_id:
                continue
            ruta_run = self.almacen.raiz / rid
            stdout = ruta_run / "stdout.txt"
            if stdout.is_file() and stdout.stat().st_size > 0:
                salida.append((rid, "stdout.txt", stdout))
            out = ruta_run / "out"
            if out.is_dir():
                for p in sorted(out.rglob("*")):
                    if p.is_file() and p.suffix.lower() in EXTENSIONES_TEXTO and p.stat().st_size > 0:
                        salida.append((rid, "out/" + str(p.relative_to(out)), p))
        return salida

    def buscar(self, consulta: str, *, k: int = TOPE_HITS, run_id: str | None = None) -> list[Hit]:
        consulta = (consulta or "").strip()
        if not consulta:
            return []
        hits = self._buscar_patron(re.escape(consulta), k, run_id)
        if hits:
            return hits
        palabras = [p for p in re.split(r"\s+", consulta) if len(p) >= 3]
        if len(palabras) < 2:
            return []
        patron = "|".join(re.escape(p) for p in palabras)
        crudos = self._buscar_patron(patron, TOPE_HITS_CRUDOS, run_id, puntuar=palabras)
        crudos.sort(key=lambda h: -h.puntuacion)
        return crudos[:k]

    def _buscar_patron(self, patron: str, tope: int, run_id: str | None,
                       puntuar: list[str] | None = None) -> list[Hit]:
        regex = re.compile(patron.encode("utf-8", errors="replace"), re.IGNORECASE)
        hits: list[Hit] = []
        vistos: set[tuple[str, str, int]] = set()
        inicio = time.monotonic()
        for rid, nombre, ruta in self.ficheros_buscables(run_id):
            for numero, linea in _lineas_con_match(ruta, regex):
                clave = (rid, nombre, numero)
                if clave in vistos:
                    continue
                vistos.add(clave)
                texto = linea.decode("utf-8", errors="replace").strip()
                if len(texto) > TOPE_CHARS_HIT:
                    pos = regex.search(linea)
                    ini = max(0, (pos.start() if pos else 0) - 60)
                    texto = texto[ini:ini + TOPE_CHARS_HIT] + "…"
                punt = 1.0
                if puntuar:
                    bajo = texto.lower()
                    punt = float(sum(1 for p in puntuar if p.lower() in bajo))
                hits.append(Hit(rid, nombre, numero, texto, punt, "literal"))
                if len(hits) >= tope:
                    return hits
            if time.monotonic() - inicio > 60:
                break
        return hits


def _lineas_con_match(ruta: Path, regex: re.Pattern[bytes]):
    """Recorre el fichero por bloques y devuelve (nº línea, línea) de cada coincidencia."""
    numero_base = 0
    resto = b""
    with ruta.open("rb") as fh:
        while True:
            bloque = fh.read(BLOQUE)
            if not bloque:
                if resto and regex.search(resto):
                    yield numero_base + 1, resto
                return
            datos = resto + bloque
            corte = datos.rfind(b"\n")
            if corte == -1:
                resto = datos
                continue
            cuerpo, resto = datos[:corte + 1], datos[corte + 1:]
            if regex.search(cuerpo):
                for i, linea in enumerate(cuerpo.split(b"\n")):
                    if linea and regex.search(linea):
                        yield numero_base + i + 1, linea
            numero_base += cuerpo.count(b"\n")
