"""Camino B: lo del camino A más un índice vectorial sobre salidas de
herramientas y mensajes, con embeddings de Ollama (`/api/embed`).

`buscar` devuelve primero los aciertos literales (evidencia exacta) y completa
con los trozos más cercanos por significado. Coste: un modelo más en RAM y una
llamada de embedding por consulta y por trozo indexado, que es justo lo que
RA-9 manda medir contra el camino A.

Índice por caso en `agente/vectores/`: `chunks.jsonl` (texto y origen) y
`vectores.npy` (matriz float32, misma fila que la línea del jsonl). Tope de
trozos por run: una salida de `strings` de cientos de MB no se vectoriza
entera; se indexan los primeros `TOPE_CHUNKS_RUN` trozos y se declara.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import numpy as np

from memoria.base import TOPE_CHARS_HIT, TOPE_HITS, Hit
from memoria.estructurada import MemoriaEstructurada

LINEAS_CHUNK = 24
CHARS_CHUNK = 1200
TOPE_CHUNKS_RUN = 300
LOTE = 32


class EmbeddingsError(RuntimeError):
    pass


class MemoriaEmbeddings:
    nombre = "embeddings"

    def __init__(self, dir_caso: Path, *, ollama_host: str, modelo: str, timeout: float = 120.0) -> None:
        self.literal = MemoriaEstructurada(dir_caso)
        self.dir = Path(dir_caso) / "agente" / "vectores"
        self.dir.mkdir(parents=True, exist_ok=True)
        self._host = ollama_host.rstrip("/")
        self._modelo = modelo
        self._timeout = timeout
        self._chunks: list[dict[str, Any]] = []
        self._matriz: np.ndarray | None = None
        self._cargar()

    # -- persistencia ---------------------------------------------------------------
    def _cargar(self) -> None:
        fichero = self.dir / "chunks.jsonl"
        matriz = self.dir / "vectores.npy"
        if fichero.is_file() and matriz.is_file():
            self._chunks = [json.loads(l) for l in fichero.read_text(encoding="utf-8").splitlines() if l.strip()]
            self._matriz = np.load(matriz)
            if len(self._chunks) != self._matriz.shape[0]:
                self._chunks, self._matriz = [], None

    def _guardar(self) -> None:
        with (self.dir / "chunks.jsonl").open("w", encoding="utf-8") as fh:
            for c in self._chunks:
                fh.write(json.dumps(c, ensure_ascii=False) + "\n")
        if self._matriz is not None:
            np.save(self.dir / "vectores.npy", self._matriz)

    # -- embeddings ----------------------------------------------------------------
    def _embed(self, textos: list[str]) -> np.ndarray:
        cuerpo = json.dumps({"model": self._modelo, "input": textos}).encode("utf-8")
        req = urllib.request.Request(
            self._host + "/api/embed", data=cuerpo, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                datos = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detalle = exc.read().decode("utf-8", errors="replace")[:300]
            raise EmbeddingsError(
                f"Ollama rechazó el embedding con {self._modelo!r}: HTTP {exc.code} {detalle}. "
                f"¿Está el modelo descargado? (ollama pull {self._modelo})"
            ) from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise EmbeddingsError(f"no se pudo pedir embeddings a {self._host}: {exc}") from exc
        vectores = datos.get("embeddings")
        if not isinstance(vectores, list) or len(vectores) != len(textos):
            raise EmbeddingsError(f"respuesta de embeddings inesperada: {str(datos)[:200]}")
        m = np.asarray(vectores, dtype=np.float32)
        normas = np.linalg.norm(m, axis=1, keepdims=True)
        normas[normas == 0] = 1.0
        return m / normas

    def _anadir(self, nuevos: list[dict[str, Any]]) -> None:
        if not nuevos:
            return
        filas = []
        for i in range(0, len(nuevos), LOTE):
            filas.append(self._embed([c["texto"] for c in nuevos[i:i + LOTE]]))
        bloque = np.concatenate(filas, axis=0)
        self._matriz = bloque if self._matriz is None else np.concatenate([self._matriz, bloque], axis=0)
        self._chunks.extend(nuevos)
        self._guardar()

    # -- interfaz Memoria ------------------------------------------------------------
    def indexar_run(self, run_id: str, tool_id: str, ficheros: list[Path]) -> dict[str, Any]:
        inicio = time.monotonic()
        self.literal.indexar_run(run_id, tool_id, ficheros)
        nuevos: list[dict[str, Any]] = []
        truncado = False
        for ruta in ficheros:
            if not ruta.is_file() or ruta.stat().st_size == 0:
                continue
            nombre = _nombre_relativo(ruta, run_id)
            for numero, texto in _trocear(ruta):
                if len(nuevos) >= TOPE_CHUNKS_RUN:
                    truncado = True
                    break
                nuevos.append({"run_id": run_id, "fichero": nombre, "linea": numero, "texto": texto, "tool_id": tool_id})
            if truncado:
                break
        self._anadir(nuevos)
        return {"run_id": run_id, "chunks": len(nuevos), "truncado": truncado,
                "segundos": round(time.monotonic() - inicio, 2), "camino": self.nombre}

    def indexar_texto(self, origen: str, texto: str) -> None:
        texto = (texto or "").strip()
        if not texto:
            return
        self._anadir([{"run_id": "mensajes", "fichero": origen, "linea": None, "texto": texto[:CHARS_CHUNK]}])

    def buscar(self, consulta: str, *, k: int = TOPE_HITS, run_id: str | None = None) -> list[Hit]:
        literales = self.literal.buscar(consulta, k=max(2, k // 2), run_id=run_id)
        if self._matriz is None or not consulta.strip():
            return literales
        q = self._embed([consulta])[0]
        puntuaciones = self._matriz @ q
        orden = np.argsort(-puntuaciones)
        semanticos: list[Hit] = []
        vistos = {(h.run_id, h.fichero, h.linea) for h in literales}
        for idx in orden:
            if len(literales) + len(semanticos) >= k:
                break
            c = self._chunks[int(idx)]
            if run_id and c["run_id"] != run_id:
                continue
            clave = (c["run_id"], c["fichero"], c.get("linea"))
            if clave in vistos:
                continue
            vistos.add(clave)
            texto = c["texto"].replace("\n", " ⏎ ")
            if len(texto) > TOPE_CHARS_HIT:
                texto = texto[:TOPE_CHARS_HIT] + "…"
            semanticos.append(Hit(c["run_id"], c["fichero"], c.get("linea"), texto, float(puntuaciones[idx]), "semantico"))
        return literales + semanticos

    def estadisticas(self) -> dict[str, Any]:
        return {"camino": self.nombre, "chunks": len(self._chunks), "modelo": self._modelo}


def _nombre_relativo(ruta: Path, run_id: str) -> str:
    partes = ruta.parts
    if run_id in partes:
        return "/".join(partes[partes.index(run_id) + 1:])
    return ruta.name


def _trocear(ruta: Path):
    """Trozos de hasta LINEAS_CHUNK líneas o CHARS_CHUNK caracteres, con su primera línea."""
    lineas: list[str] = []
    inicio = 1
    usados = 0
    with ruta.open("r", encoding="utf-8", errors="replace") as fh:
        for numero, linea in enumerate(fh, start=1):
            linea = linea.rstrip("\n")[:300]
            if lineas and (len(lineas) >= LINEAS_CHUNK or usados + len(linea) > CHARS_CHUNK):
                yield inicio, "\n".join(lineas)
                lineas, usados, inicio = [], 0, numero
            lineas.append(linea)
            usados += len(linea) + 1
    if lineas:
        yield inicio, "\n".join(lineas)
