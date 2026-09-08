"""Fábrica del camino de memoria: `LOCALFIT_MEMORIA` decide, sin tocar código (RA-9)."""

from __future__ import annotations

from pathlib import Path

from configuracion import Ajustes, ajustes
from memoria.base import Hit, Memoria
from memoria.embeddings import MemoriaEmbeddings
from memoria.estructurada import MemoriaEstructurada

__all__ = ["Hit", "Memoria", "MemoriaEmbeddings", "MemoriaEstructurada", "crear_memoria"]


def crear_memoria(dir_caso: Path, cfg: Ajustes = ajustes) -> Memoria:
    camino = cfg.memoria
    if camino == "estructurada":
        return MemoriaEstructurada(dir_caso)
    return MemoriaEmbeddings(dir_caso, ollama_host=cfg.ollama_host, modelo=cfg.modelo_embeddings)
