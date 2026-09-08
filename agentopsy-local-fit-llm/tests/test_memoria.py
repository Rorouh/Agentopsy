"""Camino A (literal) y camino B (embeddings con un servidor simulado)."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from artefactos.almacen import Almacen
from memoria.embeddings import MemoriaEmbeddings
from memoria.estructurada import MemoriaEstructurada


def _run_con_texto(dir_caso: Path, texto: str, tool_id: str = "strings_head") -> str:
    almacen = Almacen(dir_caso)
    m = almacen.abrir("c", "e", tool_id, [tool_id], baseline_sha256=None, tool_version="t", agente="t")
    almacen.cerrar(m, exit_code=0, timed_out=False, stdout_texto=texto, stderr_texto="")
    return m.run_id


def test_busqueda_literal_por_frase_y_por_palabras(tmp_path):
    texto = "\n".join(["ruido"] * 5000 + ["WIN-L0ZZQ76PMUF Administrator", "sqlmap/1.0-dev running", "otro sqlmap aquí Administrator"] + ["ruido"] * 5000)
    run = _run_con_texto(tmp_path, texto)
    mem = MemoriaEstructurada(tmp_path)
    hits = mem.buscar("administrator")
    assert [h.linea for h in hits] == [5001, 5003] and hits[0].run_id == run
    hits = mem.buscar("sqlmap Administrator")
    assert hits[0].linea == 5003 and hits[0].puntuacion == 2.0
    assert mem.buscar("noexiste") == []
    assert mem.buscar("sqlmap", run_id="otro") == []


def test_busqueda_cruza_bloques_grandes(tmp_path):
    lineas = ["x" * 100] * 200000
    lineas[150000] = "aguja en el pajar"
    run = _run_con_texto(tmp_path, "\n".join(lineas))
    hit = MemoriaEstructurada(tmp_path).buscar("aguja en el")[0]
    assert (hit.run_id, hit.linea) == (run, 150001)


def test_busqueda_incluye_ficheros_out(tmp_path):
    almacen = Almacen(tmp_path)
    m = almacen.abrir("c", "e", "bulk_extractor", ["bulk_extractor"], baseline_sha256=None, tool_version="t", agente="t")
    (almacen.ruta_out(m.run_id) / "email.txt").write_text("1\tadmin@example.com\n", encoding="utf-8")
    almacen.cerrar(m, exit_code=0, timed_out=False, stdout_texto="", stderr_texto="")
    hit = MemoriaEstructurada(tmp_path).buscar("admin@example")[0]
    assert hit.fichero == "out/email.txt" and hit.linea == 1


def test_embeddings_con_servidor_simulado(tmp_path, monkeypatch):
    vocab = ["ataque", "usuario", "correo", "red"]

    def embed_falso(self, textos):
        filas = []
        for t in textos:
            v = np.array([float(t.lower().count(p)) for p in vocab] + [0.01], dtype=np.float32)
            filas.append(v / (np.linalg.norm(v) or 1.0))
        return np.stack(filas)

    monkeypatch.setattr(MemoriaEmbeddings, "_embed", embed_falso)
    run = _run_con_texto(tmp_path, "\n".join(["el usuario administrador inició sesión"] * 3 + ["conexión de red saliente"] * 3))
    mem = MemoriaEmbeddings(tmp_path, ollama_host="http://x", modelo="falso")
    informe = mem.indexar_run(run, "strings_head", [Almacen(tmp_path).ruta_stdout(run)])
    assert informe["chunks"] >= 1
    mem.indexar_texto("perito", "sospecha de ataque por correo")
    hits = mem.buscar("ataque correo")
    assert any(h.origen == "semantico" and "ataque" in h.texto for h in hits)
    hits = mem.buscar("usuario")
    assert hits[0].origen == "literal"
    # Persistido: una instancia nueva recupera el índice.
    otra = MemoriaEmbeddings(tmp_path, ollama_host="http://x", modelo="falso")
    assert otra.estadisticas()["chunks"] == mem.estadisticas()["chunks"]
    assert json.loads((tmp_path / "agente" / "vectores" / "chunks.jsonl").read_text().splitlines()[0])["run_id"] == run
