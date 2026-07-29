#!/usr/bin/env python3
"""graph-refresh.py — deja el grafo del repo AL DÍA antes de que nadie lo lea.

`tools/graph/CONTEXT.md` y `tools/graph/out/` son el mapa que toda sesión nueva
consulta en vez de recorrer los ~160 ficheros del repo (ver `CLAUDE.md`, §Mapa de
arquitectura). Ese mapa solo vale si corresponde al código de AHORA: un grafo de
hace veinte commits es peor que no tener grafo, porque se lee con la misma
confianza y manda a leer ficheros que ya no existen.

Este script es el enganche que lo garantiza. Corre al ARRANCAR la sesión (hook
`SessionStart` en `.claude/settings.json`) y:

  1. Toma la huella del árbol de CÓDIGO (`backend/`, `web/`): el commit de HEAD
     más el (tamaño, mtime) de cada fichero indexable.
  2. La compara con la huella de la última corrida (`out/.graph-stamp.json`).
     Iguales → no hay nada que reconstruir y termina en menos de un segundo. Es
     el caso normal, y es lo que hace que el enganche no moleste.
  3. Distintas → lanza el runner de la plataforma (`graph-build.ps1` en Windows,
     `graph-build.sh` en el resto) — el MISMO que se corre a mano, para que no
     existan dos pipelines que puedan divergir.
  4. Escribe `out/GRAPH_STATUS.md`: la tarjeta de frescura que el modelo lee para
     saber a qué commit corresponde el grafo que tiene delante, cuántos nodos y
     aristas trae, y si `CONTEXT.md` (curado a mano) se ha quedado anclado a un
     commit anterior.

**Nunca tumba la sesión.** graphify es una herramienta de dev opcional (RULE 1: no
viaja en el compose; RULE 7: modo `--code-only`, sin LLM ni API key). Si no está
instalado, si el runner falla o si no hay git, esto lo dice y sale con 0: el
trabajo del perito no depende de que el grafo esté fresco, solo la comodidad de
quien lee el repo.

Uso:
    python tools/graph/graph-refresh.py             # reconstruye solo si cambió el código
    python tools/graph/graph-refresh.py --force     # reconstruye siempre
    python tools/graph/graph-refresh.py --check     # solo informa; no reconstruye

Variables de entorno:
    FORENSIA_GRAPH_REFRESH=0    desactiva el enganche por completo (salida inmediata)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Lo que imprime este script acaba en el contexto del modelo (es un hook), y el
# repo escribe en español. En una consola Windows con codepage cp1252 Python
# mojibakearía los acentos y las rayas; forzamos UTF-8 en la salida.
for _stream in (sys.stdout, sys.stderr):
    reconfigure = getattr(_stream, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(encoding="utf-8", errors="replace")

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
OUT = HERE / "out"
STAMP = OUT / ".graph-stamp.json"
STATUS = OUT / "GRAPH_STATUS.md"
CONTEXT = HERE / "CONTEXT.md"

# Directorios de CÓDIGO. NUNCA `evidence-corpus/`, `docs/pruebas/` ni `results/`:
# la evidencia es dato hostil y contiene datos personales (GDPR) — ver
# tools/graph/README.md §0. Esta lista debe coincidir con la de los runners.
TARGETS = ("backend", "web")
CODE_SUFFIXES = frozenset({".py", ".ts", ".tsx", ".js", ".jsx"})
# Subárboles que no son código del proyecto y que además harían la huella inútil
# (cambian a cada `npm ci` / `pip install`).
SKIP_DIRS = frozenset({
    ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "dist", "build", ".git",
})


def _run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Shell-free siempre (argv, `shell=False`) — misma disciplina que el producto."""
    return subprocess.run(argv, shell=False, **kwargs)  # noqa: S603


def git_head() -> str | None:
    if shutil.which("git") is None:
        return None
    try:
        proc = _run(
            ["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def code_fingerprint() -> dict[str, object]:
    """Huella barata del árbol de código: no lee un solo byte de los ficheros.

    (ruta, tamaño, mtime) por fichero indexable basta para detectar «esto cambió»,
    que es la única pregunta que hay que responder aquí. Hashear el contenido
    sería exacto y varios órdenes de magnitud más caro en cada arranque, para
    distinguir un caso —tocar un fichero sin cambiarlo— que solo cuesta una
    reconstrucción de más.
    """
    files: list[list] = []
    for target in TARGETS:
        root = REPO / target
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if path.suffix not in CODE_SUFFIXES or not path.is_file():
                continue
            if SKIP_DIRS & set(path.relative_to(REPO).parts):
                continue
            try:
                st = path.stat()
            except OSError:
                continue
            files.append([path.relative_to(REPO).as_posix(), st.st_size, st.st_mtime_ns])
    return {"head": git_head(), "files": files}


def read_stamp() -> dict | None:
    if not STAMP.is_file():
        return None
    try:
        return json.loads(STAMP.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def graph_counts() -> dict[str, dict[str, int]]:
    """Nodos/aristas de cada grafo generado, leídos del propio `graph.json`."""
    counts: dict[str, dict[str, int]] = {}
    candidates = {t: OUT / t / "graphify-out" / "graph.json" for t in TARGETS}
    candidates["merged"] = OUT / "forensia-graph.json"
    for name, path in candidates.items():
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        # graphify serializa en formato node-link de NetworkX: las aristas van en
        # `links`, no en `edges`.
        counts[name] = {
            "nodes": len(data.get("nodes") or []),
            "edges": len(data.get("links") or data.get("edges") or []),
        }
    return counts


def context_anchor() -> str | None:
    """El commit al que `CONTEXT.md` dice estar anclado (`**Anclado a:** commit X`)."""
    if not CONTEXT.is_file():
        return None
    try:
        text = CONTEXT.read_text(encoding="utf-8")
    except OSError:
        return None
    marker = "**Anclado a:** commit `"
    start = text.find(marker)
    if start == -1:
        return None
    start += len(marker)
    end = text.find("`", start)
    return text[start:end].strip() if end != -1 else None


def runner_argv() -> list[str] | None:
    """El runner de ESTA plataforma. Uno solo, el mismo que se corre a mano."""
    if sys.platform == "win32":
        script = HERE / "graph-build.ps1"
        exe = shutil.which("powershell") or shutil.which("pwsh")
        if exe is None or not script.is_file():
            return None
        return [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)]
    script = HERE / "graph-build.sh"
    bash = shutil.which("bash")
    if bash is None or not script.is_file():
        return None
    return [bash, str(script)]


def graphify_version() -> str | None:
    if shutil.which("graphify") is None:
        return None
    try:
        proc = _run(["graphify", "--version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.strip() or proc.stderr.strip() or None


def write_status(*, head: str | None, rebuilt: bool, note: str) -> None:
    """La tarjeta de frescura que lee el modelo antes de fiarse del grafo.

    Es un fichero GENERADO: se sobrescribe en cada corrida y no se edita a mano
    (a diferencia de `CONTEXT.md`, que es el mapa curado por el equipo).
    """
    OUT.mkdir(parents=True, exist_ok=True)
    counts = graph_counts()
    anchor = context_anchor()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    lines = [
        "# Grafo del repo — estado de frescura",
        "",
        "> Fichero **generado** por `tools/graph/graph-refresh.py` en cada arranque de",
        "> sesión. No se edita a mano. El mapa curado por el equipo es",
        "> [`CONTEXT.md`](../CONTEXT.md); esto solo dice a qué versión del código",
        "> corresponde el grafo que hay en `out/`.",
        "",
        f"- **Actualizado:** {now}",
        f"- **Commit del repo:** `{head or 'desconocido (sin git)'}`",
        f"- **Esta corrida:** {'reconstruyó el grafo' if rebuilt else 'no hizo falta reconstruir'}",
        f"- **Nota:** {note}",
        "",
    ]

    if counts:
        lines += [
            "## Tamaño del grafo",
            "",
            "| grafo | nodos | aristas |",
            "|---|---:|---:|",
        ]
        for name in ("backend", "web", "merged"):
            if name in counts:
                lines.append(
                    f"| {name} | {counts[name]['nodes']} | {counts[name]['edges']} |"
                )
        lines.append("")
    else:
        lines += [
            "## Tamaño del grafo",
            "",
            "No hay ningún `graph.json` en `out/`: el grafo nunca se ha construido en",
            "este clon. Córrelo con `tools/graph/graph-build.ps1` (o `.sh`).",
            "",
        ]

    if anchor and head and anchor != head:
        lines += [
            "## ⚠ `CONTEXT.md` va por detrás",
            "",
            f"`CONTEXT.md` dice estar anclado al commit `{anchor}`, pero el repo está en",
            f"`{head}`. Las CIFRAS y los god-nodes de ese fichero pueden no corresponder a",
            "este código. El grafo de `out/` sí está al día (esta corrida lo garantiza);",
            "cuando la arquitectura se haya movido de verdad, actualiza `CONTEXT.md` a mano",
            "y re-ancla el commit (RULE 4 — la doc no se queda atrás).",
            "",
        ]
    elif anchor:
        lines += [f"`CONTEXT.md` está anclado a `{anchor}`, que es el commit actual.", ""]

    lines += [
        "## Cómo consultarlo",
        "",
        "```",
        'graphify explain "EvidenceManager" --graph tools/graph/out/forensia-graph.json',
        'graphify query   "que conecta capabilities con los maletines" --graph tools/graph/out/forensia-graph.json',
        'graphify affected "AuditLog" --graph tools/graph/out/forensia-graph.json',
        "```",
        "",
    ]
    STATUS.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="reconstruye aunque nada haya cambiado")
    parser.add_argument("--check", action="store_true", help="informa si haría falta reconstruir, sin hacerlo")
    args = parser.parse_args()

    if os.environ.get("FORENSIA_GRAPH_REFRESH") == "0":
        print("[graph] enganche desactivado (FORENSIA_GRAPH_REFRESH=0)")
        return 0

    head = git_head()
    current = code_fingerprint()
    previous = read_stamp()
    stale = args.force or previous is None or previous.get("fingerprint") != current

    if not stale:
        print(f"[graph] al día (commit {head or '?'}) — nada que reconstruir")
        write_status(head=head, rebuilt=False, note="el código no ha cambiado desde la última corrida")
        return 0

    if args.check:
        print("[graph] el grafo está desfasado: corre tools/graph/graph-refresh.py")
        return 0

    version = graphify_version()
    if version is None:
        note = (
            "graphify no está instalado en esta máquina, así que el grafo de `out/` es "
            "el último que commiteó alguien y puede no corresponder a este código. "
            "Instálalo con `python -m pip install graphifyy` (herramienta de dev; no "
            "viaja en el compose — RULE 1)."
        )
        print(f"[graph] {note}")
        write_status(head=head, rebuilt=False, note=note)
        return 0

    argv = runner_argv()
    if argv is None:
        note = "no se encontró el runner de esta plataforma en tools/graph/"
        print(f"[graph] {note}")
        write_status(head=head, rebuilt=False, note=note)
        return 0

    print(f"[graph] el código cambió — reconstruyendo con {version}…")
    try:
        proc = _run(argv, cwd=str(REPO), capture_output=True, text=True, timeout=900)
    except (OSError, subprocess.TimeoutExpired) as exc:
        note = f"el runner no pudo completar ({type(exc).__name__}): {exc}"
        print(f"[graph] {note}")
        write_status(head=head, rebuilt=False, note=note)
        return 0

    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-5:]
        note = "el runner falló (exit {}): {}".format(proc.returncode, " / ".join(tail))
        print(f"[graph] {note}")
        write_status(head=head, rebuilt=False, note=note)
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    STAMP.write_text(
        json.dumps({"head": head, "fingerprint": current}, indent=0),
        encoding="utf-8",
    )
    write_status(head=head, rebuilt=True, note=f"reconstruido con {version}")
    counts = graph_counts()
    merged = counts.get("merged")
    print(
        "[graph] listo"
        + (f" — {merged['nodes']} nodos / {merged['edges']} aristas" if merged else "")
        + f" (commit {head or '?'})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
