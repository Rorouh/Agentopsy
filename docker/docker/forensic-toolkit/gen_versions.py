#!/usr/bin/env python3
"""Genera el manifiesto INMUTABLE de versiones del maletín durante el build de la imagen.

Se ejecuta como último paso de cada stage final del Dockerfile (windows / unix) y
escribe ``/opt/agentopsy/versions.json``: ``{"schema": 1, "stage": ..., "versions":
{binario: versión}}``. El exec-agent lo sirve por ``GET /versions`` y el backend lo
consulta ANTES de cada ``tool_run_start`` (FORENSIC INVARIANT 4).

Contrato (RULE 2 — sin fallbacks, sin placeholders):

- La lista de binarios declarados por stage vive en ``tool-binaries.json`` (espejo del
  catálogo del backend; un test del backend verifica que no divergen).
- Cada binario tiene UNA fuente de versión designada, resuelta EN EL BUILD:
    * paquetes apt        -> dpkg (paquete propietario del binario resuelto en PATH)
    * volatility3 (pip)   -> importlib.metadata
    * hayabusa / chainsaw -> el ARG de versión fijado del Dockerfile (env del RUN)
    * RegRipper (rip.pl)  -> commit git exacto del clone (/opt/regripper)
    * EZ Tools (.NET)     -> versión que la propia tool reporta al ejecutarse durante
                             el build (grabada en /opt/eztools/versions.tsv) + SHA-256
                             del zip desplegado — identifica el parser real, no el
                             wrapper.
- Un binario ausente, o cuya versión no pueda determinarse de forma determinista y no
  vacía, ABORTA EL BUILD (exit 1) listando cada fallo. Jamás se escribe "unknown",
  "latest", null ni el nombre del binario como versión.

Solo stdlib. No acepta paths del caller ni ejecuta comandos arbitrarios: las únicas
ejecuciones son ``dpkg``/``dpkg-query``/``git`` con argv fijos construidos aquí.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys

TOOL_BINARIES = os.path.join(os.path.dirname(__file__), "tool-binaries.json")
EZ_VERSIONS_TSV = "/opt/eztools/versions.tsv"
REGRIPPER_DIR = "/opt/regripper"
# ftkimager/aff4imager no vienen de dpkg/pip/git: el build graba su banner + SHA aquí.
FTKIMAGER_VERSION_FILE = "/opt/ftkimager/VERSION"
AFF4IMAGER_VERSION_FILE = "/opt/aff4imager/VERSION"

# Binarios cuyo artefacto real es una EZ Tool .NET envuelta en un wrapper: la versión
# viene del versions.tsv que el build escribe al desplegarlas (la tool la reporta al
# ejecutarse), no del wrapper.
_EZ_BINARIES = {
    "EvtxECmd": "evtxecmd",
    "MFTECmd": "mftecmd",
    "lecmd": "lecmd",
    "jlecmd": "jlecmd",
    "recmd": "recmd",
    "amcacheparser": "amcacheparser",
    "appcompatcacheparser": "appcompatcacheparser",
    "sbecmd": "sbecmd",
    "wxtcmd": "wxtcmd",
    "rbcmd": "rbcmd",
}

_FORBIDDEN = {"", "unknown", "latest", "null", "none"}


def _is_forbidden(version: str) -> bool:
    """Placeholder de identidad — cadena completa O incrustado como token
    ("hayabusa latest" es tan irreproducible como "latest")."""
    lowered = version.strip().lower()
    if lowered in _FORBIDDEN:
        return True
    return any(token in _FORBIDDEN for token in lowered.split())


def _run(argv: list[str]) -> str | None:
    """Ejecuta un argv fijo (shell=False) y devuelve stdout, o None si falla."""
    try:
        proc = subprocess.run(  # noqa: S603 — argv fijo construido en este script
            argv, capture_output=True, text=True, timeout=60, shell=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def _dpkg_version(binary: str, path: str) -> str | None:
    """Versión dpkg del paquete propietario del binario (paquete + Version)."""
    for candidate in dict.fromkeys([path, os.path.realpath(path)]):
        out = _run(["dpkg", "-S", candidate])
        if not out:
            continue
        first = out.splitlines()[0]
        if ":" not in first:
            continue
        package = first.split(":", 1)[0].strip()
        # "diversion by ..." lines carry no owner package in field 0.
        if not package or " " in package:
            continue
        version = _run(["dpkg-query", "-W", "-f=${Version}", package])
        if version and version.strip():
            return f"{package} {version.strip()}"
    return None


def _pip_version(dist: str) -> str | None:
    try:
        from importlib.metadata import version
        return f"{dist} {version(dist)} (pip)"
    except Exception:  # noqa: BLE001 — un fallo aquí es "sin versión" y aborta el build
        return None


def _git_commit_version(repo_dir: str, label: str) -> str | None:
    sha = _run(["git", "-C", repo_dir, "rev-parse", "HEAD"])
    if not sha or not sha.strip():
        return None
    return f"{label} git:{sha.strip()[:12]}"


def _load_ez_versions() -> dict[str, str]:
    """versions.tsv: lineas `wrapper\\tversion\\tzip_sha256` escritas al desplegar."""
    versions: dict[str, str] = {}
    try:
        with open(EZ_VERSIONS_TSV, encoding="utf-8") as handle:
            for line in handle:
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 3 and parts[1].strip():
                    versions[parts[0]] = f"{parts[0]} {parts[1]} (zip:{parts[2][:12]})"
    except OSError:
        pass
    return versions


def _recorded_file_version(path: str) -> str | None:
    """Primera línea no vacía de un fichero de identidad grabado por el build."""
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped:
                    return stripped
    except OSError:
        return None
    return None


def resolve_version(binary: str, env: dict[str, str], ez: dict[str, str]) -> str | None:
    """UNA fuente designada por binario (sin fallback entre fuentes distintas)."""
    if binary == "vol":
        return _pip_version("volatility3")
    if binary == "prefetch.py":
        # windowsprefetch se instala por pip, igual que pyhindsight.
        return _pip_version("windowsprefetch")
    if binary == "hindsight.py":
        # pyhindsight se instala por pip (requirements-windows.txt) y no lo conoce
        # dpkg, así que su fuente designada es la metadata del paquete.
        return _pip_version("pyhindsight")
    if binary == "ftkimager":
        return _recorded_file_version(FTKIMAGER_VERSION_FILE)
    if binary == "aff4imager":
        return _recorded_file_version(AFF4IMAGER_VERSION_FILE)
    if binary == "rip.pl":
        return _git_commit_version(REGRIPPER_DIR, "RegRipper3.0")
    if binary == "hayabusa":
        pinned = env.get("HAYABUSA_VERSION", "").strip()
        return f"hayabusa {pinned}" if pinned else None
    if binary == "chainsaw":
        pinned = env.get("CHAINSAW_VERSION", "").strip()
        return f"chainsaw {pinned}" if pinned else None
    if binary in _EZ_BINARIES:
        return ez.get(_EZ_BINARIES[binary])
    path = shutil.which(binary)
    if path is None:
        return None
    return _dpkg_version(binary, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True, choices=("windows", "unix"))
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    with open(TOOL_BINARIES, encoding="utf-8") as handle:
        declared = json.load(handle)
    binaries = list(declared["base"])
    if args.stage == "windows":
        binaries += list(declared["windows"])

    ez = _load_ez_versions()
    versions: dict[str, str] = {}
    failures: list[str] = []
    for binary in binaries:
        if shutil.which(binary) is None:
            failures.append(f"{binary}: binario ausente del PATH de la imagen")
            continue
        version = resolve_version(binary, dict(os.environ), ez)
        if version is None or _is_forbidden(version):
            failures.append(
                f"{binary}: sin versión determinista (fuente designada no resolvió)"
            )
            continue
        versions[binary] = version.strip()

    if failures:
        sys.stderr.write(
            "[gen_versions] BUILD ABORTADO — tools declaradas sin identidad de "
            "versión (RULE 2, FORENSIC INVARIANT 4):\n"
        )
        for failure in failures:
            sys.stderr.write(f"  - {failure}\n")
        return 1

    manifest = {"schema": 1, "stage": args.stage, "versions": versions}
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    sys.stdout.write(
        f"[gen_versions] {args.out}: {len(versions)} tools con versión ({args.stage})\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
