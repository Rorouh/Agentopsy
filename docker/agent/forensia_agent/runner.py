"""Ejecución de herramientas dentro del maletín vía `docker exec`.

Punto único por el que el orquestador "toca" el Docker. Se construye SIEMPRE un
argv (lista), nunca una cadena de shell, para evitar inyección de comandos.
Las rutas se validan para que apunten solo a /evidence (lectura) o /cases.
"""
from __future__ import annotations

import posixpath
import shutil
import subprocess
from typing import List


class ToolError(Exception):
    """Error de validación o de ejecución de una herramienta."""


def docker_available() -> bool:
    return shutil.which("docker") is not None


def container_running(name: str) -> bool:
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True, text=True, timeout=10,
        )
        return out.returncode == 0 and out.stdout.strip() == "true"
    except Exception:
        return False


def ensure_under(path: str, roots: List[str]) -> str:
    """Valida que `path` sea absoluta y caiga dentro de alguna raíz permitida."""
    if not isinstance(path, str) or not path.startswith("/"):
        raise ToolError(f"la ruta debe ser absoluta del contenedor (p. ej. /evidence/...): {path!r}")
    norm = posixpath.normpath(path)
    if not any(norm == r or norm.startswith(r.rstrip("/") + "/") for r in roots):
        raise ToolError(f"ruta fuera de las zonas permitidas {roots}: {path!r}")
    return norm


def join_root(root: str, subpath: str = "") -> str:
    sub = (subpath or "").lstrip("/")
    return posixpath.normpath(posixpath.join(root, sub)) if sub else root


def exec_in_container(container: str, argv: List[str], timeout: int = 600,
                      max_chars: int = 60000) -> dict:
    """Ejecuta `docker exec <container> <argv...>` y devuelve el resultado."""
    if not docker_available():
        return {"exit_code": 127, "stdout": "",
                "stderr": "docker no está disponible en el PATH de este equipo.",
                "truncated": False, "argv": argv}
    cmd = ["docker", "exec", container] + list(argv)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"exit_code": 124, "stdout": "",
                "stderr": f"tiempo de ejecución agotado tras {timeout}s",
                "truncated": False, "argv": argv}
    out = p.stdout or ""
    truncated = len(out) > max_chars
    if truncated:
        out = out[:max_chars]
    return {"exit_code": p.returncode, "stdout": out,
            "stderr": (p.stderr or "")[-4000:], "truncated": truncated, "argv": argv}
