#!/usr/bin/env python3
"""FORENSIA exec-agent — el canal api→maletín (§B, sin socket de Docker).

Corre DENTRO de cada maletín (`toolkit-unix` / `toolkit-windows`) y expone un HTTP
mínimo en la red interna del compose. El servicio `api` lo llama para consultar y
ejecutar herramientas sin necesidad del socket de Docker del host:

  - GET  /health                          -> ¿el maletín está vivo? (+ su stage)
  - POST /which  {"binaries": [...]}       -> subconjunto de binarios presentes en PATH
  - POST /exec   {"argv": [...],           -> ejecuta argv shell-free y devuelve
                  "timeout": N|null}          {exit, stdout, stderr, timed_out}

Por qué existe (docs/operacion/exec-agent.md, proximos-pasos.md §B):
La alternativa §A (montar `/var/run/docker.sock` en el `api` + docker-cli) le daría al
api control del Docker del HOST en cada despliegue — una escalada de privilegios que el
repo evita a propósito. Este agente mantiene al api hablando SOLO con los maletines por
la red interna, igual que hace con `ollama`.

SEGURIDAD:
  - Shell-free SIEMPRE: `subprocess.run(argv, shell=False)`; `argv` debe ser list[str]
    no vacía (SECURITY INVARIANT 4).
  - El allowlist de herramientas/flags lo impone el `api` ANTES de llamar (el LLM emite
    un id de tool + params tipados, el backend resuelve el argv real — SECURITY
    INVARIANT 5). Aquí solo se ejecuta el argv ya resuelto.
  - Sin puerto publicado: el maletín no declara `ports:` en el compose, así que este
    servidor (bind 0.0.0.0 DENTRO del contenedor) solo es alcanzable en la red interna
    del compose — nunca desde el host (SECURITY INVARIANT 1), idéntico modelo a `ollama`.
  - Endurecimiento opcional: si `FORENSIA_EXEC_AGENT_TOKEN` está definido, exige la
    cabecera `X-Forensia-Exec-Token` con ese valor; si no, sin auth (confianza de red
    interna).

Solo stdlib: el maletín trae python3 (`http.server` + `json` + `subprocess`).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_PORT = int(os.environ.get("FORENSIA_EXEC_AGENT_PORT", "8666"))
_STAGE = os.environ.get("FORENSIA_STAGE", "base")
_TOKEN = os.environ.get("FORENSIA_EXEC_AGENT_TOKEN") or None
# Tope duro de tiempo por ejecución: una tool que no termina no bloquea al agente para
# siempre. El api pide su propio timeout; este es el techo defensivo.
_MAX_TIMEOUT_S = 1800


class Handler(BaseHTTPRequestHandler):
    # Silenciamos el log por-petición a stderr para no ensuciar los logs del contenedor.
    def log_message(self, *_args) -> None:  # noqa: D401
        return

    # -- helpers ----------------------------------------------------------------
    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self) -> bool:
        if _TOKEN is None:
            return True
        return self.headers.get("X-Forensia-Exec-Token") == _TOKEN

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    # -- routes -----------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 (http.server contract)
        if self.path.rstrip("/") == "/health":
            return self._send(200, {"ok": True, "stage": _STAGE})
        return self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._authed():
            return self._send(401, {"error": "invalid or missing exec-agent token"})
        try:
            payload = self._read_json()
        except (ValueError, OSError) as exc:
            return self._send(400, {"error": f"bad json: {exc}"})
        path = self.path.rstrip("/")
        if path == "/which":
            return self._which(payload)
        if path == "/exec":
            return self._exec(payload)
        return self._send(404, {"error": "not found"})

    def _which(self, payload: dict) -> None:
        binaries = payload.get("binaries")
        if not isinstance(binaries, list) or not all(isinstance(b, str) for b in binaries):
            return self._send(400, {"error": "'binaries' must be a list[str]"})
        present = [b for b in binaries if shutil.which(b) is not None]
        return self._send(200, {"present": present})

    def _exec(self, payload: dict) -> None:
        argv = payload.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            return self._send(400, {"error": "'argv' must be a non-empty list[str]"})
        timeout = payload.get("timeout")
        if timeout is not None:
            try:
                timeout = min(float(timeout), _MAX_TIMEOUT_S)
            except (TypeError, ValueError):
                return self._send(400, {"error": "'timeout' must be a number or null"})
        try:
            proc = subprocess.run(  # noqa: S603 — argv list, shell=False, resolved by the api allowlist
                argv, capture_output=True, text=True, timeout=timeout, shell=False
            )
        except FileNotFoundError:
            return self._send(
                200, {"exit": 127, "stdout": "", "stderr": f"{argv[0]}: not found", "timed_out": False}
            )
        except subprocess.TimeoutExpired as exc:
            return self._send(
                200,
                {
                    "exit": 124,
                    "stdout": exc.stdout or "",
                    "stderr": (exc.stderr or "") + "\n[exec-agent] timeout",
                    "timed_out": True,
                },
            )
        return self._send(
            200,
            {"exit": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "timed_out": False},
        )


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", _PORT), Handler)
    print(
        f"[forensia exec-agent] stage={_STAGE} escuchando en 0.0.0.0:{_PORT} "
        f"(auth={'on' if _TOKEN else 'off'})",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
