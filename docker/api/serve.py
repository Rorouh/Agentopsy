"""Arranque del backend FastAPI dentro del contenedor `api`.

Sirve la app en 0.0.0.0:8000 — «0.0.0.0» es el namespace de red DEL CONTENEDOR,
no el host: el compose publica el puerto como 127.0.0.1:8000 y nada del stack
es alcanzable desde fuera de la máquina (SECURITY INVARIANT 1).

A diferencia de `python -m forensia.server` (modo debug en el host: puerto
efímero + token anunciado por stdout al proceso padre), aquí el puerto es fijo
para que el healthcheck del compose y el navegador lleguen siempre a
/api/health. El token de sesión sigue generándose en memoria en el arranque y
NUNCA se escribe en logs ni en disco (modelo de amenazas, gate 12); la SPA lo
obtiene por `GET /api/session`, legible solo desde el mismo-origen de la UI
(ver forensia/routers/session.py).

`FORENSIA_UI_ORIGINS` (coma-separado) declara los orígenes exactos de la UI
web — el compose fija http://127.0.0.1:5173 y http://localhost:5173. El nginx
del servicio `web` reenvía el Host original del navegador, así que estos hosts
entran en la allowlist del Host-header check (SECURITY INVARIANT 2).
"""

from __future__ import annotations

import os

import uvicorn

from forensia.server import create_app

PORT = 8000


def main() -> None:
    ui_origins = tuple(
        origin.strip()
        for origin in os.environ.get("FORENSIA_UI_ORIGINS", "").split(",")
        if origin.strip()
    )
    app = create_app(PORT, ui_origins=ui_origins)
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")


if __name__ == "__main__":
    main()
