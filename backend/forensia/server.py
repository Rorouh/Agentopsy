"""The FORENSIA api (FastAPI). Standalone mode binds 127.0.0.1 on an ephemeral port
(never 0.0.0.0).

In the compose, `docker/api/serve.py` builds the app via `create_app()` on port 8000.
`python -m forensia.server` runs the api standalone for debugging: once uvicorn has
actually bound the socket, it prints a single machine-readable line to stdout with the
url + session token (the SPA obtains the token via `GET /api/session`; this line is for
the human at the terminal or a wrapper script):

    FORENSIA_API_READY {"url": "http://127.0.0.1:54321", "token": "..."}

Emitting the line AFTER bind matters: announcing too early causes ECONNREFUSED for any
client that reacts to READY before uvicorn finishes binding.

The token goes to stdout only — never to argv or disk.
"""

from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import Sequence
from urllib.parse import urlsplit

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from forensia._version import __version__
from forensia.routers import (
    agent,
    artifacts,
    capabilities,
    cases,
    chats,
    config as config_router,
    documents,
    evidence,
    executors as executors_router,
    findings,
    mitre,
    health,
    session,
    timeline,
)
from forensia.security import HostHeaderMiddleware, allowed_hosts, new_session_token


def create_app(port: int, ui_origins: Sequence[str] = ()) -> FastAPI:
    """``ui_origins`` — orígenes exactos de la UI web (p. ej.
    ``http://127.0.0.1:5173``). En el compose los fija el servicio ``api`` vía
    ``FORENSIA_UI_ORIGINS`` (nginx reenvía el Host original del navegador, así
    que el Host-check debe reconocerlos). Vacío = solo el propio puerto, el
    comportamiento standalone de siempre. Allowlist EXACTA en ambos casos —
    nunca un regex sobre localhost.
    """
    app = FastAPI(title="FORENSIA api", version=__version__)
    app.state.token = new_session_token()
    app.state.port = port

    ui_hosts = {urlsplit(origin).netloc for origin in ui_origins if urlsplit(origin).netloc}
    app.add_middleware(HostHeaderMiddleware, hosts=allowed_hosts(port) | ui_hosts)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            f"http://127.0.0.1:{port}",
            f"http://localhost:{port}",
            *ui_origins,
        ],
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["X-Forensia-Token", "Content-Type"],
        allow_credentials=False,
    )

    app.include_router(session.router)
    app.include_router(health.router)
    app.include_router(capabilities.router)
    app.include_router(config_router.router)
    app.include_router(executors_router.router)
    app.include_router(evidence.router)
    app.include_router(cases.router)
    app.include_router(artifacts.router)
    app.include_router(chats.router)
    app.include_router(findings.router)
    app.include_router(mitre.router)
    app.include_router(documents.router)
    app.include_router(agent.router)
    app.include_router(timeline.router)
    return app


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _ReadyAnnouncingServer(uvicorn.Server):
    """Print the READY line only after `self.started` flips (sockets listening)."""

    def __init__(self, config: uvicorn.Config, *, ready_payload: dict) -> None:
        super().__init__(config)
        self._ready_payload = ready_payload

    async def serve(self, sockets=None) -> None:
        asyncio.create_task(self._announce_when_ready())
        await super().serve(sockets=sockets)

    async def _announce_when_ready(self) -> None:
        while not self.started:
            await asyncio.sleep(0.05)
        print("FORENSIA_API_READY " + json.dumps(self._ready_payload), flush=True)


def main() -> None:
    port = _free_port()
    app = create_app(port)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = _ReadyAnnouncingServer(
        config,
        ready_payload={"url": f"http://127.0.0.1:{port}", "token": app.state.token},
    )
    server.run()


if __name__ == "__main__":
    main()
