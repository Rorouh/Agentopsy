"""FastAPI sidecar. Binds 127.0.0.1 on an ephemeral port (never 0.0.0.0).

Once uvicorn has actually bound the socket, the sidecar prints a single machine-readable
line to stdout that the Electron main process parses to learn the url + session token:

    FORENSIA_SIDECAR_READY {"url": "http://127.0.0.1:54321", "token": "..."}

Emitting the line AFTER bind matters: Electron creates the window as soon as it reads
READY, and the renderer fires its first /api/health on mount. Announcing too early causes
ECONNREFUSED until uvicorn finishes binding, freezing the UI in an error state.

The token goes over the pipe to the parent process only — never to argv or disk.
"""

from __future__ import annotations

import asyncio
import json
import socket

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
    evidence,
    health,
)
from forensia.security import HostHeaderMiddleware, allowed_hosts, new_session_token


def create_app(port: int) -> FastAPI:
    app = FastAPI(title="FORENSIA sidecar", version=__version__)
    app.state.token = new_session_token()
    app.state.port = port

    app.add_middleware(HostHeaderMiddleware, hosts=allowed_hosts(port))
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[f"http://127.0.0.1:{port}", f"http://localhost:{port}"],
        allow_methods=["GET", "POST"],
        allow_headers=["X-Forensia-Token", "Content-Type"],
        allow_credentials=False,
    )

    app.include_router(health.router)
    app.include_router(capabilities.router)
    app.include_router(config_router.router)
    app.include_router(evidence.router)
    app.include_router(cases.router)
    app.include_router(artifacts.router)
    app.include_router(chats.router)
    app.include_router(agent.router)
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
        print("FORENSIA_SIDECAR_READY " + json.dumps(self._ready_payload), flush=True)


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
