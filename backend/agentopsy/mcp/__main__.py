"""Entry point — ``python -m agentopsy.mcp`` arranca el servidor MCP por stdio.

Lifecycle:
- Lee AGENTOPSY_CLOUD_CONSENT antes que nada: si el operador apunta este
  servidor a un cliente cloud (Claude Desktop), exigimos consentimiento
  explícito (RULE 2 / L3). Sin el flag → exit 2 con mensaje accionable.
- Construye el servidor (agentopsy.mcp.toolkit.build_server) y lo corre por
  stdio (transporte único — L4: cero sockets).
- Maneja SIGTERM/SIGINT cancelando el loop limpio: si el cliente cierra stdin
  abruptamente, propagamos ``asyncio.CancelledError`` para que cualquier
  subprocess.run del dispatcher pueda decidir su propio cierre.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys

from mcp.server.lowlevel.server import NotificationOptions
from mcp.server.stdio import stdio_server

from agentopsy.mcp.toolkit import build_server

# Public marker the signal handler uses to force a process exit if the
# cooperative shutdown can't unwind ``stdio_server``'s blocking stdin read.
# Round-2 panel discovered: closing the SDK's memory stream doesn't help
# because the real ``sys.stdin`` syscall is what's blocked. Closing stdin
# at the fd level frees it.
_FORCE_EXIT_DEADLINE_S = 5


def _consent_or_die() -> str:
    """Return the consent ref or exit non-zero with an actionable message.

    The variable's value identifies the cloud client the operator is
    consenting to (``claude_desktop``, ``continue``, ``cline``…). The empty
    string is rejected.
    """
    consent = os.environ.get("AGENTOPSY_CLOUD_CONSENT", "").strip()
    if not consent:
        sys.stderr.write(
            "Agentopsy MCP server refusing to start: missing AGENTOPSY_CLOUD_CONSENT.\n"
            "If this server will be reached by a cloud MCP client (Claude Desktop,\n"
            "Continue, Cline, ...), set AGENTOPSY_CLOUD_CONSENT=<client-name>; that\n"
            "value is recorded in the audit log of every case touched during the\n"
            "session. RULE 2 + security gate 7 (cloud OFF by default).\n"
        )
        sys.exit(2)
    return consent


async def _serve(consent_ref: str, shutdown_event: asyncio.Event) -> None:
    """Run the MCP server, racing ``server.run`` against an external shutdown
    event so SIGTERM / SIGINT can force-close the stdio streams.

    Round-1 panel (F2): without an explicit shutdown path, ``stdio_server``
    blocks on stdin reads forever — Claude Desktop's SIGTERM on exit left
    zombie server processes. Closing ``read_stream`` from the signal handler
    unblocks the inner read and lets ``server.run`` unwind cleanly, which
    triggers the audit ``mcp_session_close`` entry through the ``finally``.
    """
    server, lifecycle = build_server(consent_ref=consent_ref)
    async with stdio_server() as (read_stream, write_stream):
        await lifecycle.on_session_start()

        # F3 — declare the capabilities we actually use:
        # - tools_changed: we emit notifications/tools/list_changed when the
        #   active case changes (allowlist shifts with os_profile).
        # - resources_changed: not used (artifact://* URIs come and go with
        #   each run; we don't push notifications for them).
        # Spec-compliant clients only honour notifications/handlers for
        # capabilities advertised here; without this our notifications were
        # being dropped silently.
        init_options = server.create_initialization_options(
            NotificationOptions(tools_changed=True, resources_changed=False),
        )
        serve_task = asyncio.create_task(
            server.run(read_stream, write_stream, init_options)
        )
        wait_task = asyncio.create_task(shutdown_event.wait())

        try:
            done, pending = await asyncio.wait(
                {serve_task, wait_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if wait_task in done:
                # Force the inner stdin read to unblock by closing the
                # read stream. Then cancel server.run and drain.
                try:
                    await read_stream.aclose()
                except (AttributeError, RuntimeError):
                    pass
                serve_task.cancel()
                try:
                    await serve_task
                except (asyncio.CancelledError, Exception):
                    pass
            else:
                wait_task.cancel()
                try:
                    await wait_task
                except asyncio.CancelledError:
                    pass
        finally:
            await lifecycle.on_session_end()


def main() -> None:
    consent = _consent_or_die()

    loop = asyncio.new_event_loop()
    try:
        shutdown_event = asyncio.Event()
        main_task = loop.create_task(_serve(consent, shutdown_event))

        # The signal handler MUST close stdin at the fd level — that's the
        # thing that unblocks ``stdio_server``'s inner ``async for line in
        # stdin`` read. Setting an asyncio.Event isn't enough: the SDK runs
        # the reader inside an anyio task group and the OS read isn't a
        # cancellation point. (Round-2 panel finding: closing the SDK's
        # memory stream only — what F2-round-1 did — leaves the real syscall
        # stuck and the process zombie.)
        def _stop(*_args) -> None:
            sys.stderr.write("[agentopsy.mcp] signal received, shutting down...\n")
            sys.stderr.flush()
            loop.call_soon_threadsafe(shutdown_event.set)
            try:
                os.close(sys.stdin.fileno())  # unblock stdio_server's reader
            except OSError:
                pass
            # Belt-and-braces: if the cooperative path can't unwind within
            # the deadline, the watchdog forces exit so Claude Desktop's
            # SIGTERM-on-quit doesn't leave a zombie.
            loop.call_later(_FORCE_EXIT_DEADLINE_S, _force_exit)

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, _stop)
            except (NotImplementedError, RuntimeError):
                # Windows / non-default loop — fall back to KeyboardInterrupt.
                pass

        try:
            loop.run_until_complete(main_task)
        except (KeyboardInterrupt, asyncio.CancelledError):
            shutdown_event.set()
            try:
                loop.run_until_complete(main_task)
            except (asyncio.CancelledError, Exception):
                pass
    finally:
        loop.close()


def _force_exit() -> None:
    """Last-resort exit when the cooperative shutdown can't unwind within
    ``_FORCE_EXIT_DEADLINE_S``. Used by the signal handler in ``main`` so a
    Claude Desktop quit cannot leave the MCP server process running. We log to
    stderr (no audit — that audit slot is the lifecycle's on_session_end's
    job, and it ran before we get here unless the loop itself is stuck).
    """
    sys.stderr.write(
        "Agentopsy MCP server: forced exit after shutdown timeout. The "
        "stdio_server stdin reader did not unwind cooperatively.\n"
    )
    os._exit(0)


if __name__ == "__main__":
    main()
