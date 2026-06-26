"""Chat / agent-query HTTP surface.

Thin adapter (CLAUDE.md RULE 3) over ``forensia.agent.registry``. While the
reasoning loop is still a skeleton (``ForensicAgent.run`` raises), this router
performs the real wiring so the UI can prove end-to-end that the agent package
is loaded:

1. Validates inputs.
2. Pulls the ``AgentPackage`` from the registry by ``os_profile`` (RULE 2: no
   fallback agent — if none is loaded for that profile, returns 503).
3. Builds a deterministic, structured response describing the loaded agent
   (id, version, allowed tools) plus an echo of the user's prompt.

When the real loop lands, only the body of ``query`` changes; the contract
(request/response shape) stays the same.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from forensia.agent.registry import agent_registry
from forensia.security import require_token

router = APIRouter()

_VALID_OS_PROFILES = frozenset({"unix", "windows"})


class QueryRequest(BaseModel):
    os_profile: str = "unix"
    evidence_id: str | None = None
    prompt: str


@router.post("/api/agent/query", dependencies=[Depends(require_token)])
def query(req: QueryRequest) -> dict:
    prompt = (req.prompt or "").strip()
    if not prompt:
        raise HTTPException(status_code=422, detail="prompt is empty")

    if req.os_profile not in _VALID_OS_PROFILES:
        raise HTTPException(
            status_code=422,
            detail=f"os_profile must be one of {sorted(_VALID_OS_PROFILES)}, "
                   f"got {req.os_profile!r}",
        )

    try:
        pkg = agent_registry.get_for_profile(req.os_profile)
    except KeyError as exc:
        # 503: the dependency is missing, not the request. The UI maps this to
        # "no hay agente cargado para este perfil" without inventing a default.
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    # The reasoning loop is not implemented yet (see CLAUDE.md "Status"). We
    # return a deterministic, structured envelope that proves the package is
    # loaded and lists what the agent WOULD use. The renderer treats this as a
    # diagnostic message until the real loop lands.
    reply = _skeleton_reply(pkg.name, prompt, pkg.policy.allowed_tools)

    return {
        "status": "skeleton",
        "reply": reply,
        "evidence_id": req.evidence_id,
        "os_profile": req.os_profile,
        "agent": pkg.summary(),
    }


@router.get("/api/agents", dependencies=[Depends(require_token)])
def list_agents() -> dict:
    """Lista los paquetes cargados desde ``agentes/`` y la raíz utilizada.

    La UI lo consume en Settings ("Agentes cargados") y en el header del chat
    para mostrar qué agente está activo para el perfil del caso.
    """
    return {
        "root": str(agent_registry.root),
        "agents": [pkg.summary() for pkg in agent_registry.list()],
    }


def _skeleton_reply(agent_name: str, prompt: str, allowed_tools: tuple[str, ...]) -> str:
    tools_md = "\n".join(f"- `{t}`" for t in allowed_tools)
    return (
        f"**{agent_name}** está cargado y conectado, pero el loop de razonamiento "
        "aún no está implementado en este esqueleto.\n\n"
        f"He recibido tu mensaje:\n\n> {prompt}\n\n"
        "Cuando el loop esté disponible, este agente podrá invocar las siguientes "
        "herramientas del maletín (allowlist declarada en su `policy/tools.yaml`):\n\n"
        f"{tools_md}"
    )
