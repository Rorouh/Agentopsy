from fastapi import APIRouter

from agentopsy._version import __version__

router = APIRouter()


@router.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "agentopsy-api", "version": __version__}
