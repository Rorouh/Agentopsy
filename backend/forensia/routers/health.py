from fastapi import APIRouter

from forensia._version import __version__

router = APIRouter()


@router.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "forensia-api", "version": __version__}
