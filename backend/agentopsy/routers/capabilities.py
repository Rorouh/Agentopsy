from fastapi import APIRouter, Depends

from agentopsy.capabilities import snapshot
from agentopsy.security import require_token

router = APIRouter()


@router.get("/api/capabilities", dependencies=[Depends(require_token)])
def capabilities() -> dict:
    return snapshot()
