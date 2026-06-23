from fastapi import APIRouter, Depends

from forensia.capabilities import snapshot
from forensia.security import require_token

router = APIRouter()


@router.get("/api/capabilities", dependencies=[Depends(require_token)])
def capabilities() -> dict:
    return snapshot()
