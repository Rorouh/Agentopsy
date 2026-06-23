"""Evidence endpoints are deliberately minimal: sensitive evidence flows move to IPC,
not an open HTTP surface (THREAT_MODEL section A / gate 4). This skeleton exposes only a
token-gated registration that returns the baseline hash.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from forensia.evidence import evidence_manager
from forensia.security import require_token

router = APIRouter()


class RegisterRequest(BaseModel):
    path: str


@router.post("/api/evidence/register", dependencies=[Depends(require_token)])
def register(req: RegisterRequest) -> dict:
    handle = evidence_manager.register(req.path)
    return {
        "evidence_id": handle.evidence_id,
        "sha256": handle.sha256,
        "read_only_block_level": handle.read_only_block_level,
    }
