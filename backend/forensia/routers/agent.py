from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from forensia.security import require_token

router = APIRouter()


class QueryRequest(BaseModel):
    os_profile: str
    evidence_id: str
    prompt: str


@router.post("/api/agent/query", dependencies=[Depends(require_token)])
def query(req: QueryRequest) -> dict:
    raise HTTPException(status_code=501, detail="agent not implemented yet (skeleton)")
