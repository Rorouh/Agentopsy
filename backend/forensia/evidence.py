"""Evidence ingestion stub.

Real implementation: read-only block-level handle + SHA-256 baseline hash.
This stub is enough to boot the sidecar while the full implementation is pending.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass
class EvidenceHandle:
    evidence_id: str
    path: Path
    sha256: str
    read_only_block_level: bool = False


class EvidenceManager:
    def __init__(self) -> None:
        self._handles: dict[str, EvidenceHandle] = {}

    def register(self, path: str) -> EvidenceHandle:
        p = Path(path).resolve()
        if not p.exists():
            raise FileNotFoundError(f"evidence not found: {p}")
        sha256 = hashlib.sha256(p.read_bytes()).hexdigest()
        handle = EvidenceHandle(
            evidence_id=str(uuid.uuid4()),
            path=p,
            sha256=sha256,
            read_only_block_level=False,  # stub: real impl uses O_RDONLY block device
        )
        self._handles[handle.evidence_id] = handle
        return handle

    def get(self, evidence_id: str) -> EvidenceHandle:
        if evidence_id not in self._handles:
            raise KeyError(f"unknown evidence_id: {evidence_id}")
        return self._handles[evidence_id]


evidence_manager = EvidenceManager()
