"""Shared contract for references to files produced by an ArtifactRun."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class ArtifactRef(BaseModel):
    """A same-case derived input that ArtifactStore must resolve and re-hash."""

    model_config = ConfigDict(extra="forbid", strict=True)

    run_id: str = Field(min_length=1)
    relpath: str = Field(min_length=1)
    # Omission is valid; explicit None is rejected by the annotated field type.
    sha256: str = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")  # type: ignore[assignment]
    size: int = Field(default=None, ge=0)  # type: ignore[assignment]

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: Any, handler: Any
    ) -> dict[str, Any]:
        schema = handler(core_schema)
        for name in ("sha256", "size"):
            schema.get("properties", {}).get(name, {}).pop("default", None)
        return schema


def validate_artifact_ref(value: Any) -> dict[str, Any]:
    """Validate and normalize an ArtifactRef without trusting its custody hints."""
    try:
        ref = ArtifactRef.model_validate(value)
    except ValidationError as exc:
        raise ValueError(f"invalid ArtifactRef: {exc}") from exc
    return ref.model_dump(exclude_none=True)


def is_artifact_ref(value: Any) -> bool:
    try:
        validate_artifact_ref(value)
    except ValueError:
        return False
    return True


def artifact_ref_json_schema() -> dict[str, Any]:
    """Return an independent JSON Schema copy for non-Pydantic tool surfaces."""
    schema = ArtifactRef.model_json_schema()
    schema.pop("title", None)
    return deepcopy(schema)


__all__ = [
    "ArtifactRef",
    "artifact_ref_json_schema",
    "is_artifact_ref",
    "validate_artifact_ref",
]
