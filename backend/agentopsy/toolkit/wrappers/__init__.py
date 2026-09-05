"""Per-tool wrappers.

Each tool in `catalog.py` references a wrapper module that exports:
- `ALLOWED_FLAGS: frozenset[str]` — CLI flags the wrapper is allowed to emit.
- `build_argv(params: dict) -> list[str]` — validated argv from typed params.
- `parse(stdout: str) -> dict` — structured result for the agent / report.
- Optionally `host_mounts(params) -> tuple[dict, dict]` for container-delivered tools.

The LLM never sees the flags directly — it picks a tool id + typed params and the
wrapper composes the argv (THREAT_MODEL gate 6).
"""
