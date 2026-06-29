"""FORENSIA's MCP server — `mcp-toolkit` (S1).

This package implements the first MCP server in the inventory: a single
in-process / standalone server that exposes the curated maletín
(``forensia.toolkit.catalog.BY_ID``) as MCP tools, plus the Jira-pattern
session tools (``list_cases``, ``select_case``, ``list_evidence``,
``select_evidence``).

Design and decisions in ``docs/MCP_TOOLKIT_PLAN.md`` and
``docs/MCP_INVENTORY.md``. Red lines L1-L6 enforced here.
"""

from __future__ import annotations

__all__: list[str] = []
