"""One forensic agent, parametrized by OS profile (not two separate agents).

The agent loop is configured at runtime by an ``AgentPackage`` loaded from
``agentes/<id>/`` (see ``agentes/README.md`` and ``docs/AGENTS.md``).
"""

from forensia.agent.agent import ForensicAgent
from forensia.agent.loader import AgentPackageError, load_package
from forensia.agent.package import (
    AgentPackage,
    AgentPackageModel,
    AgentPackagePolicy,
    AgentPackagePrompts,
    RedactionPattern,
)
from forensia.agent.registry import AgentRegistry, AgentRegistryError, agent_registry

__all__ = [
    "ForensicAgent",
    "AgentPackage",
    "AgentPackageModel",
    "AgentPackagePolicy",
    "AgentPackagePrompts",
    "RedactionPattern",
    "AgentPackageError",
    "AgentRegistry",
    "AgentRegistryError",
    "agent_registry",
    "load_package",
]
