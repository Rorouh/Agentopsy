"""One forensic agent, parametrized by OS profile (not two separate agents).

The agent loop is configured at runtime by a single behavioral file
``agentes/agent.md`` (see ``agentes/README.md``). Agentopsy builds one
``AgentPackage`` per OS profile that shares that text and differs only in the
tool allowlist (the catalog filtered by profile).
"""

from agentopsy.agent.agent import ForensicAgent
from agentopsy.agent.loader import (
    AgentPackageError,
    build_package,
    load_packages,
    read_instructions,
)
from agentopsy.agent.package import (
    AgentPackage,
    AgentPackageModel,
    AgentPackagePolicy,
    AgentPackagePrompts,
    RedactionPattern,
)
from agentopsy.agent.registry import AgentRegistry, AgentRegistryError, agent_registry

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
    "build_package",
    "load_packages",
    "read_instructions",
]
