"""Tipos del paquete de agente entrenado (los que vienen de ``agentes/<id>/``).

Un ``AgentPackage`` es un manifiesto VALIDADO en memoria. Los entrenadores entregan
una carpeta declarativa (ver ``agentes/README.md``); el loader la convierte en estas
dataclasses inmutables y la registry las indexa por ``os_profile`` (uno por perfil,
RULE 2: nada de defaults silenciosos).

Estos tipos NO ejecutan herramientas ni hablan con el modelo: son sólo datos. El
loop (``ForensicAgent``) los consume.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AgentPackageModel:
    backend: str          # "local" | "cloud"
    name: str             # ej. "llama3.1:8b" (Ollama) o "claude-opus-4-7" (cloud)
    temperature: float
    max_iterations: int   # tope del loop tool-use (safety)


@dataclass(frozen=True)
class AgentPackagePrompts:
    system: str           # contenido leído del fichero
    identity: str
    playbook: str


@dataclass(frozen=True)
class RedactionPattern:
    name: str
    regex: str
    replacement: str


@dataclass(frozen=True)
class AgentPackagePolicy:
    allowed_tools: tuple[str, ...]
    redaction_patterns: tuple[RedactionPattern, ...]


@dataclass(frozen=True)
class AgentPackage:
    id: str
    name: str
    version: str
    os_profile: str
    authors: tuple[str, ...]
    # Path absoluto del directorio del agente en disco. Útil para auditar y para
    # mostrarlo en la UI (Settings → "Cargado desde …").
    path: Path
    model: AgentPackageModel
    prompts: AgentPackagePrompts
    policy: AgentPackagePolicy

    def summary(self) -> dict:
        """Vista JSON-friendly para ``/api/agents`` y ``/api/capabilities``. No
        incluye los prompts completos: la UI los pide aparte si los necesita."""
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "os_profile": self.os_profile,
            "authors": list(self.authors),
            "model": {
                "backend": self.model.backend,
                "name": self.model.name,
                "temperature": self.model.temperature,
                "max_iterations": self.model.max_iterations,
            },
            "allowed_tools": list(self.policy.allowed_tools),
            "path": str(self.path),
        }
