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
    # El EJECUTOR no se declara aquí: lo selecciona el operador en runtime
    # (contrato v1.2, RULE 2). `name` es el modelo recomendado para el ejecutor
    # `ollama`; los ejecutores CLI usan el modelo de la suscripción del usuario.
    name: str             # ej. "llama3.1:8b"
    temperature: float
    max_iterations: int   # tope del loop tool-use (safety)


@dataclass(frozen=True)
class AgentPackagePrompts:
    system: str           # contenido leído del fichero
    identity: str
    playbook: str


@dataclass(frozen=True)
class KnowledgeDoc:
    """Un documento de referencia que el agente consulta BAJO DEMANDA (mapa de
    memoria híbrido). El contenido se lee UNA vez al cargar el paquete —el loader
    confina el path bajo ``agentes/<id>/`` (SECURITY INVARIANT 6)— y en runtime la
    tool ``consultar_conocimiento`` lo sirve por ``id`` desde memoria, sin I/O ni
    riesgo de traversal. ``description`` es la línea del índice ("cuándo consultarlo")
    que viaja SIEMPRE en el system prompt; ``content`` solo viaja cuando se pide."""

    id: str
    title: str
    description: str
    content: str


@dataclass(frozen=True)
class RedactionPattern:
    name: str
    regex: str
    replacement: str
    # Modes in which this pattern is applied. Defaults to ``("strict",)`` —
    # i.e. only the strict mode redacts it. Patterns that should also apply
    # in relaxed mode (e.g. credentials, keys, JWTs — never forensically
    # useful, always dangerous to leak) must include ``"relaxed"``. The mode
    # ``"off"`` never applies any pattern by construction.
    apply_in: tuple[str, ...] = ("strict",)


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
    # Documentos de referencia del mapa de memoria híbrido (opcional). Un paquete
    # sin `knowledge:` en su manifiesto los tiene vacíos y el agente no ofrece
    # `consultar_conocimiento` (RULE 2: sin índice no hay tool que prometa nada).
    knowledge: tuple[KnowledgeDoc, ...] = ()

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
                "name": self.model.name,
                "temperature": self.model.temperature,
                "max_iterations": self.model.max_iterations,
            },
            "allowed_tools": list(self.policy.allowed_tools),
            "knowledge": [
                {"id": d.id, "title": d.title, "description": d.description}
                for d in self.knowledge
            ],
            "path": str(self.path),
        }
