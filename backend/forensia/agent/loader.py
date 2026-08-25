"""Carga del agente desde el **único** archivo de comportamiento ``agentes/agent.md``.

Desde 2026-07-28 el contrato de paquetes declarativo (``agent.yaml`` + ``prompts/`` +
``policy/`` + ``objetivos`` + ``knowledge/``) fue retirado. El agente se configura con
un solo documento —``agent.md``, común a todos los proveedores de IA— y todo lo que
antes se declaraba por paquete se deriva ahora en código, sin defaults silenciosos
(CLAUDE.md RULE 2):

- **La allowlist de herramientas** = el catálogo (`forensia.toolkit.catalog`) **filtrado
  por el ``os_profile``**. No hay una lista escrita a mano que pueda quedar desalineada
  con el catálogo: un tool solo es invocable si el catálogo lo declara para ese perfil.
- **Los patrones de redacción de egress** = un conjunto por defecto en código
  (``DEFAULT_REDACTION_PATTERNS``): secretos que nunca son forensicamente útiles y
  siempre peligrosos de filtrar (claves privadas, tokens). No se redacta nada que
  pudiera cegar al agente (ids del plano de control, correos, nombres de fichero).
- **El modelo/iteraciones** = constantes por defecto (el ejecutor real lo elige el
  operador en runtime; ``name`` solo orienta a Ollama).

El loader nunca ejecuta nada: lee texto y devuelve dataclasses inmutables.
"""

from __future__ import annotations

from pathlib import Path

from forensia.i18n import Mensaje, current_lang
from forensia.agent.package import (
    AgentPackage,
    AgentPackageModel,
    AgentPackagePolicy,
    AgentPackagePrompts,
    RedactionPattern,
)
from forensia.toolkit.catalog import for_profile as tools_for_profile

#: El único archivo que Agentopsy carga de ``agentes/``.
#: El fichero de comportamiento POR IDIOMA. Es el mismo método escrito dos
#: veces, no una traducción automática: el agente redacta el `title` y el
#: `summary` de cada hallazgo, y ese texto viaja tal cual al informe, así que
#: tiene que estar escrito con el cuidado de un texto de producto.
#:
#: No hay respaldo al otro idioma (RULE 2): si falta el fichero del idioma
#: elegido, el registro queda vacío y `/api/agent/query` responde 503. Cargar el
#: castellano cuando se pidió el inglés dejaría al perito con un agente que
#: escribe en un idioma que no eligió, y ese texto acaba en el informe.
AGENT_MD_FILENAMES: dict[str, str] = {
    "es": "agent.md",
    "en": "agent.en.md",
}

#: El del castellano, que es el canónico del proyecto. Se conserva como nombre
#: propio porque `agentes/README.md` y los tests lo citan.
AGENT_MD_FILENAME = AGENT_MD_FILENAMES["es"]


def agent_md_filename(lang: str | None = None) -> str:
    """El nombre del fichero de comportamiento del idioma en curso."""
    return AGENT_MD_FILENAMES.get(lang or current_lang(), AGENT_MD_FILENAME)

#: Perfiles de SO para los que Agentopsy construye un agente. El texto de ``agent.md``
#: es común; lo que cambia por perfil es la allowlist de herramientas.
VALID_OS_PROFILES = ("unix", "windows")

# --- defaults derivados (antes venían del manifiesto del paquete) -----------

#: Modelo recomendado para el ejecutor ``ollama`` (el 100% local). Los ejecutores CLI
#: usan el modelo de la suscripción del operador; este ``name`` solo orienta a Ollama
#: cuando el operador no ha elegido uno (sigue siendo explícito, no un default oculto).
DEFAULT_MODEL_NAME = "llama3.1:8b"
DEFAULT_TEMPERATURE = 0.2
#: Tope de TURNOS DEL MODELO por corrida (safety anti-bucle). Cuenta turnos, no
#: herramientas: un ``tool_batch`` lanza un lote entero en un turno.
DEFAULT_MAX_ITERATIONS = 30

#: Redacción de egress por defecto (solo se aplica cuando el ejecutor es de nube).
#: Deliberadamente conservadora: tapa secretos que jamás sirven al análisis y siempre
#: son peligrosos de filtrar, y NADA que pueda cegar al agente. Un GUID/credencial que
#: venga DENTRO de la evidencia y sea forensicamente relevante se ve en el artefacto en
#: disco; al modelo en la nube no hace falta mandárselo en claro.
DEFAULT_REDACTION_PATTERNS: tuple[RedactionPattern, ...] = (
    RedactionPattern(
        name="private_key_block",
        regex=r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
        r"[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        replacement="<CLAVE_PRIVADA_REDACTADA>",
        apply_in=("strict",),
    ),
    RedactionPattern(
        name="aws_secret_access_key",
        regex=r"(?i)aws_secret_access_key\s*[=:]\s*\S+",
        replacement="aws_secret_access_key=<REDACTADO>",
        apply_in=("strict",),
    ),
    RedactionPattern(
        name="bearer_token",
        regex=r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}",
        replacement="Bearer <REDACTADO>",
        apply_in=("strict",),
    ),
)


class AgentPackageError(ValueError):
    """Falla al leer ``agent.md``. Mensaje siempre orientado a quien lo edita
    (qué fichero falta, qué se esperaba)."""


def default_allowed_tools(os_profile: str) -> tuple[str, ...]:
    """Allowlist del perfil = catálogo filtrado por ``os_profile``.

    Es la fuente única: un tool es invocable por el agente si y solo si el catálogo lo
    declara para ese perfil. Imposible que quede desalineada con una lista a mano.
    """
    if os_profile not in VALID_OS_PROFILES:
        raise AgentPackageError(
            Mensaje(
                "agent.badOsProfile",
                profile=repr(os_profile),
                valid=list(VALID_OS_PROFILES),
            )
        )
    return tuple(t.id for t in tools_for_profile(os_profile))


def read_instructions(agents_dir: Path) -> str:
    """Lee el texto de ``agent.md`` bajo ``agents_dir``. Falla en seco si no existe o
    está vacío — un agente sin instrucciones no es un estado válido (RULE 2)."""
    agents_dir = Path(agents_dir).resolve()
    nombre = agent_md_filename()
    md_path = agents_dir / nombre
    if not md_path.is_file():
        raise AgentPackageError(
            Mensaje(
                "agent.mdMissing",
                path=md_path,
                filename=nombre,
                dir=agents_dir,
            )
        )
    text = md_path.read_text(encoding="utf-8").strip()
    if not text:
        raise AgentPackageError(Mensaje("agent.mdEmpty", path=md_path))
    return text


def build_package(
    os_profile: str,
    instructions: str,
    *,
    model_name: str = DEFAULT_MODEL_NAME,
    temperature: float = DEFAULT_TEMPERATURE,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    redaction_patterns: tuple[RedactionPattern, ...] = DEFAULT_REDACTION_PATTERNS,
    allowed_tools: tuple[str, ...] | None = None,
    agents_dir: Path | None = None,
) -> AgentPackage:
    """Construye el ``AgentPackage`` de un perfil a partir del texto de ``agent.md``.

    Las instrucciones viajan como ``prompts.system``; ``identity``/``playbook`` quedan
    vacíos (todo el comportamiento vive en un solo documento). La allowlist se deriva
    del catálogo por perfil (``allowed_tools`` la sobreescribe — útil en tests).
    ``knowledge``/``case_knowledge``/``objetivos`` quedan vacíos: el grafo de
    conocimiento POR CASO lo escribe el agente en runtime, no el paquete.
    """
    if not isinstance(instructions, str) or not instructions.strip():
        raise AgentPackageError(Mensaje("agent.instructionsEmpty"))
    allowed = tuple(allowed_tools) if allowed_tools is not None else default_allowed_tools(os_profile)
    if not allowed:
        raise AgentPackageError(
            Mensaje("agent.noToolsForProfile", profile=repr(os_profile))
        )
    return AgentPackage(
        id=f"forensia-{os_profile}",
        name=f"Agentopsy, {os_profile}",
        version="1.0.0",
        os_profile=os_profile,
        authors=(),
        path=Path(agents_dir).resolve() if agents_dir is not None else Path.cwd(),
        model=AgentPackageModel(
            name=model_name,
            temperature=float(temperature),
            max_iterations=int(max_iterations),
        ),
        prompts=AgentPackagePrompts(system=instructions.strip(), identity="", playbook=""),
        policy=AgentPackagePolicy(
            allowed_tools=allowed,
            redaction_patterns=tuple(redaction_patterns),
        ),
    )


def load_packages(agents_dir: Path) -> dict[str, AgentPackage]:
    """Lee ``agent.md`` una vez y construye el agente de CADA perfil que comparte ese
    texto. Devuelve ``{os_profile: AgentPackage}``. Propaga ``AgentPackageError`` si
    falta el archivo (el llamador decide si degrada o falla)."""
    instructions = read_instructions(agents_dir)
    return {
        profile: build_package(profile, instructions, agents_dir=agents_dir)
        for profile in VALID_OS_PROFILES
    }
