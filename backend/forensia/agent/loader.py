"""Lectura + validación de un directorio ``agentes/<id>/``.

Defensivo por diseño:
- Schema mínimo obligatorio (id, version, os_profile, model, prompts, policy).
- Cualquier path declarado (prompts/*, policy/*) debe (a) ser relativo y (b)
  resolverse DENTRO del directorio del agente — sin escapes con `..`/absolutos.
- ``policy.tools.allowed`` referencia sólo ``tool_id``s del catálogo, **y** los
  ids referenciados deben declarar el ``os_profile`` del agente. Cualquier id
  fuera del catálogo o no aplicable al perfil hace fallar la carga (CLAUDE.md
  RULE 2 — no defaults silenciosos).

El loader nunca ejecuta nada del paquete: sólo lee texto y devuelve dataclasses.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from forensia.agent.package import (
    AgentPackage,
    AgentPackageModel,
    AgentPackagePolicy,
    AgentPackagePrompts,
    CaseKnowledgeNode,
    KnowledgeDoc,
    RedactionPattern,
)
from forensia.knowledge import DOC_ID_PATTERN, MAX_NODES_PER_CASE
from forensia.toolkit.catalog import BY_ID as TOOL_BY_ID

_VALID_OS_PROFILES = frozenset({"unix", "windows"})
# El núcleo declarado en el manifiesto se valida contra el MISMO charset que el
# store impone en runtime: un id que el store rechazaría no debe poder declararse.
_CASE_NODE_ID_RE = re.compile(DOC_ID_PATTERN)

# Un doc de knowledge se sirve ENTERO como resultado de la tool consultar_conocimiento,
# que el loop acota a ~8000 chars (agent._MAX_TOOL_RESULT_CHARS). Un doc mayor se
# descartaría en runtime dejando un puntero vacío/engañoso, así que se RECHAZA en carga
# (fail-loud en la frontera correcta, RULE 2) con margen para el envoltorio JSON.
_MAX_KNOWLEDGE_DOC_CHARS = 7000
_ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")  # kebab-case
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


class AgentPackageError(ValueError):
    """Falla de validación al cargar un paquete. Mensaje siempre orientado al
    entrenador (qué fichero, qué falta, qué se esperaba)."""


def load_package(agent_dir: Path) -> AgentPackage:
    """Carga + valida un único ``agentes/<id>/`` y devuelve el ``AgentPackage``.

    Lanza ``AgentPackageError`` con mensaje accionable si algo falla. NO captura
    excepciones del sistema de ficheros: las propaga (es responsabilidad del
    llamador decidir si "este directorio se ignora" o "el arranque falla").
    """
    agent_dir = agent_dir.resolve()
    if not agent_dir.is_dir():
        raise AgentPackageError(f"agent path is not a directory: {agent_dir}")

    manifest_path = agent_dir / "agent.yaml"
    if not manifest_path.is_file():
        raise AgentPackageError(
            f"agent.yaml not found at {manifest_path}. "
            "Every agent package must declare a manifest (see agentes/README.md)."
        )

    raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise AgentPackageError(
            f"{manifest_path}: top-level YAML must be a mapping, got {type(raw).__name__}"
        )

    pkg_id = _require_str(raw, "id", manifest_path)
    if not _ID_RE.match(pkg_id):
        raise AgentPackageError(
            f"{manifest_path}: id={pkg_id!r} must be kebab-case ([a-z0-9-])"
        )

    name = _require_str(raw, "name", manifest_path)
    version = _require_str(raw, "version", manifest_path)
    if not _SEMVER_RE.match(version):
        raise AgentPackageError(
            f"{manifest_path}: version={version!r} is not semver (e.g. 0.1.0)"
        )

    os_profile = _require_str(raw, "os_profile", manifest_path)
    if os_profile not in _VALID_OS_PROFILES:
        raise AgentPackageError(
            f"{manifest_path}: os_profile must be one of "
            f"{sorted(_VALID_OS_PROFILES)}, got {os_profile!r}"
        )

    authors = _coerce_authors(raw.get("authors"), manifest_path)

    model = _parse_model(raw.get("model"), manifest_path)
    prompts = _parse_prompts(raw.get("prompts"), agent_dir, manifest_path)
    policy = _parse_policy(raw.get("policy"), agent_dir, os_profile, manifest_path)
    knowledge = _parse_knowledge(raw.get("knowledge"), agent_dir, manifest_path)
    case_knowledge = _parse_case_knowledge(raw.get("case_knowledge"), manifest_path)

    return AgentPackage(
        id=pkg_id,
        name=name,
        version=version,
        os_profile=os_profile,
        authors=authors,
        path=agent_dir,
        model=model,
        prompts=prompts,
        policy=policy,
        knowledge=knowledge,
        case_knowledge=case_knowledge,
    )


# ---- helpers ---------------------------------------------------------------


def _require_str(data: dict, key: str, source: Path) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AgentPackageError(
            f"{source}: required string field {key!r} is missing or empty"
        )
    return value.strip()


def _coerce_authors(value: Any, source: Path) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(a, str) for a in value):
        raise AgentPackageError(
            f"{source}: authors must be a list of strings, got {type(value).__name__}"
        )
    return tuple(a.strip() for a in value if a.strip())


def _parse_model(value: Any, source: Path) -> AgentPackageModel:
    if not isinstance(value, dict):
        raise AgentPackageError(
            f"{source}: 'model' must be a mapping with name/temperature/max_iterations"
        )
    if "backend" in value:
        raise AgentPackageError(
            f"{source}: 'model.backend' fue eliminado del contrato v1.2 — el "
            "ejecutor (Claude Code / Codex CLI / Gemini CLI / Ollama) lo "
            "selecciona el operador en runtime (RULE 2), el paquete no puede "
            "fijarlo. Borra la clave del manifiesto."
        )
    name = _require_str(value, "name", source)
    temperature = value.get("temperature", 0.0)
    if not isinstance(temperature, (int, float)) or not 0.0 <= float(temperature) <= 2.0:
        raise AgentPackageError(
            f"{source}: model.temperature must be a number in [0.0, 2.0], got {temperature!r}"
        )
    max_iterations = value.get("max_iterations")
    if not isinstance(max_iterations, int) or max_iterations < 1 or max_iterations > 100:
        raise AgentPackageError(
            f"{source}: model.max_iterations must be an int in [1, 100], got {max_iterations!r}"
        )
    return AgentPackageModel(
        name=name,
        temperature=float(temperature),
        max_iterations=max_iterations,
    )


def _parse_prompts(value: Any, agent_dir: Path, source: Path) -> AgentPackagePrompts:
    if not isinstance(value, dict):
        raise AgentPackageError(
            f"{source}: 'prompts' must be a mapping with system/identity/playbook"
        )
    system = _read_relative_file(value.get("system"), agent_dir, "prompts.system", source)
    identity = _read_relative_file(value.get("identity"), agent_dir, "prompts.identity", source)
    playbook = _read_relative_file(value.get("playbook"), agent_dir, "prompts.playbook", source)
    return AgentPackagePrompts(system=system, identity=identity, playbook=playbook)


def _parse_knowledge(
    value: Any, agent_dir: Path, source: Path
) -> tuple[KnowledgeDoc, ...]:
    """Parse the optional ``knowledge:`` list (mapa de memoria híbrido).

    Each entry is a mapping ``{id, title, description, path}``. ``path`` is read and
    confined under the agent dir at load time (SECURITY INVARIANT 6), so the runtime
    tool serves content from memory by id with no further I/O. Absent → no docs."""
    if value is None:
        return ()
    if not isinstance(value, list):
        raise AgentPackageError(
            f"{source}: 'knowledge' must be a list of {{id, title, description, path}} "
            f"mappings, got {type(value).__name__}"
        )
    docs: list[KnowledgeDoc] = []
    seen: set[str] = set()
    for i, entry in enumerate(value):
        if not isinstance(entry, dict):
            raise AgentPackageError(
                f"{source}: knowledge[{i}] must be a mapping, got {type(entry).__name__}"
            )
        doc_id = _require_str(entry, "id", source)
        if not _ID_RE.match(doc_id):
            raise AgentPackageError(
                f"{source}: knowledge[{i}].id={doc_id!r} must be kebab-case ([a-z0-9-])"
            )
        if doc_id in seen:
            raise AgentPackageError(
                f"{source}: duplicate knowledge id {doc_id!r} — ids must be unique"
            )
        seen.add(doc_id)
        title = _require_str(entry, "title", source)
        description = _require_str(entry, "description", source)
        content = _read_relative_file(
            entry.get("path"), agent_dir, f"knowledge[{doc_id}].path", source
        )
        if len(content) > _MAX_KNOWLEDGE_DOC_CHARS:
            raise AgentPackageError(
                f"{source}: knowledge[{doc_id}] tiene {len(content)} chars; el máximo es "
                f"{_MAX_KNOWLEDGE_DOC_CHARS} para que quepa entero en un resultado de "
                "tool (consultar_conocimiento no puede servir un doc que no cabe en "
                "contexto). Divídelo en documentos más enfocados."
            )
        docs.append(
            KnowledgeDoc(id=doc_id, title=title, description=description, content=content)
        )
    return tuple(docs)


def _parse_case_knowledge(value: Any, source: Path) -> tuple[CaseKnowledgeNode, ...]:
    """Parse the optional ``case_knowledge:`` list (núcleo del grafo POR CASO).

    Entradas ``{id, description}``, SIN ``path``: estos nodos no traen contenido —
    lo escribe el agente en runtime con ``anotar_conocimiento``. Los ids se validan
    contra el MISMO charset cerrado que impone el store, para que un núcleo mal
    declarado falle al ARRANCAR el api y no en mitad de un análisis (RULE 2).
    Ausente → grafo enteramente libre dentro del tope del store."""
    if value is None:
        return ()
    if not isinstance(value, list):
        raise AgentPackageError(
            f"{source}: 'case_knowledge' must be a list of {{id, description}} "
            f"mappings, got {type(value).__name__}"
        )
    if len(value) > MAX_NODES_PER_CASE:
        raise AgentPackageError(
            f"{source}: 'case_knowledge' declara {len(value)} nodos; el store admite "
            f"{MAX_NODES_PER_CASE} por caso y el núcleo no puede agotarlo entero."
        )
    nodes: list[CaseKnowledgeNode] = []
    seen: set[str] = set()
    for i, entry in enumerate(value):
        if not isinstance(entry, dict):
            raise AgentPackageError(
                f"{source}: case_knowledge[{i}] must be a mapping, "
                f"got {type(entry).__name__}"
            )
        node_id = _require_str(entry, "id", source)
        if not _CASE_NODE_ID_RE.match(node_id):
            raise AgentPackageError(
                f"{source}: case_knowledge[{i}].id={node_id!r} no cumple "
                f"{DOC_ID_PATTERN} — es el mismo charset cerrado que el store impone "
                "en runtime (minúsculas, dígitos y guiones)."
            )
        if node_id in seen:
            raise AgentPackageError(
                f"{source}: duplicate case_knowledge id {node_id!r} — ids must be unique"
            )
        seen.add(node_id)
        description = _require_str(entry, "description", source)
        nodes.append(CaseKnowledgeNode(id=node_id, description=description))
    return tuple(nodes)


def _parse_policy(
    value: Any, agent_dir: Path, os_profile: str, source: Path
) -> AgentPackagePolicy:
    if not isinstance(value, dict):
        raise AgentPackageError(
            f"{source}: 'policy' must be a mapping with tools/redaction"
        )
    tools_path = _resolve_relative_path(
        value.get("tools"), agent_dir, "policy.tools", source
    )
    redaction_path = _resolve_relative_path(
        value.get("redaction"), agent_dir, "policy.redaction", source
    )

    tools_raw = yaml.safe_load(tools_path.read_text(encoding="utf-8"))
    if not isinstance(tools_raw, dict) or not isinstance(tools_raw.get("allowed"), list):
        raise AgentPackageError(
            f"{tools_path}: must be a mapping with an 'allowed' list of tool ids"
        )
    allowed_tools = tuple(
        _validate_tool_id(t, os_profile, tools_path) for t in tools_raw["allowed"]
    )
    if not allowed_tools:
        raise AgentPackageError(
            f"{tools_path}: 'allowed' is empty. An agent with zero tools cannot operate."
        )
    if len(set(allowed_tools)) != len(allowed_tools):
        raise AgentPackageError(f"{tools_path}: 'allowed' contains duplicate tool ids")

    red_raw = yaml.safe_load(redaction_path.read_text(encoding="utf-8"))
    if red_raw is None:
        red_patterns: tuple[RedactionPattern, ...] = ()
    elif isinstance(red_raw, dict) and isinstance(red_raw.get("patterns"), list):
        red_patterns = tuple(
            _parse_redaction_pattern(p, redaction_path) for p in red_raw["patterns"]
        )
    else:
        raise AgentPackageError(
            f"{redaction_path}: must be a mapping with a 'patterns' list (or empty)"
        )

    return AgentPackagePolicy(
        allowed_tools=allowed_tools,
        redaction_patterns=red_patterns,
    )


def _read_relative_file(value: Any, agent_dir: Path, field: str, source: Path) -> str:
    path = _resolve_relative_path(value, agent_dir, field, source)
    return path.read_text(encoding="utf-8")


def _resolve_relative_path(value: Any, agent_dir: Path, field: str, source: Path) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise AgentPackageError(f"{source}: {field!r} must be a non-empty path string")
    relative = Path(value)
    if relative.is_absolute():
        raise AgentPackageError(
            f"{source}: {field}={value!r} must be a path RELATIVE to the agent directory"
        )
    target = (agent_dir / relative).resolve()
    # Defense against `..` escapes — the resolved path must stay inside agent_dir.
    if agent_dir != target and agent_dir not in target.parents:
        raise AgentPackageError(
            f"{source}: {field}={value!r} resolves outside the agent directory"
        )
    if not target.is_file():
        raise AgentPackageError(
            f"{source}: {field}={value!r} does not exist at {target}"
        )
    return target


def _validate_tool_id(tool_id: Any, os_profile: str, source: Path) -> str:
    if not isinstance(tool_id, str):
        raise AgentPackageError(
            f"{source}: tool ids must be strings, got {type(tool_id).__name__}: {tool_id!r}"
        )
    tool = TOOL_BY_ID.get(tool_id)
    if tool is None:
        raise AgentPackageError(
            f"{source}: tool id {tool_id!r} is not in forensia.toolkit.catalog. "
            "Allowed ids must reference the curated maletín."
        )
    if os_profile not in tool.os_profiles:
        raise AgentPackageError(
            f"{source}: tool {tool_id!r} does not declare os_profile={os_profile!r} "
            f"(catalog declares {list(tool.os_profiles)})"
        )
    return tool_id


_VALID_REDACTION_MODES = frozenset({"strict", "relaxed"})


def _parse_redaction_pattern(value: Any, source: Path) -> RedactionPattern:
    if not isinstance(value, dict):
        raise AgentPackageError(
            f"{source}: each redaction pattern must be a mapping with name/regex/replacement"
        )
    name = _require_str(value, "name", source)
    regex = _require_str(value, "regex", source)
    try:
        re.compile(regex)
    except re.error as exc:
        raise AgentPackageError(
            f"{source}: redaction pattern {name!r} has invalid regex: {exc}"
        ) from exc
    replacement = value.get("replacement")
    if not isinstance(replacement, str):
        raise AgentPackageError(
            f"{source}: redaction pattern {name!r} replacement must be a string"
        )
    apply_in_raw = value.get("apply_in", ["strict"])
    if not isinstance(apply_in_raw, list) or not all(isinstance(m, str) for m in apply_in_raw):
        raise AgentPackageError(
            f"{source}: redaction pattern {name!r} apply_in must be a list of strings"
        )
    apply_in = tuple(m.strip().lower() for m in apply_in_raw if m.strip())
    unknown = set(apply_in) - _VALID_REDACTION_MODES
    if unknown:
        raise AgentPackageError(
            f"{source}: redaction pattern {name!r} declares unknown apply_in modes "
            f"{sorted(unknown)}; expected subset of {sorted(_VALID_REDACTION_MODES)}"
        )
    if not apply_in:
        raise AgentPackageError(
            f"{source}: redaction pattern {name!r} has empty apply_in — at least "
            f"'strict' is required (use 'apply_in: [strict]' as a sensible default)"
        )
    return RedactionPattern(
        name=name, regex=regex, replacement=replacement, apply_in=apply_in
    )
