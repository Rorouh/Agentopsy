"""Configuración del orquestador (por variables de entorno y/o fichero .env).

La capa de modelos es CONFIGURABLE: el backend (ollama|anthropic|openai) y el
modelo se eligen aquí o por línea de comandos, tal y como pide el documento.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def load_dotenv(path: str = ".env") -> None:
    """Carga sencilla de un .env (sin dependencias) si existe."""
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip().strip('"').strip("'")
            os.environ.setdefault(key, val)


# Modelos por defecto razonables por backend (se pueden sobreescribir).
DEFAULT_MODELS = {
    "ollama": "qwen2.5:7b",          # soporta tool-calling y es local
    "anthropic": "claude-sonnet-4-6",
    "openai": "gpt-4o",
}


@dataclass
class Config:
    # --- Capa de modelos (seleccionable) ---
    provider: str = os.getenv("FORENSIA_PROVIDER", "ollama")
    model: str = os.getenv("FORENSIA_MODEL", "")
    ollama_host: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")

    # --- Maletín (contenedores en ejecución) ---
    win_container: str = os.getenv("FORENSIA_WIN_CONTAINER", "forensia-toolkit-windows")
    unix_container: str = os.getenv("FORENSIA_UNIX_CONTAINER", "forensia-toolkit-unix")

    # --- Rutas DENTRO del contenedor ---
    evidence_root: str = os.getenv("FORENSIA_EVIDENCE_ROOT", "/evidence")
    cases_root: str = os.getenv("FORENSIA_CASES_ROOT", "/cases")
    # --- Ruta de salida en el HOST (donde el orquestador escribe informes) ---
    cases_host: str = os.getenv("FORENSIA_CASES_HOST", "./projects")

    # --- Límites de seguridad ---
    max_tool_chars: int = int(os.getenv("FORENSIA_MAX_TOOL_CHARS", "60000"))
    max_steps: int = int(os.getenv("FORENSIA_MAX_STEPS", "8"))
    tool_timeout: int = int(os.getenv("FORENSIA_TOOL_TIMEOUT", "600"))

    def resolved_model(self) -> str:
        return self.model or DEFAULT_MODELS.get(self.provider, "")
