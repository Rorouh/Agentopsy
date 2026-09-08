"""Configuración del motor: variables de entorno y `config.json` del AGENTOPSY_HOME.

Prioridad: entorno > `config.json`. El fichero se relee en cada consulta para que
cambiar de modelo (RM-4) o de camino de memoria (RA-9) no exija reiniciar nada.

RULE 2 del repo: lo que hace falta y no está configurado falla con un mensaje que
dice qué clave poner y dónde. Los únicos defaults son parámetros de diseño
(tamaño de ventana, pasos máximos), nunca un proveedor, un modelo o una ruta.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Claves que se leen. Documentadas aquí y en README.md.
CLAVES = {
    "AGENTOPSY_HOME": "raíz de datos (config.json y cases/), la misma que usa el api",
    "LOCALFIT_HOME_MALETIN": "cómo ve el maletín AGENTOPSY_HOME (en el compose ambos son /cases)",
    "AGENTOPSY_EVIDENCE_DIR": "bandeja de evidencias en este proceso",
    "LOCALFIT_EVIDENCE_DIR_MALETIN": "cómo ve el maletín la bandeja (en el compose /evidence)",
    "AGENTOPSY_TOOLKIT_UNIX_URL": "exec-agent del maletín unix",
    "AGENTOPSY_TOOLKIT_WINDOWS_URL": "exec-agent del maletín windows",
    "OLLAMA_HOST": "URL de Ollama",
    "LOCALFIT_MODEL": "modelo Ollama del agente (se lee en cada petición)",
    "LOCALFIT_MEMORIA": "camino de memoria: estructurada | embeddings",
    "LOCALFIT_EMBED_MODEL": "modelo de embeddings (solo camino embeddings)",
}


@dataclass(frozen=True)
class Ventana:
    """Presupuesto de tokens de una llamada: lo que el sistema garantiza antes de enviar."""

    num_ctx: int
    num_predict: int
    margen: int

    @property
    def prompt_max(self) -> int:
        return self.num_ctx - self.num_predict - self.margen


class Ajustes:
    def __init__(self, entorno: dict[str, str] | None = None) -> None:
        self._env = entorno if entorno is not None else os.environ

    # -- lectura cruda -----------------------------------------------------------
    def _fichero(self) -> dict[str, Any]:
        home = self._env.get("AGENTOPSY_HOME")
        if not home:
            return {}
        ruta = Path(home) / "config.json"
        if not ruta.is_file():
            return {}
        try:
            datos = json.loads(ruta.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return datos if isinstance(datos, dict) else {}

    def get(self, clave: str) -> str | None:
        valor = self._env.get(clave)
        if valor is not None and valor != "":
            return valor
        del_fichero = self._fichero().get(clave)
        if del_fichero is None or del_fichero == "":
            return None
        return str(del_fichero)

    def requerir(self, clave: str) -> str:
        valor = self.get(clave)
        if valor is None:
            ayuda = CLAVES.get(clave, "")
            raise KeyError(
                f"falta la configuración {clave} ({ayuda}). Define la variable de "
                f"entorno {clave} o la clave en {self.get('AGENTOPSY_HOME') or '$AGENTOPSY_HOME'}"
                "/config.json. El motor no inventa un valor."
            )
        return valor

    def entero(self, clave: str, por_defecto: int) -> int:
        valor = self.get(clave)
        if valor is None:
            return por_defecto
        try:
            return int(valor)
        except ValueError as exc:
            raise ValueError(f"{clave} debe ser un entero, no {valor!r}") from exc

    def flotante(self, clave: str, por_defecto: float) -> float:
        valor = self.get(clave)
        if valor is None:
            return por_defecto
        try:
            return float(valor)
        except ValueError as exc:
            raise ValueError(f"{clave} debe ser un número, no {valor!r}") from exc

    def booleano(self, clave: str, por_defecto: bool) -> bool:
        valor = self.get(clave)
        if valor is None:
            return por_defecto
        if valor.lower() in {"1", "true", "si", "sí", "yes", "on"}:
            return True
        if valor.lower() in {"0", "false", "no", "off"}:
            return False
        raise ValueError(f"{clave} debe ser true/false, no {valor!r}")

    # -- rutas -------------------------------------------------------------------
    @property
    def home(self) -> Path:
        return Path(self.requerir("AGENTOPSY_HOME")).resolve()

    @property
    def home_maletin(self) -> str:
        # Default de diseño: el maletín ve la misma ruta (así es en el compose: /cases).
        return self.get("LOCALFIT_HOME_MALETIN") or str(self.home)

    @property
    def dir_casos(self) -> Path:
        return self.home / "cases"

    @property
    def dir_evidencias(self) -> Path:
        return Path(self.requerir("AGENTOPSY_EVIDENCE_DIR")).resolve()

    @property
    def dir_evidencias_maletin(self) -> str:
        return self.get("LOCALFIT_EVIDENCE_DIR_MALETIN") or str(self.dir_evidencias)

    def a_ruta_maletin(self, ruta_local: Path) -> str:
        """Traduce una ruta de este proceso a la vista del maletín (mismos directorios,
        montados quizá en otro sitio). Falla si la ruta no cae en ninguno de los dos
        árboles compartidos: el maletín no la vería."""
        ruta_local = Path(ruta_local).resolve()
        for local, remota in (
            (self.home, self.home_maletin),
            (self.dir_evidencias, self.dir_evidencias_maletin),
        ):
            try:
                relativa = ruta_local.relative_to(local)
            except ValueError:
                continue
            return str(Path(remota) / relativa) if str(relativa) != "." else remota
        raise ValueError(
            f"la ruta {ruta_local} no está bajo AGENTOPSY_HOME ({self.home}) ni bajo "
            f"AGENTOPSY_EVIDENCE_DIR ({self.dir_evidencias}); el maletín no puede verla"
        )

    def de_ruta_maletin(self, ruta_maletin: str) -> Path:
        """Inversa de `a_ruta_maletin`."""
        for local, remota in (
            (self.home, self.home_maletin),
            (self.dir_evidencias, self.dir_evidencias_maletin),
        ):
            remota_p = Path(remota)
            try:
                relativa = Path(ruta_maletin).relative_to(remota_p)
            except ValueError:
                continue
            return (local / relativa).resolve()
        raise ValueError(f"la ruta del maletín {ruta_maletin} no corresponde a ningún árbol compartido")

    # -- maletines ---------------------------------------------------------------
    def url_maletin(self, perfil: str) -> str:
        if perfil == "unix":
            return self.requerir("AGENTOPSY_TOOLKIT_UNIX_URL").rstrip("/")
        if perfil == "windows":
            return self.requerir("AGENTOPSY_TOOLKIT_WINDOWS_URL").rstrip("/")
        raise ValueError(f"perfil de maletín desconocido: {perfil!r} (unix | windows)")

    @property
    def token_maletin(self) -> str | None:
        return self.get("AGENTOPSY_EXEC_AGENT_TOKEN")

    # -- modelo ------------------------------------------------------------------
    @property
    def ollama_host(self) -> str:
        return self.requerir("OLLAMA_HOST").rstrip("/")

    @property
    def modelo(self) -> str:
        return self.requerir("LOCALFIT_MODEL")

    @property
    def ventana(self) -> Ventana:
        return Ventana(
            num_ctx=self.entero("LOCALFIT_NUM_CTX", 4096),
            num_predict=self.entero("LOCALFIT_NUM_PREDICT", 400),
            margen=self.entero("LOCALFIT_MARGEN_TOKENS", 64),
        )

    @property
    def temperatura(self) -> float:
        return self.flotante("LOCALFIT_TEMPERATURE", 0.1)

    @property
    def pensar(self) -> bool | None:
        """`think` de Ollama. None = no mandar la clave (modelos sin razonamiento)."""
        valor = self.get("LOCALFIT_THINK")
        if valor is None:
            return None
        return self.booleano("LOCALFIT_THINK", False)

    @property
    def timeout_modelo(self) -> float:
        return self.flotante("LOCALFIT_MODEL_TIMEOUT", 600.0)

    # -- memoria -----------------------------------------------------------------
    @property
    def memoria(self) -> str:
        # Parámetro de diseño, no un proveedor: sin elección explícita se usa el
        # camino A, que no necesita ningún modelo adicional (RA-9).
        valor = self.get("LOCALFIT_MEMORIA") or "estructurada"
        if valor not in {"estructurada", "embeddings"}:
            raise ValueError(f"LOCALFIT_MEMORIA debe ser 'estructurada' o 'embeddings', no {valor!r}")
        return valor

    @property
    def modelo_embeddings(self) -> str:
        return self.requerir("LOCALFIT_EMBED_MODEL")

    # -- bucle -------------------------------------------------------------------
    @property
    def max_pasos(self) -> int:
        return self.entero("LOCALFIT_MAX_PASOS", 10)

    @property
    def shell(self) -> bool:
        """Terminal libre dentro del maletín. APAGADA por defecto: da la vuelta a la
        regla de «el modelo emite un id de herramienta, nunca una orden» (SECURITY
        INVARIANT 5) y la enciende el operador a sabiendas. Ver README, apartado
        «La terminal del maletín»."""
        return self.booleano("LOCALFIT_SHELL", False)

    @property
    def reparto(self) -> str:
        """`revisor` (por defecto): el revisor descompone la pregunta en órdenes y el
        investigador ejecuta cada una en pocos pasos. `investigador`: el investigador
        trabaja libre sobre la pregunta y el revisor solo revisa al final."""
        valor = self.get("LOCALFIT_REPARTO") or "revisor"
        if valor not in {"revisor", "investigador"}:
            raise ValueError(f"LOCALFIT_REPARTO debe ser 'revisor' o 'investigador', no {valor!r}")
        return valor

    @property
    def max_pasos_orden(self) -> int:
        return self.entero("LOCALFIT_MAX_PASOS_ORDEN", 3)

    @property
    def max_rondas_revision(self) -> int:
        return self.entero("LOCALFIT_MAX_RONDAS_REVISION", 1)

    @property
    def timeout_herramienta(self) -> float:
        return self.flotante("LOCALFIT_TOOL_TIMEOUT", 900.0)

    # -- servicio ----------------------------------------------------------------
    @property
    def puerto(self) -> int:
        return self.entero("LOCALFIT_PORT", 8001)

    @property
    def origenes_ui(self) -> list[str]:
        crudo = self.get("AGENTOPSY_UI_ORIGINS") or ""
        return [o.strip() for o in crudo.split(",") if o.strip()]

    def resumen(self) -> dict[str, Any]:
        """Lo que el operador puede ver: sin tokens ni secretos."""
        return {
            "home": self.get("AGENTOPSY_HOME"),
            "modelo": self.get("LOCALFIT_MODEL"),
            "memoria": self.get("LOCALFIT_MEMORIA"),
            "modelo_embeddings": self.get("LOCALFIT_EMBED_MODEL"),
            "ollama_host": self.get("OLLAMA_HOST"),
            "ventana": self.ventana.__dict__,
            "think": self.get("LOCALFIT_THINK"),
            "max_pasos": self.max_pasos,
            "max_rondas_revision": self.max_rondas_revision,
        }


ajustes = Ajustes()
