"""Cliente de Ollama con la ventana bajo control (RA-4, RM-2b, RM-4).

- El nombre del modelo se lee de configuración en cada llamada: probar otro es
  cambiar un valor, no editar código.
- La ventana se garantiza ANTES de enviar: se estima el tamaño del prompt en
  tokens con una ratio chars/token que se calibra con lo que Ollama devuelve
  (`prompt_eval_count`) y se comprueba contra `num_ctx - num_predict - margen`.
  Si no cabe, el llamador recibe `PromptDemasiadoLargo` y recorta; nunca se
  descubre después por un `truncated` en los logs.
- El razonamiento se acota desde la llamada: `think` (si el operador lo
  configura) y `num_predict` siempre.
- `/api/show` confirma que `num_ctx` pedido no supera la longitud de contexto
  real del modelo.

Solo stdlib. Respuestas en JSON (`format: "json"`), que es lo que los agentes
esperan: un objeto con la acción, no prosa que haya que parsear.
"""

from __future__ import annotations

import json
import math
import time
from pathlib import Path
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from configuracion import Ajustes, Ventana, ajustes
import trazas

RATIO_INICIAL = 3.0       # chars por token, conservadora (hex y JSON tokenizan peor que prosa)
RATIO_MINIMA = 1.5
FACTOR_SEGURIDAD = 0.9    # se usa el 90 % de la ratio observada


class ModeloError(RuntimeError):
    pass


class PromptDemasiadoLargo(ModeloError):
    def __init__(self, estimado: int, maximo: int) -> None:
        super().__init__(f"el prompt estimado ({estimado} tokens) supera el presupuesto ({maximo})")
        self.estimado = estimado
        self.maximo = maximo


@dataclass
class Respuesta:
    texto: str
    prompt_tokens: int
    tokens_generados: int
    segundos: float
    segundos_prefill: float
    segundos_generacion: float
    modelo: str
    prompt_chars: int
    razonamiento: str | None = None
    crudo: dict[str, Any] = field(default_factory=dict)

    def json(self) -> dict[str, Any]:
        return _parsear_json(self.texto)


@dataclass
class Calibracion:
    """Ratio chars/token observada por modelo, para la estimación previa al envío.

    Se persiste en `AGENTOPSY_HOME/localfit-calibracion.json` para que un reinicio
    no vuelva a la ratio inicial: lo aprendido (un volcado hex tokeniza a ~2,3
    chars/token) vale para la siguiente corrida."""

    ratios: dict[str, float] = field(default_factory=dict)
    ruta: Path | None = None

    def cargar(self, ruta: Path) -> None:
        self.ruta = ruta
        try:
            datos = json.loads(ruta.read_text(encoding="utf-8"))
            self.ratios.update({k: float(v) for k, v in datos.items()})
        except (OSError, ValueError, AttributeError):
            pass

    def ratio(self, modelo: str) -> float:
        return self.ratios.get(modelo, RATIO_INICIAL)

    def observar(self, modelo: str, chars: int, tokens: int) -> None:
        if tokens <= 0 or chars <= 0:
            return
        observada = max(RATIO_MINIMA, chars / tokens)
        previa = self.ratios.get(modelo)
        # Media móvil, sesgada hacia lo observado; siempre por debajo de lo visto.
        nueva = observada if previa is None else 0.5 * previa + 0.5 * observada
        self.ratios[modelo] = max(RATIO_MINIMA, min(nueva, observada) * FACTOR_SEGURIDAD)
        if self.ruta is not None:
            try:
                self.ruta.write_text(json.dumps(self.ratios, indent=2), encoding="utf-8")
            except OSError:
                pass


calibracion = Calibracion()


class Modelo:
    def __init__(self, cfg: Ajustes = ajustes, calib: Calibracion = calibracion) -> None:
        self._cfg = cfg
        self._calib = calib
        self._contexto_real: dict[str, int] = {}
        if calib.ruta is None:
            try:
                calib.cargar(cfg.home / "localfit-calibracion.json")
            except KeyError:
                pass

    # -- ventana ---------------------------------------------------------------------
    def estimar_tokens(self, texto: str, modelo: str | None = None) -> int:
        modelo = modelo or self._cfg.modelo
        return int(math.ceil(len(texto) / self._calib.ratio(modelo)))

    def comprobar_ventana(self, system: str, user: str, ventana: Ventana | None = None) -> int:
        """Garantía previa al envío. Devuelve la estimación o lanza PromptDemasiadoLargo."""
        ventana = ventana or self._cfg.ventana
        estimado = self.estimar_tokens(system) + self.estimar_tokens(user) + 16
        if estimado > ventana.prompt_max:
            raise PromptDemasiadoLargo(estimado, ventana.prompt_max)
        return estimado

    def contexto_real(self, modelo: str) -> int | None:
        """Longitud de contexto del modelo según `/api/show` (model_info.*.context_length)."""
        if modelo in self._contexto_real:
            return self._contexto_real[modelo]
        try:
            datos = self._post("/api/show", {"name": modelo}, timeout=15)
        except ModeloError:
            return None
        info = datos.get("model_info") or {}
        for clave, valor in info.items():
            if clave.endswith(".context_length") and isinstance(valor, int):
                self._contexto_real[modelo] = valor
                return valor
        return None

    # -- llamada ---------------------------------------------------------------------
    def preguntar(self, system: str, user: str, *, modelo: str | None = None,
                  ventana: Ventana | None = None, json_forzado: bool = True,
                  num_predict: int | None = None) -> Respuesta:
        modelo = modelo or self._cfg.modelo
        ventana = ventana or self._cfg.ventana
        estimado = self.comprobar_ventana(system, user, ventana)
        real = self.contexto_real(modelo)
        if real is not None and ventana.num_ctx > real:
            raise ModeloError(
                f"LOCALFIT_NUM_CTX={ventana.num_ctx} supera la ventana real del modelo {modelo} ({real})"
            )
        cuerpo: dict[str, Any] = {
            "model": modelo,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "keep_alive": "30m",
            "options": {
                "num_ctx": ventana.num_ctx,
                "num_predict": num_predict if num_predict is not None else ventana.num_predict,
                "temperature": self._cfg.temperatura,
            },
        }
        if json_forzado:
            cuerpo["format"] = "json"
        pensar = self._cfg.pensar
        if pensar is not None:
            cuerpo["think"] = pensar
        inicio = time.monotonic()
        datos = self._chat(cuerpo, langsmith_extra=trazas.metadatos(
            ls_provider="ollama", ls_model_name=modelo, num_ctx=ventana.num_ctx,
            num_predict=cuerpo["options"]["num_predict"], estimated_prompt_tokens=estimado))
        segundos = time.monotonic() - inicio
        mensaje = datos.get("message") or {}
        texto = str(mensaje.get("content") or "")
        prompt_tokens = int(datos.get("prompt_eval_count") or 0)
        chars = len(system) + len(user)
        if prompt_tokens:
            self._calib.observar(modelo, chars, prompt_tokens)
            if prompt_tokens > ventana.prompt_max:
                # La estimación falló por debajo: se recalibra ya (observar) y se avisa.
                raise ModeloError(
                    f"el prompt real ({prompt_tokens} tokens) superó el presupuesto "
                    f"({ventana.prompt_max}); estimado {estimado}. Ratio recalibrada."
                )
        return Respuesta(
            texto=texto,
            prompt_tokens=prompt_tokens,
            tokens_generados=int(datos.get("eval_count") or 0),
            segundos=round(segundos, 2),
            segundos_prefill=round((datos.get("prompt_eval_duration") or 0) / 1e9, 2),
            segundos_generacion=round((datos.get("eval_duration") or 0) / 1e9, 2),
            modelo=modelo,
            prompt_chars=chars,
            razonamiento=mensaje.get("thinking"),
            crudo={k: v for k, v in datos.items() if k != "message"},
        )

    @trazas.trazable(name="ollama.chat", run_type="llm")
    def _chat(self, cuerpo: dict[str, Any]) -> dict[str, Any]:
        """La llamada HTTP, trazada como run `llm` con sus tokens (usage_metadata)."""
        datos = self._post("/api/chat", cuerpo, timeout=self._cfg.timeout_modelo)
        entrada = int(datos.get("prompt_eval_count") or 0)
        salida = int(datos.get("eval_count") or 0)
        datos["usage_metadata"] = {"input_tokens": entrada, "output_tokens": salida, "total_tokens": entrada + salida}
        return datos

    # -- transporte ------------------------------------------------------------------
    def _post(self, ruta: str, cuerpo: dict[str, Any], *, timeout: float) -> dict[str, Any]:
        req = urllib.request.Request(
            self._cfg.ollama_host + ruta, data=json.dumps(cuerpo).encode("utf-8"), method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detalle = exc.read().decode("utf-8", errors="replace")[:400]
            raise ModeloError(f"Ollama respondió HTTP {exc.code} en {ruta}: {detalle}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ModeloError(f"no se pudo hablar con Ollama en {self._cfg.ollama_host}{ruta}: {exc}") from exc

    def disponible(self) -> tuple[bool, str]:
        try:
            req = urllib.request.Request(self._cfg.ollama_host + "/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                datos = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
            return False, f"Ollama no responde en {self._cfg.get('OLLAMA_HOST')}: {exc}"
        nombres = {m.get("name") for m in datos.get("models") or []}
        modelo = self._cfg.get("LOCALFIT_MODEL")
        if not modelo:
            return False, "LOCALFIT_MODEL sin configurar"
        if modelo not in nombres and f"{modelo}:latest" not in nombres:
            return False, f"el modelo {modelo!r} no está en Ollama; disponibles: {sorted(n for n in nombres if n)}"
        return True, f"{modelo} en {self._cfg.ollama_host}"

    def modelos(self) -> list[dict[str, Any]]:
        req = urllib.request.Request(self._cfg.ollama_host + "/api/tags", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                datos = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ModeloError(f"no se pudo listar modelos: {exc}") from exc
        return [{"name": m.get("name"), "size": m.get("size")} for m in datos.get("models") or []]


def _parsear_json(texto: str) -> dict[str, Any]:
    """Tolerante con lo que un modelo pequeño devuelve alrededor del JSON."""
    texto = (texto or "").strip()
    if texto.startswith("```"):
        texto = texto.strip("`")
        if texto.lower().startswith("json"):
            texto = texto[4:]
    try:
        datos = json.loads(texto)
    except ValueError:
        ini, fin = texto.find("{"), texto.rfind("}")
        if ini == -1 or fin <= ini:
            raise ModeloError(f"la respuesta del modelo no es JSON: {texto[:200]!r}")
        try:
            datos = json.loads(texto[ini:fin + 1])
        except ValueError as exc:
            raise ModeloError(f"la respuesta del modelo no es JSON válido: {texto[:200]!r}") from exc
    if not isinstance(datos, dict):
        raise ModeloError(f"se esperaba un objeto JSON, llegó {type(datos).__name__}")
    return datos
