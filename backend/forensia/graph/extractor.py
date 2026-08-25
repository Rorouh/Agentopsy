"""La EXTRACCIÓN del grafo: una llamada al ejecutor por hallazgo.

Patrón deliberadamente igual al de ``forensia.reports.writer`` (llamada al
ejecutor, puertas, una ronda de corrección, auditoría con el argv literal), y
deliberadamente más pequeño: aquí no hay índice que validar ni informe que
publicar, solo dos listas de enums cerradas.

Lo que este módulo aporta sobre la validación de ``modelo`` es la TERCERA
barrera, la que no se puede escribir como una comprobación: **el texto del
hallazgo viaja delimitado y anunciado como datos, nunca como instrucciones**. La
evidencia es dato HOSTIL (CLAUDE.md, SECURITY INVARIANTS): un sospechoso puede
sembrar el disco con texto que parezca una orden, ese texto puede acabar citado
en el ``summary`` de un hallazgo, y este es el punto donde ese ``summary`` entra
en un modelo. Tres cosas lo contienen:

1. el texto viaja dentro de un bloque delimitado y ROTULADO como datos, y el
   prompt dice explícitamente que nada de lo que haya ahí dentro es una
   instrucción;
2. va codificado como cadena JSON, así que no puede cerrar su propio delimitador;
3. y sobre todo, el contrato de respuesta es CERRADO: el modelo no devuelve prosa
   libre, devuelve dos listas de enums que el servidor valida (``modelo``). Una
   instrucción inyectada no tiene ningún campo por el que salir.

RULE 2: el ejecutor lo elige el operador, no hay uno por defecto, y un grafo que
no pasa las puertas NO se persiste ni se sustituye por otro hecho a mano.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from forensia.i18n import Mensaje, t
from forensia.executors.base import ExecutorResult, PromptExecutor
from forensia.executors.session_guard import verify_session
from forensia.graph.modelo import (
    MAX_CHARS_NOTA,
    TIPOS_NODO,
    TIPOS_RELACION,
    GraphExtractError,
    texto_del_hallazgo,
    validar_grafo,
)

#: Rondas de CORRECCIÓN que se le conceden al modelo cuando una puerta rechaza su
#: grafo. Misma figura que ``reports.writer.MAX_REPARACIONES`` y por la misma
#: razón: el rechazo entero es correcto, pero tirar la llamada por un tipo mal
#: escrito no protege nada, solo pierde el trabajo. El motivo vuelve al modelo con
#: la lista de valores válidos. No es un fallback (RULE 2): mismo ejecutor, mismo
#: contrato, ninguna puerta relajada, y si la corrección tampoco pasa NO hay grafo.
MAX_REPARACIONES = 1

#: Delimitador del bloque de datos. Rotulado en mayúsculas y con marcas que no
#: aparecen en prosa forense, para que el límite entre «lo que dice Agentopsy» y
#: «lo que dice la evidencia» sea visible también para el modelo.
_ABRE = "<<<HALLAZGO_DATOS"
_CIERRA = "HALLAZGO_DATOS>>>"

def _identidad() -> str:
    """Quién extrae y qué NO hace, en el idioma del agente."""
    return t("gx.identity")


def _enum_doc() -> str:
    """Las dos enums CERRADAS con sus glosas, en el idioma del agente.

    Las glosas no son adorno: medido, sin ellas el modelo devolvía 0 aristas en
    19 hallazgos y con ellas 24, con la regla de literalidad intacta.
    """
    return t(
        "gx.types",
        nodes=", ".join(TIPOS_NODO),
        edges=", ".join(TIPOS_RELACION),
    )


def _reglas() -> str:
    """Las nueve reglas innegociables de la extracción, en el idioma del agente."""
    return t("gx.rules", max=MAX_CHARS_NOTA)


def _contrato_de_respuesta() -> str:
    """El contrato, deliberadamente sin sitio para la prosa.

    Medido el 2026-08-10 sobre este mismo encargo: un grafo de dos nodos ocupa
    unos 100 tokens de JSON y el modelo emitía entre 600 y 900. La diferencia es
    razonamiento, y la SALIDA es lo que cuesta (15 USD/Mtok frente a 3 de la
    entrada), así que la palanca de coste no es recortar el prompt, es no dejar
    hueco donde escribir explicaciones. De ahí que el contrato prohíba cualquier
    clave que no sea del esquema y exija empezar por la llave.
    """
    return t("gx.responseContract")


def build_prompt(finding: Any) -> str:
    """El prompt de la extracción de UN hallazgo.

    Mismo orden que en la redacción del informe y por la misma razón: primero lo
    ESTABLE entre hallazgos (identidad, enums, reglas), que puede entrar en un
    prefijo cacheable; después los DATOS de este hallazgo; y el contrato de
    respuesta AL FINAL, porque es lo que sostiene el parseo estricto.
    """
    datos = {
        "title": str(getattr(finding, "title", "") or ""),
        "summary": str(getattr(finding, "summary", "") or ""),
    }
    return (
        _identidad()
        + "\n\n"
        + _enum_doc()
        + "\n"
        + _reglas()
        + t("gx.findingHeader")
        + _ABRE
        + "\n"
        + json.dumps(datos, ensure_ascii=False)
        + "\n"
        + _CIERRA
        + "\n\n"
        + _contrato_de_respuesta()
    )


def build_delta_prompt(finding: Any) -> str:
    """El encargo de un hallazgo SIGUIENTE dentro de una sesión ya abierta.

    Solo los datos: la identidad, las enums, las reglas y el contrato ya están en
    el historial de la sesión, que es exactamente lo que abarata encadenar
    (medido el 2026-08-10 sobre los 19 hallazgos de un caso real: 0,0141 USD por
    hallazgo encadenando frente a 0,0353 en frío, porque el prefijo estable se
    LEE de la caché en vez de reescribirse a doble tarifa).

    Este texto solo se envía cuando ``session_guard`` ha podido CONTABILIZAR la
    sesión. Si no puede, el turno vuelve a mandar el encargo entero: es un
    fallback de contenido, mandar más y nunca menos, y queda auditado.
    """
    datos = {
        "title": str(getattr(finding, "title", "") or ""),
        "summary": str(getattr(finding, "summary", "") or ""),
    }
    return (
        "SIGUIENTE HALLAZGO. Mismas reglas, mismas enums y mismo contrato de "
        "respuesta.\n"
        + _ABRE
        + "\n"
        + json.dumps(datos, ensure_ascii=False)
        + "\n"
        + _CIERRA
    )


@dataclass
class SesionEncadenada:
    """El estado que hace falta para que ``session_guard`` pueda contabilizar una
    sesión reutilizada a lo largo de un lote.

    No es una optimización silenciosa: cada campo existe porque el guard lo exige
    (``expected_prompts`` frente a los prompts que Agentopsy escribió de verdad, y
    el ``num_turns`` que informó el último envoltorio). Verificado el 2026-08-10
    encadenando los 19 hallazgos de un caso real: los 19 turnos salieron
    contabilizables, sin compactación y sin turnos del CLI.
    """

    session_id: str | None = None
    prompts_enviados: int = 0
    ultimo_num_turns: int | None = None
    #: Motivo por el que el guard obligó a reabrir, si lo hubo en el último turno.
    reapertura: str | None = None

    def anotar(self, result: ExecutorResult) -> None:
        self.session_id = result.session_id
        self.prompts_enviados += 1
        self.ultimo_num_turns = result.num_turns

    def reiniciar(self, motivo: str | None) -> None:
        self.session_id = None
        self.prompts_enviados = 0
        self.ultimo_num_turns = None
        self.reapertura = motivo


@dataclass
class _Cuenta:
    """Lo que gastó la extracción de UN hallazgo, sumando sus intentos."""

    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    #: False cuando ningún envoltorio reportó coste (codex no lo reporta), para
    #: que la vista pueda decir «no informado» en vez de enseñar un cero falso.
    cost_reported: bool = False
    fuentes: set[str] = field(default_factory=set)

    def sumar(self, result: ExecutorResult) -> None:
        usage = result.usage
        if usage is None:
            return
        total_in = usage.total_input_tokens
        if total_in is not None:
            self.input_tokens += total_in
        if usage.output_tokens is not None:
            self.output_tokens += usage.output_tokens
        if usage.cost_usd is not None:
            self.cost_usd += usage.cost_usd
            self.cost_reported = True
        if usage.source:
            self.fuentes.add(usage.source)

    def publico(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
        }
        # El coste REAL solo viaja si un envoltorio lo informó. Nunca se rellena
        # con la estimación: son campos distintos y no se mezclan (RULE 2).
        out["cost_usd"] = self.cost_usd if self.cost_reported else None
        if self.fuentes:
            out["usage_source"] = ", ".join(sorted(self.fuentes))
        return out


def _parse_reply(text: str) -> dict[str, Any]:
    candidate = (text or "").strip()
    if candidate.startswith("```"):
        candidate = candidate.strip("`").strip()
        if candidate.startswith("json"):
            candidate = candidate[4:].strip()
    start = candidate.find("{")
    if start == -1:
        raise GraphExtractError(
            Mensaje("gx.noJson", sample=repr((text or "").strip()[:300]))
        )
    try:
        envelope, _ = json.JSONDecoder().raw_decode(candidate[start:])
    except json.JSONDecodeError as exc:
        raise GraphExtractError(
            f"no se pudo parsear el JSON del grafo ({exc}). "
            f"Respuesta (muestra): {(text or '').strip()[:300]!r}"
        ) from exc
    if not isinstance(envelope, dict):
        raise GraphExtractError("la respuesta del grafo no es un objeto JSON")
    return envelope


def _prompt_de_correccion(motivo: str, prompt_original: str | None) -> str:
    """Lo que se le dice al modelo cuando una puerta lo rechaza.

    ``prompt_original`` es ``None`` cuando la corrección viaja por una SESIÓN
    reabierta: el modelo conserva su propio borrador y el texto del hallazgo, así
    que basta con el motivo. Sin sesión hay que reenviar el encargo entero.
    """
    aviso = t("gx.repair", reason=motivo)
    return aviso if prompt_original is None else f"{prompt_original}\n\n{aviso}"


def extract_graph(
    case_id: str,
    finding: Any,
    *,
    executor: PromptExecutor,
    audit: Any,
    model: str | None = None,
    reasoning_effort: str | None = None,
    sesion: SesionEncadenada | None = None,
    on_progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Extrae el grafo de relaciones de UN hallazgo y devuelve lo que el almacén
    persiste (``{"nodos", "relaciones", "extraction"}``).

    No escribe en disco: quien persiste es ``forensia.graph.store``, y solo si
    esto devuelve. Cualquier incumplimiento del contrato o de las barreras levanta
    ``GraphExtractError`` tras agotar la ronda de corrección, y entonces no hay
    grafo (RULE 2: no existe un grafo de respaldo hecho a mano).

    ``sesion`` ENCADENA el lote: cuando viene con una sesión abierta y
    ``session_guard`` puede contabilizarla, este hallazgo viaja como delta. Si el
    guard no la avala, se manda el encargo entero y el motivo queda en el audit.
    El guard no se relaja ni se sortea: una sesión que no se puede auditar rompe
    la procedencia de un hallazgo, y eso vale más que la diferencia de coste.

    ``on_progress`` es OBSERVACIONAL (el job lo usa para pintar la fase): no altera
    ni el contenido ni la validación.
    """
    def _emit(phase: str, **extra: Any) -> None:
        if on_progress is not None:
            on_progress({"type": "graph_phase", "phase": phase, **extra})

    texto = texto_del_hallazgo(finding)
    finding_id = str(getattr(finding, "id", "") or "")

    context: dict[str, Any] = {"audit": audit, "case_id": case_id}
    if model:
        context["model"] = model
    if reasoning_effort:
        context["reasoning_effort"] = reasoning_effort

    cuenta = _Cuenta()

    def _run(prompt: str, *, en_sesion: bool) -> ExecutorResult:
        ctx = dict(context)
        if en_sesion and sesion is not None and sesion.session_id:
            ctx["session_id"] = sesion.session_id
        res = executor.run(prompt, ctx)
        cuenta.sumar(res)
        if sesion is not None:
            sesion.anotar(res)
        return res

    # ¿Puede este hallazgo viajar como delta? Solo si hay sesión, el ejecutor sabe
    # reanudar y el guard AVALA la contabilidad del turno anterior.
    delta = False
    reapertura: str | None = None
    if sesion is not None and sesion.session_id and executor.supports_session_resume:
        veredicto = verify_session(
            sesion.session_id,
            expected_prompts=sesion.prompts_enviados,
            num_turns=sesion.ultimo_num_turns,
        )
        if veredicto.can_send_delta:
            delta = True
        else:
            reapertura = veredicto.reason
            sesion.reiniciar(reapertura)
            if audit is not None:
                audit.append({
                    "action": "graph_session_reopened",
                    "case_id": case_id,
                    "finding_id": finding_id,
                    "executor": executor.id,
                    "reason": reapertura,
                    "checks": veredicto.checks,
                })

    prompt = build_delta_prompt(finding) if delta else build_prompt(finding)
    _emit("extrayendo", finding_id=finding_id, executor=executor.id,
          prompt_chars=len(prompt), resume=delta)

    result = _run(prompt, en_sesion=delta)
    intentos = 1
    while True:
        try:
            grafo = validar_grafo(_parse_reply(result.text), texto)
            break
        except GraphExtractError as exc:
            motivo = str(exc)
            if intentos > MAX_REPARACIONES:
                raise GraphExtractError(
                    Mensaje("gx.repairFailed", reason=motivo, attempts=intentos)
                ) from exc
            _emit("corrigiendo", finding_id=finding_id, intento=intentos, motivo=motivo)
            reanudable = executor.supports_session_resume and bool(result.session_id)
            if audit is not None:
                audit.append({
                    "action": "graph_repair",
                    "case_id": case_id,
                    "finding_id": finding_id,
                    "executor": executor.id,
                    "attempt": intentos,
                    "reason": motivo,
                    "resume": reanudable,
                })
            if reanudable and sesion is not None:
                result = _run(_prompt_de_correccion(motivo, None), en_sesion=True)
            else:
                # Sin sesión que sostenga el borrador hay que reenviar el encargo
                # entero: el modelo no recuerda ni el texto ni lo que propuso.
                ctx = dict(context)
                if reanudable:
                    ctx["session_id"] = result.session_id
                result = executor.run(
                    _prompt_de_correccion(motivo, None if reanudable else prompt), ctx
                )
                cuenta.sumar(result)
            intentos += 1

    _emit("listo", finding_id=finding_id, nodos=len(grafo["nodos"]),
          relaciones=len(grafo["relaciones"]))
    return {
        **grafo,
        "extraction": {
            "executor": executor.id,
            "model": model,
            "attempts": intentos,
            "prompt_chars": len(prompt),
            "resume": delta,
            "reopen_reason": reapertura,
            **cuenta.publico(),
        },
    }


__all__ = [
    "MAX_REPARACIONES",
    "SesionEncadenada",
    "build_delta_prompt",
    "build_prompt",
    "extract_graph",
]
