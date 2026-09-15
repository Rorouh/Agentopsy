"""Agente revisor: lee lo reunido por el investigador y decide. O aprueba y
redacta la respuesta al perito, o devuelve órdenes cortas del tipo
«revisa X con la herramienta Y» que el bucle convierte en un nuevo objetivo
del investigador.

No ejecuta herramientas: su única salida es un veredicto en JSON. Recibe el
estado estructurado (tareas, hallazgos con su resumen recortado, índice de
artefactos) y el informe del investigador. Su prompt cabe en la misma ventana
que el del investigador; la respuesta final tiene más `num_predict` porque es
prosa para el perito.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from artefactos.almacen import Almacen
from configuracion import Ajustes, Ventana
from custodia.ingesta import Evidencia
from custodia.registro import Registro, sha256_texto
from estado import Estado
from hallazgos import Hallazgos
from herramientas.contexto import FIRMAS_CONTEXTO, NOMBRES as CONTEXTO
from herramientas.forenses import PORTADAS, SHELL_ID, firmas as firmas_forenses
from modelo import Modelo, ModeloError, PromptDemasiadoLargo, Respuesta
import trazas

RUTA_IDENTIDAD = Path(__file__).parent / "agentes" / "revisor.md"
TOPE_ORDENES = 3
TOPE_CHARS_RESUMEN_HALLAZGO = 220

FORMATO_PLAN = (
    'Descompón lo que pide el perito en órdenes para el investigador: entre 2 y {tope}, en el orden en que deben '
    'ejecutarse, cada una corta y ejecutable con UNA herramienta de la lista y el dato concreto (qué buscar, qué '
    'scanners, qué plugin, qué run leer). Cada orden debe poder cumplirse CON LO QUE HAY: no ordenes leer ni '
    'buscar en artefactos que todavía no existen, ni repetir lo ya hecho, ni herramientas que ya fallaron. '
    'Cada orden nombra UNA herramienta y solo los parámetros de ESA herramienta. `buscar` y `leer_artefacto` '
    'actúan sobre una salida que YA existe: si hay que localizar algo dentro del resultado de una herramienta, '
    'son DOS órdenes, primero la que produce la salida y después la que busca en ella. '
    'Responde SOLO con un objeto JSON: {{"ordenes": ["extrae las cadenas imprimibles con la herramienta '
    'strings_head", "busca en ese resultado los terminos que respondan a lo que pide el perito con la '
    'herramienta buscar", ...]}}.'
)
# Los ejemplos NO llevan valores que parezcan un resultado real. Medido el 2026-09-13:
# con estos dos huecos rellenos con «Administrator» y «WIN-», un modelo de 3B ante un
# objetivo vago no planificaba, DEVOLVÍA EL EJEMPLO, y el investigador lo «confirmaba»
# después como hallazgo. Un ejemplo es una forma, no un dato del caso.
TOPE_ORDENES_PLAN = 4

FORMATO = (
    'Responde SOLO con un objeto JSON: {{"veredicto": "aprobar" | "revisar", '
    '"ordenes": ["revisa X con la herramienta Y", ...], "respuesta": "texto completo para el perito"}}. '
    'La respuesta SOLO puede afirmar lo que figura en HALLAZGOS REGISTRADOS, y cada afirmación nombra el run '
    'que la sostiene. Lo que no se haya determinado se dice que no se ha determinado: es una respuesta '
    'legítima y la que se espera. No repitas los ejemplos de este formato ni des por visto nada que no esté '
    'en la lista de hallazgos. {cierre}'
)


@dataclass
class Veredicto:
    aprobar: bool
    ordenes: list[str]
    respuesta: str
    pensamiento: str = ""
    respuesta_modelo: Respuesta | None = None
    crudo: dict[str, Any] = field(default_factory=dict)


_HERRAMIENTA_RE = re.compile(r"herramienta\s+['\"`]?([a-zA-Z_][a-zA-Z0-9_]*)", re.IGNORECASE)


def _herramienta_inventada(orden: str, permitir_shell: bool = False) -> str | None:
    """El nombre que la orden dice usar, si no es ninguna de las que hay."""
    conocidas = set(PORTADAS) | set(CONTEXTO) | {"informar"}
    if not permitir_shell:
        conocidas.discard(SHELL_ID)
    for nombre in _HERRAMIENTA_RE.findall(orden):
        if nombre.lower() not in conocidas:
            return nombre
    return None


def _orden_a_texto(orden: Any) -> str:
    """Una orden, venga como venga. El modelo de 3B las devuelve como objetos con la
    forma de la herramienta (`{"herramienta": "strings_head", "consulta": "..."}` o
    `{"buscar": ["Administrator"]}`) en vez de como frase; descartarlas dejaba al
    revisor sin plan. Aquí se aplanan a la frase que el investigador entiende."""
    if isinstance(orden, str):
        return orden.strip()
    if not isinstance(orden, dict):
        return ""
    for clave in ("orden", "texto", "text", "task", "tarea", "instruccion", "instrucción"):
        if isinstance(orden.get(clave), str) and orden[clave].strip():
            return orden[clave].strip()
    herramienta = None
    for clave in ("herramienta", "tool", "accion", "acción", "action", "name"):
        if isinstance(orden.get(clave), str) and orden[clave].strip():
            herramienta = orden[clave].strip()
            break
    resto = {k: v for k, v in orden.items()
             if k not in {"herramienta", "tool", "accion", "acción", "action", "name"} and v not in (None, "", [], {})}
    if herramienta is None and len(orden) == 1:
        # {"buscar": ["Administrator", "WIN-"]}
        herramienta, valor = next(iter(orden.items()))
        resto = {} if valor in (None, "", [], {}) else {"con": valor}
    if not herramienta:
        return ""
    detalle = ", ".join(_plano(v) if k == "con" else f"{k}: {_plano(v)}" for k, v in resto.items()) if resto else ""
    return f"usa la herramienta {herramienta}" + (f" con {detalle}" if detalle else "")


def _plano(valor: Any) -> str:
    if isinstance(valor, (list, tuple)):
        return ", ".join(str(v) for v in valor)
    if isinstance(valor, dict):
        return ", ".join(f"{k}={v}" for k, v in valor.items())
    return str(valor)


class Revisor:
    nombre = "revisor"

    def __init__(self, *, cfg: Ajustes, modelo: Modelo, estado: Estado, hallazgos: Hallazgos,
                 almacen: Almacen, evidencia: Evidencia, registro: Registro) -> None:
        self.cfg = cfg
        self.modelo = modelo
        self.estado = estado
        self.hallazgos = hallazgos
        self.almacen = almacen
        self.evidencia = evidencia
        self.registro = registro
        self.identidad = RUTA_IDENTIDAD.read_text(encoding="utf-8").strip()
        self.ultima_respuesta: Respuesta | None = None

    def sistema(self) -> str:
        """Estable entre rondas: identidad + las FIRMAS de las herramientas, no solo sus
        nombres. Sin las firmas el revisor ordena cosas imposibles: pedir «lee el
        artefacto memdump.mem» cuando aún no hay ningún artefacto quemó una orden entera
        en la primera medición. Un artefacto es la SALIDA de una ejecución previa, no la
        evidencia."""
        return (
            self.identidad
            + "\n\nHERRAMIENTAS FORENSES que el investigador puede ejecutar sobre la evidencia:\n"
            + firmas_forenses(self.evidencia.kind, permitir_shell=self.cfg.shell)
            + "\n\nHERRAMIENTAS DE CONTEXTO (trabajan sobre lo YA ejecutado):\n" + FIRMAS_CONTEXTO
            + "\n\nUn ARTEFACTO es la salida de una ejecución previa, identificada por su run_id; la evidencia "
              "en sí NO es un artefacto. Sin ejecuciones previas no hay nada que leer ni que buscar: la primera "
              "orden tiene que ser una herramienta forense."
        )

    @property
    def ventana(self) -> Ventana:
        base = self.cfg.ventana
        return Ventana(base.num_ctx, self.cfg.entero("LOCALFIT_NUM_PREDICT_REVISOR", 700), base.margen)

    def _hallazgos_texto(self, tope_chars: int) -> str:
        filas = self.hallazgos.listar()
        if not filas:
            return "(ninguno registrado)"
        lineas = []
        for h in filas[-14:]:
            resumen = h["summary"].replace("\n", " ")
            if len(resumen) > tope_chars:
                resumen = resumen[:tope_chars] + "…"
            lineas.append(f"- [{h['severity']}] {h['title']} (run {str(h.get('run_id') or '')[:8]}): {resumen}")
        return "\n".join(lineas)

    def _artefactos_texto(self) -> str:
        filas = self.almacen.indice()
        if not filas:
            return "(ninguno)"
        return "\n".join(
            f"- {f['run_id'][:8]} {f['tool_id']} exit={f['exit_code']} líneas={f['stdout_lines']} ficheros={f['output_files']}"
            for f in filas[-16:]
        )

    def _bloques(self, objetivo: str, informe: str, ronda: int, max_rondas: int, ordenes_previas: list[str],
                 *, tope_hallazgo: int, con_artefactos: bool, tope_informe: int) -> str:
        ev = self.evidencia.puntero()
        ultima = ronda >= max_rondas
        partes = [
            f"CASO: evidencia {ev['nombre']} (tipo {ev['kind']}, {ev['tamano_mb']} MB).",
            f"PERITO PIDE: {objetivo}",
            "TAREAS DEL INVESTIGADOR:\n" + self.estado.tareas_texto(),
            "HALLAZGOS REGISTRADOS:\n" + self._hallazgos_texto(tope_hallazgo),
        ]
        if con_artefactos:
            partes.append("ARTEFACTOS (ejecuciones):\n" + self._artefactos_texto())
        if ordenes_previas:
            partes.append("ÓRDENES YA DADAS (no las repitas):\n" + "\n".join(f"- {o}" for o in ordenes_previas))
        partes.append(f"INFORME DEL INVESTIGADOR:\n{informe[:tope_informe]}")
        cierre = (
            "Es la última ronda: el veredicto debe ser aprobar y la respuesta, completa."
            if ultima else
            f"Ronda {ronda} de {max_rondas}. Si das órdenes, máximo {TOPE_ORDENES}, cortas y ejecutables: cada una nombra "
            "una herramienta de la lista y el dato concreto (término a buscar, run a leer, plugin o scanner), por ejemplo "
            "«busca el término que responda a la pregunta en el run de strings_head con la herramienta buscar». "
            "Deja respuesta vacía."
        )
        partes.append(FORMATO.format(cierre=cierre))
        return "\n\n".join(partes)

    def prompt(self, objetivo: str, informe: str, ronda: int, max_rondas: int, ordenes_previas: list[str]) -> tuple[str, str, int]:
        intentos = (
            dict(tope_hallazgo=TOPE_CHARS_RESUMEN_HALLAZGO, con_artefactos=True, tope_informe=1500),
            dict(tope_hallazgo=120, con_artefactos=True, tope_informe=900),
            dict(tope_hallazgo=80, con_artefactos=False, tope_informe=500),
        )
        error: PromptDemasiadoLargo | None = None
        for opciones in intentos:
            user = self._bloques(objetivo, informe, ronda, max_rondas, ordenes_previas, **opciones)
            try:
                system = self.sistema()
                return system, user, self.modelo.comprobar_ventana(system, user, self.ventana)
            except PromptDemasiadoLargo as exc:
                error = exc
        assert error is not None
        raise error

    @trazas.trazable(name="revisor.revisar", run_type="chain")
    def revisar(self, objetivo: str, informe: str, ronda: int, max_rondas: int,
                ordenes_previas: list[str]) -> Veredicto:
        system, user, estimado = self.prompt(objetivo, informe, ronda, max_rondas, ordenes_previas)
        try:
            resp = self.modelo.preguntar(system, user, modelo=self.modelo_nombre, ventana=self.ventana,
                                         num_predict=self.ventana.num_predict)
        except ModeloError as exc:
            self._auditar(None, system, user, estimado, error=str(exc))
            raise
        self._auditar(resp, system, user, estimado)
        try:
            datos = resp.json()
        except ModeloError:
            # Un revisor ilegible no bloquea al perito: se aprueba con el informe del investigador.
            return Veredicto(True, [], informe, "(veredicto ilegible; se entrega el informe del investigador)", resp, {})
        veredicto = str(datos.get("veredicto") or datos.get("verdict") or "").strip().lower()
        ordenes = datos.get("ordenes") or datos.get("órdenes") or datos.get("orders") or []
        if isinstance(ordenes, str):
            ordenes = [o.strip(" -•") for o in ordenes.splitlines() if o.strip(" -•")]
        ordenes = [str(o).strip() for o in ordenes if str(o).strip()][:TOPE_ORDENES]
        respuesta = str(datos.get("respuesta") or datos.get("response") or datos.get("answer") or "").strip()
        pensamiento = str(datos.get("pensamiento") or datos.get("motivo") or "").strip()
        aprobar = veredicto.startswith("aprob") or veredicto in {"approve", "approved", "ok"} or not ordenes
        if ronda >= max_rondas:
            aprobar = True
        if aprobar and not respuesta:
            respuesta = informe
        return Veredicto(aprobar, [] if aprobar else ordenes, respuesta, pensamiento, resp, datos)

    # -- planificación: el revisor descompone la pregunta en órdenes ---------------------
    @trazas.trazable(name="revisor.planificar", run_type="chain")
    def planificar(self, objetivo: str) -> list[str]:
        """Órdenes concretas para el investigador a partir de lo que pide el perito y del
        estado del caso. Es el reparto invertido: la iniciativa la lleva el agente que
        demostró tenerla; el investigador ejecuta cada orden en pocos pasos."""
        ev = self.evidencia.puntero()
        indice = self.almacen.indice()
        partes = [
            f"CASO: evidencia {ev['nombre']} (tipo {ev['kind']}, {ev['tamano_mb']} MB).",
            f"PERITO PIDE: {objetivo}",
            "HALLAZGOS REGISTRADOS:\n" + self._hallazgos_texto(120),
            ("EJECUCIONES YA HECHAS (exit≠0 = falló; no las repitas):\n" + self._artefactos_texto())
            if indice else
            "EJECUCIONES YA HECHAS: NINGUNA. No hay ningún artefacto todavía, así que no ordenes leer ni "
            "buscar nada: la primera orden tiene que ejecutar una herramienta forense sobre la evidencia.",
            FORMATO_PLAN.format(tope=TOPE_ORDENES_PLAN),
        ]
        user = "\n\n".join(partes)
        system = self.sistema()
        ventana = Ventana(self.cfg.ventana.num_ctx, 300, self.cfg.ventana.margen)
        estimado = self.modelo.comprobar_ventana(system, user, ventana)
        try:
            resp = self.modelo.preguntar(system, user, modelo=self.modelo_nombre, ventana=ventana, num_predict=300)
        except ModeloError as exc:
            self._auditar(None, system, user, estimado, error=str(exc), fase="plan")
            raise
        self._auditar(resp, system, user, estimado, fase="plan")
        self.ultima_respuesta = resp
        try:
            datos = resp.json()
        except ModeloError:
            return []
        ordenes = datos.get("ordenes") or datos.get("órdenes") or datos.get("orders") or datos.get("tareas") or []
        if isinstance(ordenes, str):
            ordenes = [o.strip(" -•") for o in ordenes.splitlines() if o.strip(" -•")]
        salida = []
        for o in ordenes:
            texto = _orden_a_texto(o)
            if not texto:
                continue
            inventada = _herramienta_inventada(texto, self.cfg.shell)
            if inventada:
                # Medido: el modelo pequeño ordenó «usa la herramienta cmd», y el
                # investigador gastó tres pasos chocando contra una herramienta que no
                # existe. Una orden que nombra algo inexistente no se le pasa.
                self.registro.anotar({
                    "action": "reviewer_order_discarded", "case_id": self.evidencia.case_id,
                    "order": texto, "reason": f"herramienta inexistente: {inventada}",
                    "engine": "local-fit-llm",
                })
                continue
            salida.append(texto[:200])
        return salida[:TOPE_ORDENES_PLAN]

    @property
    def modelo_nombre(self) -> str | None:
        """El revisor puede correr en otro modelo (LOCALFIT_MODEL_REVISOR): un planificador
        mejor y un ejecutor más rápido. None = el mismo que el investigador."""
        return self.cfg.get("LOCALFIT_MODEL_REVISOR")

    def _auditar(self, resp: Respuesta | None, system: str, user: str, estimado: int, error: str | None = None,
                 fase: str = "revision") -> None:
        evento: dict[str, Any] = {
            "action": "model_call",
            "agent": self.nombre,
            "case_id": self.evidencia.case_id,
            "model": self.modelo_nombre or self.cfg.get("LOCALFIT_MODEL"),
            "phase": fase,
            "prompt_sha256": sha256_texto(system + "\n" + user),
            "prompt_chars": len(system) + len(user),
            "prompt_tokens_estimated": estimado,
            "engine": "local-fit-llm",
        }
        if resp is not None:
            evento.update({
                "prompt_tokens": resp.prompt_tokens, "eval_count": resp.tokens_generados,
                "seconds": resp.segundos, "prefill_seconds": resp.segundos_prefill,
                "generation_seconds": resp.segundos_generacion, "response_sha256": sha256_texto(resp.texto),
            })
        if error:
            evento["error"] = error
        self.registro.anotar(evento)
