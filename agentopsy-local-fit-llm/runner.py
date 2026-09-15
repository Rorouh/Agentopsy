"""El bucle: un turno del perito, dos agentes, N pasos, eventos de progreso.

    perito escribe
      → revisor: descompone la pregunta en órdenes concretas (reparto `revisor`)
      → investigador: ejecuta cada orden en pocos pasos (o trabaja libre, reparto `investigador`)
      → revisor: aprueba (respuesta final) o da órdenes nuevas
      → ... hasta aprobar o agotar rondas
    → se persiste el turno en el chat y en la cadena

El bucle está expresado como grafo de LangGraph (`grafo.py`): los nodos son los
métodos `nodo_*` de `Corrida`.

Cada llamada al modelo recibe el estado estructurado (tareas, último
resultado, punteros), nunca la conversación (RA-7). El progreso sale por
`emitir(evento)` con el mismo vocabulario que usa la web para el motor
actual (reasoning, tool_call, tool_result, finding) más `tareas`, `revision`
y `orden`, que son propios de este motor.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable

from artefactos.almacen import Almacen
from casos import Casos, casos
from chats import Chats
from configuracion import Ajustes, ajustes
from custodia.ingesta import Evidencia, Ingesta, ingesta
from custodia.registro import Registro, sha256_texto
from estado import Estado
from hallazgos import Hallazgos
from herramientas.contexto import Contexto
from herramientas.ejecutor import Ejecutor
from herramientas.forenses import PORTADAS
from investigador import Investigador, Paso
from maletin import Maletin
from memoria import crear_memoria
from modelo import Modelo, ModeloError
from revisor import Revisor
import grafo
import trazas

Emisor = Callable[[dict[str, Any]], None]

IDENTIDAD_MOTOR = {"id": "local-fit-llm", "name": "Local fit LLM", "local": True}


def _nada(_: dict[str, Any]) -> None:
    return None


class Corrida:
    """Un turno completo. Construye los agentes sobre el caso y los ejecuta."""

    def __init__(
        self,
        *,
        case_id: str,
        evidence_id: str,
        sesion: str,
        prompt: str,
        cfg: Ajustes = ajustes,
        cs: Casos = casos,
        ing: Ingesta = ingesta,
        emitir: Emisor = _nada,
        modelo: Modelo | None = None,
        maletin: Maletin | None = None,
        persistir_chat: bool = True,
    ) -> None:
        prompt = (prompt or "").strip()
        if not prompt:
            raise ValueError("el prompt del perito está vacío")
        self.cfg = cfg
        self.case_id = case_id
        self.sesion = sesion
        self.prompt = prompt
        self.emitir = emitir
        # Parada cooperativa (botón «Parar» de la web): se consulta entre pasos y rondas.
        self.cancelado: Callable[[], bool] = lambda: False
        # La web persiste el chat por su cuenta (como con el api); la CLI no.
        self.persistir_chat = persistir_chat
        self.caso = cs.cargar(case_id)
        self.dir_caso: Path = cs.dir_caso(case_id)
        self.evidencia: Evidencia = ing.obtener(case_id, evidence_id)
        self.perfil = cs.perfil(case_id)
        self.registro = Registro(self.dir_caso / "audit.jsonl")
        self.estado = Estado(cs.dir_agente(case_id, sesion))
        self.almacen = Almacen(self.dir_caso)
        self.memoria = crear_memoria(self.dir_caso, cfg)
        self.hallazgos = Hallazgos(self.dir_caso, case_id)
        self.chats = Chats(self.dir_caso)
        self.modelo = modelo or Modelo(cfg)
        self.ejecutor = Ejecutor(case_id=case_id, dir_caso=self.dir_caso, evidencia=self.evidencia,
                                 perfil=self.perfil, cfg=cfg, maletin=maletin, agente="investigador")
        self.contexto = Contexto(estado=self.estado, almacen=self.almacen, memoria=self.memoria,
                                 hallazgos=self.hallazgos, kind=self.evidencia.kind,
                                 evidence_id=self.evidencia.evidence_id, agente="investigador",
                                 shell=cfg.shell)
        self.investigador = Investigador(
            cfg=cfg, modelo=self.modelo, contexto=self.contexto, ejecutor=self.ejecutor, estado=self.estado,
            evidencia=self.evidencia, hallazgos=self.hallazgos, chats=self.chats, sesion=sesion,
            registro=self.registro, indexar=self.memoria.indexar_run,
        )
        self.revisor = Revisor(cfg=cfg, modelo=self.modelo, estado=self.estado, hallazgos=self.hallazgos,
                               almacen=self.almacen, evidencia=self.evidencia, registro=self.registro)
        self.actividad: list[dict[str, Any]] = []
        self.tool_calls: list[dict[str, Any]] = []
        self.iteracion = 0
        self.metricas: dict[str, Any] = {"llamadas_modelo": 0, "prompt_tokens": 0, "tokens_generados": 0,
                                         "segundos_modelo": 0.0, "pasos": 0, "rondas": 0, "herramientas": 0}
        self._objetivo = prompt
        self._ordenes_dadas: list[str] = []

    # -- eventos -----------------------------------------------------------------------
    def _evento(self, tipo: str, **campos: Any) -> None:
        evento = {"type": tipo, "iteration": self.iteracion, **campos}
        self.actividad.append(evento)
        self.emitir(evento)

    def _contabilizar(self, paso: Paso | None, resp: Any) -> None:
        if resp is None:
            return
        self.metricas["llamadas_modelo"] += 1
        self.metricas["prompt_tokens"] += resp.prompt_tokens
        self.metricas["tokens_generados"] += resp.tokens_generados
        self.metricas["segundos_modelo"] += resp.segundos

    # -- investigador --------------------------------------------------------------------
    @trazas.trazable(name="orden del revisor", run_type="chain")
    def _investigar(self, objetivo: str, max_pasos: int) -> str:
        self.estado.fijar_objetivo(objetivo)
        informe: str | None = None
        for n in range(1, max_pasos + 1):
            if self.cancelado():
                informe = "Parado por el operador. " + self.estado.tareas_texto()
                self._evento("final", text=informe, agent="investigador", exhausted=True)
                break
            self.iteracion += 1
            self.metricas["pasos"] += 1
            paso = self.investigador.paso(objetivo, n, max_pasos)
            self._contabilizar(paso, paso.respuesta)
            if paso.pensamiento:
                self._evento("reasoning", text=paso.pensamiento, agent="investigador")
            if paso.terminado:
                informe = paso.informe
                self._evento("final", text=informe or "", agent="investigador", exhausted=False)
                break
            self._evento("tool_call", tool_id=paso.accion, params=paso.args, agent="investigador")
            if paso.accion in PORTADAS:
                self.metricas["herramientas"] += 1
                self.tool_calls.append({"tool_id": paso.accion, "run_id": paso.run_id, "exit_code": paso.exit_code,
                                        "refused": paso.estado == "refused", "error": paso.resultado if paso.estado == "error" else None})
            self._evento(
                "tool_result", tool_id=paso.accion, status=paso.estado, exit_code=paso.exit_code,
                run_id=paso.run_id, argv=paso.argv, summary=paso.resultado[:600], agent="investigador",
                seconds=paso.respuesta.segundos if paso.respuesta else None,
            )
            if paso.hallazgo:
                self._evento("finding", title=paso.hallazgo["title"], severity=paso.hallazgo["severity"],
                             agent="investigador", finding_id=paso.hallazgo["id"])
            if paso.tareas is not None:
                self._evento("tareas", tareas=paso.tareas, agent="investigador")
        if informe is None:
            informe = (
                f"Presupuesto de {max_pasos} pasos agotado sin informe. Tareas:\n{self.estado.tareas_texto()}\n"
                f"Hallazgos:\n{self.hallazgos.texto_compacto()}\nÚltimos pasos:\n{self.estado.pasos_texto()}"
            )
            self._evento("final", text=informe, agent="investigador", exhausted=True)
        self.memoria.indexar_texto("investigador", informe)
        self.estado.limpiar_ultimo()
        return informe

    # -- órdenes del revisor, una a una -------------------------------------------------------
    def _ejecutar_ordenes(self, ordenes: list[str]) -> str:
        """Cada orden es el objetivo del investigador durante pocos pasos. Las órdenes son
        además su lista de tareas: el operador ve el plan y cómo se va cerrando."""
        previas = [t for t in self.estado.tareas if t["estado"] in {"hecha", "descartada"}][-6:]
        tareas = [{"texto": t["texto"], "estado": t["estado"]} for t in previas]
        tareas += [{"texto": o, "estado": "pendiente"} for o in ordenes]
        self.estado.escribir_tareas(tareas)
        self._evento("tareas", tareas=self.estado.tareas, agent="revisor")
        informes = []
        for i, orden in enumerate(ordenes):
            if self.cancelado():
                break
            idx = len(previas) + i
            self.estado.tareas[idx]["estado"] = "en_curso"
            self.estado.guardar()
            self._evento("orden", agent="revisor", text=orden)
            objetivo = f"{orden} (pregunta del perito: «{self.prompt[:160]}»)"
            antes = len(self.estado.datos["pasos"])
            informe = self._investigar(objetivo, self.cfg.max_pasos_orden,
                                       langsmith_extra=trazas.metadatos(orden=orden, indice=idx))
            hizo_algo = self._acciones_desde(antes) > 0
            # Una orden que el investigador cerró sin ejecutar NADA no es una orden
            # cumplida. Medido el 2026-09-13: la segunda orden del plan se saltó con
            # «no se requiere realizar más análisis», se marcó «hecha» igual que la
            # primera, y el revisor aprobó el turno creyendo que se habían ejecutado las
            # dos. Marcarla como cumplida es decirle al operador algo que no pasó.
            self.estado.tareas[idx]["estado"] = "hecha" if hizo_algo else "descartada"
            self.estado.guardar()
            self._evento("tareas", tareas=self.estado.tareas, agent="revisor")
            if hizo_algo:
                informes.append(f"- Orden «{orden}»: {informe[:400]}")
            else:
                self.registro.anotar({
                    "action": "reviewer_order_abandoned", "case_id": self.case_id, "order": orden,
                    "reason": informe[:300], "engine": "local-fit-llm",
                })
                informes.append(f"- Orden «{orden}»: NO EJECUTADA. El investigador la cerró sin ejecutar "
                                f"ninguna herramienta. Lo que alegó: {informe[:300]}")
        return "\n".join(informes) if informes else "(sin órdenes ejecutadas)"

    #: Pasos que NO son trabajo: cerrar el turno, o una respuesta que no se pudo leer.
    _SIN_TRABAJO = frozenset({"informar", "(sin accion)", "(ilegible)"})

    def _acciones_desde(self, antes: int) -> int:
        """Cuántos pasos con acción real se dieron desde el índice `antes`."""
        return sum(1 for p in self.estado.datos["pasos"][antes:]
                   if p.get("accion") not in self._SIN_TRABAJO)

    # -- nodos del grafo (grafo.py) ----------------------------------------------------------
    def nodo_planificar(self, estado: dict[str, Any]) -> dict[str, Any]:
        """Reparto `revisor`: el revisor descompone la pregunta en órdenes concretas."""
        ordenes: list[str] = []
        if self.cfg.reparto == "revisor":
            self.iteracion += 1
            ordenes = self.revisor.planificar(self.prompt)
            self._contabilizar(None, self.revisor.ultima_respuesta)
            self._evento("plan", agent="revisor", orders=ordenes,
                         text="; ".join(ordenes) if ordenes else "sin órdenes: el investigador trabaja libre")
            for orden in ordenes:
                self.registro.anotar({"action": "reviewer_order", "case_id": self.case_id, "order": orden,
                                      "round": 0, "engine": "local-fit-llm"})
        return {"ronda": 1, "ordenes": ordenes, "terminado": False}

    def nodo_investigar(self, estado: dict[str, Any]) -> dict[str, Any]:
        ronda = estado.get("ronda", 1)
        ordenes = estado.get("ordenes") or []
        if ordenes and (ronda == 1 or self.cfg.reparto == "revisor"):
            informe = self._ejecutar_ordenes(ordenes)
            if ronda == 1:
                self._ordenes_dadas.extend(ordenes)
        else:
            max_pasos = self.cfg.max_pasos if ronda == 1 else self.cfg.max_pasos_orden
            informe = self._investigar(self._objetivo, max_pasos)
        self.metricas["rondas"] = ronda
        if self.cancelado():
            # «Parar»: no se gasta una llamada más en el revisor.
            return {"informe": informe, "respuesta": informe, "terminado": True}
        return {"informe": informe}

    def nodo_revisar(self, estado: dict[str, Any]) -> dict[str, Any]:
        if estado.get("terminado"):
            return {}
        ronda = estado.get("ronda", 1)
        informe = estado.get("informe") or ""
        max_rondas = self.cfg.max_rondas_revision + 1
        self.iteracion += 1
        veredicto = self.revisor.revisar(self.prompt, informe, ronda, max_rondas, self._ordenes_dadas)
        self._contabilizar(None, veredicto.respuesta_modelo)
        self.estado.anotar_ronda({"ronda": ronda, "aprobar": veredicto.aprobar, "ordenes": veredicto.ordenes,
                                  "informe": informe[:400]})
        self._evento("revision", agent="revisor", approved=veredicto.aprobar, orders=veredicto.ordenes,
                     text=veredicto.pensamiento or ("aprobado" if veredicto.aprobar else "pide revisión"))
        if veredicto.aprobar or self.cancelado():
            return {"respuesta": veredicto.respuesta or informe, "terminado": True}
        for orden in veredicto.ordenes:
            self._evento("orden", agent="revisor", text=orden)
            self.registro.anotar({"action": "reviewer_order", "case_id": self.case_id, "order": orden,
                                  "round": ronda, "engine": "local-fit-llm"})
        self._ordenes_dadas.extend(veredicto.ordenes)
        if self.cfg.reparto == "revisor":
            return {"ronda": ronda + 1, "ordenes": veredicto.ordenes, "terminado": False}
        self._objetivo = ("ORDEN DEL REVISOR sobre la pregunta del perito «" + self.prompt[:200] + "»: "
                          + " ; ".join(veredicto.ordenes))
        return {"ronda": ronda + 1, "ordenes": [], "terminado": False}

    # -- turno completo --------------------------------------------------------------------
    def ejecutar(self) -> dict[str, Any]:
        """Un turno: el grafo de `grafo.py` sobre los nodos de arriba, con persistencia
        y auditoría alrededor. Con LANGSMITH_TRACING=true todo el turno queda trazado."""
        inicio = time.monotonic()
        if self.persistir_chat:
            self.chats.anadir(self.sesion, "user", self.prompt)
        self.memoria.indexar_texto("perito", self.prompt)
        self.registro.anotar({
            "action": "agent_turn_start", "case_id": self.case_id, "evidence_id": self.evidencia.evidence_id,
            "session_id": self.sesion, "prompt_sha256": sha256_texto(self.prompt), "prompt_chars": len(self.prompt),
            "model": self.cfg.get("LOCALFIT_MODEL"), "memory": self.memoria.nombre, "reparto": self.cfg.reparto,
            "engine": "local-fit-llm",
        })
        self._objetivo = self.prompt
        self._ordenes_dadas = []
        # Las lecturas sostienen las citas de los hallazgos y son DE ESTE TURNO: lo que el
        # modelo leyó en el turno anterior ya no lo tiene delante y no puede citarlo.
        self.estado.olvidar_lecturas()
        respuesta = ""
        error: str | None = None
        try:
            final = self._correr_grafo(langsmith_extra=trazas.metadatos(
                case_id=self.case_id, session_id=self.sesion, evidence_id=self.evidencia.evidence_id,
                model=self.cfg.get("LOCALFIT_MODEL"), memory=self.memoria.nombre, reparto=self.cfg.reparto,
            ))
            respuesta = final.get("respuesta") or final.get("informe") or ""
            self.memoria.indexar_texto("revisor", respuesta)
        except ModeloError as exc:
            error = str(exc)
            respuesta = f"El motor local no pudo completar el turno: {exc}"
        segundos = round(time.monotonic() - inicio, 1)
        self.metricas["segundos_total"] = segundos
        if self.persistir_chat:
            self.chats.anadir(self.sesion, "assistant", respuesta, tool_calls=self.tool_calls, actividad=self.actividad)
        self.registro.anotar({
            "action": "agent_turn_finish", "case_id": self.case_id, "session_id": self.sesion,
            "reply_sha256": sha256_texto(respuesta), "error": error, "cancelled": self.cancelado(),
            "engine": "local-fit-llm", **self.metricas,
        })
        return {
            "reply": respuesta,
            "iterations": self.iteracion,
            "tool_calls": self.tool_calls,
            "evidence_id": self.evidencia.evidence_id,
            "case_id": self.case_id,
            "os_profile": self.perfil,
            "executor": IDENTIDAD_MOTOR,
            "agent": resumen_agente(self.cfg, self.perfil),
            "metrics": self.metricas,
            "tasks": self.estado.tareas,
            "error": error,
            "cancelled": self.cancelado(),
        }

    @trazas.trazable(name="turno local-fit-llm", run_type="chain")
    def _correr_grafo(self) -> dict[str, Any]:
        return grafo.construir(self).invoke({"ronda": 1, "ordenes": [], "terminado": False},
                                            config={"recursion_limit": 40})

def resumen_agente(cfg: Ajustes, perfil: str) -> dict[str, Any]:
    """Lo que la web pinta como «agente» (misma forma que AgentSummary del api)."""
    return {
        "id": "local-fit-llm",
        "name": "investigador + revisor",
        "version": "0.1",
        "os_profile": perfil,
        "authors": [],
        "model": {
            "name": cfg.get("LOCALFIT_MODEL") or "",
            "temperature": cfg.temperatura,
            "max_iterations": cfg.max_pasos,
        },
        "allowed_tools": sorted(PORTADAS),
        "path": "agentopsy-local-fit-llm/agentes/investigador.md",
        "memory": cfg.get("LOCALFIT_MEMORIA") or "estructurada",
    }
