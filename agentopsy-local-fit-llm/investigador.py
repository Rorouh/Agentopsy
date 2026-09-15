"""Agente investigador: identifica la evidencia, ejecuta herramientas y produce
hallazgos. Un paso por llamada al modelo (RA-5, RA-6).

Cada paso monta el prompt pequeño del diseño (apartado 5): identidad, lista de
tareas, último resultado acotado, firmas de herramientas, punteros del caso y
lo que pidió el perito. Nunca la conversación entera, nunca el catálogo
completo, nunca un artefacto sin haberlo pedido. Si aun así no cabe en la
ventana, se recorta el último resultado y los pasos previos antes de enviar.

La instrucción de formato va AL FINAL del prompt: es lo que sobrevive a
cualquier recorte y lo que la prueba B demostró que el modelo pequeño sigue.
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from chats import Chats
from configuracion import Ajustes, Ventana
from custodia.ingesta import Evidencia
from custodia.registro import Registro, sha256_texto
from estado import Estado
from hallazgos import Hallazgos
from herramientas.contexto import FIRMAS_CONTEXTO, NOMBRES as CONTEXTO, Contexto, firmas_forenses
from herramientas.ejecutor import Ejecutor
from herramientas.forenses import PORTADAS, SHELL_ID
from modelo import Modelo, ModeloError, PromptDemasiadoLargo, Respuesta
import trazas

RUTA_IDENTIDAD = Path(__file__).parent / "agentes" / "investigador.md"
#: Una fecha INEQUÍVOCA: año-mes-día y hora. A propósito no reconoce un `20150902`
#: suelto, que en este mismo caso aparece dentro de `sqlmap/1.0-dev-nongit-20150902` y
#: no es la hora de nada: pedir una marca temporal por eso sería pedir que se invente.
_FECHA_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")
TOPE_ULTIMO_RESULTADO = 1200
TOPE_INFORME = 1500
HERRAMIENTAS_UNA_VEZ = {"file_info", "hashdeep"}
# Un fallo con esta marca en la PISTA es estructural (no depende de los parámetros): la
# herramienta deja de ofrecerse para esta evidencia en el resto de la sesión.
MARCAS_FALLO_ESTRUCTURAL = ("no ha podido perfilar este volcado", "no está en el maletín")

FORMATO = (
    'Paso {n} de {max}. {extra}Elige UNA sola acción de las herramientas. Responde SOLO con un objeto JSON: '
    '{{"pensamiento": "por qué este paso", "accion": "nombre_de_herramienta", "args": {{...}}}}. '
    'Para terminar: {{"pensamiento": "...", "accion": "informar", '
    '"args": {{"texto": "qué has averiguado, con qué run_id, y qué queda sin determinar"}}}}.'
)


@dataclass
class Paso:
    n: int
    pensamiento: str
    accion: str
    args: dict[str, Any]
    resultado: str
    estado: str                      # ok | nonzero | error | refused | informe
    run_id: str | None = None
    argv: list[str] | None = None
    exit_code: int | None = None
    informe: str | None = None
    hallazgo: dict[str, Any] | None = None
    tareas: list[dict[str, Any]] | None = None
    respuesta: Respuesta | None = None
    detalle: dict[str, Any] = field(default_factory=dict)

    @property
    def terminado(self) -> bool:
        return self.informe is not None


class Investigador:
    nombre = "investigador"

    def __init__(
        self,
        *,
        cfg: Ajustes,
        modelo: Modelo,
        contexto: Contexto,
        ejecutor: Ejecutor,
        estado: Estado,
        evidencia: Evidencia,
        hallazgos: Hallazgos,
        chats: Chats,
        sesion: str,
        registro: Registro,
        indexar: Callable[[str, str, list[Path]], Any] | None = None,
    ) -> None:
        self.cfg = cfg
        self.modelo = modelo
        self.contexto = contexto
        self.ejecutor = ejecutor
        self.estado = estado
        self.evidencia = evidencia
        self.hallazgos = hallazgos
        self.chats = chats
        self.sesion = sesion
        self.registro = registro
        self.indexar = indexar
        self.identidad = RUTA_IDENTIDAD.read_text(encoding="utf-8").strip()

    # -- prompt --------------------------------------------------------------------
    # El mensaje de sistema es ESTABLE entre pasos (identidad + firmas): el servidor del
    # modelo reutiliza la caché KV del prefijo común y solo paga el prefill de lo que
    # cambia. Lo variable va en el mensaje de usuario, con la instrucción de formato al
    # final, que es lo que sobrevive a cualquier recorte (prueba B).
    def sistema(self) -> str:
        retiradas = set(self.retiradas())
        return (
            self.identidad
            + "\n\nHERRAMIENTAS FORENSES:\n" + firmas_forenses(self.evidencia.kind, retiradas, self.cfg.shell)
            + "\n\nHERRAMIENTAS DE CONTEXTO:\n" + FIRMAS_CONTEXTO
        )

    def retiradas(self) -> dict[str, str]:
        """Herramientas forenses que ya no se ofrecen en esta sesión, con el motivo:
        las de una sola vez ya ejecutadas (su resultado está en el artefacto) y las que
        fallaron por una causa estructural (para esta evidencia no van a funcionar).
        Es lo que evita el bucle «repetir la misma llamada» de los modelos pequeños:
        no se les pide que no la repitan, deja de estar en la lista."""
        salida: dict[str, str] = {}
        for p in self.estado.datos["pasos"]:
            accion = p["accion"]
            if accion not in PORTADAS or not p.get("run_id"):
                continue
            if accion in HERRAMIENTAS_UNA_VEZ and p["estado"] == "ok":
                salida[accion] = f"ya ejecutada (run {p['run_id'][:8]}); su salida está en el artefacto"
            resultado = p.get("resultado") or ""
            if any(marca in resultado for marca in MARCAS_FALLO_ESTRUCTURAL):
                salida[accion] = f"no sirve con esta evidencia (run {p['run_id'][:8]}): {resultado[:120]}"
        return salida

    def _extra_formato(self) -> str:
        """Lo que va pegado a la instrucción final, donde el modelo pequeño más lo lee."""
        extra = ""
        pasos = self.estado.datos["pasos"]
        if pasos and pasos[-1]["estado"] == "refused":
            retiradas = set(self.retiradas())
            disponibles = [h for h in PORTADAS if self.evidencia.kind in PORTADAS[h].kinds and h not in retiradas
                           and (h != SHELL_ID or self.cfg.shell)]
            extra += (f"Tu acción anterior ({pasos[-1]['accion']}) fue rechazada: elige otra distinta. "
                      f"Forenses disponibles ahora: {', '.join(disponibles)}; o una de contexto. ")
        if not self.estado.tareas and self.cfg.reparto == "investigador":
            extra += "Aún no tienes lista de tareas: en este paso escríbela con escribir_tareas (3 a 6 tareas concretas). "
        extra += self._hechos()
        return extra

    def _hechos(self) -> str:
        """Hechos del estado, en positivo. La versión anterior decía «salidas grandes aún
        sin buscar ni leer», y cuando la lista estaba vacía el modelo lo leía como
        «no hay nada que hacer» y se saltaba la orden. Ahora solo se nombra lo que SÍ
        está disponible para explotar, y nunca en forma de ausencia."""
        leidos = set()
        for p in self.estado.datos["pasos"]:
            if p["accion"] in {"buscar", "leer_artefacto"}:
                leidos.add(p["args"][:200])
        pendientes = []
        for f in self.contexto.almacen.indice():
            if f["exit_code"] != 0 or ((f["stdout_lines"] or 0) < 30 and not f["output_files"]):
                continue
            corto = f["run_id"][:8]
            if not any(corto in linea or f["run_id"] in linea for linea in leidos):
                # El TAMAÑO va aquí, no solo en el resumen de la herramienta: el resumen
                # vive en ÚLTIMO RESULTADO y lo pisa el paso siguiente, mientras que esto
                # persiste. Medido el 2026-09-13: el modelo concluyó sobre un strings de
                # 3.168.635 líneas del que tenía 25 delante, y para cuando decidió, el
                # dato de cuántas líneas había ya no estaba en su contexto.
                lineas = f["stdout_lines"] or 0
                pendientes.append(f"{f['tool_id']} (run {corto}, {lineas} líneas)" if lineas
                                  else f"{f['tool_id']} (run {corto})")
        if not pendientes:
            return ""
        return "Salidas ya disponibles para explotar con buscar o leer_artefacto: " + ", ".join(pendientes[-4:]) + ". "

    def _calificar(self) -> str:
        """El crudo se sella SIEMPRE al terminar la herramienta (RC-5, RC-7); lo que no
        decide el sistema es si ese crudo sostiene un hallazgo. Esa determinación es del
        investigador y aquí se le pone delante en cuanto hay una salida sin calificar, en
        vez de esperar a que se acuerde de `registrar_hallazgo`: una salida que nadie
        califica no desaparece, pero se queda fuera del expediente.

        Un `descarte` es una respuesta legítima: deja constancia de que esa vía no aportó.
        """
        pasos = self.estado.datos["pasos"]
        if not pasos:
            return ""
        ultimo = pasos[-1]
        if ultimo["estado"] != "ok" or not ultimo.get("run_id"):
            return ""
        # Material es lo que produjo una herramienta forense O lo que una búsqueda/lectura
        # sacó de un artefacto ya sellado: en los dos casos el crudo está en custodia y lo
        # que falta es la determinación pericial.
        if ultimo["accion"] not in PORTADAS and ultimo["accion"] not in {"buscar", "leer_artefacto"}:
            return ""
        # No se compara contra los run_id ya citados: una búsqueda saca material NUEVO de
        # un artefacto que quizá ya sostenía otro hallazgo, y comparando run_id el aviso
        # se callaba justo cuando el agente acababa de encontrar el usuario y el equipo.
        # Tras registrar, el último paso deja de ser material y el aviso desaparece solo.
        origen = ("la salida del run" if ultimo["accion"] in PORTADAS else "lo que acabas de leer del run")
        # El aviso pide la CITA, no solo el run_id. Pedir «regístralo AHORA» a secas, con una
        # salida de la que solo se ha visto la cabecera, es invitar a concluir sin leer: es
        # justo lo que se midió el 2026-09-13. Registrar exige una línea leída (custodia/cita.py).
        # El aviso de la fecha sale SOLO si el material que tiene delante la lleva: un valor
        # de registro no tiene hora, y pedirla siempre invitaría a inventársela. La
        # consecuencia de omitirla es real y por eso se le dice: sin `observed_at` el
        # hallazgo no entra en la cronología del INCIDENTE (timeline/hallazgos.py), la
        # línea que un tercero lee primero.
        fecha = (" Si la línea que cites lleva fecha, ponla en observado_en con su zona."
                 if _FECHA_RE.search(ultimo.get("texto") or "") else "")
        return (f"{origen.capitalize()} {ultimo['run_id'][:8]} ya está sellado en la cadena de custodia.{fecha} "
                "Decide TÚ si sostiene algo del caso: si sí, regístralo con registrar_hallazgo citando run_id "
                f"'{ultimo['run_id'][:8]}' y en 'cita' la línea leída que lo sostiene; si no aporta, regístralo "
                "con tipo 'descarte' o sigue por otra vía. ")

    def _salida_orden(self, n: int) -> str:
        """La puerta de salida («no se puede cumplir») se abre a partir del SEGUNDO paso.
        Ofrecida en el primero, un modelo pequeño la toma antes de intentar nada: medido,
        se saltó una orden de `strings_head` alegando que el volcado era muy grande."""
        if self.cfg.reparto != "revisor" or n < 2:
            return ""
        return ("Si la orden ya no se puede cumplir con lo que hay, usa informar diciendo por qué. ")

    #: Lo último que se le puso delante al modelo, ya recortado por la ventana. Lo fija
    #: `_bloques` y lo consume `prompt()` para anotar la lectura del intento que se envía.
    _mostrado: str = ""

    def _bloques(self, objetivo: str, n: int, max_pasos: int, *, tope_resultado: int,
                 con_pasos: bool, con_conversacion: bool) -> str:
        ev = self.evidencia.puntero()
        indice = self.contexto.almacen.indice()
        cabecera = (
            f"CASO: evidencia {ev['nombre']} (tipo {ev['kind']}, {ev['tamano_mb']} MB, sha256 {ev['sha256']}); "
            f"artefactos: {len(indice)}; hallazgos: {len(self.hallazgos.listar())}."
        )
        partes = [cabecera, f"PERITO PIDE: {objetivo}"]
        if con_conversacion:
            partes.append("CONVERSACIÓN RECIENTE:\n" + self.chats.ultimos_turnos_texto(self.sesion))
        partes.append("TUS TAREAS:\n" + self.estado.tareas_texto())
        if con_pasos:
            partes.append("PASOS ANTERIORES:\n" + self.estado.pasos_texto())
        ultimo = self.estado.ultimo_resultado()
        self._mostrado = ""
        if ultimo:
            texto = ultimo.get("texto") or ""
            if len(texto) > tope_resultado:
                texto = texto[:tope_resultado] + "… (recortado; usa leer_artefacto o buscar para más)"
            # Lo que de VERDAD se le pone delante, ya recortado por la ventana. `prompt()`
            # lo anota como lectura solo si este intento es el que acaba enviándose: lo que
            # el modelo no llegó a ver no puede sostener la cita de un hallazgo.
            self._mostrado = texto
            partes.append(f"ÚLTIMO RESULTADO ({ultimo.get('accion')} {ultimo.get('args') or ''}):\n{texto}")
        partes.append(FORMATO.format(
            n=n, max=max_pasos,
            extra=self._extra_formato() + self._calificar() + self._salida_orden(n)))
        return "\n\n".join(partes)

    def prompt(self, objetivo: str, n: int, max_pasos: int) -> tuple[str, str, int]:
        """Devuelve (system, user, tokens_estimados) garantizando la ventana antes de enviar."""
        system = self.sistema()
        intentos = (
            dict(tope_resultado=TOPE_ULTIMO_RESULTADO, con_pasos=True, con_conversacion=True),
            dict(tope_resultado=700, con_pasos=True, con_conversacion=False),
            dict(tope_resultado=400, con_pasos=False, con_conversacion=False),
            dict(tope_resultado=200, con_pasos=False, con_conversacion=False),
        )
        ultimo_error: PromptDemasiadoLargo | None = None
        for opciones in intentos:
            user = self._bloques(objetivo, n, max_pasos, **opciones)
            try:
                estimado = self.modelo.comprobar_ventana(system, user)
            except PromptDemasiadoLargo as exc:
                ultimo_error = exc
                continue
            self.estado.anotar_lectura(self._mostrado)
            return system, user, estimado
        assert ultimo_error is not None
        raise ultimo_error

    # -- un paso -------------------------------------------------------------------
    @trazas.trazable(name="investigador.paso", run_type="chain")
    def paso(self, objetivo: str, n: int, max_pasos: int) -> Paso:
        system, user, estimado = self.prompt(objetivo, n, max_pasos)
        try:
            resp = self.modelo.preguntar(system, user)
        except ModeloError as exc:
            self._auditar_llamada(None, system, user, estimado, error=str(exc))
            raise
        self._auditar_llamada(resp, system, user, estimado)
        try:
            datos = resp.json()
        except ModeloError as exc:
            paso = Paso(n, "", "(respuesta ilegible)", {}, f"ERROR: {exc}", "error", respuesta=resp)
            self.estado.anotar_paso(agente=self.nombre, accion="(ilegible)", args=None,
                                    resultado=f"tu respuesta no era JSON válido: {resp.texto[:120]!r}", estado="error")
            return paso
        pensamiento, accion, args = interpretar(datos)
        paso = Paso(n, pensamiento, accion, args, "", "ok", respuesta=resp)
        self._despachar(paso)
        return paso

    def _nombre_real(self, accion: str) -> str:
        """Corrige una errata evidente en el nombre («lee_artefacto» por «leer_artefacto»).
        Un modelo pequeño falla el nombre de vez en cuando y cada fallo cuesta un paso
        entero de 20-90 s: se corrige y se sigue, no se gasta el turno en enseñarle a
        deletrear. Un nombre que no se parezca a ninguno sigue rechazándose."""
        conocidas = [h for h in PORTADAS if h != SHELL_ID or self.cfg.shell] + list(CONTEXTO) + ["informar"]
        if accion in conocidas:
            return accion
        # Con la terminal encendida, el modelo la pide por su nombre de siempre.
        if self.cfg.shell and accion.lower() in {"cmd", "bash", "sh", "terminal", "consola", "run", "exec", "comando"}:
            return SHELL_ID
        # «volatility3 - plugin windows.pslist.PsList» es la herramienta más el argumento
        # pegados: el nombre está al principio, y quedarse con él cuesta cero.
        primera = re.split(r"[^a-zA-Z0-9_]+", accion.strip())[0].lower()
        if primera in conocidas:
            return primera
        cercanas = difflib.get_close_matches(accion.lower(), conocidas, n=1, cutoff=0.75)
        return cercanas[0] if cercanas else accion

    def _despachar(self, paso: Paso) -> None:
        paso.accion = self._nombre_real(paso.accion)
        accion, args = paso.accion, paso.args
        if accion == "informar":
            texto = str(args.get("texto") or args.get("informe") or args.get("text") or paso.pensamiento or "").strip()
            paso.informe = texto[:TOPE_INFORME] or "(el investigador no dejó informe)"
            paso.estado = "informe"
            paso.resultado = paso.informe
            self.estado.anotar_paso(agente=self.nombre, accion="informar", args=None, resultado=paso.informe, estado="informe")
            return
        if self.contexto.es_contexto(accion):
            repetido = self._repetido(accion, args)
            if repetido:
                paso.estado, paso.resultado = "refused", repetido
                self.estado.anotar_paso(agente=self.nombre, accion=accion, args=args, resultado=repetido, estado="refused")
                return
            try:
                texto, detalle = self.contexto.ejecutar(accion, args)
                paso.detalle = detalle
                if accion == "registrar_hallazgo":
                    paso.hallazgo = detalle.get("hallazgo")
                if accion == "escribir_tareas":
                    paso.tareas = detalle.get("tareas")
                # El material que sostiene un hallazgo puede salir de una búsqueda o de la
                # lectura de un artefacto: se anota de qué run vino para poder citarlo.
                if accion == "buscar" and detalle.get("hits"):
                    paso.run_id = detalle["hits"][0].get("run_id")
                elif accion == "leer_artefacto" and detalle.get("run_id"):
                    paso.run_id = detalle["run_id"]
            except (ValueError, KeyError) as exc:
                texto, paso.estado = f"ERROR en {accion}: {exc}", "error"
            paso.resultado = texto
            self.estado.anotar_paso(agente=self.nombre, accion=accion, args=args, resultado=texto,
                                    run_id=paso.run_id, estado=paso.estado)
            return
        if accion in PORTADAS:
            retirada = self.retiradas().get(accion)
            if retirada:
                paso.estado = "refused"
                paso.resultado = f"NO DISPONIBLE: {accion} {retirada}. Elige otra herramienta de la lista."
                self.estado.anotar_paso(agente=self.nombre, accion=accion, args=args, resultado=paso.resultado, estado="refused")
                return
            repetido = self._repetido(accion, args)
            if repetido:
                paso.estado = "refused"
                paso.resultado = repetido
                self.estado.anotar_paso(agente=self.nombre, accion=accion, args=args, resultado=repetido, estado="refused")
                return
            r = self.ejecutor.ejecutar(accion, args)
            paso.run_id, paso.argv, paso.exit_code, paso.estado = r.run_id, r.argv, r.exit_code, r.estado
            paso.resultado = r.resumen
            paso.detalle = r.detalle
            if r.run_id and r.estado in {"ok", "nonzero"} and self.indexar is not None:
                almacen = self.contexto.almacen
                ficheros = [almacen.ruta_stdout(r.run_id)] + [
                    almacen.ruta_out(r.run_id) / f["relpath"] for f in almacen.manifiesto(r.run_id).get("output_files") or []
                ]
                paso.detalle["indexado"] = self.indexar(r.run_id, accion, ficheros)
            self.estado.anotar_paso(agente=self.nombre, accion=accion, args=args, resultado=r.resumen,
                                    run_id=r.run_id, estado=r.estado)
            return
        texto = (f"ERROR: la acción {accion!r} no existe. Herramientas forenses: {', '.join(sorted(PORTADAS))}; "
                 "de contexto: ver_tareas, escribir_tareas, listar_artefactos, leer_artefacto, buscar, ver_catalogo, "
                 "registrar_hallazgo, ver_hallazgos, informar.")
        paso.estado, paso.resultado = "refused", texto
        self.estado.anotar_paso(agente=self.nombre, accion=accion, args=args, resultado=texto, estado="refused")

    #: Herramientas de contexto que cuestan un paso entero y son deterministas: repetirlas
    #: con los mismos argumentos devuelve exactamente lo mismo. Medido: el agente buscó dos
    #: veces seguidas «Administrator» en el mismo artefacto y perdió un paso de 60 s.
    REPETIBLES_CONTEXTO = ("buscar", "leer_artefacto", "listar_artefactos", "ver_hallazgos", "ver_catalogo")

    def _repetido(self, accion: str, args: dict[str, Any]) -> str | None:
        """La misma llamada con los mismos parámetros no se relanza: el resultado ya está
        (en un artefacto, o en el paso anterior). Es lo que evita los bucles medidos."""
        firma = json.dumps(args or {}, sort_keys=True, ensure_ascii=False)
        for p in self.estado.datos["pasos"]:
            if p["accion"] != accion or p["estado"] not in {"ok", "nonzero"}:
                continue
            if json.dumps(_args_de_resumen(p["args"]), sort_keys=True, ensure_ascii=False) != firma:
                continue
            if accion in PORTADAS and p.get("run_id"):
                return (f"YA EJECUTADO: {accion} con esos mismos parámetros es el run {p['run_id']} "
                        f"(paso {p['n']}, resultado: {p['resultado'][:120]}). Repetirlo no cambia nada: "
                        "lee ese artefacto (leer_artefacto/buscar) o elige otra vía.")
            if accion in self.REPETIBLES_CONTEXTO:
                return (f"YA HECHO en el paso {p['n']}: {accion} con esos mismos argumentos devolvió esto, y "
                        f"devolvería lo mismo:\n{p['resultado'][:400]}\n"
                        "Da el paso siguiente: califica lo que ya tienes con registrar_hallazgo, busca OTRO "
                        "término, o cierra con informar.")
        return None

    def _auditar_llamada(self, resp: Respuesta | None, system: str, user: str, estimado: int,
                         error: str | None = None) -> None:
        evento: dict[str, Any] = {
            "action": "model_call",
            "agent": self.nombre,
            "case_id": self.evidencia.case_id,
            "model": self.cfg.get("LOCALFIT_MODEL"),
            "prompt_sha256": sha256_texto(system + "\n" + user),
            "prompt_chars": len(system) + len(user),
            "prompt_tokens_estimated": estimado,
            "engine": "local-fit-llm",
        }
        if resp is not None:
            evento.update({
                "prompt_tokens": resp.prompt_tokens,
                "eval_count": resp.tokens_generados,
                "seconds": resp.segundos,
                "prefill_seconds": resp.segundos_prefill,
                "generation_seconds": resp.segundos_generacion,
                "response_sha256": sha256_texto(resp.texto),
            })
        if error:
            evento["error"] = error
        self.registro.anotar(evento)


def interpretar(datos: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    """Del JSON del modelo a (pensamiento, accion, args), tolerando variantes de nombre."""
    pensamiento = str(datos.get("pensamiento") or datos.get("razonamiento") or datos.get("thought") or datos.get("reasoning") or "").strip()
    accion: Any = None
    for clave in ("accion", "acción", "herramienta", "tool", "action", "name", "tool_name", "function"):
        if clave in datos and datos[clave]:
            accion = datos[clave]
            break
    args: Any = None
    for clave in ("args", "argumentos", "parametros", "parámetros", "params", "arguments", "input", "parameters"):
        if clave in datos and datos[clave] is not None:
            args = datos[clave]
            break
    if isinstance(accion, dict):
        interno = accion
        accion = interno.get("nombre") or interno.get("name") or interno.get("accion") or interno.get("tool")
        if args is None:
            args = interno.get("args") or interno.get("params") or interno.get("arguments") or {
                k: v for k, v in interno.items() if k not in {"nombre", "name", "accion", "tool"}
            }
    if accion is None:
        for clave in ("informar", "informe", "respuesta", "final", "answer", "report"):
            if clave in datos and isinstance(datos[clave], str) and datos[clave].strip():
                return pensamiento, "informar", {"texto": datos[clave]}
        return pensamiento, "(sin accion)", {}
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            args = {"texto": args}
    if not isinstance(args, dict):
        args = {} if args is None else {"valor": args}
    accion = str(accion).strip().strip("()")
    return pensamiento, accion, args


def _args_de_resumen(resumen: str) -> Any:
    try:
        return json.loads(resumen) if resumen else {}
    except ValueError:
        return {"_": resumen}
