"""Herramientas de contexto (diseño, apartado 3.2): lo que convierte «recibirlo
todo» en «pedir lo que hace falta».

Todas devuelven recortes acotados. Ninguna carga el caso completo. El agente
navega los artefactos con `listar_artefactos`, `leer_artefacto` y `buscar`,
gestiona su lista con `ver_tareas`/`escribir_tareas` y deja constancia con
`registrar_hallazgo`. `informar` no está aquí: la resuelve el bucle (es el
paso que cierra el turno del investigador).
"""

from __future__ import annotations

import json
import re
from typing import Any

from artefactos.almacen import Almacen
from estado import Estado
from hallazgos import Hallazgos
from herramientas import forenses
from memoria.base import TOPE_HITS, Memoria
import trazas

FIRMAS_CONTEXTO = """- ver_tareas(): tu lista de tareas tal como la dejaste.
- escribir_tareas(tareas: [{texto, estado: pendiente|en_curso|hecha|descartada}]): reescribe tu lista completa.
- listar_artefactos(): qué salidas hay ya (run_id, herramienta, exit, líneas, ficheros).
- leer_artefacto(run_id, desde?: 1, n?: 40, fichero?: 'stdout.txt' | 'out/<nombre>'): un trozo de una salida, nunca entera.
- buscar(consulta, run_id?): dónde aparece un texto LITERAL en las salidas (líneas con run_id y nº de línea). Varios términos se separan con | o coma y se buscan por separado.
- ver_catalogo(): herramientas forenses disponibles para esta evidencia.
- registrar_hallazgo(titulo, resumen, severidad: low|medium|high|critical, run_id, confianza?: 0-1, observado_en?: ISO-8601 con zona, tipo?: afirmacion|descarte): deja constancia de una conclusión y su justificación.
- ver_hallazgos(): lo que llevas concluido.
- informar(texto): cierras tu turno: qué has averiguado, con qué runs, y qué queda sin determinar."""

NOMBRES = ("ver_tareas", "escribir_tareas", "listar_artefactos", "leer_artefacto", "buscar",
           "ver_catalogo", "registrar_hallazgo", "ver_hallazgos")

TOPE_ARTEFACTOS = 20


class Contexto:
    def __init__(self, *, estado: Estado, almacen: Almacen, memoria: Memoria,
                 hallazgos: Hallazgos, kind: str, evidence_id: str, agente: str,
                 shell: bool = False) -> None:
        self.shell = shell
        self.estado = estado
        self.almacen = almacen
        self.memoria = memoria
        self.hallazgos = hallazgos
        self.kind = kind
        self.evidence_id = evidence_id
        self.agente = agente

    def es_contexto(self, nombre: str) -> bool:
        return nombre in NOMBRES

    @trazas.trazable(name="herramienta de contexto", run_type="tool")
    def ejecutar(self, nombre: str, args: dict[str, Any] | None) -> tuple[str, dict[str, Any]]:
        """Devuelve (texto para el modelo, detalle para el operador)."""
        args = dict(args or {})
        metodo = getattr(self, f"_{nombre}", None)
        if metodo is None:
            raise KeyError(f"herramienta de contexto desconocida: {nombre}")
        return metodo(args)

    # -- tareas ----------------------------------------------------------------------
    def _ver_tareas(self, args: dict) -> tuple[str, dict]:
        return self.estado.tareas_texto(), {"tareas": self.estado.tareas}

    def _escribir_tareas(self, args: dict) -> tuple[str, dict]:
        tareas = args.get("tareas", args.get("lista", args.get("tasks")))
        if tareas is None and isinstance(args, dict) and args:
            # El modelo pequeño a veces manda la lista como valor único.
            valores = list(args.values())
            tareas = valores[0] if len(valores) == 1 else None
        if tareas is None:
            raise ValueError("escribir_tareas necesita 'tareas': una lista de {texto, estado}")
        nuevas = self.estado.escribir_tareas(tareas)
        return "tareas guardadas:\n" + self.estado.tareas_texto(), {"tareas": nuevas}

    # -- artefactos ------------------------------------------------------------------
    def _listar_artefactos(self, args: dict) -> tuple[str, dict]:
        filas = self.almacen.indice()
        if not filas:
            return "(no hay artefactos todavía)", {"artefactos": []}
        lineas = []
        for f in filas[-TOPE_ARTEFACTOS:]:
            lineas.append(
                f"- {f['run_id']} {f['tool_id']} exit={f['exit_code']} líneas={f['stdout_lines']} "
                f"bytes={f['stdout_size']} ficheros_out={f['output_files']}"
            )
        if len(filas) > TOPE_ARTEFACTOS:
            lineas.insert(0, f"(… {len(filas) - TOPE_ARTEFACTOS} anteriores)")
        return "\n".join(lineas), {"artefactos": filas[-TOPE_ARTEFACTOS:]}

    def _leer_artefacto(self, args: dict) -> tuple[str, dict]:
        run_id = _run_id_de(args)
        if not run_id:
            raise ValueError("leer_artefacto necesita run_id (mira listar_artefactos)")
        run_id = self._completar_run_id(run_id)
        desde = _entero(args.get("desde", args.get("from", 1)), 1)
        n = _entero(args.get("n", args.get("lineas", 40)), 40)
        fichero = args.get("fichero") or args.get("file")
        if fichero is None:
            ficheros = self.almacen.ficheros(run_id)
            out = [f["fichero"] for f in ficheros if f["fichero"].startswith("out/")]
            m = self.almacen.manifiesto(run_id)
            if (m.get("stdout_size") or 0) == 0 and out:
                listado = ", ".join(out[:25]) + (" …" if len(out) > 25 else "")
                return (f"stdout vacío; este run tiene ficheros en out/: {listado}. "
                        f"Lee uno con fichero='out/<nombre>'."), {"ficheros": out}
        trozo = self.almacen.leer(run_id, desde=desde, n=n, fichero=fichero)
        cabecera = (f"{run_id[:8]}:{trozo['fichero']} líneas {trozo['desde']}-"
                    f"{trozo['desde'] + len(trozo['lineas']) - 1} de {trozo['total_lineas']}"
                    + (" (hay más)" if trozo["truncado"] else ""))
        return cabecera + "\n" + "\n".join(trozo["lineas"]), trozo

    def _buscar(self, args: dict) -> tuple[str, dict]:
        consulta = args.get("consulta") or args.get("query") or args.get("texto") or args.get("q")
        if not consulta or not isinstance(consulta, str):
            raise ValueError("buscar necesita 'consulta': el texto a localizar")
        # La consulta es texto LITERAL, no un patrón: un "*" busca asteriscos y devuelve
        # ruido. Se rechaza antes de gastar un paso en una búsqueda que no dice nada.
        if not any(ch.isalnum() for ch in consulta) or len(consulta.strip().strip("|,")) < 3:
            raise ValueError(
                f"consulta {consulta!r} no sirve: buscar localiza texto LITERAL, no admite comodines. "
                "Usa un término concreto: Administrator, WIN-, C:\\Users, sqlmap, password, 192.168."
            )
        run_id = _run_id_de(args)
        if run_id:
            run_id = self._completar_run_id(run_id)
        # Varios términos en una consulta: el modelo escribe «Administrator|WIN-» o
        # «sqlmap, mimikatz» esperando alternativas, y buscar es LITERAL, así que esa
        # cadena entera no aparece en ningún sitio y devolvía cero. Se buscan por
        # separado y se dice cuál aportó: la búsqueda sigue siendo literal, lo que
        # cambia es que se entiende cómo la pide quien la pide.
        terminos = [_limpiar(t) for t in re.split(r"[|,]|\bOR\b|\bAND\b|\s+o\s+", consulta, flags=re.IGNORECASE)]
        terminos = [t for t in terminos if t]
        if len(terminos) <= 1:
            terminos = [consulta]
        hits, vistos, vacios = [], set(), []
        for termino in terminos:
            parciales = self.memoria.buscar(termino, k=max(3, TOPE_HITS // len(terminos)), run_id=run_id)
            if not parciales:
                vacios.append(termino)
            for h in parciales:
                clave = (h.run_id, h.fichero, h.linea)
                if clave not in vistos:
                    vistos.add(clave)
                    hits.append(h)
        donde = f" en {run_id[:8]}" if run_id else ""
        if not hits:
            return (f"sin coincidencias para {', '.join(repr(t) for t in terminos)}{donde}. "
                    "Prueba otro término, más corto o distinto."), {"hits": []}
        cabecera = f"{len(hits)} coincidencias{donde}"
        if vacios:
            cabecera += f" (sin coincidencias: {', '.join(vacios)})"
        return cabecera + ":\n" + "\n".join(h.a_texto() for h in hits), {"hits": [h.__dict__ for h in hits]}

    def _ver_catalogo(self, args: dict) -> tuple[str, dict]:
        filtro = args.get("filtro") or args.get("kind") or self.kind
        kind = filtro if filtro in ("memory", "disk", "container", "document") else self.kind
        filas = forenses.catalogo(kind, permitir_shell=self.shell)
        return "\n".join(f"- {f['firma']}" for f in filas), {"catalogo": filas}

    # -- hallazgos -------------------------------------------------------------------
    def _registrar_hallazgo(self, args: dict) -> tuple[str, dict]:
        if "run_id" in args and isinstance(args["run_id"], str) and args["run_id"]:
            args["run_id"] = self._completar_run_id(args["run_id"])
        h = self.hallazgos.registrar(args, evidence_id=self.evidence_id, agente=self.agente)
        return f"hallazgo registrado [{h['severity']}] {h['title']} (id {h['id'][:8]})", {"hallazgo": h}

    def _ver_hallazgos(self, args: dict) -> tuple[str, dict]:
        return self.hallazgos.texto_compacto(), {"hallazgos": self.hallazgos.listar()}

    # -- utilidades ------------------------------------------------------------------
    def _completar_run_id(self, parcial: str) -> str:
        """Acepta el prefijo del run_id que el modelo vio en los resúmenes."""
        parcial = parcial.strip()
        candidatos = [f["run_id"] for f in self.almacen.indice() if f["run_id"].startswith(parcial)]
        if len(candidatos) == 1:
            return candidatos[0]
        if not candidatos:
            raise ValueError(f"run_id {parcial!r} no existe en este caso; mira listar_artefactos()")
        raise ValueError(f"run_id {parcial!r} es ambiguo; usa más caracteres")


def _limpiar(termino: str) -> str:
    """Un término tal y como lo escribe el modelo: con comillas, espacios o paréntesis
    alrededor. La búsqueda es literal, así que un `'Administrator'` entrecomillado no
    aparece en ninguna salida; se quitan los adornos y se busca la palabra."""
    return termino.strip().strip("\"'`()[]<>").strip()


def _run_id_de(args: dict) -> str | None:
    for clave in ("run_id", "run", "artefacto", "id"):
        v = args.get(clave)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _entero(valor: Any, defecto: int) -> int:
    try:
        return int(valor)
    except (TypeError, ValueError):
        return defecto


def firmas_forenses(kind: str, excluir: set[str] | None = None, permitir_shell: bool = False) -> str:
    return forenses.firmas(kind, excluir, permitir_shell)


def resumen_json(datos: Any, tope: int = 300) -> str:
    texto = json.dumps(datos, ensure_ascii=False, sort_keys=True)
    return texto if len(texto) <= tope else texto[:tope] + "…"
