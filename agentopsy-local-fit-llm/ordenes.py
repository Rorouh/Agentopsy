"""Qué es una orden ejecutable, y qué no.

El revisor descompone la pregunta del perito en órdenes para el investigador, y una
orden es PROSA. Hasta ahora lo único que se comprobaba era que el nombre de la
herramienta existiera (`herramienta inventada`), y eso deja pasar dos formas de orden
que el investigador no puede cumplir. Las dos se midieron el 2026-09-13 en la misma
corrida (traza `01a09bcb`):

- **Un parámetro que la herramienta nombrada no tiene**: «usa la herramienta
  strings_head con consulta: 'Administrator'|'WIN-'». `consulta` es de `buscar`, no de
  `strings_head`, que no filtra nada. El investigador ignoró esa mitad de la orden, se
  quedó con un volcado de 3.168.635 líneas y concluyó sin leerlo.
- **Una herramienta de contexto como orden**: «usa la herramienta ver_tareas».
  `ver_tareas` es contabilidad interna del agente, no una vía de investigación. Como
  orden es un paso perdido.

La regla de los parámetros, enunciada: **un parámetro nombrado en la orden tiene que
pertenecer a alguna de las herramientas nombradas en esa misma orden**. Así la forma
correcta del patrón de dos pasos («extrae las cadenas con strings_head» y después
«busca X en ese run con la herramienta buscar») sigue siendo válida, porque ahí
`consulta` va con `buscar`, que está nombrada.

Qué se hace con una orden inválida: se descarta y se audita, nunca se adivina lo que
el revisor quiso decir (RULE 2). Partir «strings_head con consulta X» en las dos
órdenes que probablemente quería sería inventar un plan que nadie escribió.

La fuente de verdad de los nombres y los parámetros son las MISMAS firmas que se le
ponen delante al modelo (`herramientas.forenses.PORTADAS` y
`herramientas.contexto.FIRMAS_CONTEXTO`): si una firma cambia, la validación cambia
con ella y no hay una segunda lista que mantener a mano.
"""

from __future__ import annotations

import re

from herramientas.contexto import FIRMAS_CONTEXTO, NOMBRES as CONTEXTO
from herramientas.forenses import PORTADAS, SHELL_ID

#: Herramientas de contexto que NO son una vía de investigación: llevan la contabilidad
#: del agente (su lista de tareas, lo que ya concluyó, qué herramientas hay). Como orden
#: no avanzan el caso. `buscar`, `leer_artefacto` y `listar_artefactos` sí quedan fuera de
#: esta lista: operan sobre las salidas y son la segunda mitad del patrón de dos pasos.
NO_SON_ORDEN = frozenset({"ver_tareas", "escribir_tareas", "ver_hallazgos", "ver_catalogo", "informar"})

_HERRAMIENTA_RE = re.compile(r"herramienta\s+['\"`]?([a-zA-Z_][a-zA-Z0-9_]*)", re.IGNORECASE)
#: `consulta:` o `consulta=`, que es como el modelo pega un parámetro a una orden.
_PARAMETRO_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]")
#: `nombre(param?: tipo, otro: tipo)` dentro de una firma.
_FIRMA_RE = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)")


def _parametros_de_firma(firma: str) -> tuple[str, set[str]]:
    m = _FIRMA_RE.search(firma)
    if not m:
        return "", set()
    nombre, dentro = m.group(1), m.group(2)
    params = set()
    for trozo in dentro.split(","):
        t = trozo.strip().split(":")[0].strip().rstrip("?").strip()
        if re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", t):
            params.add(t.lower())
    return nombre.lower(), params


def _tabla() -> dict[str, set[str]]:
    """`{herramienta: {parámetros}}` derivado de las firmas que ve el modelo."""
    tabla: dict[str, set[str]] = {}
    for h in PORTADAS.values():
        nombre, params = _parametros_de_firma(h.firma)
        if nombre:
            tabla[nombre] = params
    for linea in FIRMAS_CONTEXTO.splitlines():
        nombre, params = _parametros_de_firma(linea)
        if nombre:
            tabla[nombre] = params
    return tabla


PARAMETROS: dict[str, set[str]] = _tabla()
#: Todo nombre que en alguna firma es un parámetro. Solo se mira si una palabra de la
#: orden está aquí: una palabra cualquiera seguida de dos puntos no es un parámetro.
TODOS_LOS_PARAMETROS: frozenset[str] = frozenset().union(*PARAMETROS.values()) if PARAMETROS else frozenset()


def herramientas_nombradas(orden: str) -> list[str]:
    return [n.lower() for n in _HERRAMIENTA_RE.findall(orden)]


def motivo_inejecutable(orden: str, *, permitir_shell: bool = False) -> str | None:
    """El motivo por el que esta orden no se puede ejecutar, o `None` si está bien.

    El texto vuelve tal cual al registro de auditoría, así que nombra el problema
    concreto: es lo que un operador lee para entender por qué su plan encogió.
    """
    conocidas = set(PORTADAS) | set(CONTEXTO) | {"informar"}
    if not permitir_shell:
        conocidas.discard(SHELL_ID)

    nombradas = herramientas_nombradas(orden)
    for nombre in nombradas:
        if nombre not in conocidas:
            return f"herramienta inexistente: {nombre}"

    utiles = [n for n in nombradas if n not in NO_SON_ORDEN]
    if nombradas and not utiles:
        return (f"no es una orden de investigación: {nombradas[0]} lleva la contabilidad del "
                "agente, no avanza el caso")

    if not nombradas:
        return None
    permitidos: set[str] = set()
    for nombre in nombradas:
        permitidos |= PARAMETROS.get(nombre, set())
    for candidato in _PARAMETRO_RE.findall(orden):
        p = candidato.lower()
        if p in TODOS_LOS_PARAMETROS and p not in permitidos:
            dueños = sorted(n for n, ps in PARAMETROS.items() if p in ps)
            return (f"la orden pide '{p}' a {nombradas[0]}, que no lo tiene; '{p}' es de "
                    f"{', '.join(dueños)}. Si hace falta, son DOS órdenes")
    return None
