"""El MODELO del grafo de relaciones: dos enums cerradas y las puertas que las
hacen valer.

El grafo responde a «qué se conecta con qué» dentro de UN hallazgo: qué máquina,
qué cuenta, qué fichero, qué dominio y qué IP intervienen, y con qué relación
entre ellos. Los nodos NO salen de datos estructurados, porque Agentopsy no tiene
entidades tipadas: viven dentro del ``summary`` del hallazgo, en prosa. Los extrae
el modelo, y por eso este módulo existe: **un grafo extraído por un modelo es, por
defecto, indistinguible de un grafo inventado.**

Tres barreras, en este orden, y las dos primeras viven aquí:

1. **Referentes cerrados.** Toda entidad propuesta tiene que aparecer LITERALMENTE
   en el ``title`` o el ``summary`` del hallazgo (subcadena, insensible a
   mayúsculas). Una entidad que no esté en el texto es fabricación y tumba el
   grafo entero. Es el mismo criterio de la puerta 3 de ``forensia.reports.writer``
   (``_validar_referentes``): lo que se cita tiene que existir ya en el material.
2. **Enums cerradas.** Cinco tipos de nodo y trece de relación, y nada más. Un
   tipo inventado tumba el grafo, igual que un id ATT&CK alucinado tumba el
   hallazgo (``findings.store._validate_mitre_hints``). El rechazo ENUMERA los
   valores válidos porque viaja al modelo como cuerpo de error: el coste tiene
   que ser un reintento, no un grafo perdido.
3. La tercera barrera no es de validación y por eso no está aquí: el texto del
   hallazgo viaja DELIMITADO y anunciado como datos (``extractor``), y la
   interfaz lo pinta como texto, nunca como HTML (SECURITY INVARIANT 8).

Un detalle del modelo que se respeta a propósito, tomado de Nexus (PowerForensics),
la referencia de este apartado: **no hay tipo «proceso»**. Un proceso se representa
por su EJECUTABLE, que es un nodo ``file``. No se añade un sexto tipo.

Lógica pura (RULE 3): sin HTTP, sin disco, sin llamadas al modelo.
"""

from __future__ import annotations

from forensia.i18n import Mensaje

import re
from typing import Any

#: Tipos de NODO. Enum cerrada de cinco valores, calcada de Nexus.
TIPOS_NODO: tuple[str, ...] = ("ip", "domain", "hostname", "user", "file")

#: Tipos de RELACIÓN. Enum cerrada de trece valores, calcada de Nexus.
TIPOS_RELACION: tuple[str, ...] = (
    "connection",
    "process_spawn",
    "network_connection",
    "lateral_move",
    "malware",
    "c2",
    "exfiltration",
    "beacon",
    "persistence",
    "priv_esc",
    "rce",
    "logon",
    "file_transfer",
)

#: Cotas de la respuesta. Acotan lo absurdo (una respuesta que se desboca sobre un
#: texto de 4.000 caracteres), no el tamaño legítimo del grafo de un hallazgo
#: denso: medido sobre los casos reales, un hallazgo nombra entre 2 y 9 entidades.
MAX_NODOS = 40
MAX_RELACIONES = 80
MAX_CHARS_VALOR = 200
MAX_CHARS_NOTA = 240

#: Cuántas violaciones se listan en el motivo del rechazo. Se comprueban TODAS
#: (la ronda de corrección tiene que poder arreglarlas de una vez); se nombran las
#: primeras, igual que en ``reports.writer``.
MAX_VIOLACIONES_LISTADAS = 12


class GraphExtractError(ValueError):
    """El grafo no puede persistirse: el contrato de respuesta se incumplió o una
    de las barreras no pasa. El mensaje es ACCIONABLE y enumera los valores
    válidos, porque vuelve al modelo como cuerpo de error para el reintento.
    NADA se persiste."""


def _lista_de_fallos(fallos: list[str]) -> str:
    visibles = "; ".join(fallos[:MAX_VIOLACIONES_LISTADAS])
    resto = len(fallos) - MAX_VIOLACIONES_LISTADAS
    return (
        str(Mensaje("graphx.andMore", visible=visibles, rest=resto))
        if resto > 0
        else visibles
    )


def texto_del_hallazgo(finding: Any) -> str:
    """El texto contra el que se comprueban los referentes: título y resumen.

    Es TODO lo que el modelo ha visto del hallazgo, así que es exactamente el
    universo de entidades que puede proponer sin fabricar.
    """
    title = str(getattr(finding, "title", "") or "")
    summary = str(getattr(finding, "summary", "") or "")
    return f"{title}\n{summary}"


def _aparece_literalmente(valor: str, texto: str) -> bool:
    """¿La entidad está ESCRITA en el texto del hallazgo?

    Subcadena insensible a mayúsculas, y nada más: ni normalización de rutas, ni
    quitar comillas, ni «se parece bastante». Cada relajación de esta comparación
    es un hueco por el que entra una entidad que el perito no puede encontrar
    leyendo el hallazgo, y el grafo dejaría de ser verificable contra su fuente.
    """
    return valor.casefold() in texto.casefold()


def _normalizar_espacios(valor: str) -> str:
    return re.sub(r"\s+", " ", valor).strip()


def _validar_nodos(raw: Any, texto: str) -> list[dict[str, str]]:
    """Los nodos, comprobados contra la enum cerrada y contra el texto.

    Devuelve la lista deduplicada y en el orden en que el modelo los declaró (que
    el layout luego reordena de forma determinista). Recoge TODAS las violaciones
    antes de rechazar.
    """
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise GraphExtractError(
            Mensaje("graphx.noNodes")
        )
    if len(raw) > MAX_NODOS:
        raise GraphExtractError(
            Mensaje("graphx.tooManyNodes", count=len(raw), max=MAX_NODOS)
        )

    fallos_tipo: list[str] = []
    fallos_texto: list[str] = []
    fallos_forma: list[str] = []
    tipo_por_valor: dict[str, str] = {}
    out: list[dict[str, str]] = []

    for nodo in raw:
        if not isinstance(nodo, dict):
            fallos_forma.append("un nodo no es un objeto JSON")
            continue
        tipo = str(nodo.get("tipo", "")).strip().lower()
        valor = _normalizar_espacios(str(nodo.get("valor", "")))
        if not valor:
            fallos_forma.append("un nodo llega sin `valor`")
            continue
        if len(valor) > MAX_CHARS_VALOR:
            fallos_forma.append(
                Mensaje("graphx.valueTooLong", length=len(valor), max=MAX_CHARS_VALOR)
            )
            continue
        if tipo not in TIPOS_NODO:
            fallos_tipo.append(f"el nodo «{valor}» llega con tipo {tipo!r}")
            continue
        if not _aparece_literalmente(valor, texto):
            fallos_texto.append(f"«{valor}»")
            continue
        anterior = tipo_por_valor.get(valor.casefold())
        if anterior is None:
            tipo_por_valor[valor.casefold()] = tipo
            out.append({"tipo": tipo, "valor": valor})
        elif anterior != tipo:
            fallos_forma.append(
                Mensaje(
                    "graphx.twoTypes", value=valor, first=anterior, second=tipo
                )
            )

    if fallos_tipo:
        raise GraphExtractError(
            Mensaje(
                "graphx.badNodeType",
                failures=_lista_de_fallos(fallos_tipo),
                valid=", ".join(TIPOS_NODO),
            )
        )
    if fallos_texto:
        raise GraphExtractError(
            Mensaje(
                "graphx.notLiteral",
                count=len(fallos_texto),
                failures=_lista_de_fallos(fallos_texto),
            )
        )
    if fallos_forma:
        raise GraphExtractError(
            Mensaje("graphx.badNodeShape", failures=_lista_de_fallos(fallos_forma))
        )
    return out


def _validar_relaciones(
    raw: Any, nodos: list[dict[str, str]], texto: str
) -> list[dict[str, str]]:
    """Las relaciones, dirigidas, entre nodos ya declarados.

    ``origen`` y ``destino`` se resuelven contra los valores de ``nodos`` (la
    comparación es insensible a mayúsculas, como la del texto) y se FIJAN a la
    forma declarada del nodo, para que dos escrituras del mismo valor no pinten
    dos nodos.
    """
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise GraphExtractError(
            Mensaje("graphx.noEdges")
        )
    if len(raw) > MAX_RELACIONES:
        raise GraphExtractError(
            Mensaje("graphx.tooManyEdges", count=len(raw), max=MAX_RELACIONES)
        )

    canonico = {n["valor"].casefold(): n["valor"] for n in nodos}
    fallos_tipo: list[str] = []
    fallos_nodo: list[str] = []
    fallos_forma: list[str] = []
    vistas: set[tuple[str, str, str]] = set()
    out: list[dict[str, str]] = []

    for rel in raw:
        if not isinstance(rel, dict):
            fallos_forma.append(str(Mensaje("graphx.edgeNotObject")))
            continue
        tipo = str(rel.get("tipo", "")).strip().lower()
        origen = _normalizar_espacios(str(rel.get("origen", "")))
        destino = _normalizar_espacios(str(rel.get("destino", "")))
        if tipo not in TIPOS_RELACION:
            fallos_tipo.append(
                str(
                    Mensaje(
                        "graphx.badEdgeTypeItem",
                        source=origen,
                        target=destino,
                        type=repr(tipo),
                    )
                )
            )
            continue
        origen_canon = canonico.get(origen.casefold())
        destino_canon = canonico.get(destino.casefold())
        if origen_canon is None or destino_canon is None:
            falta = origen if origen_canon is None else destino
            fallos_nodo.append(f"«{falta}»")
            continue
        if origen_canon == destino_canon:
            fallos_forma.append(
                Mensaje("graphx.selfRelation", value=origen_canon)
            )
            continue
        clave = (origen_canon, destino_canon, tipo)
        if clave in vistas:
            continue  # la misma arista dos veces no es un dato nuevo
        vistas.add(clave)

        relacion: dict[str, str] = {
            "origen": origen_canon,
            "destino": destino_canon,
            "tipo": tipo,
        }
        nota = _normalizar_espacios(str(rel.get("nota", "") or ""))
        if nota:
            relacion["nota"] = nota[:MAX_CHARS_NOTA]
        out.append(relacion)

    if fallos_tipo:
        raise GraphExtractError(
            Mensaje(
                "graphx.badEdgeType",
                failures=_lista_de_fallos(fallos_tipo),
                valid=", ".join(TIPOS_RELACION),
            )
        )
    if fallos_nodo:
        raise GraphExtractError(
            Mensaje(
                "graphx.unknownEndpoint",
                count=len(fallos_nodo),
                failures=_lista_de_fallos(fallos_nodo),
            )
        )
    if fallos_forma:
        raise GraphExtractError(
            Mensaje("graphx.badEdgeShape", failures=_lista_de_fallos(fallos_forma))
        )
    return out


def validar_grafo(envelope: dict[str, Any], texto: str) -> dict[str, Any]:
    """Las dos listas del grafo, validadas contra las enums y contra el texto.

    Devuelve ``{"nodos": [...], "relaciones": [...]}`` listo para persistir, o
    levanta ``GraphExtractError`` con el motivo accionable. Un grafo VACÍO (el
    hallazgo no nombra ninguna entidad) es un resultado legítimo y no es un error:
    hay hallazgos que afirman algo sobre el sistema sin nombrar una sola entidad,
    y ahí lo correcto es un grafo sin nodos, no un nodo inventado.
    """
    nodos = _validar_nodos(envelope.get("nodos"), texto)
    relaciones = _validar_relaciones(envelope.get("relaciones"), nodos, texto)
    return {"nodos": nodos, "relaciones": relaciones}


__all__ = [
    "MAX_CHARS_NOTA",
    "MAX_CHARS_VALOR",
    "MAX_NODOS",
    "MAX_RELACIONES",
    "TIPOS_NODO",
    "TIPOS_RELACION",
    "GraphExtractError",
    "texto_del_hallazgo",
    "validar_grafo",
]
