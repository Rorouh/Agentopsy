"""El grafo del CASO: los grafos de los hallazgos, fundidos por entidad.

Por qué existe. Un hallazgo es una observación, no una historia: medido sobre un
caso real de 19 hallazgos, el grafo de cada uno tiene entre 0 y 15 nodos y la
mayoría no llega a tres aristas. Lo que se lleva a un informe es el grafo del
CASO, donde el mismo ``IEUser`` que aparece en siete hallazgos es UN nodo y ata
el ejecutable con los documentos, la papelera y la cuenta de correo. Esa
estructura no la aporta ninguna extracción nueva: aparece al fundir, sin gastar
una sola llamada al modelo.

Fundir es una AFIRMACIÓN sobre el caso, así que se hace de la forma más
conservadora posible y declarada:

- La clave es el par (TIPO, valor normalizado), nunca el valor solo: un fichero
  llamado ``administrador`` y la cuenta ``administrador`` no son la misma cosa.
- Se recortan espacios y se pliegan mayúsculas para ``hostname``, ``user``,
  ``domain`` e ``ip``, donde la equivalencia es una propiedad conocida del
  dominio (DNS y NetBIOS no distinguen caja; ``IEUser`` e ``ieuser`` son la
  misma cuenta).
- Para ``file`` NO: solo se recortan espacios. No se colapsa por nombre base y
  tampoco se pliega la caja, porque decir que dos ``key.exe`` en rutas distintas
  son el mismo fichero es una conclusión que nadie ha verificado. Si el texto no
  da ruta, el nodo es el literal que da.
- Cada nodo fundido conserva la LISTA de hallazgos que lo sostienen. Es lo que
  mantiene citable un nodo después de fundir y lo que deja navegar de la figura
  a la procedencia.

Lógica pura (RULE 3): sin disco, sin HTTP, sin modelo.
"""

from __future__ import annotations

from typing import Any

from forensia.graph.modelo import TIPOS_NODO

#: Tipos cuya identidad NO distingue mayúsculas de minúsculas. ``file`` queda
#: fuera a propósito (ver el docstring): en un grafo pericial, fundir de menos
#: deja dos nodos donde había uno, que se ve; fundir de más borra una distinción
#: que ya no se puede recuperar.
_PLIEGAN_CAJA = frozenset({"hostname", "user", "domain", "ip"})


def clave_de_nodo(tipo: str, valor: str) -> tuple[str, str]:
    """La clave de fusión: (tipo, valor normalizado). Declarada y conservadora."""
    v = " ".join(str(valor).split())
    if tipo in _PLIEGAN_CAJA:
        v = v.casefold()
    return (tipo, v)


def _orden_tipo(tipo: str) -> int:
    return TIPOS_NODO.index(tipo) if tipo in TIPOS_NODO else len(TIPOS_NODO)


def merge_case_graph(grafos: list[dict[str, Any]]) -> dict[str, Any]:
    """Funde los grafos de varios hallazgos en el grafo del caso.

    ``grafos`` es ``[{"finding_id", "nodos", "relaciones"}]`` (lo que persiste el
    almacén). Devuelve ``{"nodos", "relaciones", "hallazgos"}`` donde cada nodo y
    cada arista llevan ``hallazgos`` con los ids que los sostienen, y el orden es
    DETERMINISTA (grado descendente, luego tipo, luego valor) para que la figura
    del caso no dependa del orden en que se extrajeron los hallazgos.
    """
    nodos: dict[tuple[str, str], dict[str, Any]] = {}
    aristas: dict[tuple[tuple[str, str], tuple[str, str], str], dict[str, Any]] = {}
    hallazgos_vistos: list[str] = []

    for g in grafos:
        finding_id = str(g.get("finding_id") or "")
        if finding_id and finding_id not in hallazgos_vistos:
            hallazgos_vistos.append(finding_id)

        # Los extremos de una arista se nombran por el valor TAL Y COMO viaja en
        # el grafo de su hallazgo, así que el mapa local traduce de ese valor a la
        # clave fundida. Sin él, una arista de un hallazgo apuntaría a un nodo que
        # en el grafo del caso ya se llama de otra forma.
        local: dict[str, tuple[str, str]] = {}
        for n in g.get("nodos") or []:
            tipo = str(n.get("tipo") or "")
            valor = str(n.get("valor") or "")
            if not tipo or not valor:
                continue
            k = clave_de_nodo(tipo, valor)
            local[valor] = k
            entrada = nodos.get(k)
            if entrada is None:
                # El valor que se PINTA es el primero que se vio, no el
                # normalizado: la caja plegada es para comparar, no para enseñar.
                nodos[k] = {
                    "tipo": tipo,
                    "valor": " ".join(valor.split()),
                    "hallazgos": [finding_id] if finding_id else [],
                }
            elif finding_id and finding_id not in entrada["hallazgos"]:
                entrada["hallazgos"].append(finding_id)

        for r in g.get("relaciones") or []:
            origen = str(r.get("origen") or "")
            destino = str(r.get("destino") or "")
            tipo = str(r.get("tipo") or "")
            ko, kd = local.get(origen), local.get(destino)
            if ko is None or kd is None or not tipo or ko == kd:
                continue
            k = (ko, kd, tipo)
            entrada = aristas.get(k)
            if entrada is None:
                aristas[k] = {
                    "origen": nodos[ko]["valor"],
                    "destino": nodos[kd]["valor"],
                    "tipo": tipo,
                    "hallazgos": [finding_id] if finding_id else [],
                    "notas": [r["nota"]] if r.get("nota") else [],
                }
            else:
                if finding_id and finding_id not in entrada["hallazgos"]:
                    entrada["hallazgos"].append(finding_id)
                nota = r.get("nota")
                if nota and nota not in entrada["notas"]:
                    entrada["notas"].append(nota)

    grado: dict[tuple[str, str], int] = {k: 0 for k in nodos}
    for ko, kd, _ in aristas:
        grado[ko] = grado.get(ko, 0) + 1
        grado[kd] = grado.get(kd, 0) + 1

    ordenados = sorted(
        nodos.items(),
        key=lambda kv: (-grado.get(kv[0], 0), _orden_tipo(kv[1]["tipo"]), kv[1]["valor"]),
    )
    nodos_out = [{**n, "grado": grado.get(k, 0)} for k, n in ordenados]
    aristas_out = sorted(
        aristas.values(), key=lambda a: (a["origen"], a["destino"], a["tipo"])
    )
    return {
        "nodos": nodos_out,
        "relaciones": aristas_out,
        "hallazgos": hallazgos_vistos,
    }


__all__ = ["clave_de_nodo", "merge_case_graph"]
