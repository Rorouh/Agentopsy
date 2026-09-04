"""La GEOMETRÍA del grafo, determinista y calculada en el servidor.

Por qué no hay simulación de fuerzas. Es lo que hace la referencia (Nexus) y es
lo que no sirve aquí: una simulación con semilla aleatoria dibuja el MISMO grafo
distinto en cada render, y una figura que se adjunta a un informe pericial tiene
que ser reproducible, es decir, el mismo grafo tiene que dar la misma imagen hoy
y dentro de un año. Así que la posición de cada nodo sale de una función pura de
(identificador, tipo, valor): mismo grafo, misma imagen, en cualquier máquina.

Esto NO impide que la figura sea explorable. La exploración del navegador (zoom,
desplazamiento, enfocar, plegar, arrastrar) es una transformación de la VISTA y
vive en el cliente; la geometría canónica, la que se exporta, es la que calcula
este módulo. Son dos momentos distintos y no se mezclan.

Por qué en el backend y no en el navegador. La reproducibilidad no puede depender
de la versión del navegador ni del orden en que React monte los componentes, y la
lógica vive en ``forensia/*`` (RULE 3). El cliente recibe coordenadas y pinta.

Dos figuras distintas, porque dos problemas distintos:

- **Grafo de un hallazgo**: pocos nodos (medido: entre 0 y 15). Estrella. El nodo
  de mayor grado va al centro y el resto a un anillo, que es como se lee
  «IEUser ejecutó estos tres ficheros» de un vistazo. Sin aristas, anillo simple.
- **Grafo del caso**: decenas de nodos (medido: 63). Una estrella se vuelve una
  maraña, así que van ANILLOS CONCÉNTRICOS POR TIPO.

El desfase angular sale de un hash del identificador (``finding_id`` o
``case_id``). No es azar: es una constante distinta por figura para que dos
grafos del mismo caso no salgan calcados, y es estable porque el hash lo es.

Tres decisiones vienen de MEDIR la figura anterior, que salía ilegible, y las
tres eran aritmética, no gusto:

1. **El anillo es una ELIPSE, no un círculo.** El radio salía de
   ``min(ANCHO, ALTO) / 2 - MARGEN``, o sea ``min(1000, 700) / 2 - 110 = 240``:
   un círculo de 480 px de ancho en un lienzo de 1000, que desperdiciaba el 52 %
   del ancho y apelmazaba el centro. El ``min`` convertía un lienzo apaisado en
   uno cuadrado. Ahora el anillo se estira a lo ancho (``_APAISADO``) y los nodos
   se reparten por LONGITUD DE ARCO, no por ángulo: en una elipse, pasos
   angulares iguales amontonan los nodos en los extremos del eje mayor, que es
   justo donde no se quiere.

2. **El radio sale de la POBLACIÓN del anillo, no de su posición.** El radio era
   ``radio_max * (indice + 1) / len(presentes)``, que ignora cuántos nodos lleva
   el anillo. Medido sobre un caso real de tres tipos: el anillo de cuentas
   quedaba a radio 80 con 12 nodos (42 px de arco por nodo, cuando una etiqueta
   como ``wilsonjimmy8…`` necesita unos 90) y el de dominios a radio 160 con 5
   (201 px por nodo). Estaba repartido al revés. Ahora cada anillo pide el
   perímetro que necesitan SUS etiquetas y empieza donde acaba el anterior.

3. **El orden de los anillos se DERIVA del grafo.** Era la tupla fija
   ``("user", "hostname", "ip", "domain", "file")``, con el razonamiento correcto
   de meter dentro lo que concentra aristas, y el efecto contrario: las cuentas
   son también el tipo más numeroso, así que el tipo con más nodos acababa en la
   circunferencia más corta. Ahora manda el GRADO MEDIO REAL de cada tipo en ESE
   grafo (lo que concentra aristas sigue yendo dentro, pero medido), y la
   población la absorbe el radio del punto 2. ``ANILLOS`` se queda solo como
   desempate estable cuando dos tipos tienen el mismo grado medio.

Y una cuarta, que es la que garantiza el «cero solapamientos»: después de
colocar los anillos, un RELAJADOR separa las cajas que se pisen. Es determinista
por construcción: número FIJO de iteraciones (``_ITERACIONES``), recorrido de
pares en orden estable y ningún uso de azar ni de reloj. Sobre una figura bien
dimensionada no mueve nada; existe para el caso en que dos anillos vecinos
alineen un nodo con otro.

Cuando la figura no cabe, el LIENZO CRECE. Nunca se comprime en silencio
(RULE 2): el lienzo calculado viaja en la respuesta junto con las notas de lo
que hubo que ampliar.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any

#: Lienzo MÍNIMO de la figura, en unidades de ``viewBox``. Es un suelo, no un
#: techo: una figura con muchos nodos devuelve un lienzo mayor (ver ``_lienzo``).
ANCHO = 1000
ALTO = 700

#: Margen entre la CAJA del nodo más exterior (disco más etiqueta) y el borde.
#: Es aire adicional, no el sitio de la etiqueta: ese ya lo reserva ``_lienzo``
#: sumando la media caja de cada nodo. Por eso es pequeño; el margen generoso de
#: antes (110) era el que dejaba la figura nadando en un lienzo vacío.
_MARGEN_X = 40
_MARGEN_Y = 34

#: Cuánto se estira el anillo a lo ancho. Sale de la proporción del lienzo
#: mínimo una vez descontados sus márgenes: (1000 - 80) / (700 - 68) = 1,456.
#: Es lo que convierte el círculo desaprovechado de antes en una elipse que sí
#: usa el lienzo apaisado.
_APAISADO = (ANCHO - 2 * _MARGEN_X) / (ALTO - 2 * _MARGEN_Y)

#: Radio del disco de un nodo. Tiene que coincidir con ``RADIO_NODO`` del
#: cliente (``web/src/pages/graphs/RelationGraph.tsx``): aquí se reserva el
#: sitio y allí se pinta, así que si divergen la figura vuelve a solaparse.
RADIO_NODO = 19

#: Ancho estimado de un carácter de la etiqueta, y cuántos caben antes de
#: recortar. Se ESTIMA en vez de medirse con el canvas del navegador porque la
#: figura se exporta a PNG y se adjunta a un informe: tiene que salir igual en
#: cualquier máquina, y una medida tomada de la tipografía instalada la haría
#: depender del equipo. Los dos valores son los del cliente.
ANCHO_CARACTER = 5.9
MAX_CHARS_ETIQUETA = 22

#: Aire alrededor de la caja de un nodo, a lo ancho y a lo alto.
_AIRE_X = 18.0
_AIRE_Y = 12.0

#: Alto de las DOS líneas de etiqueta que van debajo del disco (el valor y, más
#: pequeño, el tipo).
ALTO_ETIQUETA = 30.0

#: Separación mínima entre dos anillos consecutivos, de centro a centro. Dos
#: cajas vecinas necesitan la SUMA de sus medias alturas, que con estos valores
#: es ``2 * RADIO_NODO + ALTO_ETIQUETA + _AIRE_Y``; el paso va por encima de esa
#: cuenta para que el relajador sea una red de seguridad y no el mecanismo
#: principal. Con el paso justo, medido, corregía 41 pares de una figura de 35
#: nodos, y corregir tantos deforma los anillos hasta que dejan de leerse.
_PASO_ANILLO = 2 * RADIO_NODO + ALTO_ETIQUETA + 2 * _AIRE_Y

#: Holgura con la que se pide el perímetro de un anillo, por encima de lo que
#: suman sus cajas. Ver ``_radio_para``.
_HOLGURA = 1.12

#: Radio mínimo de un anillo. Tres nodos con etiquetas cortas piden un perímetro
#: de 216 px, o sea un anillo de radio 31: técnicamente correcto y visualmente
#: un montoncito. Los grafos de referencia reparten quince nodos por la pantalla
#: entera, y esa holgura es lo que los hace legibles de un vistazo.
_RADIO_MINIMO = 140.0

#: Iteraciones del relajador de solapamientos. FIJO: el bucle no pregunta si ya
#: ha convergido, porque un criterio de parada por convergencia haría depender la
#: figura de la aritmética en coma flotante de la máquina.
_ITERACIONES = 60

#: Hasta cuánto se puede ESTIRAR una figura pequeña para que llene el lienzo
#: mínimo en vez de quedarse en un punto en medio del vacío. Con tope, porque un
#: grafo de dos nodos escalado sin límite los manda a las esquinas y deja la
#: arista cruzando la figura entera.
_ESTIRADO_MAX = 2.4

#: Cuántos puntos se muestrean de la elipse para repartir por longitud de arco.
#: Fijo, y por tanto determinista.
_MUESTRAS_ARCO = 720

#: Desempate del orden de anillos cuando dos tipos tienen el mismo grado medio.
#: Ya NO decide por sí solo el orden (ver punto 3 del encabezado).
ANILLOS: tuple[str, ...] = ("user", "hostname", "ip", "domain", "file")


def _desfase(semilla: str) -> float:
    """Un ángulo en [0, 2pi) derivado del identificador. Estable por definición."""
    h = hashlib.sha256(semilla.encode("utf-8")).hexdigest()[:8]
    return (int(h, 16) % 3600) / 3600 * 2 * math.pi


def _etiqueta(valor: str) -> str:
    """Lo que el cliente pinta debajo del nodo, recortado igual que allí."""
    return valor if len(valor) <= MAX_CHARS_ETIQUETA else f"{valor[:MAX_CHARS_ETIQUETA - 1]}…"


def ancho_caja(nodo: dict[str, Any]) -> float:
    """Ancho que ocupa un nodo con su etiqueta, aire incluido.

    Es pública porque la reserva de sitio de un nodo tiene que ser LA MISMA en
    todo lo que coloque nodos, y desde 2026-09-04 la banda de entidades sueltas
    (``forensia.graph.inventario``) también coloca."""
    etiqueta = _etiqueta(str(nodo.get("valor", "")))
    return max(2 * RADIO_NODO, len(etiqueta) * ANCHO_CARACTER) + _AIRE_X


def _caja(nodo: dict[str, Any]) -> tuple[float, float, float, float]:
    """Media anchura, cuánto sube y cuánto baja la caja, y el ancho completo.

    La caja NO está centrada en el nodo: el disco sube ``RADIO_NODO`` y la
    etiqueta baja otro tanto más sus dos líneas.
    """
    ancho = ancho_caja(nodo)
    return (
        ancho / 2,
        RADIO_NODO + _AIRE_Y / 2,
        RADIO_NODO + ALTO_ETIQUETA + _AIRE_Y / 2,
        ancho,
    )


def _grados(nodos: list[dict[str, Any]], relaciones: list[dict[str, Any]]) -> dict[str, int]:
    grado = {str(n.get("valor")): 0 for n in nodos}
    for r in relaciones:
        for extremo in (str(r.get("origen")), str(r.get("destino"))):
            if extremo in grado:
                grado[extremo] += 1
    return grado


def _perimetro(ry: float) -> float:
    """Perímetro de la elipse de semieje menor ``ry`` (aproximación de Ramanujan)."""
    a = ry * _APAISADO
    b = ry
    return math.pi * (3 * (a + b) - math.sqrt((3 * a + b) * (a + 3 * b)))


#: El perímetro es lineal en ``ry``, así que basta con su valor unitario para
#: despejar el radio que necesita un anillo.
_PERIMETRO_UNIDAD = _perimetro(1.0)


def _puntos_por_arco(ry: float, cuantos: int, desfase: float) -> list[tuple[float, float]]:
    """``cuantos`` puntos EQUIESPACIADOS EN ARCO sobre la elipse de semieje ``ry``.

    Repartir por ángulo amontonaría los nodos en los extremos del eje mayor: en
    una elipse la velocidad del parámetro no es constante, y ahí es mínima.
    ``desfase`` entra como fracción del perímetro, no como ángulo, por la misma
    razón.
    """
    if cuantos <= 0:
        return []
    rx = ry * _APAISADO
    # Longitud de arco acumulada sobre una malla fija.
    acumulado = [0.0]
    previo = (rx, 0.0)
    for i in range(1, _MUESTRAS_ARCO + 1):
        t = 2 * math.pi * i / _MUESTRAS_ARCO
        actual = (rx * math.cos(t), ry * math.sin(t))
        acumulado.append(
            acumulado[-1] + math.hypot(actual[0] - previo[0], actual[1] - previo[1])
        )
        previo = actual
    total = acumulado[-1]
    if total <= 0:
        return [(0.0, 0.0)] * cuantos

    salida: list[tuple[float, float]] = []
    for k in range(cuantos):
        objetivo = (desfase / (2 * math.pi) * total + k * total / cuantos) % total
        # Búsqueda del tramo que contiene ese arco, e interpolación dentro de él.
        lo, hi = 0, _MUESTRAS_ARCO
        while lo < hi:
            medio = (lo + hi) // 2
            if acumulado[medio] < objetivo:
                lo = medio + 1
            else:
                hi = medio
        i = max(1, lo)
        tramo = acumulado[i] - acumulado[i - 1]
        frac = 0.0 if tramo <= 0 else (objetivo - acumulado[i - 1]) / tramo
        t = 2 * math.pi * (i - 1 + frac) / _MUESTRAS_ARCO
        salida.append((rx * math.cos(t), ry * math.sin(t)))
    return salida


def _radio_para(grupo: list[dict[str, Any]]) -> float:
    """El semieje menor que necesita un anillo para que sus etiquetas no se toquen.

    Con el perímetro JUSTO las cajas quedan tocándose, y entonces cualquier
    redondeo dispara el relajador: medido, 309 correcciones en una figura de 48
    nodos, que deja los anillos irreconocibles. La holgura es lo que mantiene al
    relajador en su papel de red de seguridad.
    """
    if not grupo:
        return 0.0
    necesario = sum(ancho_caja(n) for n in grupo)
    return max(_RADIO_MINIMO, _HOLGURA * necesario / _PERIMETRO_UNIDAD)


def _relajar(colocados: list[dict[str, Any]]) -> int:
    """Separa las cajas que se pisen. Devuelve cuántos pares corrigió.

    Determinista: iteraciones fijas, pares en el orden en que llegan (que ya es
    estable, porque quien llama ordena por (tipo, valor)) y desplazamiento
    simétrico. Sobre una figura bien dimensionada no mueve nada.
    """
    if len(colocados) < 2:
        return 0
    cajas = [_caja(n) for n in colocados]
    corregidos = 0
    for _ in range(_ITERACIONES):
        movido = False
        for i in range(len(colocados)):
            for j in range(i + 1, len(colocados)):
                if colocados[i].get("centro") and colocados[j].get("centro"):
                    continue
                semi_i, sube_i, baja_i, _ = cajas[i]
                semi_j, sube_j, baja_j, _ = cajas[j]
                dx = colocados[j]["x"] - colocados[i]["x"]
                dy = colocados[j]["y"] - colocados[i]["y"]
                solape_x = (semi_i + semi_j) - abs(dx)
                # El centro vertical de cada caja está desplazado respecto al nodo.
                ci = (baja_i - sube_i) / 2
                cj = (baja_j - sube_j) / 2
                alto_i = (sube_i + baja_i) / 2
                alto_j = (sube_j + baja_j) / 2
                solape_y = (alto_i + alto_j) - abs(dy + cj - ci)
                if solape_x <= 0 or solape_y <= 0:
                    continue
                movido = True
                corregidos += 1
                # Se empuja por el eje de MENOR penetración: es el desplazamiento
                # más corto que resuelve el solape, y por tanto el que menos
                # deforma la figura calculada.
                if solape_x <= solape_y:
                    paso = (solape_x + 1.0) / 2
                    signo = 1.0 if dx >= 0 else -1.0
                    colocados[i]["x"] -= paso * signo
                    colocados[j]["x"] += paso * signo
                else:
                    paso = (solape_y + 1.0) / 2
                    signo = 1.0 if dy >= 0 else -1.0
                    colocados[i]["y"] -= paso * signo
                    colocados[j]["y"] += paso * signo
        if not movido:
            break
    return corregidos


def _lienzo(colocados: list[dict[str, Any]]) -> dict[str, int]:
    """El lienzo que hace falta para que ninguna caja se salga.

    Nunca por debajo del mínimo, y nunca recortando: si la figura no cabe en
    ``ANCHO x ALTO``, crece el lienzo (RULE 2).
    """
    if not colocados:
        return {"ancho": ANCHO, "alto": ALTO}
    ancho_necesario = 0.0
    alto_necesario = 0.0
    for n in colocados:
        semi, sube, baja, _ = _caja(n)
        ancho_necesario = max(ancho_necesario, abs(n["x"]) + semi)
        alto_necesario = max(alto_necesario, abs(n["y"]) + max(sube, baja))
    return {
        "ancho": max(ANCHO, int(math.ceil(2 * (ancho_necesario + _MARGEN_X)))),
        "alto": max(ALTO, int(math.ceil(2 * (alto_necesario + _MARGEN_Y)))),
    }


def _estirar(colocados: list[dict[str, Any]]) -> None:
    """Reparte una figura pequeña por el lienzo mínimo en vez de apiñarla al centro.

    Los nodos tienen tamaño fijo, así que separarlos es exactamente lo que hace
    que un grafo de cinco nodos se lea como los de referencia (quince nodos en la
    pantalla entera) y no como un puñado en medio de un lienzo vacío. Escalar
    solo AUMENTA distancias, de modo que no puede crear un solapamiento.
    """
    if len(colocados) < 2:
        return
    ancho = 0.0
    alto = 0.0
    for n in colocados:
        semi, sube, baja, _ = _caja(n)
        ancho = max(ancho, abs(n["x"]) + semi)
        alto = max(alto, abs(n["y"]) + max(sube, baja))
    if ancho <= 0 or alto <= 0:
        return
    factor = min(
        (ANCHO / 2 - _MARGEN_X) / ancho,
        (ALTO / 2 - _MARGEN_Y) / alto,
        _ESTIRADO_MAX,
    )
    if factor <= 1.0:
        return
    for n in colocados:
        n["x"] *= factor
        n["y"] *= factor


def _publicar(
    colocados: list[dict[str, Any]], notas: list[dict[str, Any]]
) -> dict[str, Any]:
    """Traslada de coordenadas centradas en (0, 0) al origen del ``viewBox``."""
    _estirar(colocados)
    lienzo = _lienzo(colocados)
    cx, cy = lienzo["ancho"] / 2, lienzo["alto"] / 2
    nodos = [
        {**n, "x": round(n["x"] + cx, 2), "y": round(n["y"] + cy, 2)} for n in colocados
    ]
    if lienzo["ancho"] > ANCHO or lienzo["alto"] > ALTO:
        notas.append({"codigo": "lienzo_ampliado", **lienzo})
    return {"nodos": nodos, "lienzo": lienzo, "notas": notas}


def layout_hallazgo(
    finding_id: str, nodos: list[dict[str, Any]], relaciones: list[dict[str, Any]]
) -> dict[str, Any]:
    """Estrella determinista para el grafo de UN hallazgo.

    El centro es el nodo de mayor grado, con desempate por (tipo, valor) para que
    no lo decida el orden en que el modelo los declaró, que no es estable.
    """
    if not nodos:
        return {"nodos": [], "lienzo": {"ancho": ANCHO, "alto": ALTO}, "notas": []}

    grado = _grados(nodos, relaciones)
    if len(nodos) == 1:
        return _publicar([{**nodos[0], "x": 0.0, "y": 0.0, "centro": True}], [])

    ordenados = sorted(
        nodos,
        key=lambda n: (-grado.get(str(n.get("valor")), 0), str(n.get("tipo")), str(n.get("valor"))),
    )
    hay_centro = grado.get(str(ordenados[0].get("valor")), 0) >= 2
    centro = ordenados[0] if hay_centro else None
    anillo = ordenados[1:] if hay_centro else ordenados

    # El anillo tiene que rodear al nodo central sin pisarlo, y además dar sitio
    # a sus propias etiquetas.
    ry = max(_PASO_ANILLO if centro is not None else 0.0, _radio_para(anillo))
    puntos = _puntos_por_arco(ry, len(anillo), _desfase(finding_id))

    colocados: list[dict[str, Any]] = []
    if centro is not None:
        colocados.append({**centro, "x": 0.0, "y": 0.0, "centro": True})
    for n, (x, y) in zip(anillo, puntos, strict=True):
        colocados.append({**n, "x": x, "y": y, "centro": False})

    notas: list[dict[str, Any]] = []
    corregidos = _relajar(colocados)
    if corregidos:
        notas.append({"codigo": "solapes_corregidos", "pares": corregidos})
    return _publicar(colocados, notas)


def _orden_anillos(
    por_tipo: dict[str, list[dict[str, Any]]], grado: dict[str, int]
) -> list[str]:
    """De dentro afuera: primero el tipo con más aristas POR NODO.

    Medido, no supuesto: lo que concentra aristas va al centro para que sus
    radios crucen lo menos posible, pero quién concentra aristas lo dice ESTE
    grafo. El desempate es ``ANILLOS`` y luego el nombre del tipo, para que el
    orden siga siendo estable cuando no hay aristas.
    """

    def clave(tipo: str) -> tuple[float, int, str]:
        grupo = por_tipo[tipo]
        medio = sum(grado.get(str(n.get("valor")), 0) for n in grupo) / len(grupo)
        posicion = ANILLOS.index(tipo) if tipo in ANILLOS else len(ANILLOS)
        return (-medio, posicion, tipo)

    return sorted(por_tipo, key=clave)


def layout_caso(
    case_id: str, nodos: list[dict[str, Any]], relaciones: list[dict[str, Any]]
) -> dict[str, Any]:
    """Anillos concéntricos por tipo para el grafo del CASO."""
    if not nodos:
        return {"nodos": [], "lienzo": {"ancho": ANCHO, "alto": ALTO}, "notas": []}

    por_tipo: dict[str, list[dict[str, Any]]] = {}
    for n in nodos:
        por_tipo.setdefault(str(n.get("tipo")), []).append(n)
    grado = _grados(nodos, relaciones)
    presentes = _orden_anillos(por_tipo, grado)

    desfase = _desfase(case_id)
    colocados: list[dict[str, Any]] = []
    notas: list[dict[str, Any]] = []
    ry_previo = 0.0
    for indice, tipo in enumerate(presentes):
        del_tipo = sorted(por_tipo[tipo], key=lambda n: str(n.get("valor")))
        # Un anillo interior con UN solo nodo se planta en el centro. Medido
        # sobre un caso real: con una cuenta y once ficheros, la cuenta es el
        # concentrador de todas las aristas y ponerla en una órbita de radio
        # medio dejaba la figura descentrada y las aristas cruzando el hueco.
        if indice == 0 and len(del_tipo) == 1 and len(presentes) > 1:
            colocados.append({**del_tipo[0], "x": 0.0, "y": 0.0, "centro": True})
            ry_previo = 0.0
            continue
        # El radio lo pide la POBLACIÓN del anillo; el suelo es dejar libre el
        # anillo anterior. Nunca se comprime para que quepa (RULE 2): si el
        # anillo necesita más sitio, se lo lleva y el lienzo crece con él.
        ry = max(ry_previo + _PASO_ANILLO, _radio_para(del_tipo))
        for n, (x, y) in zip(
            del_tipo, _puntos_por_arco(ry, len(del_tipo), desfase + indice * 0.7), strict=True
        ):
            colocados.append({**n, "x": x, "y": y, "centro": False})
        ry_previo = ry

    corregidos = _relajar(colocados)
    if corregidos:
        notas.append({"codigo": "solapes_corregidos", "pares": corregidos})
    return _publicar(colocados, notas)


__all__ = [
    "ALTO",
    "ALTO_ETIQUETA",
    "ANCHO",
    "ANCHO_CARACTER",
    "ANILLOS",
    "MAX_CHARS_ETIQUETA",
    "RADIO_NODO",
    "ancho_caja",
    "layout_caso",
    "layout_hallazgo",
]
