"""La geometría del grafo: determinismo, cero solapamientos y uso del lienzo.

Estos cuatro gates son la diferencia entre la figura anterior, que salía como una
maraña, y una que se puede adjuntar a un informe pericial. Los tres primeros son
MEDIBLES sobre las coordenadas devueltas, así que no hacen falta capturas ni
juicios de gusto; el cuarto es el que impide que alguien cambie el relajador por
un bucle que itera «hasta que converja», que es justo lo que haría depender la
figura de la máquina que la dibuja.

Las cajas se recalculan aquí a partir de las constantes PÚBLICAS del módulo, no
de sus internas: lo que se comprueba es lo que el cliente PINTA (el disco y sus
dos líneas de etiqueta), sin el aire que el layout se reserva por dentro. Si un
día el layout deja de reservar aire, este test tiene que seguir diciendo la
verdad sobre la figura.
"""

from __future__ import annotations

import math

from forensia.graph.layout import (
    ALTO,
    ALTO_ETIQUETA,
    ANCHO,
    ANCHO_CARACTER,
    MAX_CHARS_ETIQUETA,
    RADIO_NODO,
    layout_caso,
    layout_hallazgo,
)
from forensia.graph.layout import _ITERACIONES, _relajar


def _n(tipo: str, valor: str) -> dict[str, str]:
    return {"tipo": tipo, "valor": valor}


def _dibujado(nodo: dict) -> tuple[float, float, float, float]:
    """El rectángulo que el cliente pinta: disco arriba, dos líneas de texto abajo."""
    valor = str(nodo["valor"])
    etiqueta = valor if len(valor) <= MAX_CHARS_ETIQUETA else valor[: MAX_CHARS_ETIQUETA - 1] + "…"
    medio = max(RADIO_NODO, len(etiqueta) * ANCHO_CARACTER / 2)
    return (
        nodo["x"] - medio,
        nodo["y"] - RADIO_NODO,
        nodo["x"] + medio,
        nodo["y"] + RADIO_NODO + ALTO_ETIQUETA,
    )


def _pares_solapados(nodos: list[dict]) -> list[tuple[str, str]]:
    mal: list[tuple[str, str]] = []
    for i in range(len(nodos)):
        ax0, ay0, ax1, ay1 = _dibujado(nodos[i])
        for j in range(i + 1, len(nodos)):
            bx0, by0, bx1, by1 = _dibujado(nodos[j])
            if ax0 < bx1 and bx0 < ax1 and ay0 < by1 and by0 < ay1:
                mal.append((str(nodos[i]["valor"]), str(nodos[j]["valor"])))
    return mal


#: El caso real que se midió al diagnosticar la maraña: doce cuentas con
#: etiquetas largas, cinco dominios y dieciocho ficheros de la papelera.
def _caso_medido() -> list[dict[str, str]]:
    return (
        [_n("user", f"wilsonjimmy{i}@fineloans.org") for i in range(12)]
        + [_n("domain", f"dom{i}.example.org") for i in range(5)]
        + [_n("file", f"$R{i:06X}.txt") for i in range(18)]
    )


def test_the_same_graph_always_gives_the_same_geometry():
    """Una figura que va a un informe tiene que dar la misma imagen dentro de un año.

    Y no solo los nodos: también el lienzo, porque un ``viewBox`` distinto es una
    imagen distinta aunque las coordenadas coincidan.
    """
    nodos = _caso_medido()
    relaciones = [{"origen": nodos[0]["valor"], "destino": nodos[20]["valor"], "tipo": "malware"}]

    a = layout_caso("caso-1", nodos, relaciones)
    b = layout_caso("caso-1", list(reversed(nodos)), relaciones)

    assert a["lienzo"] == b["lienzo"]
    assert sorted((n["valor"], n["x"], n["y"]) for n in a["nodos"]) == sorted(
        (n["valor"], n["x"], n["y"]) for n in b["nodos"]
    )


def test_no_two_labels_overlap():
    """Cero solapamientos: ni dos discos ni dos etiquetas, en las dos figuras.

    Es el criterio que se puede comprobar sin mirar la imagen, y el que fallaba
    de forma masiva: el anillo de cuentas daba 42 px de arco por nodo para
    etiquetas que necesitan unos 90.
    """
    nodos = _caso_medido()
    relaciones = [{"origen": nodos[0]["valor"], "destino": nodos[20]["valor"], "tipo": "malware"}]
    assert _pares_solapados(layout_caso("caso-1", nodos, relaciones)["nodos"]) == []

    # Y con etiquetas largas de verdad, que es donde el reparto por población
    # tiene que ganarle al reparto por índice de anillo.
    largas = [_n("file", f"documento-larguisimo-{i}.docx") for i in range(40)] + [
        _n("user", f"usuario.apellido{i}@correo.example") for i in range(8)
    ]
    assert _pares_solapados(layout_caso("caso-2", largas, [])["nodos"]) == []

    # La estrella de un hallazgo, con el centro rodeado.
    estrella = [_n("user", "IEUser")] + [_n("file", f"herramienta-{i}.exe") for i in range(9)]
    aristas = [
        {"origen": "IEUser", "destino": f"herramienta-{i}.exe", "tipo": "process_spawn"}
        for i in range(9)
    ]
    figura = layout_hallazgo("3c80c7bc-9b9c-4db1-9a55-a27104fac756", estrella, aristas)
    assert _pares_solapados(figura["nodos"]) == []


def test_the_figure_fills_the_canvas_instead_of_floating_in_it():
    """El dibujo tiene que usar el lienzo, no un círculo en medio del vacío.

    La figura anterior gastaba el 52 % del ancho porque el radio salía de
    ``min(ANCHO, ALTO)``, que convierte un lienzo apaisado en uno cuadrado.
    """
    nodos = _caso_medido()
    figura = layout_caso("caso-1", nodos, [])
    xs = [n["x"] for n in figura["nodos"]]
    ocupacion = (max(xs) - min(xs)) / figura["lienzo"]["ancho"]
    assert ocupacion > 0.75, f"la figura solo ocupa el {ocupacion:.0%} del ancho"

    # Y una figura PEQUEÑA se estira para llenar el lienzo mínimo en vez de
    # quedarse apiñada en el centro: es lo que hace que cinco nodos se lean como
    # en los grafos de referencia y no como un puñado en una esquina.
    pocos = [_n("user", "IEUser"), _n("file", "key.exe"), _n("ip", "192.168.65.135")]
    chica = layout_hallazgo("3c80c7bc-9b9c-4db1-9a55-a27104fac756", pocos, [])
    xs = [n["x"] for n in chica["nodos"]]
    ys = [n["y"] for n in chica["nodos"]]
    assert max(xs) - min(xs) > ANCHO * 0.3 or max(ys) - min(ys) > ALTO * 0.3


def test_the_canvas_grows_instead_of_compressing_the_figure():
    """Si no cabe, crece el lienzo, y se DICE (RULE 2). Nunca se comprime en silencio."""
    muchos = [_n("file", f"documento-larguisimo-{i}.docx") for i in range(40)]
    figura = layout_caso("caso-2", muchos, [])

    assert figura["lienzo"]["ancho"] > ANCHO
    codigos = [n["codigo"] for n in figura["notas"]]
    assert "lienzo_ampliado" in codigos
    ampliacion = next(n for n in figura["notas"] if n["codigo"] == "lienzo_ampliado")
    assert ampliacion["ancho"] == figura["lienzo"]["ancho"]

    # Un grafo que cabe no inventa notas.
    assert layout_caso("caso-3", [_n("user", "IEUser"), _n("file", "a.exe")], [])["notas"] == []


def test_the_relaxer_always_stops():
    """Iteraciones FIJAS, sin criterio de convergencia y sin azar.

    Un bucle que itera «hasta que converja» haría depender la figura de la
    aritmética en coma flotante de la máquina, que es exactamente lo que este
    módulo existe para evitar.
    """
    assert isinstance(_ITERACIONES, int) and _ITERACIONES > 0

    # Todos en el mismo punto: el peor caso posible para un relajador.
    apilados = [
        {"tipo": "file", "valor": f"colision-{i}.bin", "x": 0.0, "y": 0.0, "centro": False}
        for i in range(12)
    ]
    corregidos = _relajar(apilados)

    pares = len(apilados) * (len(apilados) - 1) // 2
    assert 0 < corregidos <= pares * _ITERACIONES
    # Y termina habiendo separado de verdad: ningún par sigue en el mismo sitio.
    posiciones = {(round(n["x"], 3), round(n["y"], 3)) for n in apilados}
    assert len(posiciones) == len(apilados)


def test_the_innermost_ring_is_the_one_that_concentrates_edges():
    """El orden de anillos lo decide el GRADO MEDIO de cada tipo en ESE grafo.

    Antes lo decidía una tupla fija que ponía las cuentas dentro siempre, y como
    las cuentas son también el tipo más numeroso, el tipo con más nodos acababa
    en la circunferencia más corta.
    """
    nodos = [_n("user", f"cuenta{i}") for i in range(6)] + [
        _n("hostname", f"equipo{i}") for i in range(3)
    ]
    # Aquí quien concentra aristas son los EQUIPOS, no las cuentas.
    relaciones = [
        {"origen": f"cuenta{i}", "destino": f"equipo{i % 3}", "tipo": "logon"} for i in range(6)
    ]
    figura = layout_caso("caso-4", nodos, relaciones)

    cx = figura["lienzo"]["ancho"] / 2
    cy = figura["lienzo"]["alto"] / 2
    radio = {
        n["valor"]: math.hypot(n["x"] - cx, n["y"] - cy) for n in figura["nodos"]
    }
    equipos = max(radio[f"equipo{i}"] for i in range(3))
    cuentas = min(radio[f"cuenta{i}"] for i in range(6))
    assert equipos < cuentas, "el tipo que concentra aristas tiene que ir dentro"
