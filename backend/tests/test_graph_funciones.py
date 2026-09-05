"""Las tres funciones EN PRUEBA de la sección de grafos (2026-09-04).

Van en un fichero aparte, y no dentro de ``test_graph_relaciones.py``, para que
retirar una función sea borrar su módulo, su bloque del router y sus tests de
aquí, sin tocar lo que fija el contrato del grafo. Cada bloque de este fichero
está rotulado con el nombre de su función:

- «INVENTARIO» (``agentopsy.graph.inventario``): la figura dibuja la RED, y las
  entidades que ningún hallazgo relaciona bajan a una banda declarada que solo
  compone el PNG.
- «VISTAS» (``agentopsy.graph.vistas``): cortes del grafo del caso por un eje que
  el caso ya tiene persistido.
- La tercera, «LOCALIZADOR», es enteramente del cliente (buscar una entidad y
  encuadrarla, y el foco a dos saltos) y no tiene superficie que fijar aquí.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

import pytest
from fastapi.testclient import TestClient

from agentopsy.cases.manager import CaseManager
from agentopsy.findings.store import FindingStore
from agentopsy.graph import inventario, vistas
from agentopsy.graph.layout import ALTO_ETIQUETA, RADIO_NODO, ancho_caja, layout_caso
from agentopsy.graph.store import GraphStore
from agentopsy.server import create_app

PORT = 51137


# ── FUNCIÓN «INVENTARIO» ──────────────────────────────────────────────────────


def _nodo(tipo: str, valor: str) -> dict[str, str]:
    return {"tipo": tipo, "valor": valor}


def test_loose_entities_leave_the_network_but_never_the_figure() -> None:
    """Partir es por GRADO, y no pierde ni una entidad.

    Es la garantía que separa esto de una poda: los nodos sin arista salen del
    anillo, pero siguen estando, con su tipo y su valor intactos, y el recuento
    de la banda más el de la red da el total (RULE 2: nada se descarta en
    silencio)."""
    nodos = [
        _nodo("user", "jcloudy"),
        _nodo("file", "key.exe"),
        _nodo("domain", "gmail.com"),
        _nodo("file", "pagefile.sys"),
    ]
    relaciones = [{"origen": "jcloudy", "destino": "key.exe", "tipo": "process_spawn"}]

    conectados, sueltos = inventario.partir(nodos, relaciones)

    assert [n["valor"] for n in conectados] == ["jcloudy", "key.exe"]
    assert [n["valor"] for n in sueltos] == ["gmail.com", "pagefile.sys"]
    assert len(conectados) + len(sueltos) == len(nodos)

    figura = inventario.componer(layout_caso("c", conectados, relaciones), sueltos)
    assert figura["inventario"]["total"] == 2
    assert figura["inventario"]["en_la_red"] == 2
    assert {n["valor"] for n in figura["inventario"]["nodos"]} == {
        "gmail.com",
        "pagefile.sys",
    }
    # Y quedan marcados, para que el cliente no los confunda con la red.
    assert all(n["suelto"] for n in figura["inventario"]["nodos"])


def test_the_band_never_changes_the_canvas_of_the_network() -> None:
    """La razón de ser del módulo, y la que se midió.

    La primera versión metía la banda en el MISMO lienzo, y sobre el caso real
    ese lienzo pasaba de 1258 x 887 a 1258 x 1531: la figura volvía a ajustarse
    al 46 % y la etiqueta se quedaba en 4,8 px, casi los 4,0 px de los que se
    venía. Si este test se rompe, la banda ha vuelto a comerse la ganancia.

    Que el ANCHO tampoco cambie es lo que permite decir que se exporta lo que se
    está mirando: las coordenadas de la red son las mismas en las dos figuras."""
    conectados = [_nodo("user", "jcloudy"), _nodo("file", "key.exe")]
    relaciones = [{"origen": "jcloudy", "destino": "key.exe", "tipo": "process_spawn"}]
    sueltos = [_nodo("file", f"suelto-{i}.tmp") for i in range(46)]

    red = layout_caso("c", conectados, relaciones)
    figura = inventario.componer(red, sueltos)

    assert figura["lienzo"] == red["lienzo"]
    assert figura["nodos"] == red["nodos"]
    banda = figura["inventario"]
    assert banda["lienzo"]["ancho"] == red["lienzo"]["ancho"]
    assert banda["lienzo"]["alto"] > red["lienzo"]["alto"]
    assert red["lienzo"]["alto"] < banda["y"] < banda["lienzo"]["alto"]


def test_the_band_is_a_grid_that_does_not_overlap_and_stays_inside_its_canvas() -> None:
    """Sitio reservado por construcción: la banda es una tabla, no un grafo, así
    que no pasa por el relajador y tiene que salir bien colocada de una vez."""
    sueltos = [_nodo("file", f"documento-largo-{i}.docx") for i in range(46)]
    figura = inventario.componer(
        layout_caso("c", [_nodo("user", "a"), _nodo("user", "b")],
                    [{"origen": "a", "destino": "b", "tipo": "logon"}]),
        sueltos,
    )
    banda = figura["inventario"]
    colocados = banda["nodos"]
    alto_caja = 2 * RADIO_NODO + ALTO_ETIQUETA

    for n in colocados:
        assert n["x"] - ancho_caja(n) / 2 >= 0
        assert n["x"] + ancho_caja(n) / 2 <= banda["lienzo"]["ancho"]
        assert n["y"] + RADIO_NODO + ALTO_ETIQUETA <= banda["lienzo"]["alto"]

    solapes = [
        (a["valor"], b["valor"])
        for i, a in enumerate(colocados)
        for b in colocados[i + 1:]
        if abs(a["x"] - b["x"]) < (ancho_caja(a) + ancho_caja(b)) / 2
        and abs(a["y"] - b["y"]) < alto_caja
    ]
    assert not solapes, solapes


def test_a_figure_where_everything_is_connected_gets_no_band() -> None:
    """Una banda vacía no explica nada, así que no se pinta."""
    conectados = [_nodo("user", "jcloudy"), _nodo("file", "key.exe")]
    relaciones = [{"origen": "jcloudy", "destino": "key.exe", "tipo": "process_spawn"}]
    figura = inventario.componer(layout_caso("c", conectados, relaciones), [])
    assert figura["inventario"] is None


def test_the_band_is_deterministic() -> None:
    """Misma exigencia que el resto de la geometría: una figura que se adjunta a
    un informe pericial tiene que dar la misma imagen hoy y dentro de un año."""
    sueltos = [_nodo("domain", f"d{i}.example.org") for i in range(15)]
    red = layout_caso("c", [_nodo("user", "a"), _nodo("user", "b")],
                      [{"origen": "a", "destino": "b", "tipo": "logon"}])
    primera = inventario.componer(red, sueltos)["inventario"]
    segunda = inventario.componer(red, sueltos)["inventario"]
    assert primera == segunda


# ── FUNCIÓN «VISTAS» ──────────────────────────────────────────────────────────


@dataclass
class _Hallazgo:
    """Lo mínimo que ``vistas`` lee de un hallazgo."""

    id: str
    severity: str = "high"
    evidence_id: str | None = None
    mitre_hints: list[str] = field(default_factory=list)


def test_a_view_cuts_by_findings_and_declares_what_it_cut() -> None:
    """El corte elige HALLAZGOS, no nodos.

    Es la diferencia entre recortar el grafo y filtrarlo: un nodo entra si lo
    sostiene un hallazgo que entra. Descartar un nodo por parecer ajeno a la
    vista sería afirmar sobre él algo que ningún hallazgo dice."""
    findings = [
        _Hallazgo("f1", mitre_hints=["T1114"], evidence_id="e1"),
        _Hallazgo("f2", mitre_hints=["T1114", "T1059"], evidence_id="e2"),
        _Hallazgo("f3", mitre_hints=[], evidence_id="e1", severity="low"),
    ]

    elegidos, declarada = vistas.hallazgos_de("tecnica:T1114", findings, {})
    assert elegidos == ["f1", "f2"]
    assert declarada["eje"] == "tecnica"
    assert declarada["hallazgos"] == 2

    por_evidencia, _ = vistas.hallazgos_de("evidencia:e1", findings, {})
    assert por_evidencia == ["f1", "f3"]

    por_severidad, _ = vistas.hallazgos_de("severidad:low", findings, {})
    assert por_severidad == ["f3"]


def test_a_view_merges_the_two_sources_of_attack_proposals() -> None:
    """Los ``mitre_hints`` del hallazgo MÁS lo que ``annotate_mitre`` le ancló.

    Misma fusión que hace la línea de tiempo del incidente y por la misma razón
    medida: la mayor parte de la correlación real de un caso llega por la segunda
    vía, así que sin fusionar el corte dejaría fuera a casi todos."""
    findings = [_Hallazgo("f1"), _Hallazgo("f2", mitre_hints=["T1114"])]
    anotaciones = {"f1": ["T1114"]}

    assert vistas.tecnicas_del_hallazgo(findings[0], anotaciones) == ["T1114"]
    elegidos, _ = vistas.hallazgos_de("tecnica:T1114", findings, anotaciones)
    assert elegidos == ["f1", "f2"]


def test_an_unknown_axis_is_refused_naming_the_valid_ones() -> None:
    """RULE 2: un corte que no se entiende no se sustituye por el caso entero."""
    with pytest.raises(vistas.VistaDesconocida) as exc:
        vistas.resolver("colorDelNodo:azul")
    for eje in vistas.EJES:
        assert eje in str(exc.value)
    with pytest.raises(vistas.VistaDesconocida):
        vistas.resolver("tecnica")


def test_only_views_that_would_paint_something_are_offered() -> None:
    """Un corte que no cubra ningún hallazgo CON grafo no se ofrece: elegirlo
    daría una figura vacía y el perito no sabría si es que no hay relaciones o
    es que no se ha extraído nada."""
    findings = [
        _Hallazgo("f1", mitre_hints=["T1114"], evidence_id="e1"),
        _Hallazgo("f2", mitre_hints=["T1486"], evidence_id="e2"),
    ]
    catalogo = vistas.catalogo(findings, {}, con_grafo={"f1"})
    ids = {v["id"] for v in catalogo}
    assert "tecnica:T1114" in ids
    assert "tecnica:T1486" not in ids
    assert "evidencia:e1" in ids
    assert "evidencia:e2" not in ids
    # Y el orden es determinista: primero el eje, luego los más poblados.
    assert [v["eje"] for v in catalogo] == sorted(
        (v["eje"] for v in catalogo), key=vistas.EJES.index
    )


def test_a_view_that_covers_nothing_says_so_instead_of_falling_back() -> None:
    """Un corte válido pero vacío es un resultado legítimo, y se dice."""
    elegidos, declarada = vistas.hallazgos_de(
        "tecnica:T9999", [_Hallazgo("f1", mitre_hints=["T1114"])], {}
    )
    assert elegidos == []
    assert declarada["hallazgos"] == 0


# ── la superficie HTTP de las dos ─────────────────────────────────────────────


@pytest.fixture()
def http(tmp_path, monkeypatch):
    import agentopsy.routers.graphs as graphs_router

    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Murcielago", examiner="Daniel Ramos", os_profile="windows")
    findings = FindingStore(cases)
    store = GraphStore(cases)

    monkeypatch.setattr(graphs_router, "case_manager", cases)
    monkeypatch.setattr(graphs_router, "finding_store", findings)
    monkeypatch.setattr(graphs_router, "graph_store", store)
    monkeypatch.setattr(graphs_router.config, "get", lambda _k: None)

    client = TestClient(create_app(PORT), base_url=f"http://127.0.0.1:{PORT}")
    return {
        "client": client, "case": case, "cases": cases,
        "findings": findings, "store": store,
        "auth": {"X-Agentopsy-Token": client.app.state.token},
    }


def _con_grafo(http_env, *, hints: list[str], nodos, relaciones) -> str:
    f = http_env["findings"].append(http_env["case"].id, {
        "title": "key.exe ejecutado por jcloudy", "summary": "jcloudy ejecutó key.exe",
        "severity": "high", "run_id": str(uuid.uuid4()), "mitre_hints": hints,
    })
    http_env["store"].save(
        http_env["case"].id, f.id, {"nodos": nodos, "relaciones": relaciones}
    )
    return f.id


def test_the_case_graph_carries_its_band_and_its_available_views(http) -> None:
    _con_grafo(
        http,
        hints=["T1059"],
        nodos=[_nodo("user", "jcloudy"), _nodo("file", "key.exe"),
               _nodo("domain", "gmail.com")],
        relaciones=[{"origen": "jcloudy", "destino": "key.exe", "tipo": "process_spawn"}],
    )
    r = http["client"].get(
        f"/api/cases/{http['case'].id}/graphs/case", headers=http["auth"]
    )
    assert r.status_code == 200
    cuerpo = r.json()

    # La red va en `nodos`; la entidad sin relación va en la banda, no perdida.
    assert {n["valor"] for n in cuerpo["nodos"]} == {"jcloudy", "key.exe"}
    assert cuerpo["inventario"]["total"] == 1
    assert cuerpo["inventario"]["nodos"][0]["valor"] == "gmail.com"

    # Sin `vista` no hay corte aplicado, y se ofrecen los que el caso admite.
    assert cuerpo["vista"] is None
    assert "tecnica:T1059" in {v["id"] for v in cuerpo["vistas"]}


def test_asking_for_a_view_cuts_the_figure_and_declares_it(http) -> None:
    _con_grafo(
        http, hints=["T1059"],
        nodos=[_nodo("user", "jcloudy"), _nodo("file", "key.exe")],
        relaciones=[{"origen": "jcloudy", "destino": "key.exe", "tipo": "process_spawn"}],
    )
    _con_grafo(
        http, hints=["T1486"],
        nodos=[_nodo("user", "otro"), _nodo("file", "otro.exe")],
        relaciones=[{"origen": "otro", "destino": "otro.exe", "tipo": "process_spawn"}],
    )

    entero = http["client"].get(
        f"/api/cases/{http['case'].id}/graphs/case", headers=http["auth"]
    ).json()
    assert len(entero["nodos"]) == 4

    cortado = http["client"].get(
        f"/api/cases/{http['case'].id}/graphs/case?vista=tecnica:T1059",
        headers=http["auth"],
    ).json()
    assert {n["valor"] for n in cortado["nodos"]} == {"jcloudy", "key.exe"}
    # Y la figura DECLARA su corte: la vista viaja en la respuesta para que el
    # cliente la escriba dentro del PNG.
    assert cortado["vista"]["id"] == "tecnica:T1059"
    assert cortado["vista"]["hallazgos"] == 1
    # El catálogo sigue siendo el del CASO, no el del corte: si solo ofreciera
    # los cortes de lo ya filtrado, no habría forma de volver a otra vista.
    assert "tecnica:T1486" in {v["id"] for v in cortado["vistas"]}


def test_an_unknown_view_is_a_422_and_never_the_whole_case(http) -> None:
    """El fallo tiene que verse. Devolver el caso entero ante un corte que no se
    entiende es exactamente el default silencioso que prohíbe RULE 2."""
    _con_grafo(
        http, hints=[], nodos=[_nodo("user", "jcloudy")], relaciones=[],
    )
    r = http["client"].get(
        f"/api/cases/{http['case'].id}/graphs/case?vista=inventado:x",
        headers=http["auth"],
    )
    assert r.status_code == 422
    for eje in vistas.EJES:
        assert eje in r.json()["detail"]
