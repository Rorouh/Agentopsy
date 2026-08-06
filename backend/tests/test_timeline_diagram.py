"""El DIBUJO de la línea temporal (2026-08-06).

Dos partes, porque son dos cosas que se rompen por separado:

1. el LAYOUT (``forensia.timeline.diagram``), puro, con fixtures: que las barras
   midan la duración auditada y no un instante, que un carril por evidencia sea
   distinguible del siguiente, que la banda de fases cuente la historia en el
   orden de la matriz, y que las cubetas de la banda de densidad sean DENSAS (un
   hueco es un dato) y no se calculen sobre una ventana recortada;
2. la SUPERFICIE (``GET …/timeline/diagram``): que la capa sea obligatoria, que la
   banda de densidad exija su evidencia, y que «todavía no hay nada que dibujar»
   se diga con un motivo accionable en vez de con un eje vacío (RULE 2).
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from forensia.cases.manager import CaseManager
from forensia.evidence import EvidenceManager
from forensia.findings.store import Finding, FindingStore
from forensia.mitre import catalog
from forensia.server import create_app
from forensia.timeline.builder import assemble_investigation_timeline
from forensia.timeline.diagram import (
    MAX_CUBETAS,
    MAX_MARCAS_EJE,
    build_filesystem_diagram,
    build_investigation_diagram,
)
from forensia.timeline.relevance import select_relevant_events

PORT = 51044

_E1 = "11111111-1111-4111-8111-111111111111"
_E2 = "22222222-2222-4222-8222-222222222222"


# --------------------------------------------------------------------------- #
# Fixtures de dominio
# --------------------------------------------------------------------------- #
def _run(
    run_id: str,
    inicio: str,
    fin: str | None = None,
    *,
    tool_id: str = "tsk_fls",
    evidence_id: str | None = _E1,
    exit_code: int = 0,
) -> list[dict[str, Any]]:
    """Las DOS entradas que el log encadenado escribe por ejecución."""
    start = {
        "action": "tool_run_start",
        "ts_utc": inicio,
        "run_id": run_id,
        "tool_id": tool_id,
        "argv": [tool_id, "img.raw"],
        "evidence_id": evidence_id,
    }
    if fin is None:
        return [start]
    return [
        start,
        {
            "action": "tool_run_finish",
            "ts_utc": fin,
            "run_id": run_id,
            "status": "finished" if exit_code == 0 else "error",
            "exit_code": exit_code,
            "output_files_count": 1,
        },
    ]


def _finding(
    fid: str,
    created_at: str,
    *,
    hints: list[str] | None = None,
    evidence_id: str | None = _E1,
    severity: str = "high",
) -> Finding:
    return Finding(
        id=fid,
        case_id="c1",
        title="Título del hallazgo",
        summary="resumen",
        severity=severity,
        evidence_id=evidence_id,
        tool_id="tsk_fls",
        run_id=None,
        created_at=created_at,
        mitre_hints=hints or [],
    )


def _fs(ts: str, path: str, macb: str = "m.c.") -> dict[str, Any]:
    return {"kind": "fs", "ts": ts, "path": path, "macb": macb, "size": 10, "inode": "5"}


# --------------------------------------------------------------------------- #
# Dibujo A — franja de trabajos
# --------------------------------------------------------------------------- #
def test_a_bar_measures_the_audited_duration_not_an_instant() -> None:
    """La barra sale del par start/finish del log, que es lo que la hace barra."""
    audit = _run("r1", "2026-08-06T12:00:00+00:00", "2026-08-06T12:00:45+00:00")
    events = assemble_investigation_timeline(audit, [])

    dibujo = build_investigation_diagram(events, case_id="c1", case_name="Caso")

    assert dibujo is not None
    (barra,) = dibujo["carriles"][0]["barras"]
    assert barra["dur_s"] == 45.0
    assert barra["duracion"] == "45 s"
    assert barra["ts_fin"].startswith("2026-08-06T12:00:45")
    # La ventana llega hasta el CIERRE, no hasta el arranque: si no, la única
    # barra del dibujo se saldría del eje.
    assert dibujo["eje"]["span_s"] >= 45.0


def test_a_run_still_in_flight_has_no_duration_instead_of_zero() -> None:
    """Sin entrada de fin la duración NO se conoce; cero se leería como
    «tardó nada», que es un dato distinto (RULE 2)."""
    events = assemble_investigation_timeline(
        _run("r1", "2026-08-06T12:00:00+00:00", None), []
    )

    dibujo = build_investigation_diagram(events, case_id="c1", case_name="Caso")

    assert dibujo is not None
    (barra,) = dibujo["carriles"][0]["barras"]
    assert barra["dur_s"] is None
    assert barra["estado"] == "running"
    assert any("trazo" in aviso for aviso in dibujo["avisos"])


def test_a_finish_before_its_start_is_not_drawn_as_a_negative_bar() -> None:
    """Reloj movido entre las dos entradas: una duración negativa es una
    inconsistencia, no un dato, y dibujarla como cero la esconde."""
    events = assemble_investigation_timeline(
        _run("r1", "2026-08-06T12:00:30+00:00", "2026-08-06T12:00:00+00:00"), []
    )

    dibujo = build_investigation_diagram(events, case_id="c1", case_name="Caso")

    assert dibujo is not None
    assert dibujo["carriles"][0]["barras"][0]["dur_s"] is None


def test_one_lane_per_evidence_plus_one_for_the_unanchored() -> None:
    audit = [
        *_run("r1", "2026-08-06T12:00:00+00:00", "2026-08-06T12:00:10+00:00"),
        *_run("r2", "2026-08-06T12:01:00+00:00", "2026-08-06T12:01:10+00:00",
              evidence_id=_E2),
        *_run("r3", "2026-08-06T12:02:00+00:00", "2026-08-06T12:02:10+00:00",
              tool_id="jq", evidence_id=None),
    ]
    dibujo = build_investigation_diagram(
        assemble_investigation_timeline(audit, []),
        case_id="c1",
        case_name="Caso",
        evidence_labels={_E1: "disco.E01 · 11111111", _E2: "ram.raw · 22222222"},
    )

    assert dibujo is not None
    etiquetas = [c["etiqueta"] for c in dibujo["carriles"]]
    assert etiquetas == ["disco.E01 · 11111111", "ram.raw · 22222222",
                         "Sin evidencia anclada"]
    assert [c["evidence_id"] for c in dibujo["carriles"]] == [_E1, _E2, None]


def test_bars_are_packed_into_rows_so_one_label_never_covers_the_next() -> None:
    """Tres ejecuciones seguidas de un segundo en una ventana de 100 s: pegadas en
    una sola fila serían tres trazos sin nombre. La que va MUY después vuelve a la
    primera fila, porque ya no tapa a nadie: las filas crecen con la densidad, no
    con el número de eventos."""
    audit = [
        *_run("r1", "2026-08-06T12:00:00+00:00", "2026-08-06T12:00:01+00:00"),
        *_run("r2", "2026-08-06T12:00:02+00:00", "2026-08-06T12:00:03+00:00"),
        *_run("r3", "2026-08-06T12:00:04+00:00", "2026-08-06T12:00:05+00:00"),
        *_run("r4", "2026-08-06T12:01:40+00:00", "2026-08-06T12:01:41+00:00"),
    ]

    dibujo = build_investigation_diagram(
        assemble_investigation_timeline(audit, []), case_id="c1", case_name="Caso"
    )

    assert dibujo is not None
    carril = dibujo["carriles"][0]
    filas = {b["run_id"]: b["fila"] for b in carril["barras"]}
    assert filas["r1"] == 0 and filas["r2"] == 1 and filas["r3"] == 2
    assert filas["r4"] == 0
    assert carril["filas_barras"] == 3


def test_the_row_reserves_the_bar_AND_its_label_not_the_longer_of_the_two() -> None:
    """Se pinta la barra y su nombre justo detrás, así que el hueco reservado es la
    suma. Reservando el máximo, «regripper» caía encima de «tsk_icat»."""
    audit = [
        # Una ejecución larga (25 s de una ventana de 100 s) y otra justo detrás.
        *_run("r1", "2026-08-06T12:00:00+00:00", "2026-08-06T12:00:25+00:00"),
        *_run("r2", "2026-08-06T12:00:26+00:00", "2026-08-06T12:00:27+00:00",
              tool_id="regripper"),
        *_run("r3", "2026-08-06T12:01:40+00:00", "2026-08-06T12:01:41+00:00"),
    ]

    dibujo = build_investigation_diagram(
        assemble_investigation_timeline(audit, []), case_id="c1", case_name="Caso"
    )

    assert dibujo is not None
    filas = {b["run_id"]: b["fila"] for b in dibujo["carriles"][0]["barras"]}
    assert filas["r2"] != filas["r1"], "la etiqueta de r1 ocupa donde empieza r2"


def test_a_label_that_would_leave_the_axis_is_placed_to_the_left_by_the_layout() -> None:
    """El LADO lo decide el layout, no el pintor: un pintor que volteara por su
    cuenta una etiqueta que el empaquetado contó a la derecha la dejaría encima de
    la anterior, que es justo lo que pasaba al final del eje."""
    audit = [
        *_run("r1", "2026-08-06T12:00:00+00:00", "2026-08-06T12:00:01+00:00"),
        # La última, pegada al final de la ventana: su nombre no cabe a la derecha.
        *_run("r2", "2026-08-06T12:01:39+00:00", "2026-08-06T12:01:40+00:00",
              tool_id="plaso_log2timeline"),
    ]

    dibujo = build_investigation_diagram(
        assemble_investigation_timeline(audit, []), case_id="c1", case_name="Caso"
    )

    assert dibujo is not None
    lados = {b["run_id"]: b["lado"] for b in dibujo["carriles"][0]["barras"]}
    assert lados["r1"] == "derecha"
    assert lados["r2"] == "izquierda"


def test_an_evidence_without_a_label_falls_back_to_its_id_never_to_a_generic_name() -> None:
    dibujo = build_investigation_diagram(
        assemble_investigation_timeline(
            _run("r1", "2026-08-06T12:00:00+00:00", "2026-08-06T12:00:05+00:00"), []
        ),
        case_id="c1",
        case_name="Caso",
        evidence_labels={},
    )

    assert dibujo is not None
    assert dibujo["carriles"][0]["etiqueta"] == _E1


def test_the_phase_band_follows_the_matrix_order_not_the_clock() -> None:
    """Las fases se enuncian en el orden editorial de la matriz; los INTERVALOS
    son los medidos, así que un solapamiento se ve en vez de reordenarse."""
    tarde, temprano = _tecnicas_de_dos_fases()
    findings = [
        _finding("f1", "2026-08-06T12:00:10.000Z", hints=[tarde]),
        _finding("f2", "2026-08-06T12:00:40.000Z", hints=[temprano]),
    ]
    dibujo = build_investigation_diagram(
        assemble_investigation_timeline([], findings), case_id="c1", case_name="Caso"
    )

    assert dibujo is not None
    orden_matriz = [clave for clave, _ in catalog.PHASES]
    claves = [f["clave"] for f in dibujo["fases"]]
    assert claves == [c for c in orden_matriz if c in claves]
    assert len(claves) == 2
    # Cada tramo lleva su técnica y su recuento de hallazgos.
    assert all(f["hallazgos"] == 1 and len(f["tecnicas"]) == 1 for f in dibujo["fases"])


def test_a_technique_the_seed_does_not_place_still_paints_without_an_invented_phase() -> None:
    """RULE 2: la técnica se pinta en la marca; la fase no se adivina."""
    findings = [_finding("f1", "2026-08-06T12:00:10.000Z", hints=["T9999"])]

    dibujo = build_investigation_diagram(
        assemble_investigation_timeline([], findings), case_id="c1", case_name="Caso"
    )

    assert dibujo is not None
    (marca,) = dibujo["carriles"][0]["marcas"]
    assert marca["tecnicas"] == ["T9999"]
    assert marca["fase"] is None
    assert dibujo["fases"] == []
    assert any("banda de fases" in aviso for aviso in dibujo["avisos"])


def test_a_mark_carries_the_severity_in_spanish_and_its_finding_id() -> None:
    findings = [_finding("f1", "2026-08-06T12:00:10.000Z", severity="critical")]

    dibujo = build_investigation_diagram(
        assemble_investigation_timeline([], findings), case_id="c1", case_name="Caso"
    )

    assert dibujo is not None
    (marca,) = dibujo["carriles"][0]["marcas"]
    assert marca["etiqueta_severidad"] == "Crítica"
    assert marca["finding_id"] == "f1"


def test_an_event_without_a_timestamp_is_announced_never_silently_dropped() -> None:
    audit = [
        *_run("r1", "2026-08-06T12:00:00+00:00", "2026-08-06T12:00:05+00:00"),
        *_run("r2", "no es una fecha", None),
    ]

    dibujo = build_investigation_diagram(
        assemble_investigation_timeline(audit, []), case_id="c1", case_name="Caso"
    )

    assert dibujo is not None
    assert dibujo["resumen"]["ejecuciones"] == 1
    assert any("sin marca temporal" in aviso for aviso in dibujo["avisos"])


def test_a_case_with_nothing_to_draw_has_no_diagram_instead_of_an_empty_axis() -> None:
    assert build_investigation_diagram([], case_id="c1", case_name="Caso") is None


def test_every_event_at_the_same_instant_still_yields_a_drawable_axis() -> None:
    """Un eje de longitud cero haría que todo pintor dividiera por él."""
    findings = [
        _finding("f1", "2026-08-06T12:00:00.000Z"),
        _finding("f2", "2026-08-06T12:00:00.000Z"),
    ]

    dibujo = build_investigation_diagram(
        assemble_investigation_timeline([], findings), case_id="c1", case_name="Caso"
    )

    assert dibujo is not None
    assert dibujo["eje"]["span_s"] > 0


@pytest.mark.parametrize(
    ("fin", "formato_esperado"),
    [
        ("2026-08-06T12:00:20+00:00", ":"),      # segundos: HH:MM:SS
        ("2026-08-06T18:00:00+00:00", ":"),      # horas: HH:MM
        ("2026-09-20T12:00:00+00:00", "-"),      # días: YYYY-MM-DD
    ],
)
def test_the_axis_never_exceeds_its_tick_budget(fin: str, formato_esperado: str) -> None:
    audit = _run("r1", "2026-08-06T12:00:00+00:00", fin)

    dibujo = build_investigation_diagram(
        assemble_investigation_timeline(audit, []), case_id="c1", case_name="Caso"
    )

    assert dibujo is not None
    marcas = dibujo["eje"]["marcas"]
    assert 0 < len(marcas) <= MAX_MARCAS_EJE + 1
    assert all(formato_esperado in m["etiqueta"] for m in marcas)
    # Toda marca cae DENTRO de la ventana: una etiqueta fuera del eje se pintaría
    # sobre el margen.
    assert all(0 <= m["t_s"] <= dibujo["eje"]["span_s"] + 1 for m in marcas)


def test_a_time_axis_carries_the_date_on_the_first_tick_and_on_each_day_change() -> None:
    """Sin la fecha, un dibujo de tres días se lee como si fuera de uno."""
    audit = _run("r1", "2026-08-06T22:00:00+00:00", "2026-08-07T04:00:00+00:00")

    dibujo = build_investigation_diagram(
        assemble_investigation_timeline(audit, []), case_id="c1", case_name="Caso"
    )

    assert dibujo is not None
    marcas = dibujo["eje"]["marcas"]
    assert marcas[0]["sub"] == "2026-08-06"
    assert [m["sub"] for m in marcas].count("2026-08-07") == 1


def test_the_provenance_names_the_case_and_the_window() -> None:
    audit = _run("r1", "2026-08-06T12:00:00+00:00", "2026-08-06T12:06:30+00:00")

    dibujo = build_investigation_diagram(
        assemble_investigation_timeline(audit, []),
        case_id="c1",
        case_name="Caso Ñandú",
        generated_at="2026-08-06T13:00:00Z",
    )

    assert dibujo is not None
    procedencia = dict((campo, valor) for campo, valor in dibujo["procedencia"])
    assert procedencia["Caso"] == "Caso Ñandú"
    assert procedencia["Exportado (UTC)"] == "2026-08-06T13:00:00Z"
    assert "6 min 30 s" in procedencia["Ventana"]
    # El nombre del fichero que el perito se lleva: transcrito a ASCII y con la
    # marca temporal, para que dos figuras del mismo caso no se pisen.
    assert dibujo["basename"] == "agentopsy-timeline-dibujo-caso-nandu-20260806T130000Z"
    assert dibujo["basename"].isascii()


def _tecnicas_de_dos_fases() -> tuple[str, str]:
    """Dos técnicas REALES de la semilla en fases distintas, en orden de matriz.

    Se leen del catálogo en vez de teclearse: una lista a mano aquí sería una
    segunda enum que se desincroniza de la semilla.
    """
    por_fase: dict[str, str] = {}
    for tactic in catalog.load().tactics:
        if tactic.phase not in por_fase and tactic.techniques:
            por_fase[tactic.phase] = tactic.techniques[0].id
    orden = [clave for clave, _ in catalog.PHASES if clave in por_fase]
    if len(orden) < 2:
        pytest.skip("la semilla ATT&CK no está disponible con dos fases distintas")
    return por_fase[orden[0]], por_fase[orden[1]]


# --------------------------------------------------------------------------- #
# Dibujo B — banda de densidad MACB
# --------------------------------------------------------------------------- #
def test_the_buckets_are_dense_so_a_gap_stays_visible() -> None:
    """Un tramo sin actividad es un DATO. Si solo se emitieran las cubetas con
    eventos, dos meses de silencio se leerían como un día."""
    eventos = [
        _fs("2026-01-01T00:00:00Z", "/a"),
        _fs("2026-01-05T00:00:00Z", "/b"),
    ]

    dibujo = build_filesystem_diagram(eventos, [], case_id="c1", case_name="Caso")

    assert dibujo is not None
    assert dibujo["granularidad"]["clave"] == "hora"
    totales = [c["total"] for c in dibujo["cubetas"]]
    assert sum(totales) == 2
    assert totales.count(0) == len(totales) - 2
    # Las cubetas cubren el eje EXACTAMENTE: la última acaba donde acaba la ventana.
    ultima = dibujo["cubetas"][-1]
    assert ultima["t_s"] + ultima["dur_s"] == pytest.approx(dibujo["eje"]["span_s"])


def test_the_granularity_grows_with_the_span_instead_of_the_bucket_count() -> None:
    """Tres años en cubetas de una hora serían 26.000 barras de un píxel."""
    eventos = [
        _fs("2023-01-01T00:00:00Z", "/a"),
        _fs("2026-01-01T00:00:00Z", "/b"),
    ]

    dibujo = build_filesystem_diagram(eventos, [], case_id="c1", case_name="Caso")

    assert dibujo is not None
    assert len(dibujo["cubetas"]) <= MAX_CUBETAS
    assert dibujo["granularidad"]["bucket_s"] >= 604800


def test_the_letters_are_counted_per_letter_not_per_event() -> None:
    """Un evento con varias letras cuenta en cada una: es lo que separa «se
    modificó» de «se creó» en la misma cubeta."""
    # En la misma cubeta: con un rango de 20 segundos la granularidad es el minuto.
    eventos = [
        _fs("2026-01-01T00:00:00Z", "/a", "macb"),
        _fs("2026-01-01T00:00:20Z", "/b", "m..."),
    ]

    dibujo = build_filesystem_diagram(eventos, [], case_id="c1", case_name="Caso")

    assert dibujo is not None
    con_datos = [c for c in dibujo["cubetas"] if c["total"]]
    letras = con_datos[0]["letras"]
    assert letras == {"m": 2, "a": 1, "c": 1, "b": 1}
    assert dibujo["max_total"] == 2
    assert dibujo["max_letra"] == 2


def test_relevance_is_aggregated_per_bucket_and_labelled_by_its_top_event() -> None:
    """Cientos de marcas sobre una banda son ruido: cada cubeta lleva su recuento
    y el evento de más peso, que es el que se etiqueta."""
    eventos = [
        _fs("2026-01-01T00:00:00Z", "/windows/system32/kernel32.dll", "..cb"),
        _fs("2026-01-01T00:00:20Z", "/etc/shadow", "m.c."),
        _fs("2026-01-01T00:00:40Z", "/home/u/.bash_history", "m.c."),
    ]
    relevantes, _ = select_relevant_events(eventos, limit=None)

    dibujo = build_filesystem_diagram(
        eventos, relevantes, case_id="c1", case_name="Caso"
    )

    assert dibujo is not None
    assert len(dibujo["marcas"]) == 1
    marca = dibujo["marcas"][0]
    assert marca["total"] == 3
    # Credenciales pesa 5, el binario de sistema 3: manda el de más peso.
    assert marca["principal"]["categoria"] == "credenciales"
    assert marca["principal"]["motivo"] == "Fichero de credenciales del sistema"
    assert dibujo["max_peso"] == 5
    assert dibujo["cubetas"][marca["cubeta"]]["relevantes"] == 3
    claves = {c["clave"] for c in dibujo["categorias"]}
    assert claves == {"credenciales", "historial", "binario_sistema"}


def test_the_macb_diagram_declares_its_evidence_in_the_provenance() -> None:
    """Una figura que no dice de qué evidencia es no vale como anexo."""
    dibujo = build_filesystem_diagram(
        [_fs("2026-01-01T00:00:00Z", "/a")],
        [],
        case_id="c1",
        case_name="Caso",
        evidence_id=_E1,
        evidence_label="disco.E01 · 11111111",
        generated_at="2026-08-06T13:00:00Z",
    )

    assert dibujo is not None
    procedencia = dict((campo, valor) for campo, valor in dibujo["procedencia"])
    assert procedencia["Evidencia"] == "disco.E01 · 11111111"
    assert procedencia["Identificador de la evidencia"] == _E1
    assert "cubetas" in procedencia["Cubetas"]
    assert dibujo["basename"].startswith("agentopsy-timeline-macb-dibujo-caso-")


def test_an_empty_filesystem_layer_has_no_diagram() -> None:
    assert build_filesystem_diagram([], [], case_id="c1", case_name="Caso") is None


# --------------------------------------------------------------------------- #
# Superficie HTTP
# --------------------------------------------------------------------------- #
@pytest.fixture
def cases(tmp_path, monkeypatch) -> CaseManager:
    store = CaseManager(root=tmp_path / "cases")
    import forensia.routers.timeline as timeline_router
    import forensia.timeline.builder as builder

    monkeypatch.setattr(timeline_router, "case_manager", store)
    # El builder del timeline y el gestor de evidencias resuelven el caso por sus
    # PROPIOS singletons: en producción son el mismo objeto, en el test hay que
    # decírselo o el router mira en el directorio de casos del usuario.
    monkeypatch.setattr(builder, "case_manager", store)
    monkeypatch.setattr(builder, "finding_store", FindingStore(store))
    monkeypatch.setattr(timeline_router, "evidence_manager", EvidenceManager(store))
    return store


@pytest.fixture
def client(cases) -> TestClient:
    return TestClient(create_app(PORT), base_url=f"http://127.0.0.1:{PORT}")


@pytest.fixture
def auth(client) -> dict[str, str]:
    return {"X-Forensia-Token": client.app.state.token}


def test_the_layer_is_required_never_chosen_for_the_operator(client, auth, cases) -> None:
    case = cases.create(name="Caso", examiner="perito", os_profile="windows")

    res = client.get(f"/api/cases/{case.id}/timeline/diagram", headers=auth)

    assert res.status_code == 422, res.text
    assert "layer" in res.json()["detail"]
    assert "investigation" in res.json()["detail"]


def test_an_unknown_layer_is_rejected_with_the_valid_ones(client, auth, cases) -> None:
    case = cases.create(name="Caso", examiner="perito", os_profile="windows")

    res = client.get(
        f"/api/cases/{case.id}/timeline/diagram?layer=relevant", headers=auth
    )

    assert res.status_code == 422, res.text
    assert "filesystem" in res.json()["detail"]


def test_a_case_with_no_activity_says_so_instead_of_drawing_an_empty_axis(
    client, auth, cases
) -> None:
    case = cases.create(name="Caso", examiner="perito", os_profile="windows")

    res = client.get(
        f"/api/cases/{case.id}/timeline/diagram?layer=investigation", headers=auth
    )

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["diagram"] is None
    assert "marca temporal" in body["message"]


def test_the_density_band_requires_its_evidence(client, auth, cases) -> None:
    case = cases.create(name="Caso", examiner="perito", os_profile="windows")

    res = client.get(
        f"/api/cases/{case.id}/timeline/diagram?layer=filesystem", headers=auth
    )

    assert res.status_code == 422, res.text
    assert "evidence_id" in res.json()["detail"]


def test_an_unknown_case_is_a_404(client, auth) -> None:
    res = client.get(
        "/api/cases/00000000-0000-4000-8000-000000000000/timeline/diagram"
        "?layer=investigation",
        headers=auth,
    )
    assert res.status_code == 404, res.text
