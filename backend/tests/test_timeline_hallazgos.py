"""La capa 4 del timeline: la línea de tiempo del INCIDENTE (2026-08-10).

Es la cronología de lo que pasó en el DISPOSITIVO INVESTIGADO, no la del trabajo del
agente (esa es ``test_timeline.py``). Su eje es ``Finding.observed_at`` y solo ese, así
que lo que se fija aquí es sobre todo qué NO entra y cómo se declara: un hallazgo que no
se puede situar en el tiempo es un dato del caso, no un residuo (CLAUDE.md RULE 2).

Se prueba el ensamblador PURO con hallazgos construidos a mano, y la superficie HTTP
por separado, que es donde se ve lo que el ensamblador no puede fallar solo (el 404 de
un caso inexistente, y que un caso sin hallazgos trae su mensaje).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from forensia.cases.manager import CaseManager
from forensia.findings.store import Finding, FindingStore
from forensia.server import create_app
from forensia.timeline.hallazgos import assemble_findings_timeline

PORT = 51041

_RUN_ID = "33333333-3333-4333-8333-333333333333"


def _finding(
    fid: str,
    *,
    observed_at: str | None = None,
    title: str = "hallazgo",
    severity: str = "high",
    mitre_hints: list[str] | None = None,
) -> Finding:
    return Finding(
        id=fid,
        case_id="c1",
        title=title,
        summary="resumen",
        severity=severity,
        evidence_id=None,
        tool_id="tsk_fls",
        run_id=_RUN_ID,
        created_at="2026-08-10T12:00:00.000Z",
        mitre_hints=mitre_hints or [],
        observed_at=observed_at,
    )


# --------------------------------------------------------------------------- #
# El eje: qué entra, en qué orden
# --------------------------------------------------------------------------- #
def test_events_are_ordered_by_observed_at_ascending() -> None:
    """El orden es el del HECHO en la evidencia, no el del registro del hallazgo.

    Los tres se registraron en orden inverso al que ocurrieron (mismo ``created_at``,
    orden de fichero descendente): si el eje se ordenara por cualquier otra cosa, este
    test lo vería.
    """
    findings = [
        _finding("f3", observed_at="2021-03-23T19:24:35Z", title="el último"),
        _finding("f1", observed_at="2021-03-18T01:13:54Z", title="el primero"),
        _finding("f2", observed_at="2021-03-19T08:40:00Z", title="el de en medio"),
    ]

    tl = assemble_findings_timeline(findings, {})

    assert [e["title"] for e in tl["eventos"]] == ["el primero", "el de en medio", "el último"]
    assert [e["ts"] for e in tl["eventos"]] == [
        "2021-03-18T01:13:54Z",
        "2021-03-19T08:40:00Z",
        "2021-03-23T19:24:35Z",
    ]


def test_findings_sharing_an_instant_keep_their_registration_order() -> None:
    """Varios hallazgos del MISMO instante conservan el orden en que se registraron.

    Pasa de verdad: en un caso real seis hallazgos comparten el instante de
    adquisición de la RAM. El orden estable es una decisión, no una casualidad, y en
    particular NO se desempata con ``created_at``, que no entra en este eje.
    """
    instante = "2021-03-23T19:24:35Z"
    findings = [
        _finding("f1", observed_at=instante, title="primero registrado"),
        _finding("f2", observed_at=instante, title="segundo registrado"),
        _finding("f3", observed_at=instante, title="tercero registrado"),
    ]

    tl = assemble_findings_timeline(findings, {})

    assert [e["title"] for e in tl["eventos"]] == [
        "primero registrado",
        "segundo registrado",
        "tercero registrado",
    ]


def test_an_offset_timestamp_is_normalized_to_utc_without_moving_the_instant() -> None:
    """Un artefacto convertido desde hora local viaja con su offset; el eje es UTC."""
    findings = [_finding("f1", observed_at="2021-03-23T20:24:35+01:00")]

    tl = assemble_findings_timeline(findings, {})

    assert tl["eventos"][0]["ts"] == "2021-03-23T19:24:35Z"


# --------------------------------------------------------------------------- #
# Lo que NO entra: contado y declarado, nunca descartado en silencio (RULE 2)
# --------------------------------------------------------------------------- #
def test_a_finding_without_observed_at_stays_out_and_is_counted() -> None:
    """Sin marca del artefacto no hay evento, y NO se cae a ``created_at``.

    Fecharlo con la hora del análisis falsearía el incidente. El hallazgo no
    desaparece: se cuenta aparte para que la vista y la imagen exportada lo declaren.
    """
    findings = [
        _finding("f1", observed_at="2021-03-18T01:13:54Z"),
        _finding("f2", observed_at=None, title="sin marca"),
        _finding("f3", observed_at=None, title="tampoco"),
    ]

    tl = assemble_findings_timeline(findings, {})

    assert [e["finding_id"] for e in tl["eventos"]] == ["f1"]
    assert tl["sin_observed_at"] == 2
    assert tl["total_hallazgos"] == 3
    # El instante del análisis no se ha colado por ninguna vía.
    assert "2026-08-10" not in str(tl["eventos"])


def test_an_unreadable_observed_at_stays_out_and_is_declared_apart() -> None:
    """Una marca ilegible no es lo mismo que no tenerla, y se declara por separado.

    Los valores LITERALES viajan: el perito tiene que poder ver qué se escribió para
    saber si es un fallo del agente o un artefacto raro. Incluye el caso que la
    validación del store ataja hoy (marca SIN zona), porque los hallazgos escritos
    antes de esa validación siguen en disco y ``list()`` los reconstruye sin
    revalidar.
    """
    findings = [
        _finding("f1", observed_at="2021-03-18T01:13:54Z"),
        _finding("f2", observed_at="hace tres semanas", title="texto libre"),
        _finding("f3", observed_at="2021-03-23T19:24:35", title="sin zona"),
    ]

    tl = assemble_findings_timeline(findings, {})

    assert [e["finding_id"] for e in tl["eventos"]] == ["f1"]
    assert tl["no_parseable"] == 2
    assert tl["no_parseable_valores"] == ["hace tres semanas", "2021-03-23T19:24:35"]
    # Son dos cuentas distintas: tener una marca ilegible no es no tenerla.
    assert tl["sin_observed_at"] == 0


def test_a_case_whose_findings_cannot_be_placed_says_why_instead_of_showing_nothing() -> None:
    """Un eje vacío sin explicación sugiere que se midió algo y no salió nada."""
    tl = assemble_findings_timeline([_finding("f1", observed_at=None)], {})

    assert tl["eventos"] == []
    assert tl["message"]
    assert "sin marca temporal" in tl["message"]

    con_eventos = assemble_findings_timeline([_finding("f1", observed_at="2021-03-18T01:13:54Z")], {})
    assert con_eventos["message"] is None


# --------------------------------------------------------------------------- #
# Severidad y ATT&CK
# --------------------------------------------------------------------------- #
def test_severity_is_labelled_from_the_single_table() -> None:
    """Las etiquetas salen de ``timeline.vocabulario``, no de una segunda tabla.

    Dos tablas para el mismo valor serían dos nombres para el mismo hecho en dos
    anexos del mismo informe. Se comprueba contra la tabla misma, no contra literales
    copiados aquí.
    """
    from forensia.timeline.vocabulario import SEVERITY_LABEL

    findings = [
        _finding(f"f{i}", observed_at=f"2021-03-1{i}T01:00:00Z", severity=sev)
        for i, sev in enumerate(["low", "medium", "high", "critical"])
    ]

    tl = assemble_findings_timeline(findings, {})

    assert [e["severity"] for e in tl["eventos"]] == ["low", "medium", "high", "critical"]
    assert [e["severity_label"] for e in tl["eventos"]] == [
        SEVERITY_LABEL["low"],
        SEVERITY_LABEL["medium"],
        SEVERITY_LABEL["high"],
        SEVERITY_LABEL["critical"],
    ]


def test_techniques_merge_record_time_hints_with_later_annotations() -> None:
    """La correlación son las DOS fuentes, no solo los `mitre_hints` del registro.

    Medido sobre los casos reales: de 39 eventos, 5 llevan técnica en sus hints y 17
    la llevan tras fusionar las anotaciones de ``annotate_mitre``. Sin la fusión, el
    87 % de la figura saldría sin ATT&CK.
    """
    findings = [
        _finding("f1", observed_at="2021-03-18T01:00:00Z", mitre_hints=["T1055"]),
        _finding("f2", observed_at="2021-03-19T01:00:00Z", mitre_hints=[]),
    ]
    annotations = {"f1": ["T1036"], "f2": ["T1005"]}

    tl = assemble_findings_timeline(findings, annotations)

    assert [t["technique_id"] for t in tl["eventos"][0]["mitre"]] == ["T1055", "T1036"]
    assert [t["technique_id"] for t in tl["eventos"][1]["mitre"]] == ["T1005"]


def test_an_annotation_repeating_a_hint_is_not_duplicated() -> None:
    findings = [_finding("f1", observed_at="2021-03-18T01:00:00Z", mitre_hints=["T1055"])]

    tl = assemble_findings_timeline(findings, {"f1": ["T1055", "T1036"]})

    assert [t["technique_id"] for t in tl["eventos"][0]["mitre"]] == ["T1055", "T1036"]


def test_each_technique_carries_the_tactic_the_catalog_places_it_in() -> None:
    findings = [_finding("f1", observed_at="2021-03-18T01:00:00Z", mitre_hints=["T1055"])]

    tl = assemble_findings_timeline(findings, {})

    tecnica = tl["eventos"][0]["mitre"][0]
    assert tecnica["technique_id"] == "T1055"
    assert tecnica["tactic_id"]
    assert tecnica["tactic"]
    # La táctica sale del catálogo, en castellano, no de una tabla local.
    from forensia.mitre import catalog

    esperada = {t.id: t.name_es for t in catalog.load().tactics}[tecnica["tactic_id"]]
    assert tecnica["tactic"] == esperada


def test_a_technique_the_catalog_cannot_place_keeps_its_id_and_has_no_tactic() -> None:
    """Ni se adivina la táctica ni se omite la técnica (RULE 2).

    El hallazgo la propuso; omitirla ocultaría una correlación real, y adivinar a qué
    táctica pertenece sería inventar. Se enseña con su id y sin táctica.
    """
    findings = [_finding("f1", observed_at="2021-03-18T01:00:00Z")]

    tl = assemble_findings_timeline(findings, {"f1": ["T9999"]})

    assert tl["eventos"][0]["mitre"] == [
        {"technique_id": "T9999", "technique_name": None, "tactic_id": None, "tactic": None}
    ]


# --------------------------------------------------------------------------- #
# La superficie HTTP
# --------------------------------------------------------------------------- #
@pytest.fixture
def cases(tmp_path, monkeypatch) -> CaseManager:
    store = CaseManager(root=tmp_path / "cases")

    import forensia.mitre.coverage as coverage_mod
    import forensia.timeline.hallazgos as hallazgos_mod
    from forensia.mitre.coverage import CoverageStore

    findings = FindingStore(store)
    coverage = CoverageStore(store, findings)
    # `build_findings_timeline` resuelve por sus PROPIOS singletons, como el builder
    # de al lado: en producción son los mismos objetos, en el test hay que decírselo.
    monkeypatch.setattr(hallazgos_mod, "case_manager", store)
    monkeypatch.setattr(hallazgos_mod, "finding_store", findings)
    monkeypatch.setattr(hallazgos_mod, "coverage_store", coverage)
    monkeypatch.setattr(coverage_mod, "coverage_store", coverage)
    return store


@pytest.fixture
def client(cases) -> TestClient:
    return TestClient(create_app(PORT), base_url=f"http://127.0.0.1:{PORT}")


@pytest.fixture
def auth(client) -> dict[str, str]:
    return {"X-Forensia-Token": client.app.state.token}


def test_http_unknown_case_is_a_404_not_an_empty_axis(client, auth) -> None:
    res = client.get(
        "/api/cases/11111111-1111-4111-8111-111111111111/timeline/findings", headers=auth
    )

    assert res.status_code == 404


def test_http_a_case_without_findings_answers_with_an_actionable_message(
    client, auth, cases
) -> None:
    """Lista vacía Y el porqué: nunca un eje vacío que sugiera que se midió algo."""
    case = cases.create(name="Caso sin hallazgos", examiner="perito", os_profile="windows")

    res = client.get(f"/api/cases/{case.id}/timeline/findings", headers=auth)

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["eventos"] == []
    assert body["timezone"] == "UTC"
    assert body["total_hallazgos"] == 0
    assert "no tiene hallazgos registrados" in body["message"]


def test_http_serves_the_incident_axis_with_what_stayed_out(client, auth, cases) -> None:
    case = cases.create(name="Caso con hallazgos", examiner="perito", os_profile="windows")
    from forensia.timeline import hallazgos as hallazgos_mod

    store = hallazgos_mod.finding_store
    store.append(case.id, {
        "title": "Cuenta local creada durante el incidente",
        "summary": "resumen",
        "severity": "high",
        "run_id": _RUN_ID,
        "observed_at": "2021-03-23T19:07:38Z",
    })
    store.append(case.id, {
        "title": "Vía descartada",
        "summary": "resumen",
        "severity": "low",
        "finding_kind": "descarte",
    })

    res = client.get(f"/api/cases/{case.id}/timeline/findings", headers=auth)

    assert res.status_code == 200, res.text
    body = res.json()
    assert len(body["eventos"]) == 1
    assert body["eventos"][0]["ts"] == "2021-03-23T19:07:38Z"
    assert body["eventos"][0]["severity_label"] == "Alta"
    assert body["sin_observed_at"] == 1
    assert body["no_parseable"] == 0
    assert body["message"] is None


def test_http_carries_the_provenance_the_exported_figure_needs(client, auth, cases) -> None:
    """La figura se dibuja en el navegador, pero su identidad se resuelve aquí.

    El nombre sale de ``export_basename``, la misma función que nombra las dos hojas,
    y con su propio ``kind``, para que la figura del incidente no pise en la carpeta
    de descargas a la hoja del timeline de investigación.
    """
    case = cases.create(name="Análisis Ñandú", examiner="perito", os_profile="windows")

    body = client.get(f"/api/cases/{case.id}/timeline/findings", headers=auth).json()

    assert body["case_name"] == "Análisis Ñandú"
    assert body["exported_at"].endswith("Z")
    # Transcrito a ASCII y marcado con la hora, como el resto de exportaciones.
    assert body["export_basename"].startswith("agentopsy-timeline-incidente-analisis-nandu-")
    assert body["export_basename"].isascii()


def test_http_requires_the_session_token(client, cases) -> None:
    case = cases.create(name="Caso", examiner="perito", os_profile="windows")

    res = client.get(f"/api/cases/{case.id}/timeline/findings")

    assert res.status_code in (401, 403)
