"""«Finalizar investigación»: la ÚNICA superficie que emite un informe pericial.

Los gates que importan (``agentopsy.routers.documents``):

- Un informe se emite SOLO al finalizar la investigación. No hay borrador
  automático al cerrar un análisis (retirado el 2026-07-30) ni endpoint de
  síntesis determinista: ``POST …/documents/generate`` ya no existe.
- RULE 2 en la puerta: sin ejecutor seleccionado → 422 nombrando los válidos;
  sin hallazgos → 422 diciendo que no hay investigación que informar; ejecutor
  inutilizable → 503 con el motivo accionable. Nunca se elige un ejecutor por el
  operador ni se degrada a una redacción de repuesto.
- La redacción corre en SEGUNDO PLANO: la petición devuelve un ``job_id`` y el
  documento aparece cuando el job termina.
- Las rutas literales (`/finalize`, `/jobs`) no las secuestra `/{doc_id}`.
"""

from __future__ import annotations

import json
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from agentopsy.i18n import LANG_HEADER, t
from agentopsy.cases.manager import CaseManager
from agentopsy.evidence import EvidenceManager
from agentopsy.executors.base import ExecutorAvailability, ExecutorResult, PromptExecutor
from agentopsy.findings.store import FindingStore
from agentopsy.graph.store import GraphStore
from agentopsy.mitre.coverage import CoverageStore
from agentopsy.reports.figuras import figuras_del_caso
from agentopsy.reports.indice import NUMS, titulos
from agentopsy.reports.material import build_material
from agentopsy.reports.store import DocumentStore
from agentopsy.reports.svg import validar_svg
from agentopsy.server import create_app
from agentopsy.toolkit.usage import tool_usage


def tool_usage_de(cases: CaseManager):
    """``tool_usage`` sobre los casos de ESTE test (el módulo usa el singleton)."""
    import agentopsy.toolkit.usage as usage_mod

    def _usage(case_id: str):
        original = usage_mod.case_manager
        usage_mod.case_manager = cases
        try:
            return tool_usage(case_id)
        finally:
            usage_mod.case_manager = original

    return _usage

PORT = 51120


def _reply() -> str:
    """Una respuesta VÁLIDA del redactor: cubre el índice canónico exacto."""
    return json.dumps({
        "resumen": "Informe pericial del caso Murcielago.",
        "secciones": [
            {"num": n, "titulo": titulos()[n],
             "bloques": [{"t": "p", "text": f"Redaccion de la seccion {n}."}]}
            for n in NUMS
        ],
    }, ensure_ascii=False)


class _Executor(PromptExecutor):
    id = "claude-code"
    name = "Claude Code"
    is_local = False

    def __init__(self, *, available: bool = True, text: str | None = None) -> None:
        self._available = available
        self._text = text if text is not None else _reply()

    def is_available(self) -> ExecutorAvailability:
        if self._available:
            return ExecutorAvailability(available=True)
        return ExecutorAvailability(
            available=False,
            reason="claude no tiene sesión: `docker compose exec -it api claude auth login`",
        )

    def run(self, prompt: str, context: dict | None = None) -> ExecutorResult:
        return ExecutorResult(
            executor=self.id, text=self._text, argv=("claude", "-p"), exit_code=0,
            duration_ms=1, raw=self._text,
        )


@pytest.fixture
def entorno(tmp_path, monkeypatch):
    cases = CaseManager(root=tmp_path / "cases")
    evidence = EvidenceManager(cases)
    findings = FindingStore(cases)
    documents = DocumentStore(cases)

    import agentopsy.reports.writer as writer_mod
    import agentopsy.routers.cases as cases_router
    import agentopsy.routers.documents as docs_router

    monkeypatch.setattr(cases_router, "case_manager", cases)
    monkeypatch.setattr(cases_router, "evidence_manager", evidence)
    monkeypatch.setattr(docs_router, "case_manager", cases)
    monkeypatch.setattr(docs_router, "document_store", documents)
    monkeypatch.setattr(docs_router, "finding_store", findings)

    # El redactor resuelve el constructor del material en la llamada, así que
    # aquí se sustituye por el REAL con los almacenes de este tmp_path: la
    # cadena router → writer → material → validación es la de producción.
    def _material(case_id, perito=None):
        return build_material(
            case_id, perito, cases=cases, evidence=evidence, findings=findings,
            coverage=CoverageStore(cases, findings), documents=documents,
            usage_fn=tool_usage_de(cases), traza_fn=lambda _c: [],
            fs_timeline_fn=lambda _c, _e: None,
        )

    monkeypatch.setattr(writer_mod, "build_material", _material)

    # Igual con las figuras del anexo C: el cargador REAL, sobre los almacenes de
    # este tmp_path.
    def _figuras(case_id):
        return figuras_del_caso(
            case_id, cases=cases, findings=findings, graphs=GraphStore(cases),
            coverage=CoverageStore(cases, findings),
        )

    monkeypatch.setattr(writer_mod, "figuras_del_caso", _figuras)

    case = cases.create(
        name="Murcielago", examiner="Daniel Ramos", os_profile="windows",
        notes="Determinar si hubo exfiltracion.",
    )
    src = tmp_path / "disk.raw"
    src.write_bytes(b"AGENTOPSY" * 128)
    evidence.register(case.id, str(src))

    return {
        "cases": cases, "case": case, "findings": findings, "documents": documents,
        "docs_router": docs_router,
    }


@pytest.fixture
def client(entorno):
    app = create_app(PORT)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}")


@pytest.fixture
def auth(client):
    return {"X-Agentopsy-Token": client.app.state.token}


def _con_hallazgo(entorno) -> None:
    entorno["findings"].append(entorno["case"].id, {
        "title": "Tarea programada de persistencia",
        "summary": "Se crea la tarea `updater`.",
        "severity": "high", "run_id": str(uuid.uuid4()),
        "artifact_sha256": "a" * 64, "tool_id": "tsk_fls",
        # Con marca del artefacto, para que el anexo C lleve su línea de tiempo.
        "observed_at": "2026-03-14T08:12:44Z",
    })


def _use(entorno, executor: _Executor, monkeypatch) -> None:
    monkeypatch.setattr(
        entorno["docs_router"], "get_executor", lambda _id: executor
    )
    monkeypatch.setattr(entorno["docs_router"].config, "get", lambda _k: None)


def _wait(client, auth, case_id: str, job_id: str, timeout: float = 10.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = client.get(
            f"/api/cases/{case_id}/documents/jobs/{job_id}", headers=auth
        ).json()
        if snap["status"] != "running":
            return snap
        time.sleep(0.02)
    raise AssertionError(f"el job {job_id} no terminó en {timeout}s")


# ── la vía retirada ───────────────────────────────────────────────────────────


def test_the_deterministic_generate_endpoint_is_gone(client, auth, entorno) -> None:
    r = client.post(
        f"/api/cases/{entorno['case'].id}/documents/generate", json={}, headers=auth
    )
    # Ya no hay ruta POST ahí: FastAPI resuelve `generate` contra el GET de
    # `/{doc_id}` y responde 405. Lo que importa es que no redacta nada.
    assert r.status_code in (404, 405)
    assert entorno["documents"].list(entorno["case"].id) == []


# ── RULE 2 en la puerta ───────────────────────────────────────────────────────


def test_without_a_selected_executor_it_is_a_422_naming_the_valid_ones(
    client, auth, entorno, monkeypatch
) -> None:
    _con_hallazgo(entorno)
    monkeypatch.setattr(entorno["docs_router"].config, "get", lambda _k: None)
    r = client.post(
        f"/api/cases/{entorno['case'].id}/documents/finalize", json={}, headers=auth
    )
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert "claude-code" in detail and "ollama" in detail


def test_without_findings_there_is_no_report(client, auth, entorno, monkeypatch) -> None:
    _use(entorno, _Executor(), monkeypatch)
    r = client.post(
        f"/api/cases/{entorno['case'].id}/documents/finalize",
        json={"executor": "claude-code"}, headers=auth,
    )
    assert r.status_code == 422
    # El texto sale en el idioma de la PETICIÓN, así que el test fija la
    # entrada del catálogo, no una frase castellana que dejaría de valer en
    # cuanto la interfaz esté en inglés.
    assert r.json()["detail"] == t("api.noFindingsForReport", "en")
    # Y en castellano dice lo suyo, con la misma clave.
    es = client.post(
        f"/api/cases/{entorno['case'].id}/documents/finalize",
        json={"executor": "claude-code"},
        headers={**auth, LANG_HEADER: "es"},
    )
    assert "hallazgo" in es.json()["detail"]
    assert entorno["documents"].list(entorno["case"].id) == []


def test_an_unusable_executor_is_a_503_with_the_login_command(
    client, auth, entorno, monkeypatch
) -> None:
    _con_hallazgo(entorno)
    _use(entorno, _Executor(available=False), monkeypatch)
    r = client.post(
        f"/api/cases/{entorno['case'].id}/documents/finalize",
        json={"executor": "claude-code"}, headers=auth,
    )
    assert r.status_code == 503
    assert "auth login" in r.json()["detail"]


def test_an_unknown_case_is_a_404(client, auth, entorno, monkeypatch) -> None:
    _use(entorno, _Executor(), monkeypatch)
    r = client.post(
        f"/api/cases/{uuid.uuid4()}/documents/finalize",
        json={"executor": "claude-code"}, headers=auth,
    )
    assert r.status_code == 404


def test_the_surface_is_token_gated(client, entorno) -> None:
    r = client.post(
        f"/api/cases/{entorno['case'].id}/documents/finalize",
        json={"executor": "claude-code"},
    )
    assert r.status_code == 401


# ── el camino feliz, en segundo plano ─────────────────────────────────────────


def test_finalizing_writes_the_report_in_the_background(
    client, auth, entorno, monkeypatch
) -> None:
    _con_hallazgo(entorno)
    _use(entorno, _Executor(), monkeypatch)
    case_id = entorno["case"].id

    started = client.post(
        f"/api/cases/{case_id}/documents/finalize",
        json={"executor": "claude-code", "name": "Daniel Ramos"}, headers=auth,
    )
    assert started.status_code == 200
    job = started.json()
    assert job["status"] == "running"
    assert job["kind"] == "report"
    assert job["executor"]["id"] == "claude-code"

    snap = _wait(client, auth, case_id, job["job_id"])
    assert snap["status"] == "done", snap.get("error")
    doc_id = snap["result"]["doc_id"]

    doc = client.get(f"/api/cases/{case_id}/documents/{doc_id}", headers=auth).json()
    assert doc["status"] == "draft"
    assert doc["type"] == "pericial"
    assert doc["author"] == "Daniel Ramos"
    assert [s["num"] for s in doc["sections"]] == [
        "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "A", "B", "C",
    ]
    # El anexo C lo compone Agentopsy con los datos del caso, y su figura sale
    # del almacén intacta: el SVG pasa la lista blanca y va bajo el SHA-256.
    figuras = [b for b in doc["sections"][-1]["blocks"] if b["t"] == "figure"]
    assert [f["kind"] for f in figuras] == ["incident_timeline"]
    validar_svg(figuras[0]["svg"])
    assert "Tarea programada de persistencia" in figuras[0]["svg"]
    verify = client.post(
        f"/api/cases/{case_id}/documents/{doc_id}/verify", headers=auth
    ).json()
    assert verify["ok"] is True
    # Y el PDF del informe redactado sale bien formado.
    pdf = client.get(f"/api/cases/{case_id}/documents/{doc_id}/pdf", headers=auth)
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF-")


def test_a_rejected_redaction_persists_nothing_and_says_why(
    client, auth, entorno, monkeypatch
) -> None:
    _con_hallazgo(entorno)
    # El modelo se salta una sección del índice: nada se publica.
    _use(entorno, _Executor(text='{"resumen": "x", "secciones": []}'), monkeypatch)
    case_id = entorno["case"].id

    job = client.post(
        f"/api/cases/{case_id}/documents/finalize",
        json={"executor": "claude-code"}, headers=auth,
    ).json()
    snap = _wait(client, auth, case_id, job["job_id"])

    assert snap["status"] == "error"
    assert "secciones" in snap["error"]
    assert entorno["documents"].list(case_id) == []


def test_report_jobs_of_the_case_are_listed_for_re_attaching(
    client, auth, entorno, monkeypatch
) -> None:
    _con_hallazgo(entorno)
    _use(entorno, _Executor(), monkeypatch)
    case_id = entorno["case"].id
    job = client.post(
        f"/api/cases/{case_id}/documents/finalize",
        json={"executor": "claude-code"}, headers=auth,
    ).json()
    _wait(client, auth, case_id, job["job_id"])

    listed = client.get(f"/api/cases/{case_id}/documents/jobs", headers=auth).json()
    assert [j["job_id"] for j in listed] == [job["job_id"]]
    assert all(j["kind"] == "report" for j in listed)


def test_a_job_from_another_case_is_not_readable_here(
    client, auth, entorno, monkeypatch
) -> None:
    _con_hallazgo(entorno)
    _use(entorno, _Executor(), monkeypatch)
    case_id = entorno["case"].id
    job = client.post(
        f"/api/cases/{case_id}/documents/finalize",
        json={"executor": "claude-code"}, headers=auth,
    ).json()
    _wait(client, auth, case_id, job["job_id"])

    otro = entorno["cases"].create(name="Otro", examiner="x", os_profile="unix")
    r = client.get(
        f"/api/cases/{otro.id}/documents/jobs/{job['job_id']}", headers=auth
    )
    assert r.status_code == 404


def test_a_tampered_figure_is_not_printed_and_says_why(
    client, auth, entorno, monkeypatch
) -> None:
    """Un documento retocado en disco con un SVG fuera de la lista blanca no
    llega a fpdf2: el PDF responde 422 con el motivo, no un 500 ni un fichero."""
    _con_hallazgo(entorno)
    _use(entorno, _Executor(), monkeypatch)
    case_id = entorno["case"].id
    job = client.post(
        f"/api/cases/{case_id}/documents/finalize",
        json={"executor": "claude-code"}, headers=auth,
    ).json()
    snap = _wait(client, auth, case_id, job["job_id"])
    assert snap["status"] == "done", snap.get("error")
    doc_id = snap["result"]["doc_id"]

    path = entorno["cases"].case_dir(case_id) / "documents" / f"{doc_id}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    figura = next(b for b in data["sections"][-1]["blocks"] if b["t"] == "figure")
    figura["svg"] = figura["svg"].replace(
        "</svg>", '<image href="file:///etc/passwd" width="1" height="1"/></svg>'
    )
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    r = client.get(f"/api/cases/{case_id}/documents/{doc_id}/pdf", headers=auth)
    assert r.status_code == 422
    assert "image" in r.json()["detail"]
