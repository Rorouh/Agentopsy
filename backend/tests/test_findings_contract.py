"""Contrato de hallazgo: procedencia obligatoria + confidence / observed_at.

Cierra el drift esquema↔prompt: los `system.md` de los paquetes prescriben
`confidence` (0..1), `observed_at` (marca del artefacto) y la procedencia de
artefacto (`run_id`, `artifact_sha256`), pero `record_finding` los descartaba
(`additionalProperties: false`) — el mismo bug que ya se cerró para `mitre_hints`.

Gates:
- El store PERSISTE los nuevos campos y los valida (confidence en [0,1];
  observed_at string; artifact_sha256 hex de 64).
- Anti-alucinación (RULE 2 / SECURITY INVARIANT 5): un hallazgo AFIRMATIVO sin
  `run_id` se RECHAZA; un `descarte` explícito queda exento.
- Los campos aparecen en el schema de `record_finding` que ve el modelo.
"""

from __future__ import annotations

import json

import pytest

from forensia.agent.tool_schemas import TOOL_PARAM_SCHEMAS, internal_tool_specs
from forensia.cases import CaseManager
from forensia.findings.store import FindingStore

_RUN_ID = "11111111-1111-4111-8111-111111111111"


@pytest.fixture
def store_case(tmp_path) -> tuple[FindingStore, str]:
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Caso contrato", examiner="ramos", os_profile="unix")
    return FindingStore(cases), case.id


# ── nuevos campos: se persisten y se validan ────────────────────────────────


def test_affirmative_finding_persists_confidence_observed_at_and_provenance(store_case) -> None:
    store, case_id = store_case
    f = store.append(case_id, {
        "title": "Kernel Linux 5.15 detectado",
        "summary": "El banner del volcado revela la versión.",
        "severity": "medium",
        "run_id": _RUN_ID,
        "confidence": 0.75,
        "observed_at": "2026-07-15T13:42:00Z",
        "artifact_sha256": "a" * 64,
    })
    assert f.confidence == 0.75
    assert f.observed_at == "2026-07-15T13:42:00Z"
    assert f.artifact_sha256 == "a" * 64
    assert f.finding_kind == "afirmacion"
    # Y sobrevive el round-trip a disco (list reconstruye el dataclass).
    reloaded = store.list(case_id)[0]
    assert reloaded.confidence == 0.75
    assert reloaded.artifact_sha256 == "a" * 64


@pytest.mark.parametrize("bad", [-0.1, 1.1, 2, "high", True])
def test_confidence_out_of_range_or_wrong_type_is_rejected(store_case, bad) -> None:
    store, case_id = store_case
    with pytest.raises(ValueError, match="confidence"):
        store.append(case_id, {
            "title": "x", "summary": "y", "severity": "low",
            "run_id": _RUN_ID, "confidence": bad,
        })


@pytest.mark.parametrize(
    "bueno",
    [
        "2026-07-15T13:42:00Z",
        "2026-07-15T13:42:00+00:00",
        "2021-03-23T20:24:35+01:00",
        "2026-07-15T13:42:00.500Z",
    ],
)
def test_observed_at_accepts_iso8601_with_an_explicit_zone(store_case, bueno) -> None:
    """Y lo guarda LITERAL: un `+01:00` dice de qué zona venía el artefacto."""
    store, case_id = store_case
    f = store.append(case_id, {
        "title": "x", "summary": "y", "severity": "low",
        "run_id": _RUN_ID, "observed_at": bueno,
    })
    assert f.observed_at == bueno


@pytest.mark.parametrize(
    "malo",
    [
        "2026-07-15T13:42:00",  # sin zona: no es UTC salvo que lo diga
        "2026-07-15",           # fecha suelta: ni hora que situar ni zona
        "hace tres semanas",
        "15/07/2026 13:42",
        "",
        "   ",
        1752585720,
    ],
)
def test_observed_at_without_an_explicit_zone_is_rejected(store_case, malo) -> None:
    """Validación B: se hace cumplir en el servidor lo que el esquema ya promete.

    Una marca sin zona no es UTC salvo que lo diga, y darla por UTC desplazaría el eje
    del incidente las horas que fuese presentándolo como dato verificado (RULE 2).
    """
    store, case_id = store_case
    with pytest.raises(ValueError, match="observed_at"):
        store.append(case_id, {
            "title": "x", "summary": "y", "severity": "low",
            "run_id": _RUN_ID, "observed_at": malo,
        })


def test_the_observed_at_rejection_tells_the_model_how_to_fix_it(store_case) -> None:
    """El TEXTO del error, no solo que lanza.

    El rechazo tira el hallazgo entero, pero no se pierde: viaja al modelo como cuerpo
    de error del tool result (`agent.py`, "record_finding rejected"). Para que el coste
    sea un reintento y no un hallazgo perdido, el mensaje tiene que traer el formato
    esperado CON ejemplo y qué hacer cuando la zona no se puede determinar.
    """
    store, case_id = store_case
    with pytest.raises(ValueError) as exc:
        store.append(case_id, {
            "title": "x", "summary": "y", "severity": "low",
            "run_id": _RUN_ID, "observed_at": "2026-07-15T13:42:00",
        })
    mensaje = str(exc.value)

    assert "ISO-8601" in mensaje
    # Un ejemplo literal, no solo el nombre del formato.
    assert "2021-03-23T19:24:35Z" in mensaje
    # El valor recibido, para que el modelo vea qué escribió.
    assert "2026-07-15T13:42:00" in mensaje
    # La salida cuando la zona no se puede determinar: omitir, no aproximar.
    assert "omite el campo" in mensaje
    # Y de qué hora se habla: la del hecho, no la del análisis.
    assert "dispositivo investigado" in mensaje


def test_observed_at_is_null_when_absent(store_case) -> None:
    """Omitirlo es legítimo y sigue siéndolo: un descarte no tiene hora del artefacto."""
    store, case_id = store_case
    f = store.append(case_id, {
        "title": "x", "summary": "y", "severity": "low", "run_id": _RUN_ID,
    })
    assert f.observed_at is None


def test_a_finding_written_before_the_validation_still_reloads(store_case) -> None:
    """`list()` reconstruye sin revalidar: lo escrito antes de la validación sigue ahí.

    Es la razón de que la capa del incidente mantenga su cuenta `no_parseable` en vez
    de confiar en que el store ya lo impide.
    """
    store, case_id = store_case
    from forensia.cases import case_manager  # noqa: F401  (el store trae el suyo)

    path = store._cases.case_dir(case_id) / "findings.jsonl"
    path.write_text(
        json.dumps({
            "id": "f-antiguo", "case_id": case_id, "title": "viejo", "summary": "s",
            "severity": "low", "evidence_id": None, "tool_id": None, "run_id": None,
            "created_at": "2026-07-01T00:00:00.000Z", "mitre_hints": [],
            "confidence": None, "observed_at": "hace tres semanas",
            "artifact_sha256": None, "finding_kind": "afirmacion",
        }) + "\n",
        encoding="utf-8",
    )

    reloaded = store.list(case_id)
    assert len(reloaded) == 1
    assert reloaded[0].observed_at == "hace tres semanas"


def test_artifact_sha256_must_be_64_hex(store_case) -> None:
    store, case_id = store_case
    with pytest.raises(ValueError, match="artifact_sha256"):
        store.append(case_id, {
            "title": "x", "summary": "y", "severity": "low",
            "run_id": _RUN_ID, "artifact_sha256": "not-a-sha",
        })


# ── procedencia obligatoria para afirmaciones ───────────────────────────────


def test_affirmative_finding_without_run_id_is_rejected(store_case) -> None:
    store, case_id = store_case
    with pytest.raises(ValueError, match="procedencia"):
        store.append(case_id, {
            "title": "Afirmación sin respaldo",
            "summary": "Afirmo algo pero no digo de qué run salió.",
            "severity": "high",
        })
    # No se persistió nada.
    assert store.list(case_id) == []


def test_descarte_finding_without_run_id_is_allowed(store_case) -> None:
    """Un descarte legítimo (una vía que NO aportó) queda exento de procedencia."""
    store, case_id = store_case
    f = store.append(case_id, {
        "title": "El timeline no muestra ejecución de X",
        "summary": "tsk_mactime no arroja rastros de la hipótesis; vía descartada.",
        "severity": "low",
        "finding_kind": "descarte",
    })
    assert f.finding_kind == "descarte"
    assert f.run_id is None
    assert len(store.list(case_id)) == 1


def test_invalid_finding_kind_is_rejected(store_case) -> None:
    store, case_id = store_case
    with pytest.raises(ValueError, match="finding_kind"):
        store.append(case_id, {
            "title": "x", "summary": "y", "severity": "low",
            "run_id": _RUN_ID, "finding_kind": "inventado",
        })


# ── el schema que ve el modelo lleva los campos ─────────────────────────────


def test_record_finding_schema_exposes_the_new_fields() -> None:
    spec = next(s for s in internal_tool_specs() if s["function"]["name"] == "record_finding")
    props = spec["function"]["parameters"]["properties"]
    assert {"confidence", "observed_at", "artifact_sha256", "finding_kind"} <= set(props)
    assert props["confidence"]["minimum"] == 0
    assert props["confidence"]["maximum"] == 1
    assert props["finding_kind"]["enum"] == ["afirmacion", "descarte"]
    # additionalProperties sigue cerrado: la enum es exhaustiva, no un colador.
    assert spec["function"]["parameters"]["additionalProperties"] is False


def test_finding_serialization_is_stable_json(store_case) -> None:
    """El asdict del hallazgo con los nuevos campos serializa a JSON válido."""
    store, case_id = store_case
    store.append(case_id, {
        "title": "x", "summary": "y", "severity": "low",
        "run_id": _RUN_ID, "confidence": 0.5,
    })
    line = (store._cases.case_dir(case_id) / "findings.jsonl").read_text().strip()
    data = json.loads(line)
    assert data["confidence"] == 0.5
    assert data["finding_kind"] == "afirmacion"


# ── tsk_icat: schema que faltaba (paso obligatorio de la cadena Windows) ─────


def test_tsk_icat_has_a_schema_with_required_inode() -> None:
    assert "tsk_icat" in TOOL_PARAM_SCHEMAS
    schema = TOOL_PARAM_SCHEMAS["tsk_icat"]
    assert schema["required"] == ["inode"]
    assert {"inode", "partition_offset", "filesystem"} <= set(schema["properties"])
    assert schema["additionalProperties"] is False


def test_ez_tools_accept_a_derived_artifact_input() -> None:
    """Las EZ Tools encadenan tsk_icat.output → tool.input vía ArtifactRef."""
    expected = {
        "mftecmd": "mft_path",
        "evtxecmd": "evtx_path",
        "lecmd": "target_path",
        "jlecmd": "target_path",
        "sbecmd": "target_path",
        "wxtcmd": "target_path",
        "appcompatcacheparser": "hive_path",
    }
    for tool_id, param in expected.items():
        props = TOOL_PARAM_SCHEMAS[tool_id]["properties"]
        assert param in props, f"{tool_id} debe aceptar {param} como ArtifactRef"
        # Forma de ArtifactRef: run_id + relpath requeridos.
        assert set(props[param]["required"]) == {"run_id", "relpath"}
