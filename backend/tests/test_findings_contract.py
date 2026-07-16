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
