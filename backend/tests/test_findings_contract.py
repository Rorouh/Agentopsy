"""Contrato de hallazgo: procedencia VERIFICADA + confidence / observed_at.

Cierra el drift esquema-prompt: los `system.md` de los paquetes prescriben
`confidence` (0..1), `observed_at` (marca del artefacto) y la procedencia de
artefacto (`run_id`, `artifact_sha256`), pero `record_finding` los descartaba
(`additionalProperties: false`) — el mismo bug que ya se cerró para `mitre_hints`.

Y cierra el agujero de F03: hasta 2026-09-08 el almacén comprobaba la FORMA de
los identificadores y nada más, así que un hallazgo con una ejecución que nunca
existió, la herramienta `nonexistent` y un hash de sesenta y cuatro efes se
aceptaba igual que uno real.

Gates:
- El store PERSISTE los nuevos campos y los valida (confidence en [0,1];
  observed_at con zona explícita; artifact_sha256 hex de 64).
- Procedencia REAL: la ejecución existe, es de este caso, leyó esa evidencia, la
  ejecutó esa herramienta y el artefacto conserva su hash. Un run inexistente,
  ajeno, con evidencia discordante, herramienta que no casa, hash ficticio o
  localizador fuera de rango se RECHAZAN, y no se persiste nada.
- Varias fuentes por hallazgo, cada una con su artefacto y su localizador.
- `afirmacion` exige fuente íntegra; `limitacion` es la única que puede citar una
  ejecución fallida; `descarte` y `limitacion` deben declarar su alcance.
- Las revisiones se conservan: revisar añade, no sobrescribe.
- La auditoría ancla contenido, referencias y revisión UNA vez por escritura.
- Los campos aparecen en el schema de `record_finding` que ve el modelo.
"""

from __future__ import annotations

import json

import pytest

from _procedencia import EvidenciaFalsa, crear_run, procedencia, referencia
from agentopsy.agent.tool_schemas import TOOL_PARAM_SCHEMAS, internal_tool_specs
from agentopsy.artifacts.store import ArtifactStore
from agentopsy.audit.log import AuditLog
from agentopsy.cases import CaseManager
from agentopsy.findings.procedencia import ProcedenciaError
from agentopsy.findings.store import FindingStore

#: Un UUID4 bien formado que NO corresponde a ninguna ejecución. Antes bastaba
#: para registrar un hallazgo; ahora es exactamente lo que se rechaza.
_RUN_INEXISTENTE = "11111111-1111-4111-8111-111111111111"


@pytest.fixture
def store_case(tmp_path) -> tuple[FindingStore, str]:
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Caso contrato", examiner="ramos", os_profile="unix")
    return FindingStore(cases), case.id


@pytest.fixture
def entorno(tmp_path):
    """Caso real, ejecución real y su procedencia: el suelo de estos tests."""
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Caso contrato", examiner="ramos", os_profile="unix")
    store = FindingStore(cases)
    run = crear_run(cases, case.id)
    return {
        "cases": cases,
        "case_id": case.id,
        "store": store,
        "run": run,
        "proc": procedencia(run),
    }


# ── nuevos campos: se persisten y se validan ────────────────────────────────


def test_affirmative_finding_persists_confidence_observed_at_and_provenance(
    entorno,
) -> None:
    store, case_id, run = entorno["store"], entorno["case_id"], entorno["run"]
    f = store.append(case_id, {
        "title": "Kernel Linux 5.15 detectado",
        "summary": "El banner del volcado revela la versión.",
        "severity": "medium",
        **entorno["proc"],
        "confidence": 0.75,
        "observed_at": "2026-07-15T13:42:00Z",
    })
    assert f.confidence == 0.75
    assert f.observed_at == "2026-07-15T13:42:00Z"
    # El hash NO es el que declaró quien escribió: es el del registro.
    assert f.artifact_sha256 == run["stdout_sha256"]
    assert f.finding_kind == "afirmacion"
    assert f.provenance_state == "verificada"
    # Y sobrevive el round-trip a disco (list reconstruye el dataclass).
    reloaded = store.list(case_id)[0]
    assert reloaded.confidence == 0.75
    assert reloaded.artifact_sha256 == run["stdout_sha256"]


@pytest.mark.parametrize("bad", [-0.1, 1.1, 2, "high", True])
def test_confidence_out_of_range_or_wrong_type_is_rejected(entorno, bad) -> None:
    store, case_id = entorno["store"], entorno["case_id"]
    with pytest.raises(ValueError, match="confidence"):
        store.append(case_id, {
            "title": "x", "summary": "y", "severity": "low",
            **entorno["proc"], "confidence": bad,
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
def test_observed_at_accepts_iso8601_with_an_explicit_zone(entorno, bueno) -> None:
    """Y lo guarda LITERAL: un `+01:00` dice de qué zona venía el artefacto."""
    store, case_id = entorno["store"], entorno["case_id"]
    f = store.append(case_id, {
        "title": "x", "summary": "y", "severity": "low",
        **entorno["proc"], "observed_at": bueno,
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
def test_observed_at_without_an_explicit_zone_is_rejected(entorno, malo) -> None:
    """Validación B: se hace cumplir en el servidor lo que el esquema ya promete.

    Una marca sin zona no es UTC salvo que lo diga, y darla por UTC desplazaría el eje
    del incidente las horas que fuese presentándolo como dato verificado (RULE 2).
    """
    store, case_id = entorno["store"], entorno["case_id"]
    with pytest.raises(ValueError, match="observed_at"):
        store.append(case_id, {
            "title": "x", "summary": "y", "severity": "low",
            **entorno["proc"], "observed_at": malo,
        })


def test_the_observed_at_rejection_tells_the_model_how_to_fix_it(entorno) -> None:
    """El TEXTO del error, no solo que lanza.

    El rechazo tira el hallazgo entero, pero no se pierde: viaja al modelo como cuerpo
    de error del tool result (`agent.py`, "record_finding rejected"). Para que el coste
    sea un reintento y no un hallazgo perdido, el mensaje tiene que traer el formato
    esperado CON ejemplo y qué hacer cuando la zona no se puede determinar.
    """
    store, case_id = entorno["store"], entorno["case_id"]
    with pytest.raises(ValueError) as exc:
        store.append(case_id, {
            "title": "x", "summary": "y", "severity": "low",
            **entorno["proc"], "observed_at": "2026-07-15T13:42:00",
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


def test_observed_at_is_null_when_absent(entorno) -> None:
    """Omitirlo es legítimo y sigue siéndolo: un descarte no tiene hora del artefacto."""
    store, case_id = entorno["store"], entorno["case_id"]
    f = store.append(case_id, {
        "title": "x", "summary": "y", "severity": "low", **entorno["proc"],
    })
    assert f.observed_at is None


def test_a_finding_written_before_the_validation_still_reloads(store_case) -> None:
    """`list()` reconstruye sin revalidar: lo escrito antes de la validación sigue ahí.

    Es la razón de que la capa del incidente mantenga su cuenta `no_parseable` en vez
    de confiar en que el store ya lo impide.
    """
    store, case_id = store_case
    from agentopsy.cases import case_manager  # noqa: F401  (el store trae el suyo)

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
    # Y se lee SIN atribuirle las garantías nuevas: su procedencia no se
    # verificó nunca, y eso viaja explícito en vez de aparentar lo contrario.
    assert reloaded[0].provenance_state == "no_verificada"
    assert reloaded[0].references == []
    assert reloaded[0].revision == 1


def test_artifact_sha256_must_be_64_hex(entorno) -> None:
    store, case_id = entorno["store"], entorno["case_id"]
    with pytest.raises(ValueError, match="artifact_sha256"):
        store.append(case_id, {
            "title": "x", "summary": "y", "severity": "low",
            **entorno["proc"], "artifact_sha256": "not-a-sha",
        })


# ── procedencia obligatoria para afirmaciones ───────────────────────────────


def test_affirmative_finding_without_run_id_is_rejected(store_case) -> None:
    store, case_id = store_case
    with pytest.raises(ValueError, match="fuente verificada"):
        store.append(case_id, {
            "title": "Afirmación sin respaldo",
            "summary": "Afirmo algo pero no digo de qué run salió.",
            "severity": "high",
        })
    # No se persistió nada.
    assert store.list(case_id) == []


def test_descarte_finding_without_run_id_is_allowed(store_case) -> None:
    """Un descarte legítimo queda exento de procedencia, pero NO de alcance."""
    store, case_id = store_case
    f = store.append(case_id, {
        "title": "El timeline no muestra ejecución de X",
        "summary": "tsk_mactime no arroja rastros de la hipótesis; vía descartada.",
        "severity": "low",
        "finding_kind": "descarte",
        "alcance_examinado": (
            "Se recorrió la super-timeline completa de la partición 2 con "
            "tsk_mactime. Limite: no cubre ficheros borrados sin entrada MFT."
        ),
    })
    assert f.finding_kind == "descarte"
    assert f.run_id is None
    assert f.alcance_examinado.startswith("Se recorrió")
    assert len(store.list(case_id)) == 1


def test_a_discard_without_scope_is_rejected(store_case) -> None:
    """«No se pudo analizar» y «no se encontró» no son la misma frase (F03)."""
    store, case_id = store_case
    with pytest.raises(ValueError, match="alcance_examinado"):
        store.append(case_id, {
            "title": "Nada que ver",
            "summary": "no aparece",
            "severity": "low",
            "finding_kind": "descarte",
        })
    assert store.list(case_id) == []


def test_invalid_finding_kind_is_rejected(entorno) -> None:
    store, case_id = entorno["store"], entorno["case_id"]
    with pytest.raises(ValueError, match="finding_kind"):
        store.append(case_id, {
            "title": "x", "summary": "y", "severity": "low",
            **entorno["proc"], "finding_kind": "inventado",
        })


# ── el schema que ve el modelo lleva los campos ─────────────────────────────


def test_record_finding_schema_exposes_the_new_fields() -> None:
    spec = next(s for s in internal_tool_specs() if s["function"]["name"] == "record_finding")
    props = spec["function"]["parameters"]["properties"]
    assert {"confidence", "observed_at", "artifact_sha256", "finding_kind"} <= set(props)
    assert props["confidence"]["minimum"] == 0
    assert props["confidence"]["maximum"] == 1
    assert props["finding_kind"]["enum"] == ["afirmacion", "descarte", "limitacion"]
    # additionalProperties sigue cerrado: la enum es exhaustiva, no un colador.
    assert spec["function"]["parameters"]["additionalProperties"] is False


def test_finding_serialization_is_stable_json(entorno) -> None:
    """El asdict del hallazgo con los nuevos campos serializa a JSON válido."""
    store, case_id = entorno["store"], entorno["case_id"]
    store.append(case_id, {
        "title": "x", "summary": "y", "severity": "low",
        **entorno["proc"], "confidence": 0.5,
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

# -- F03: la procedencia se comprueba contra el REGISTRO ---------------------


def test_a_run_that_never_existed_is_rejected(store_case) -> None:
    """El caso reproducido por la auditoría: UUID4 bien formado, run inexistente."""
    store, case_id = store_case
    with pytest.raises(ProcedenciaError, match="no existe en el caso"):
        store.append(case_id, {
            "title": "Procedencia inventada",
            "summary": "Afirmo algo sobre una ejecución que nunca ocurrió.",
            "severity": "high",
            "run_id": _RUN_INEXISTENTE,
            "tool_id": "nonexistent",
            "artifact_sha256": "f" * 64,
        })
    assert store.list(case_id) == []


def test_a_run_of_another_case_is_rejected(tmp_path) -> None:
    """Una ejecución REAL, pero de otro caso, no sostiene un hallazgo de este."""
    cases = CaseManager(root=tmp_path / "cases")
    propio = cases.create(name="Propio", examiner="e", os_profile="unix")
    ajeno = cases.create(name="Ajeno", examiner="e", os_profile="unix")
    run_ajeno = crear_run(cases, ajeno.id)
    store = FindingStore(cases)
    with pytest.raises(ProcedenciaError, match="no existe en el caso"):
        store.append(propio.id, {
            "title": "x", "summary": "y", "severity": "low",
            **procedencia(run_ajeno),
        })
    assert store.list(propio.id) == []


def test_a_mismatched_evidence_is_rejected(entorno) -> None:
    """La evidencia la fija el manifiesto de la ejecución, no quien escribe."""
    otra = crear_run(entorno["cases"], entorno["case_id"])["evidence_id"]
    with pytest.raises(ProcedenciaError, match="pero la ejecución"):
        entorno["store"].append(entorno["case_id"], {
            "title": "x", "summary": "y", "severity": "low",
            **{**entorno["proc"], "evidence_id": otra},
        })


def test_a_mismatched_tool_is_rejected(entorno) -> None:
    with pytest.raises(ProcedenciaError, match="ejecutó"):
        entorno["store"].append(entorno["case_id"], {
            "title": "x", "summary": "y", "severity": "low",
            **{**entorno["proc"], "tool_id": "regripper"},
        })


def test_a_fictitious_hash_is_rejected(entorno) -> None:
    """Sesenta y cuatro efes son un hash bien FORMADO y una fuente inexistente."""
    with pytest.raises(ProcedenciaError, match="no sale del registro"):
        entorno["store"].append(entorno["case_id"], {
            "title": "x", "summary": "y", "severity": "low",
            **{**entorno["proc"], "artifact_sha256": "f" * 64},
        })


def test_a_hash_that_is_not_the_artifacts_own_is_rejected(entorno) -> None:
    """Un hash de otro contenido tampoco vale para el artefacto que se cita."""
    ref = referencia(entorno["run"])
    ref["sha256"] = "b" * 64
    with pytest.raises(ProcedenciaError, match="pero sus bytes dan"):
        entorno["store"].append(entorno["case_id"], {
            "title": "x", "summary": "y", "severity": "low", "references": [ref],
        })


def test_a_locator_out_of_range_is_rejected(entorno) -> None:
    """La salida tiene tres líneas: citar la 900 es una coordenada inventada."""
    with pytest.raises(ProcedenciaError, match="cae fuera"):
        entorno["store"].append(entorno["case_id"], {
            "title": "x", "summary": "y", "severity": "low",
            "references": [referencia(entorno["run"], desde=900, hasta=901)],
        })


def test_an_inverted_locator_is_rejected(entorno) -> None:
    ref = referencia(entorno["run"])
    ref["localizador"] = {"tipo": "lineas", "desde": 3, "hasta": 1}
    with pytest.raises(ProcedenciaError, match="invertido"):
        entorno["store"].append(entorno["case_id"], {
            "title": "x", "summary": "y", "severity": "low", "references": [ref],
        })


def test_an_extract_that_is_not_at_the_locator_is_rejected(entorno) -> None:
    """El extracto tiene que ser lo que hay AHÍ, no lo que el modelo recuerda."""
    ref = referencia(entorno["run"], desde=1, hasta=1, extracto="texto que no está")
    with pytest.raises(ProcedenciaError, match="no es lo que el localizador"):
        entorno["store"].append(entorno["case_id"], {
            "title": "x", "summary": "y", "severity": "low", "references": [ref],
        })


def test_a_tampered_artifact_is_rejected_at_write_time(entorno) -> None:
    """Alterar la salida DESPUÉS de la ejecución invalida cualquier cita nueva."""
    ruta = (
        entorno["cases"].case_dir(entorno["case_id"])
        / "artifacts" / entorno["run"]["run_id"] / "stdout.txt"
    )
    ruta.write_text("MANIPULADO\n", encoding="utf-8")
    with pytest.raises(ProcedenciaError, match="integridad"):
        entorno["store"].append(entorno["case_id"], {
            "title": "x", "summary": "y", "severity": "low", **entorno["proc"],
        })


def test_several_sources_per_finding_are_all_verified(entorno) -> None:
    """Un hecho puede sostenerse en dos artefactos, y los dos se comprueban."""
    otro = crear_run(entorno["cases"], entorno["case_id"], tool_id="regripper")
    f = entorno["store"].append(entorno["case_id"], {
        "title": "Persistencia por tarea programada",
        "summary": "La tarea aparece en la MFT y en el hive SOFTWARE.",
        "severity": "high",
        "references": [
            referencia(entorno["run"], desde=1, hasta=2),
            referencia(otro, desde=3, hasta=3, extracto="tercera linea"),
        ],
    })
    assert len(f.references) == 2
    assert {r["tool_id"] for r in f.references} == {"tsk_fls", "regripper"}
    assert all(r["estado"] == "verificada" for r in f.references)
    assert f.references[1]["extracto"] == "tercera linea"


def test_a_failed_run_cannot_support_an_assertion(entorno) -> None:
    """Un exit distinto de cero es información pericial, no una afirmación."""
    fallido = crear_run(
        entorno["cases"], entorno["case_id"], exit_code=1,
        stdout="", stderr="Cannot determine file system type\n",
    )
    with pytest.raises(ProcedenciaError, match="limitacion"):
        entorno["store"].append(entorno["case_id"], {
            "title": "El sistema de ficheros es ext4",
            "summary": "Lo afirmo pese a que la herramienta falló.",
            "severity": "high",
            **procedencia(fallido),
        })


def test_a_failed_run_does_support_a_declared_limitation(entorno) -> None:
    """Y ese mismo diagnóstico SÍ sostiene una limitación, que es lo que es."""
    fallido = crear_run(
        entorno["cases"], entorno["case_id"], exit_code=1,
        stdout="", stderr="Cannot determine file system type\n",
    )
    f = entorno["store"].append(entorno["case_id"], {
        "title": "La partición 3 no se pudo analizar",
        "summary": "tsk_fls no determina el sistema de ficheros de la partición 3.",
        "severity": "medium",
        "finding_kind": "limitacion",
        "alcance_examinado": (
            "Se intentó listar la partición 3 (offset 51200) con tsk_fls. "
            "Limite: su contenido queda sin examinar."
        ),
        "references": [
            {
                "run_id": fallido["run_id"],
                "artefacto": "stderr",
                "sha256": fallido["stderr_sha256"],
                "localizador": {"tipo": "lineas", "desde": 1, "hasta": 1},
            }
        ],
    })
    assert f.finding_kind == "limitacion"
    assert f.references[0]["resultado_parcial"] is True
    assert f.references[0]["exit_code"] == 1


# -- revisiones: se conservan, no se sobrescriben ----------------------------


def test_revising_a_finding_keeps_the_previous_revision(entorno) -> None:
    store, case_id = entorno["store"], entorno["case_id"]
    original = store.append(case_id, {
        "title": "Primera lectura", "summary": "resumen inicial", "severity": "low",
        **entorno["proc"],
    })
    revisado = store.revise(case_id, original.id, {
        "title": "Lectura corregida", "summary": "resumen corregido",
        "severity": "high", **entorno["proc"],
        "motivo_revision": "La severidad inicial no reflejaba el alcance.",
    })

    assert revisado.id == original.id
    assert revisado.revision == 2
    assert revisado.supersedes == original.content_sha256
    assert revisado.content_sha256 != original.content_sha256

    # La vigente es la 2, pero la 1 SIGUE siendo inspeccionable.
    assert [f.revision for f in store.list(case_id)] == [2]
    historial = store.revisions(case_id, original.id)
    assert [f.revision for f in historial] == [1, 2]
    assert historial[0].title == "Primera lectura"
    assert store.get(case_id, original.id, revision=1).severity == "low"


def test_a_revision_without_a_reason_is_rejected(entorno) -> None:
    store, case_id = entorno["store"], entorno["case_id"]
    f = store.append(case_id, {
        "title": "x", "summary": "y", "severity": "low", **entorno["proc"],
    })
    with pytest.raises(ValueError, match="por qué|motivo_revision"):
        store.revise(case_id, f.id, {
            "title": "z", "summary": "w", "severity": "low", **entorno["proc"],
        })
    assert store.revisions(case_id, f.id)[-1].revision == 1


# -- auditoría: una entrada por escritura, con contenido y fuentes -----------


def test_the_audit_anchors_content_references_and_revision_once(entorno) -> None:
    store, case_id, cases = entorno["store"], entorno["case_id"], entorno["cases"]
    f = store.append(case_id, {
        "title": "Anclado", "summary": "resumen", "severity": "low",
        **entorno["proc"],
    })
    log = AuditLog(cases.case_dir(case_id) / "audit.jsonl")
    assert log.verify() is True

    entradas = [e for e in log.entries() if e.get("finding_id") == f.id]
    # UNA sola: agente y almacén no auditan por separado el mismo acto.
    assert len(entradas) == 1
    entrada = entradas[0]
    assert entrada["action"] == "finding_recorded"
    assert entrada["content_sha256"] == f.content_sha256
    assert entrada["revision"] == 1
    assert entrada["provenance_state"] == "verificada"
    assert entrada["references"][0]["run_id"] == entorno["run"]["run_id"]
    assert entrada["references"][0]["sha256"] == entorno["run"]["stdout_sha256"]
    # El cuerpo del hallazgo NO se duplica en el audit: viaja su hash.
    assert "summary" not in entrada


def test_a_revision_is_audited_as_such(entorno) -> None:
    store, case_id, cases = entorno["store"], entorno["case_id"], entorno["cases"]
    f = store.append(case_id, {
        "title": "x", "summary": "y", "severity": "low", **entorno["proc"],
    })
    store.revise(case_id, f.id, {
        "title": "x2", "summary": "y2", "severity": "low", **entorno["proc"],
        "motivo_revision": "corregido",
    })
    log = AuditLog(cases.case_dir(case_id) / "audit.jsonl")
    acciones = [e["action"] for e in log.entries() if e.get("finding_id") == f.id]
    assert acciones == ["finding_recorded", "finding_revised"]
    assert log.verify() is True


def test_nothing_is_persisted_when_provenance_fails(entorno) -> None:
    """Ni el hallazgo ni una entrada de auditoría que aparente una escritura."""
    store, case_id, cases = entorno["store"], entorno["case_id"], entorno["cases"]
    antes = len(AuditLog(cases.case_dir(case_id) / "audit.jsonl").entries())
    with pytest.raises(ProcedenciaError):
        store.append(case_id, {
            "title": "x", "summary": "y", "severity": "low",
            "run_id": _RUN_INEXISTENTE,
        })
    assert store.list(case_id) == []
    despues = AuditLog(cases.case_dir(case_id) / "audit.jsonl").entries()
    assert len(despues) == antes
    assert not [e for e in despues if e.get("action") == "finding_recorded"]


def test_an_unwritable_audit_blocks_the_write(entorno, monkeypatch) -> None:
    """Una escritura sin registro de custodia no es una escritura completada."""
    store, case_id = entorno["store"], entorno["case_id"]

    def _falla(self, event):
        raise OSError("audit chain unavailable")

    monkeypatch.setattr(AuditLog, "append", _falla)
    with pytest.raises(ValueError, match="cadena de auditoría"):
        store.append(case_id, {
            "title": "x", "summary": "y", "severity": "low", **entorno["proc"],
        })
    monkeypatch.undo()
    assert store.list(case_id) == []


# -- un artefacto derivado también se puede citar ---------------------------


def test_a_derived_output_file_can_be_cited_with_its_locator(entorno) -> None:
    run = crear_run(
        entorno["cases"], entorno["case_id"], tool_id="regripper",
        ficheros={"software.txt": "clave A\nclave B\nclave C\n"},
    )
    f = entorno["store"].append(entorno["case_id"], {
        "title": "Clave de ejecución automática",
        "summary": "El hive SOFTWARE registra la clave B.",
        "severity": "high",
        "references": [
            referencia(
                run, artefacto="fichero", relpath="software.txt",
                desde=2, hasta=2, extracto="clave B",
            )
        ],
    })
    assert f.references[0]["artefacto"] == "fichero"
    assert f.references[0]["relpath"] == "software.txt"
    assert f.references[0]["extracto"] == "clave B"
    assert f.references[0]["sha256"] == run["output_files"]["software.txt"]


def test_a_source_from_an_unsealed_run_is_rejected(entorno) -> None:
    """Una salida parcial de un trabajo VIVO no respalda una conclusión."""
    store_art = ArtifactStore(entorno["cases"])
    run_id, _out = store_art.start_run(
        entorno["case_id"], "tsk_fls", ["fls"],
        evidence_id=entorno["run"]["evidence_id"],
        evidence_baseline_sha256="a" * 64,
        tool_version="sleuthkit 4.12.1",
    )
    with pytest.raises(ProcedenciaError, match="sigue en curso"):
        entorno["store"].append(entorno["case_id"], {
            "title": "x", "summary": "y", "severity": "low", "run_id": run_id,
        })


def test_the_evidence_of_the_run_must_still_exist_in_the_case(entorno) -> None:
    """La evidencia se comprueba contra el registro del caso, no se supone."""
    store = FindingStore(entorno["cases"], evidence=EvidenciaFalsa())
    with pytest.raises(ProcedenciaError, match="no está registrada"):
        store.append(entorno["case_id"], {
            "title": "x", "summary": "y", "severity": "low", **entorno["proc"],
        })


# -- la ruta REST aplica EXACTAMENTE las mismas reglas -----------------------


def test_rest_and_record_finding_apply_the_same_rules(entorno, monkeypatch) -> None:
    """La política vive en el DOMINIO, así que no puede diferir entre superficies.

    Antes, la validación de forma estaba en el almacén y el contrato REST llevaba
    un subconjunto de sus campos: un campo que el agente podía escribir era
    inalcanzable por HTTP y se perdía en silencio (F03).
    """
    from fastapi.testclient import TestClient

    import agentopsy.routers.findings as findings_router
    from agentopsy.server import create_app

    monkeypatch.setattr(findings_router, "finding_store", entorno["store"])
    client = TestClient(create_app(51192), base_url="http://127.0.0.1:51192")
    auth = {"X-Agentopsy-Token": client.app.state.token}
    case_id = entorno["case_id"]

    # Una procedencia inventada se rechaza IGUAL que por la vía del agente.
    inventado = client.post(
        f"/api/cases/{case_id}/findings",
        headers=auth,
        json={
            "title": "Procedencia inventada",
            "summary": "Una ejecución que nunca existió.",
            "severity": "high",
            "run_id": _RUN_INEXISTENTE,
            "tool_id": "nonexistent",
            "artifact_sha256": "f" * 64,
        },
    )
    assert inventado.status_code == 422
    assert "no existe en el caso" in inventado.json()["detail"]
    assert entorno["store"].list(case_id) == []

    # Y una real se acepta, con el contrato COMPLETO de citas.
    real = client.post(
        f"/api/cases/{case_id}/findings",
        headers=auth,
        json={
            "title": "Con fuente verificada",
            "summary": "La segunda línea lo sostiene.",
            "severity": "high",
            "references": [referencia(entorno["run"], desde=2, hasta=2)],
        },
    )
    assert real.status_code == 200, real.text
    cuerpo = real.json()
    # Los campos nuevos NO se pierden al atravesar la superficie.
    assert cuerpo["provenance_state"] == "verificada"
    assert cuerpo["revision"] == 1
    assert len(cuerpo["content_sha256"]) == 64
    assert cuerpo["origin"] == "rest"
    assert cuerpo["references"][0]["localizador"] == {
        "tipo": "lineas", "desde": 2, "hasta": 2
    }

    # Un descarte sin alcance se rechaza también por HTTP.
    sin_alcance = client.post(
        f"/api/cases/{case_id}/findings",
        headers=auth,
        json={
            "title": "Descarte", "summary": "no aparece", "severity": "low",
            "finding_kind": "descarte",
        },
    )
    assert sin_alcance.status_code == 422
    assert "alcance_examinado" in sin_alcance.json()["detail"]


def test_rest_serves_the_revisions_and_the_resolved_sources(entorno, monkeypatch) -> None:
    from fastapi.testclient import TestClient

    import agentopsy.routers.findings as findings_router
    from agentopsy.server import create_app

    monkeypatch.setattr(findings_router, "finding_store", entorno["store"])
    client = TestClient(create_app(51193), base_url="http://127.0.0.1:51193")
    auth = {"X-Agentopsy-Token": client.app.state.token}
    case_id = entorno["case_id"]

    f = entorno["store"].append(case_id, {
        "title": "Original", "summary": "primera lectura", "severity": "low",
        "references": [referencia(entorno["run"], desde=1, hasta=1)],
    })
    entorno["store"].revise(case_id, f.id, {
        "title": "Corregido", "summary": "segunda lectura", "severity": "medium",
        "references": [referencia(entorno["run"], desde=1, hasta=1)],
        "motivo_revision": "la severidad no reflejaba el alcance",
    })

    revisiones = client.get(
        f"/api/cases/{case_id}/findings/{f.id}/revisions", headers=auth
    ).json()
    assert [r["revision"] for r in revisiones] == [1, 2]
    assert revisiones[0]["title"] == "Original"

    # Y la cita se resuelve en el BACKEND, con su extracto real.
    fuentes = client.get(
        f"/api/cases/{case_id}/findings/{f.id}/sources", headers=auth
    ).json()
    assert fuentes["revision"] == 2
    assert fuentes["fuentes"][0]["estado"] == "verificada"
    assert "primera linea" in fuentes["fuentes"][0]["extracto"]
