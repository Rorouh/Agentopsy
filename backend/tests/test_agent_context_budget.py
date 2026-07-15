"""Context-budget / token-consumption guards (Bug 008).

The executor is stateless and provider-agnostic: FORENSIA re-sends the whole
conversation on every iteration. To keep a single run from burning the token
budget, FORENSIA manages its own outbound context — bounding tool results,
trimming the fixed prefix, and windowing the transcript. These tests pin the
provider-agnostic pieces (no docker, no executor, pure functions).
"""

from __future__ import annotations

import json

from forensia.agent.agent import (
    _MAX_TOOL_RESULT_CHARS,
    ForensicAgent,
    _bounded_json,
)
from forensia.agent.context import select_playbook_section, window_messages


def _tool_msg(run_id: str, payload: str = "x" * 4000) -> dict:
    return {
        "role": "tool",
        "tool_call_id": run_id,
        "content": json.dumps(
            {"tool_id": "volatility3", "exit_code": 0, "run_id": run_id, "big": payload}
        ),
    }


class TestWindowMessages:
    def _transcript(self, n_tools: int) -> list[dict]:
        msgs: list[dict] = [{"role": "system", "content": "SYS"}, {"role": "user", "content": "TASK"}]
        for i in range(n_tools):
            msgs.append({"role": "assistant", "content": f"reasoning {i}"})
            msgs.append(_tool_msg(f"run{i:03d}"))
        return msgs

    def test_short_transcript_is_unchanged(self) -> None:
        msgs = self._transcript(3)
        out = window_messages(msgs, keep_last_tool_results=4)
        assert [m["content"] for m in out] == [m["content"] for m in msgs]

    def test_old_tool_results_are_stubbed_last_k_verbatim(self) -> None:
        msgs = self._transcript(10)
        out = window_messages(msgs, keep_last_tool_results=4)
        tool_msgs = [m for m in out if m["role"] == "tool"]
        assert len(tool_msgs) == 10
        # The 6 oldest are stubs; the 4 most recent are verbatim JSON.
        for m in tool_msgs[:-4]:
            assert m["content"].startswith("[resultado de tool elidido")
            assert "run=" in m["content"]  # still points at the artifact
        for m in tool_msgs[-4:]:
            assert json.loads(m["content"])["tool_id"] == "volatility3"

    def test_system_user_assistant_never_touched(self) -> None:
        msgs = self._transcript(10)
        out = window_messages(msgs, keep_last_tool_results=2)
        assert out[0]["content"] == "SYS"
        assert out[1]["content"] == "TASK"
        assert [m["content"] for m in out if m["role"] == "assistant"] == [
            f"reasoning {i}" for i in range(10)
        ]

    def test_input_is_not_mutated(self) -> None:
        msgs = self._transcript(8)
        before = [dict(m) for m in msgs]
        window_messages(msgs, keep_last_tool_results=2)
        assert msgs == before  # canonical transcript untouched (custody/replay)


class TestBoundedJson:
    def test_small_body_is_verbatim_and_valid(self) -> None:
        body = {"tool_id": "volatility3", "exit_code": 0, "run_id": "r1"}
        out = _bounded_json(body, _MAX_TOOL_RESULT_CHARS)
        assert json.loads(out) == body

    def test_oversize_body_sheds_sample_but_keeps_pointer_and_stays_valid(self) -> None:
        # A parsed sample big enough to blow the cap; the old blind slice would
        # have cut mid-structure (invalid JSON) and could drop artifact_run.
        body = {
            "tool_id": "volatility3",
            "exit_code": 0,
            "run_id": "r1",
            "artifact_run": {"run_id": "r1", "output_files_count": 1},
            "parsed": {
                "row_count": 5000,
                "columns": ["PID", "Name", "Path"],
                "sample": [{"PID": i, "Path": "C:/x" * 100} for i in range(500)],
                "sample_truncated": True,
            },
            "stdout_sample": "x" * 3000,
            "stderr_sample": "",
        }
        out = _bounded_json(body, _MAX_TOOL_RESULT_CHARS)
        # ALWAYS valid JSON — never a mid-structure slice.
        decoded = json.loads(out)
        assert len(out) <= _MAX_TOOL_RESULT_CHARS
        # The custody pointer survived the shedding.
        assert decoded["artifact_run"]["run_id"] == "r1"
        assert decoded["tool_id"] == "volatility3"
        # The heavy sample was elided, row_count preserved.
        assert decoded["parsed"]["sample"] == []
        assert decoded["parsed"]["row_count"] == 5000

    def test_pathological_body_falls_back_to_valid_skeleton(self) -> None:
        # No sheddable sample, but a giant stdout that can't fit even trimmed.
        body = {
            "tool_id": "bulk_extractor",
            "exit_code": 0,
            "run_id": "r2",
            "artifact_run": {"run_id": "r2"},
            "parsed": {"note": "x" * 20000},
            "stdout_sample": "y" * 20000,
            "stderr_sample": "z" * 20000,
        }
        out = _bounded_json(body, _MAX_TOOL_RESULT_CHARS)
        decoded = json.loads(out)  # still valid
        assert decoded["truncated"] is True
        assert decoded["run_id"] == "r2"
        assert decoded["artifact_run"] == {"run_id": "r2"}


_SYNTH_PLAYBOOK = """# Playbook

Intro común, siempre presente.

---

## 0. Routing por tipo de evidencia

Tabla de routing.

---

## A. Imagen de disco Windows (`.raw`, `.E01`)

Pasos de disco: tsk_mmls, tsk_fls.

---

## B. Volcado de memoria RAM Windows (`.mem`)

Pasos de memoria: volatility3.

---

## Buenas prácticas siempre

Cruza fuentes.
"""


class TestSelectPlaybookSection:
    def test_memory_drops_disk_branch(self) -> None:
        out = select_playbook_section(_SYNTH_PLAYBOOK, "memory")
        assert "Volcado de memoria RAM" in out
        assert "Imagen de disco" not in out
        # common sections survive
        assert "Routing por tipo de evidencia" in out
        assert "Buenas prácticas siempre" in out
        assert "Intro común" in out

    def test_disk_drops_memory_branch(self) -> None:
        out = select_playbook_section(_SYNTH_PLAYBOOK, "disk")
        assert "Imagen de disco" in out
        assert "Volcado de memoria RAM" not in out

    def test_container_disk_behaves_like_disk(self) -> None:
        out = select_playbook_section(_SYNTH_PLAYBOOK, "container_disk")
        assert "Imagen de disco" in out
        assert "Volcado de memoria RAM" not in out

    def test_unknown_keeps_both_branches(self) -> None:
        out = select_playbook_section(_SYNTH_PLAYBOOK, "unknown")
        assert "Imagen de disco" in out
        assert "Volcado de memoria RAM" in out

    def test_unexpected_kind_keeps_everything(self) -> None:
        out = select_playbook_section(_SYNTH_PLAYBOOK, "weird_value")
        assert "Imagen de disco" in out
        assert "Volcado de memoria RAM" in out

    def test_empty_playbook_passthrough(self) -> None:
        assert select_playbook_section("", "memory") == ""

    def test_no_headers_passthrough(self) -> None:
        text = "plain playbook with no level-2 headers"
        assert select_playbook_section(text, "memory") == text

    def test_real_windows_package_memory_is_smaller(self) -> None:
        from pathlib import Path

        pb = (
            Path(__file__).resolve().parents[2]
            / "agentes"
            / "forensia-windows"
            / "prompts"
            / "playbook.md"
        ).read_text(encoding="utf-8")
        mem = select_playbook_section(pb, "memory")
        disk = select_playbook_section(pb, "disk")
        full = select_playbook_section(pb, "unknown")
        assert len(mem) < len(full)
        assert len(disk) < len(full)
        # memory branch kept, disk branch dropped
        assert "Volcado de memoria RAM Windows" in mem
        assert "Imagen de disco Windows" not in mem


_SYNTH_ANNEX_PLAYBOOK = """## 0. Routing
Intro.

## A. Imagen de disco Windows
Disco.

## B. Volcado de memoria RAM Windows
Memoria.

## Anexo — Playbook por herramienta
Anexo intro (común, siempre).

### Particiones / imagen
tsk_mmls, tsk_fls.

### EZ Tools (parsers KAPE — maletín windows)
mftecmd, regripper.

### Memoria volátil
volatility3.

### IOCs / firmas
yara, strings.
"""


class TestAnnexSubsectionTrim:
    """Bug 008 §2 Nivel 1: el Anexo por-herramienta (común) trocea sus ### de
    disco/memoria por rama, y falla seguro (lo no clasificado se conserva)."""

    def test_memory_drops_disk_tool_subsections_keeps_memory_and_common(self) -> None:
        out = select_playbook_section(_SYNTH_ANNEX_PLAYBOOK, "memory")
        assert "Anexo — Playbook por herramienta" in out  # el Anexo sigue
        assert "Anexo intro" in out                        # intro del Anexo se queda
        assert "Memoria volátil" in out                    # tool de memoria: sí
        assert "IOCs / firmas" in out                      # común: sí
        assert "Particiones / imagen" not in out           # tool de disco: fuera
        assert "EZ Tools" not in out                       # tool de disco: fuera

    def test_disk_drops_memory_tool_subsections(self) -> None:
        out = select_playbook_section(_SYNTH_ANNEX_PLAYBOOK, "disk")
        assert "Particiones / imagen" in out
        assert "EZ Tools" in out
        assert "IOCs / firmas" in out
        assert "Memoria volátil" not in out

    def test_unknown_keeps_the_whole_annex(self) -> None:
        out = select_playbook_section(_SYNTH_ANNEX_PLAYBOOK, "unknown")
        assert "Particiones / imagen" in out
        assert "Memoria volátil" in out
        assert "EZ Tools" in out
        assert "IOCs / firmas" in out

    def test_unclassified_subsection_is_kept(self) -> None:
        pb = (
            "## Anexo — herramientas\nintro\n\n"
            "### Herramienta nueva sin rama clara\ncontenido\n"
        )
        assert "Herramienta nueva sin rama clara" in select_playbook_section(pb, "memory")

    def test_real_windows_annex_is_trimmed_for_memory(self) -> None:
        from pathlib import Path

        pb = (
            Path(__file__).resolve().parents[2]
            / "agentes" / "forensia-windows" / "prompts" / "playbook.md"
        ).read_text(encoding="utf-8")
        mem = select_playbook_section(pb, "memory")
        # el bloque de EZ Tools (disco) desaparece del Anexo en un memdump…
        assert "EZ Tools" not in mem
        # …pero la guía de memoria del Anexo se conserva.
        assert "Memoria volátil" in mem


class TestToolResultPayloadOrder:
    def test_artifact_run_serialized_before_parsed(self) -> None:
        result = {
            "tool_id": "volatility3",
            "exit_code": 0,
            "run_id": "r1",
            "parsed": {"row_count": 1, "sample": [{"PID": 4}]},
            "stdout_sample": "[]",
            "stderr_sample": "",
            "artifact_run": {"run_id": "r1", "output_files": []},
        }
        payload = ForensicAgent._tool_result_payload(result)
        keys = list(payload.keys())
        assert keys.index("artifact_run") < keys.index("parsed")
