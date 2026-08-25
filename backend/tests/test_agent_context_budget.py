"""Context-budget / token-consumption guards (Bug 008).

The executor is stateless and provider-agnostic: Agentopsy re-sends the whole
conversation on every iteration. To keep a single run from burning the token
budget, Agentopsy manages its own outbound context — bounding tool results,
trimming the fixed prefix, and windowing the transcript. These tests pin the
provider-agnostic pieces (no docker, no executor, pure functions).
"""

from __future__ import annotations

import json

from forensia.i18n import t
from forensia.agent.agent import (
    _MAX_TOOL_RESULT_CHARS,
    _UNTRUSTED_CLOSE,
    _untrusted_open,
    ForensicAgent,
    _bounded_json,
)
from forensia.agent.context import _stub_for, window_messages
from forensia.models.base import ToolCall


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

    def test_events_list_is_shed_progressively_not_skeleton(self) -> None:
        # consultar_actividad: the heavy field is a top-level `events` list. It must be
        # trimmed to fit, PRESERVING the summary (status/matched/by_category) — never the
        # all-null skeleton, which would read as "no activity" for a matched query.
        body = {
            "status": "ok",
            "evidence_id": "e1",
            "matched": 240,
            "by_category": {"web": 4, "credenciales": 1},
            "events": [
                {"ts": f"2024-01-25T00:{i // 60:02d}:{i % 60:02d}Z",
                 "path": "/var/www/html/" + "a" * 40, "macb": "macb"}
                for i in range(240)
            ],
        }
        out = _bounded_json(body, 2000)
        decoded = json.loads(out)  # valid JSON
        assert decoded["status"] == "ok"           # summary survived (not null skeleton)
        assert decoded["matched"] == 240
        assert decoded["by_category"] == {"web": 4, "credenciales": 1}
        assert decoded["events_truncated_for_context"] is True
        assert 0 <= len(decoded["events"]) < 240   # trimmed to fit
        assert len(out) <= 2000

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


class TestUntrustedToolResultSpotlighting:
    """Anti-inyección (SECURITY INVARIANTS): un resultado de tool con bytes de
    evidencia se envuelve en delimitadores de NO-confianza; los internos no."""

    def _call(self) -> ToolCall:
        return ToolCall(tool_id="tsk_fls", params={}, call_id="c1")

    def test_evidence_tool_result_is_wrapped(self) -> None:
        body = {"tool_id": "tsk_fls", "exit_code": 0, "run_id": "r1"}
        msg = ForensicAgent._tool_result_msg(self._call(), body, untrusted=True)
        assert msg["content"].startswith(_untrusted_open())
        assert msg["content"].rstrip().endswith(_UNTRUSTED_CLOSE)
        assert _untrusted_open() == t("agentLoop.untrustedOpen")
        # La marca dice que lo que sigue son DATOS y que NUNCA son
        # instrucciones. Se comprueba en los dos idiomas, porque es una barrera
        # de seguridad y no puede aflojarse en ninguno.
        assert "DATA" in t("agentLoop.untrustedOpen", "en")
        assert "NEVER" in t("agentLoop.untrustedOpen", "en")
        assert "DATOS" in t("agentLoop.untrustedOpen", "es")
        assert "NUNCA" in t("agentLoop.untrustedOpen", "es")

    def test_internal_tool_result_is_not_wrapped(self) -> None:
        body = {"finding_id": "f1", "stored": True}
        msg = ForensicAgent._tool_result_msg(self._call(), body)  # untrusted defaults False
        assert not msg["content"].startswith(_untrusted_open())
        assert json.loads(msg["content"]) == body

    def test_windowing_still_extracts_metadata_from_a_wrapped_result(self) -> None:
        """El stub de un resultado envuelto sigue nombrando tool/exit/run (context.py
        tolera los delimitadores de spotlighting)."""
        body = {"tool_id": "volatility3", "exit_code": 0, "run_id": "run042"}
        wrapped = ForensicAgent._tool_result_msg(self._call(), body, untrusted=True)
        stub = _stub_for(wrapped["content"])
        assert "run=run042" in stub  # el puntero al artefacto sobrevive
        assert "volatility3" in stub


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
