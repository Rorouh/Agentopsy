"""ChatStore contract: append/read JSONL with role + session_id validation."""

from __future__ import annotations

import json
import uuid

import pytest

from forensia.cases.manager import CaseManager
from forensia.chats.store import ChatMessage, ChatStore


@pytest.fixture
def cases(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


@pytest.fixture
def store(cases) -> ChatStore:
    return ChatStore(cases)


@pytest.fixture
def case(cases):
    return cases.create(name="op", examiner="alice", os_profile="unix")


@pytest.fixture
def session_id() -> str:
    return str(uuid.uuid4())


def _msg(role: str = "user", content: str = "hi", ts: str = "") -> ChatMessage:
    return ChatMessage(role=role, content=content, ts=ts)


class TestAppend:
    def test_append_writes_one_jsonl_line(self, store, case, session_id, cases):
        store.append(case.id, session_id, _msg("user", "hello", ts=""))
        path = cases.root / case.id / "chats" / f"{session_id}.jsonl"
        text = path.read_text(encoding="utf-8")
        assert text.endswith("\n")
        # Exactly one line.
        lines = [ln for ln in text.split("\n") if ln]
        assert len(lines) == 1
        obj = json.loads(lines[0])
        assert obj["role"] == "user"
        assert obj["content"] == "hello"
        assert obj["ts"]  # auto-filled

    def test_append_autofills_ts_when_empty(self, store, case, session_id):
        store.append(case.id, session_id, _msg(ts=""))
        msgs = store.read(case.id, session_id)
        assert msgs[0].ts  # non-empty after roundtrip

    def test_append_preserves_explicit_ts(self, store, case, session_id):
        explicit = "2026-06-26T12:00:00.000+00:00"
        store.append(case.id, session_id, _msg(ts=explicit))
        msgs = store.read(case.id, session_id)
        assert msgs[0].ts == explicit

    @pytest.mark.parametrize("bad_role", ["admin", "", "USER", "Tool", "human"])
    def test_append_rejects_invalid_role(self, store, case, session_id, bad_role):
        with pytest.raises(ValueError, match="role"):
            store.append(case.id, session_id, _msg(role=bad_role))

    @pytest.mark.parametrize(
        "ok_role", ["user", "assistant", "system", "tool"]
    )
    def test_append_accepts_each_allowed_role(self, store, case, session_id, ok_role):
        store.append(case.id, session_id, _msg(role=ok_role))

    def test_append_accepts_uuid_session_id(self, store, case):
        store.append(case.id, str(uuid.uuid4()), _msg())

    @pytest.mark.parametrize(
        "slug", ["a", "abc-123_xyz", "x" * 64, "session_1"]
    )
    def test_append_accepts_valid_slug(self, store, case, slug):
        store.append(case.id, slug, _msg())

    @pytest.mark.parametrize(
        "bad",
        [
            "a/b",
            "a\\b",
            "..",
            "../etc",
            "x" * 65,
            "",
            "with space",
            "with.dot",
        ],
    )
    def test_append_rejects_invalid_session_id(self, store, case, bad):
        with pytest.raises(ValueError, match="session_id"):
            store.append(case.id, bad, _msg())

    def test_append_unknown_case_raises_keyerror(self, store, session_id):
        with pytest.raises(KeyError):
            store.append(
                "11111111-1111-4111-8111-111111111111", session_id, _msg()
            )


class TestRead:
    def test_read_roundtrips_sequence(self, store, case, session_id):
        for n in range(20):
            store.append(case.id, session_id, _msg(content=f"msg-{n}"))
        msgs = store.read(case.id, session_id)
        assert [m.content for m in msgs] == [f"msg-{n}" for n in range(20)]

    def test_read_unknown_session_raises_keyerror(self, store, case, session_id):
        with pytest.raises(KeyError):
            store.read(case.id, session_id)

    def test_read_tolerates_truncated_last_line(
        self, store, case, session_id, cases, caplog
    ):
        # Write 3 valid messages, then a truncated trailing fragment.
        for n in range(3):
            store.append(case.id, session_id, _msg(content=f"m{n}"))
        path = cases.root / case.id / "chats" / f"{session_id}.jsonl"
        with path.open("a", encoding="utf-8") as fh:
            fh.write('{"role": "user", "content": "trunc')  # no closing brace/newline
        with caplog.at_level("WARNING"):
            msgs = store.read(case.id, session_id)
        assert [m.content for m in msgs] == ["m0", "m1", "m2"]
        assert any("truncated last line" in m for m in caplog.messages)


class TestListSessions:
    def test_list_sessions_returns_stems_sorted(self, store, case):
        for slug in ("alpha", "beta", "gamma"):
            store.append(case.id, slug, _msg())
        sessions = store.list_sessions(case.id)
        assert sessions == ["alpha", "beta", "gamma"]

    def test_list_sessions_empty(self, store, case):
        assert store.list_sessions(case.id) == []


class TestSequentialAppendsAreOrdered:
    def test_fifty_sequential_appends_preserve_order(self, store, case, session_id):
        for n in range(50):
            store.append(case.id, session_id, _msg(content=str(n)))
        msgs = store.read(case.id, session_id)
        assert [m.content for m in msgs] == [str(n) for n in range(50)]
