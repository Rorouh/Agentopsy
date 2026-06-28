"""CaseManager contract: create / list / load / close + path-traversal guard."""

from __future__ import annotations

import json
import re
from dataclasses import asdict

import pytest

from forensia.cases.manager import Case, CaseManager

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
)


@pytest.fixture
def manager(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


class TestCreate:
    def test_create_returns_case_with_uuid4_iso_and_active_status(self, manager):
        case = manager.create(name="Op X", examiner="alice", os_profile="unix")
        assert isinstance(case, Case)
        assert _UUID4_RE.match(case.id)
        assert _ISO_RE.match(case.created_at)
        assert case.status == "active"
        assert case.os_profile == "unix"
        assert case.examiner == "alice"
        assert case.notes == ""

    def test_create_materializes_four_subdirs(self, manager):
        case = manager.create(name="Op X", examiner="alice", os_profile="windows")
        case_dir = manager.root / case.id
        for sub in ("evidence", "artifacts", "chats", "reports"):
            assert (case_dir / sub).is_dir(), f"expected subdir {sub}"

    def test_create_writes_case_json_with_all_fields(self, manager):
        case = manager.create(
            name="Op X", examiner="alice", os_profile="unix", notes="initial notes"
        )
        payload = json.loads((manager.root / case.id / "case.json").read_text())
        assert payload == asdict(case)

    @pytest.mark.parametrize("bad_name", ["", "   ", "\t\n"])
    def test_create_rejects_empty_name(self, manager, bad_name):
        with pytest.raises(ValueError, match="name"):
            manager.create(name=bad_name, examiner="alice", os_profile="unix")

    def test_create_rejects_name_over_200_chars(self, manager):
        with pytest.raises(ValueError, match="<= 200"):
            manager.create(name="x" * 201, examiner="alice", os_profile="unix")

    @pytest.mark.parametrize("bad_name", [None, 5, 5.0, ["op"], {"name": "op"}])
    def test_create_rejects_non_string_name(self, manager, bad_name):
        with pytest.raises(ValueError, match="name"):
            manager.create(name=bad_name, examiner="alice", os_profile="unix")

    def test_create_rejects_empty_examiner(self, manager):
        with pytest.raises(ValueError, match="examiner"):
            manager.create(name="op", examiner="", os_profile="unix")

    @pytest.mark.parametrize("bad_profile", ["linux", "mac", "", "UNIX", "win", None, 5])
    def test_create_rejects_invalid_os_profile(self, manager, bad_profile):
        with pytest.raises(ValueError, match="os_profile"):
            manager.create(name="op", examiner="alice", os_profile=bad_profile)


class TestLoad:
    def test_load_unknown_id_raises_keyerror(self, manager):
        # A well-formed uuid that does not exist on disk.
        with pytest.raises(KeyError):
            manager.load("11111111-1111-4111-8111-111111111111")

    def test_load_malformed_id_raises_valueerror(self, manager):
        with pytest.raises(ValueError, match="UUID4"):
            manager.load("not-a-uuid")

    def test_load_roundtrips_case_json(self, manager):
        original = manager.create(
            name="Roundtrip", examiner="bob", os_profile="windows", notes="notes!"
        )
        reloaded = manager.load(original.id)
        assert reloaded == original


class TestCaseDirConfinement:
    @pytest.mark.parametrize("hostile", ["../../etc", "/etc", "..", "./.."])
    def test_case_dir_rejects_path_traversal(self, manager, hostile):
        # All of these should fail the UUID4 regex before touching the filesystem.
        with pytest.raises(ValueError, match="UUID4"):
            manager.case_dir(hostile)

    def test_case_dir_rejects_non_string(self, manager):
        with pytest.raises(ValueError, match="case_id"):
            manager.case_dir(42)


class TestList:
    def test_list_is_sorted_desc_by_created_at(self, manager):
        # Contract: list() returns "most recent first" — sorted by created_at desc.
        cases = [
            manager.create(name=f"op-{n}", examiner="alice", os_profile="unix")
            for n in range(3)
        ]
        listed = manager.list()
        # Every created case is listed exactly once...
        assert {c.id for c in listed} == {c.id for c in cases}
        # ...and the order is non-increasing by created_at. Asserting exact
        # reverse-insertion order would over-specify the contract: created_at has
        # millisecond resolution, so cases created within the same tick legitimately
        # share a stamp and the sort makes no promise about their relative order.
        stamps = [c.created_at for c in listed]
        assert stamps == sorted(stamps, reverse=True)

    def test_list_skips_non_uuid_dirs(self, manager):
        manager.create(name="real", examiner="alice", os_profile="unix")
        (manager.root / "not-a-uuid-dir").mkdir()
        (manager.root / "1234").mkdir()
        listed = manager.list()
        assert len(listed) == 1

    def test_list_skips_dir_missing_case_json(self, manager, caplog):
        manager.create(name="real", examiner="alice", os_profile="unix")
        orphan = manager.root / "22222222-2222-4222-8222-222222222222"
        orphan.mkdir()
        with caplog.at_level("WARNING"):
            listed = manager.list()
        assert len(listed) == 1
        assert any("skipping unreadable case" in m for m in caplog.messages)


class TestClose:
    def test_close_flips_status_to_closed_and_rewrites_disk(self, manager):
        case = manager.create(name="op", examiner="alice", os_profile="unix")
        closed = manager.close(case.id)
        assert closed.status == "closed"
        on_disk = json.loads((manager.root / case.id / "case.json").read_text())
        assert on_disk["status"] == "closed"

    def test_close_is_idempotent(self, manager):
        case = manager.create(name="op", examiner="alice", os_profile="unix")
        first = manager.close(case.id)
        second = manager.close(case.id)
        assert first.status == "closed"
        assert second.status == "closed"
        # Same fields after a second close — no exception, no rewrite of e.g. timestamps.
        assert first == second

    def test_close_unknown_id_raises_keyerror(self, manager):
        with pytest.raises(KeyError):
            manager.close("11111111-1111-4111-8111-111111111111")
