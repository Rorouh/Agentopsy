"""CaseManager contract: create / list / load / close + path-traversal guard."""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import asdict

import pytest

from agentopsy.cases.manager import Case, CaseManager

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

    # ``None`` is intentionally NOT here: os_profile is now DERIVED from the
    # evidence content, so omitting it at creation is the normal path (see
    # ``test_create_without_os_profile_is_unresolved``). A *provided* value must
    # still be a valid profile (operator anchor).
    @pytest.mark.parametrize("bad_profile", ["linux", "mac", "", "UNIX", "win", 5])
    def test_create_rejects_invalid_os_profile(self, manager, bad_profile):
        with pytest.raises(ValueError, match="os_profile"):
            manager.create(name="op", examiner="alice", os_profile=bad_profile)

    def test_create_without_os_profile_is_unresolved(self, manager):
        # Auto-detección de SO: the operator no longer picks the OS at creation.
        # A fresh case has no profile and no source until triage derives one.
        case = manager.create(name="op", examiner="alice")
        assert case.os_profile is None
        assert case.os_profile_source is None

    def test_create_with_os_profile_records_operator_anchor(self, manager):
        # A provided os_profile is an OPTIONAL manual anchor (operator override).
        case = manager.create(name="op", examiner="alice", os_profile="windows")
        assert case.os_profile == "windows"
        assert case.os_profile_source == "operator"


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


def _audit(manager: CaseManager, case_id: str) -> list[dict]:
    path = manager.case_dir(case_id) / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


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

    def test_close_records_case_closed_in_audit(self, manager):
        case = manager.create(name="op", examiner="alice", os_profile="unix")
        manager.close(case.id)
        events = [e["action"] for e in _audit(manager, case.id)]
        assert events == ["case_closed"]

    def test_close_idempotent_second_call_does_not_re_audit(self, manager):
        case = manager.create(name="op", examiner="alice", os_profile="unix")
        manager.close(case.id)
        manager.close(case.id)
        events = [e["action"] for e in _audit(manager, case.id)]
        assert events == ["case_closed"]


class TestReopen:
    def test_reopen_flips_closed_case_back_to_active(self, manager):
        case = manager.create(name="op", examiner="alice", os_profile="unix")
        manager.close(case.id)
        reopened = manager.reopen(case.id)
        assert reopened.status == "active"
        on_disk = json.loads((manager.root / case.id / "case.json").read_text())
        assert on_disk["status"] == "active"

    def test_reopen_is_idempotent_on_active_case(self, manager):
        case = manager.create(name="op", examiner="alice", os_profile="unix")
        first = manager.reopen(case.id)
        second = manager.reopen(case.id)
        assert first == case
        assert second == case

    def test_reopen_unknown_id_raises_keyerror(self, manager):
        with pytest.raises(KeyError):
            manager.reopen("11111111-1111-4111-8111-111111111111")

    def test_reopen_records_case_reopened_in_audit(self, manager):
        case = manager.create(name="op", examiner="alice", os_profile="unix")
        manager.close(case.id)
        manager.reopen(case.id)
        events = [e["action"] for e in _audit(manager, case.id)]
        assert events == ["case_closed", "case_reopened"]

    def test_reopen_on_never_closed_case_does_not_audit(self, manager):
        case = manager.create(name="op", examiner="alice", os_profile="unix")
        manager.reopen(case.id)
        assert _audit(manager, case.id) == []


class TestDelete:
    """Borrado PERMANENTE del caso: destruye TODA la cadena de custodia, así que
    la confirmación (repetir el nombre del caso) es parte del contrato, no de la
    UI — RULE 2: sin ella no se borra nada."""

    def test_delete_removes_the_whole_case_directory(self, manager):
        case = manager.create(name="op", examiner="alice", os_profile="unix")
        case_dir = manager.root / case.id
        # Contenido representativo de la cadena de custodia del caso.
        (case_dir / "audit.jsonl").write_text('{"action":"case_created"}\n')
        (case_dir / "evidence" / "e1").mkdir()
        (case_dir / "evidence" / "e1" / "original.raw").write_bytes(b"x" * 16)

        assert manager.delete_case(case.id, "op") == case.id
        assert not case_dir.exists()
        assert manager.list() == []
        with pytest.raises(KeyError):
            manager.load(case.id)

    def test_delete_leaves_other_cases_untouched(self, manager):
        keep = manager.create(name="keep", examiner="alice", os_profile="unix")
        drop = manager.create(name="drop", examiner="alice", os_profile="unix")
        manager.delete_case(drop.id, "drop")
        assert [c.id for c in manager.list()] == [keep.id]
        assert manager.load(keep.id) == keep

    def test_delete_with_wrong_confirm_name_raises_and_keeps_the_case(self, manager):
        case = manager.create(name="Operación X", examiner="alice", os_profile="unix")
        with pytest.raises(ValueError, match="confirm_name"):
            manager.delete_case(case.id, "operación x")  # casi, pero no
        assert (manager.root / case.id).is_dir()
        assert manager.load(case.id) == case

    @pytest.mark.parametrize("bad_confirm", ["", "   ", None, 5, ["op"]])
    def test_delete_rejects_empty_or_non_string_confirm(self, manager, bad_confirm):
        case = manager.create(name="op", examiner="alice", os_profile="unix")
        with pytest.raises(ValueError, match="confirm_name"):
            manager.delete_case(case.id, bad_confirm)
        assert (manager.root / case.id).is_dir()

    def test_delete_unknown_id_raises_keyerror(self, manager):
        with pytest.raises(KeyError):
            manager.delete_case("11111111-1111-4111-8111-111111111111", "op")

    def test_delete_malformed_id_raises_valueerror(self, manager):
        with pytest.raises(ValueError, match="UUID4"):
            manager.delete_case("../../etc", "op")

    def test_delete_refuses_a_case_dir_outside_the_root(self, manager, tmp_path, monkeypatch):
        """El rmtree JAMÁS corre sobre una ruta que se resolvió fuera de la raíz
        de casos (SECURITY INVARIANT 6). Se fuerza el escenario sustituyendo la
        resolución del directorio (un case dir enlazado fuera resolvería así): la
        guarda de confinamiento es lo que se está probando."""
        case = manager.create(name="op", examiner="alice", os_profile="unix")
        outside = tmp_path / "fuera" / case.id
        outside.mkdir(parents=True)
        # Un case.json válido: así la carga y la confirmación pasan y lo ÚNICO
        # que puede detener el borrado es la guarda de confinamiento.
        shutil.copy2(manager.root / case.id / "case.json", outside / "case.json")
        (outside / "no-tocar.txt").write_text("intacto")
        monkeypatch.setattr(manager, "case_dir", lambda _case_id: outside)

        with pytest.raises(ValueError, match="outside the cases root"):
            manager.delete_case(case.id, "op")
        assert (outside / "no-tocar.txt").read_text() == "intacto"

    def test_delete_removes_read_only_evidence_copies(self, manager, tmp_path):
        """Las copias de evidencia son inmutables (chmod 0444). Borrar el caso
        debe llevárselas igualmente — si no, el borrado quedaría a medias (en
        Windows el unlink de un fichero de solo lectura falla)."""
        from agentopsy.evidence import EvidenceManager

        case = manager.create(name="op", examiner="alice", os_profile="unix")
        source = tmp_path / "disco.raw"
        source.write_bytes(b"EVIDENCIA" * 64)
        EvidenceManager(manager).register(case.id, str(source))

        manager.delete_case(case.id, "op")
        assert not (manager.root / case.id).exists()
        # El origen en la bandeja NO se toca: solo se borra la copia del caso.
        assert source.exists()


class TestUpdate:
    def test_update_single_field(self, manager):
        case = manager.create(name="op", examiner="alice", os_profile="unix")
        updated = manager.update(case.id, notes="new notes")
        assert updated.notes == "new notes"
        assert updated.name == case.name
        assert updated.examiner == case.examiner

    def test_update_multiple_fields(self, manager):
        case = manager.create(name="op", examiner="alice", os_profile="unix")
        updated = manager.update(case.id, name="op renamed", examiner="bob")
        assert updated.name == "op renamed"
        assert updated.examiner == "bob"
        on_disk = json.loads((manager.root / case.id / "case.json").read_text())
        assert on_disk["name"] == "op renamed"
        assert on_disk["examiner"] == "bob"

    def test_update_with_no_fields_raises_valueerror(self, manager):
        case = manager.create(name="op", examiner="alice", os_profile="unix")
        with pytest.raises(ValueError, match="at least one field"):
            manager.update(case.id)

    def test_update_unknown_id_raises_keyerror(self, manager):
        with pytest.raises(KeyError):
            manager.update("11111111-1111-4111-8111-111111111111", notes="x")

    def test_update_rejects_empty_name(self, manager):
        case = manager.create(name="op", examiner="alice", os_profile="unix")
        with pytest.raises(ValueError, match="name"):
            manager.update(case.id, name="   ")

    def test_update_does_not_touch_os_profile_or_id(self, manager):
        case = manager.create(name="op", examiner="alice", os_profile="windows")
        updated = manager.update(case.id, notes="x")
        assert updated.id == case.id
        assert updated.os_profile == case.os_profile
        assert updated.os_profile_source == case.os_profile_source
        assert updated.created_at == case.created_at

    def test_update_records_changed_fields_in_audit(self, manager):
        case = manager.create(name="op", examiner="alice", os_profile="unix")
        manager.update(case.id, name="op2", notes="hi")
        events = _audit(manager, case.id)
        assert len(events) == 1
        assert events[0]["action"] == "case_updated"
        assert events[0]["changes"] == {
            "name": {"from": "op", "to": "op2"},
            "notes": {"from": "", "to": "hi"},
        }

    def test_update_with_same_value_does_not_audit(self, manager):
        case = manager.create(name="op", examiner="alice", os_profile="unix")
        manager.update(case.id, name="op")
        assert _audit(manager, case.id) == []
