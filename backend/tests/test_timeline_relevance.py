"""Deterministic relevance classifier for filesystem MACB events.

Covers the path/MACB rules (credentials, ssh, shell history, persistence, temp
executables, web artifacts, logs, system binaries) and the selection/sort/cap of
``select_relevant_events`` — every "relevant" event is a REAL event tagged with why
(RULE 2), sorted by importance and capped with the overflow reported.
"""

from __future__ import annotations

from agentopsy.timeline.relevance import classify, select_relevant_events


def _ev(path: str, macb: str, ts: str = "2021-01-01T00:00:00Z") -> dict:
    return {"ts": ts, "path": path, "macb": macb, "size": 10, "inode": "1"}


def test_credentials_files_are_top_weight() -> None:
    for path in ("/etc/shadow", "/etc/passwd", "/etc/sudoers"):
        hit = classify(path, "m.c.")
        assert hit is not None and hit["category"] == "credenciales" and hit["weight"] == 5


def test_windows_hives_are_credentials_case_insensitive() -> None:
    hit = classify(r"C:\\Windows\\System32\\config\\SAM", "..cb")
    assert hit is not None and hit["category"] == "credenciales"


def test_ssh_material_matches_dir_and_key_names() -> None:
    assert classify("/root/.ssh/id_rsa", "..cb")["category"] == "ssh"
    assert classify("/home/u/.ssh/authorized_keys", "m...")["category"] == "ssh"


def test_shell_history_and_persistence() -> None:
    assert classify("/home/u/.bash_history", "m...")["category"] == "historial"
    assert classify("/etc/cron.d/evil", "...b")["category"] == "persistencia"
    assert classify("/etc/systemd/system/backdoor.service", "...b")["category"] == "persistencia"
    assert classify("/home/u/.bashrc", "m...")["category"] == "persistencia"


def test_temp_executable_requires_executable_extension() -> None:
    assert classify("/tmp/payload.sh", "...b")["category"] == "ejecutable_temporal"
    assert classify("/var/tmp/x.elf", "...b")["category"] == "ejecutable_temporal"
    # Un fichero de datos normal en /tmp no es relevante (evita ruido).
    assert classify("/tmp/notes.txt", "m...") is None


def test_web_artifact_only_executable_kinds() -> None:
    assert classify("/var/www/html/shell.php", "...b")["category"] == "web"
    assert classify("/var/www/html/index.html", "m...") is None


def test_system_binary_gated_on_modify_or_birth() -> None:
    # Solo acceso (a) → no relevante; creado/modificado → sí.
    assert classify("/usr/bin/ls", ".a..") is None
    assert classify("/usr/bin/ls", "m...")["category"] == "binario_sistema"
    assert classify("/usr/sbin/sshd", "...b")["category"] == "binario_sistema"


def test_ordinary_file_is_not_relevant() -> None:
    assert classify("/home/u/photo.jpg", "macb") is None


def test_select_sorts_by_weight_then_time_and_reports_total() -> None:
    events = [
        _ev("/home/u/photo.jpg", "m...", "2021-01-01T00:00:00Z"),  # irrelevante
        _ev("/home/u/.bash_history", "m...", "2021-01-03T00:00:00Z"),  # weight 4
        _ev("/etc/shadow", "m...", "2021-01-02T00:00:00Z"),  # weight 5
    ]
    relevant, total = select_relevant_events(events)
    assert total == 2
    # weight 5 antes que weight 4, aunque su ts sea anterior.
    assert [e["path"] for e in relevant] == ["/etc/shadow", "/home/u/.bash_history"]
    assert relevant[0]["reason"]  # cada relevante lleva el porqué


def test_select_caps_and_reports_overflow() -> None:
    events = [_ev(f"/etc/cron.d/job{i}", "...b", "2021-01-01T00:00:00Z") for i in range(10)]
    relevant, total = select_relevant_events(events, limit=3)
    assert total == 10
    assert len(relevant) == 3
