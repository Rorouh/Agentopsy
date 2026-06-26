"""Artifact storage: one directory per tool invocation under ``<case_dir>/artifacts/<run-id>/``.

Each run owns a ``manifest.json`` (the canonical record), ``stdout.txt`` and
``stderr.txt`` captures, and an ``out/`` directory that the wrapper uses as its
``output_dir``. Every captured byte is hashed (chunked SHA-256) on finalize so
the chain-of-custody invariants hold: the manifest records the LITERAL argv
executed (never the LLM's stated intent), the exit code, and the SHA-256 of
each artifact produced.

Manifest writes are atomic (``*.tmp`` + ``os.replace``) — a crash mid-write
never leaves a half-baked canonical record on disk.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from forensia.cases.manager import CaseManager, case_manager

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_CHUNK_SIZE = 1024 * 1024  # 1 MiB — never read whole files into memory.


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_file(path: Path) -> tuple[str, int]:
    """Chunked SHA-256 + size in bytes. Never loads the file fully into memory."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _atomic_write_text(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _atomic_write_json(path: Path, data: dict) -> None:
    _atomic_write_text(path, json.dumps(data, sort_keys=True, indent=2))


@dataclass(frozen=True)
class OutputFile:
    relpath: str  # POSIX-style relative path inside ``out/``.
    sha256: str
    size: int


@dataclass(frozen=True)
class ArtifactRun:
    run_id: str
    case_id: str
    tool_id: str
    argv: list[str]  # literal argv as executed (NOT the LLM's intent)
    started_at: str  # ISO-8601 UTC
    finished_at: str | None  # None while in-flight
    exit_code: int | None  # None while in-flight
    output_files: list[OutputFile] = field(default_factory=list)
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None


class ArtifactStore:
    """Filesystem-backed store for tool-invocation artifacts."""

    def __init__(self, case_manager: CaseManager) -> None:
        self._cases = case_manager

    # ---------- internal helpers ----------

    def _runs_dir(self, case_id: str) -> Path:
        # ``case_dir`` raises KeyError on unknown case_id — propagate.
        return self._cases.case_dir(case_id) / "artifacts"

    def _run_dir(self, case_id: str, run_id: str) -> Path:
        if not _UUID4_RE.match(run_id):
            raise ValueError(f"invalid run_id (expected UUID4): {run_id!r}")
        return self._runs_dir(case_id) / run_id

    @staticmethod
    def _scan_out_dir(out_dir: Path) -> list[OutputFile]:
        """Recursively walk ``out/`` and hash every regular file."""
        if not out_dir.exists():
            return []
        files: list[OutputFile] = []
        for path in sorted(out_dir.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            sha256, size = _hash_file(path)
            relpath = path.relative_to(out_dir).as_posix()
            files.append(OutputFile(relpath=relpath, sha256=sha256, size=size))
        return files

    @staticmethod
    def _manifest_to_run(case_id: str, manifest: dict) -> ArtifactRun:
        output_files = [
            OutputFile(relpath=of["relpath"], sha256=of["sha256"], size=of["size"])
            for of in manifest.get("output_files", [])
        ]
        return ArtifactRun(
            run_id=manifest["run_id"],
            case_id=case_id,
            tool_id=manifest["tool_id"],
            argv=list(manifest["argv"]),
            started_at=manifest["started_at"],
            finished_at=manifest.get("finished_at"),
            exit_code=manifest.get("exit_code"),
            output_files=output_files,
            stdout_sha256=manifest.get("stdout_sha256"),
            stderr_sha256=manifest.get("stderr_sha256"),
        )

    # ---------- public API ----------

    def start_run(
        self, case_id: str, tool_id: str, argv: list[str]
    ) -> tuple[str, Path]:
        """Open a new run and return ``(run_id, out_dir)``.

        Creates ``artifacts/<run-id>/out/`` and writes a half-baked
        ``manifest.json`` marking ``status='running'``. The returned ``out_dir``
        is the path the dispatcher must hand to the wrapper as ``output_dir``.
        """
        if not isinstance(tool_id, str) or not tool_id:
            raise ValueError("tool_id must be a non-empty string")
        if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
            raise ValueError("argv must be a list[str] (literal executed argv)")

        run_id = str(uuid.uuid4())
        run_dir = self._runs_dir(case_id) / run_id
        out_dir = run_dir / "out"
        out_dir.mkdir(parents=True, exist_ok=False)

        manifest = {
            "run_id": run_id,
            "case_id": case_id,
            "tool_id": tool_id,
            "argv": list(argv),
            "started_at": _now_iso(),
            "finished_at": None,
            "exit_code": None,
            "status": "running",
            "output_files": [],
            "stdout_sha256": None,
            "stderr_sha256": None,
        }
        _atomic_write_json(run_dir / "manifest.json", manifest)
        return run_id, out_dir

    def finalize_run(
        self,
        case_id: str,
        run_id: str,
        *,
        exit_code: int,
        stdout: str,
        stderr: str,
    ) -> ArtifactRun:
        """Close a run: persist stdout/stderr, hash every output, write the
        final manifest, and return the canonical :class:`ArtifactRun`.

        Hashes ``stdout.txt``, ``stderr.txt`` and every file under ``out/``
        (recursively, 1 MiB blocks). An empty ``out/`` is valid.

        Raises ``KeyError`` if the run does not exist or was already finalized.
        """
        if not isinstance(exit_code, int):
            raise ValueError("exit_code must be an int")
        if not isinstance(stdout, str) or not isinstance(stderr, str):
            raise ValueError("stdout/stderr must be str (decoded)")

        run_dir = self._run_dir(case_id, run_id)
        manifest_path = run_dir / "manifest.json"
        if not manifest_path.exists():
            raise KeyError(f"unknown run_id for case {case_id}: {run_id}")

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("status") == "finished":
            raise KeyError(f"run {run_id} for case {case_id} is already finalized")

        # Persist stdout/stderr atomically, then hash from disk so the recorded
        # digest matches the bytes that actually live on the filesystem.
        stdout_path = run_dir / "stdout.txt"
        stderr_path = run_dir / "stderr.txt"
        _atomic_write_text(stdout_path, stdout)
        _atomic_write_text(stderr_path, stderr)
        stdout_sha256, _ = _hash_file(stdout_path)
        stderr_sha256, _ = _hash_file(stderr_path)

        out_dir = run_dir / "out"
        output_files = self._scan_out_dir(out_dir)

        manifest.update(
            {
                "finished_at": _now_iso(),
                "exit_code": exit_code,
                "status": "finished",
                "stdout_sha256": stdout_sha256,
                "stderr_sha256": stderr_sha256,
                "output_files": [asdict(of) for of in output_files],
            }
        )
        _atomic_write_json(manifest_path, manifest)
        return self._manifest_to_run(case_id, manifest)

    def get_run(self, case_id: str, run_id: str) -> ArtifactRun:
        """Read ``manifest.json`` for the given run. Raises ``KeyError`` if missing."""
        manifest_path = self._run_dir(case_id, run_id) / "manifest.json"
        if not manifest_path.exists():
            raise KeyError(f"unknown run_id for case {case_id}: {run_id}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        return self._manifest_to_run(case_id, manifest)

    def list_runs(self, case_id: str) -> list[ArtifactRun]:
        """Return every run with a manifest, sorted by ``started_at`` descending."""
        runs_dir = self._runs_dir(case_id)
        if not runs_dir.exists():
            return []
        runs: list[ArtifactRun] = []
        for entry in runs_dir.iterdir():
            if not entry.is_dir() or not _UUID4_RE.match(entry.name):
                continue
            manifest_path = entry / "manifest.json"
            if not manifest_path.exists():
                continue
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            runs.append(self._manifest_to_run(case_id, manifest))
        runs.sort(key=lambda r: r.started_at, reverse=True)
        return runs


artifact_store = ArtifactStore(case_manager)
