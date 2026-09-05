"""Seeding de credenciales al volumen ``agentopsy-cli-auth`` (docker/api/entrypoint.sh).

El modelo (2026-07-03): el HOME del servicio ``api`` vive en un volumen del
stack; las credenciales del host llegan EN SOLO LECTURA como staging bajo
``/host-creds/`` y el entrypoint las copia UNA sola vez al volumen. Aquí se
verifica el contrato del script fuera de Docker (sh + HOME/staging temporales):

- Primer arranque: seedea lo que exista en el staging y escribe el marker.
- Idempotente: con marker no toca nada; sin marker, un destino ya existente
  (p. ej. un login hecho dentro del contenedor) NUNCA se sobreescribe.
- Rutas ausentes en el host (directorios vacíos que deja Docker, incluso donde
  se esperaba un fichero como ~/.claude.json) se omiten sin error.
- Los logs nombran rutas, jamás contenido de credenciales.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = REPO_ROOT / "docker" / "api" / "entrypoint.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("sh") is None, reason="requiere un shell POSIX (`sh`) en el PATH"
)


def _posix_perms_enforced() -> bool:
    """True iff ``chmod`` group/other bits actually stick. On Windows ``st_mode``
    is synthesized and the ``0o077`` bits never clear, so a private-permissions
    assertion is unobservable there — enforced for real inside the Linux api
    container; the check runs unchanged on Linux/CI."""
    with tempfile.TemporaryDirectory() as d:
        probe = Path(d) / "probe"
        probe.write_text("x", encoding="utf-8")
        try:
            os.chmod(probe, 0o600)
        except OSError:
            return False
        return probe.stat().st_mode & 0o077 == 0


requires_posix_perms = pytest.mark.skipif(
    not _posix_perms_enforced(),
    reason="el host no impone permisos POSIX (p. ej. Windows: st_mode sintetizado); "
    "la propiedad se garantiza en el contenedor Linux del servicio api",
)

SECRET_HOST = "token-del-host-que-jamas-debe-aparecer-en-logs"
SECRET_CONTAINER = "sesion-creada-con-login-dentro-del-contenedor"


def run_entrypoint(home: Path, staging: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "HOME": str(home), "AGENTOPSY_HOST_CREDS_DIR": str(staging)}
    return subprocess.run(
        ["sh", str(ENTRYPOINT), "true"],  # exec true: solo el seeding, sin servidor
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.fixture
def dirs(tmp_path: Path) -> tuple[Path, Path]:
    home = tmp_path / "volume-home"
    staging = tmp_path / "host-creds"
    home.mkdir()
    staging.mkdir()
    return home, staging


def populate_staging(staging: Path) -> None:
    (staging / "claude").mkdir()
    (staging / "claude" / ".credentials.json").write_text(
        json.dumps({"token": SECRET_HOST}), encoding="utf-8"
    )
    (staging / "claude.json").write_text("{}", encoding="utf-8")
    (staging / "codex").mkdir()
    (staging / "codex" / "auth.json").write_text(
        json.dumps({"token": SECRET_HOST}), encoding="utf-8"
    )
    (staging / "gemini").mkdir()
    (staging / "gemini" / "oauth_creds.json").write_text(
        json.dumps({"refresh_token": SECRET_HOST}), encoding="utf-8"
    )


def test_first_boot_seeds_everything(dirs: tuple[Path, Path]) -> None:
    home, staging = dirs
    populate_staging(staging)
    proc = run_entrypoint(home, staging)
    assert proc.returncode == 0, proc.stderr
    assert SECRET_HOST in (home / ".claude" / ".credentials.json").read_text(encoding="utf-8")
    assert (home / ".claude.json").is_file()
    assert (home / ".codex" / "auth.json").is_file()
    assert (home / ".gemini" / "oauth_creds.json").is_file()
    assert (home / ".agentopsy-cli-auth-seeded").is_file()


@requires_posix_perms
def test_seeded_files_are_private(dirs: tuple[Path, Path]) -> None:
    home, staging = dirs
    populate_staging(staging)
    assert run_entrypoint(home, staging).returncode == 0
    mode = (home / ".claude" / ".credentials.json").stat().st_mode
    assert mode & 0o077 == 0, "las credenciales seeded deben quedar sin permisos group/other"


def test_second_boot_is_idempotent(dirs: tuple[Path, Path]) -> None:
    home, staging = dirs
    populate_staging(staging)
    assert run_entrypoint(home, staging).returncode == 0
    # El host cambia (p. ej. re-login en el host): el volumen NO se toca.
    (staging / "codex" / "auth.json").write_text(
        json.dumps({"token": "otro-token-posterior"}), encoding="utf-8"
    )
    proc = run_entrypoint(home, staging)
    assert proc.returncode == 0
    assert "ya poblado" in proc.stdout
    assert SECRET_HOST in (home / ".codex" / "auth.json").read_text(encoding="utf-8")


def test_never_overwrites_existing_target_even_without_marker(
    dirs: tuple[Path, Path],
) -> None:
    home, staging = dirs
    populate_staging(staging)
    # Sesión creada con login DENTRO del contenedor, sin marker (p. ej. el
    # marker se borró a mano): el destino existente nunca se sobreescribe.
    (home / ".codex").mkdir()
    (home / ".codex" / "auth.json").write_text(
        json.dumps({"token": SECRET_CONTAINER}), encoding="utf-8"
    )
    proc = run_entrypoint(home, staging)
    assert proc.returncode == 0
    assert SECRET_CONTAINER in (home / ".codex" / "auth.json").read_text(encoding="utf-8")
    # Los demás destinos sí se seedean.
    assert (home / ".claude" / ".credentials.json").is_file()


def test_absent_host_paths_are_skipped_without_error(dirs: tuple[Path, Path]) -> None:
    home, staging = dirs
    # Lo que Docker deja cuando el host no tiene nada: directorios VACÍOS —
    # incluso donde se esperaba un fichero (~/.claude.json).
    (staging / "claude").mkdir()
    (staging / "claude.json").mkdir()
    (staging / "codex").mkdir()
    # gemini ni siquiera montado.
    proc = run_entrypoint(home, staging)
    assert proc.returncode == 0, proc.stderr
    assert not (home / ".claude").exists()
    assert not (home / ".claude.json").exists()
    assert not (home / ".codex").exists()
    assert not (home / ".gemini").exists()
    assert (home / ".agentopsy-cli-auth-seeded").is_file()
    assert "omitido" in proc.stdout


def test_logs_never_contain_credential_content(dirs: tuple[Path, Path]) -> None:
    home, staging = dirs
    populate_staging(staging)
    first = run_entrypoint(home, staging)
    second = run_entrypoint(home, staging)
    for proc in (first, second):
        assert SECRET_HOST not in proc.stdout
        assert SECRET_HOST not in proc.stderr
