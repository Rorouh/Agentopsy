"""Gate de la policy de redacción del paquete `forensia-windows`.

Verifica, sin importar el motor (solo lee `policy/redaction.yaml`):
  1. Cada regex compila.
  2. Ninguna sufre backtracking catastrófico (ReDoS) sobre inputs adversarios,
     medido con un presupuesto de tiempo por patrón.
  3. Las redacciones representativas funcionan y no rompen las preexistentes.

El bucle `_apply` replica fielmente cómo el motor aplica los patrones
(`forensia.mcp.redaction.apply_redaction` / `forensia.agent.redaction`): en orden
de fichero, con `re.sub`, que soporta backreferences (`\1`) en el replacement.
"""
from __future__ import annotations

import re
import threading
import time
from pathlib import Path

import pytest
import yaml

_POLICY = (
    Path(__file__).resolve().parents[2]
    / "agentes"
    / "forensia-windows"
    / "policy"
    / "redaction.yaml"
)

_DATA = yaml.safe_load(_POLICY.read_text(encoding="utf-8"))
PATTERNS: list[dict] = _DATA["patterns"]
_IDS = [p["name"] for p in PATTERNS]


def _apply(sample: str, mode: str = "strict") -> str:
    """Aplica los patrones del modo dado, en orden, como el motor."""
    out = sample
    for p in PATTERNS:
        modes = [m.strip().lower() for m in p.get("apply_in", ["strict"])]
        if mode in modes:
            out = re.sub(p["regex"], p["replacement"], out)
    return out


def _run_with_budget(fn, budget_s: float = 1.0) -> float | None:
    """Ejecuta fn() en un hilo; devuelve el tiempo o None si excede el presupuesto
    (síntoma de backtracking catastrófico). Portable (sin signal.alarm)."""
    result: dict[str, float] = {}

    def worker() -> None:
        t0 = time.perf_counter()
        fn()
        result["elapsed"] = time.perf_counter() - t0

    th = threading.Thread(target=worker, daemon=True)
    th.start()
    th.join(budget_s)
    return None if th.is_alive() else result.get("elapsed", 0.0)


# ---- 1. compila -----------------------------------------------------------


@pytest.mark.parametrize("pattern", PATTERNS, ids=_IDS)
def test_pattern_compiles(pattern: dict) -> None:
    re.compile(pattern["regex"])
    assert isinstance(pattern["replacement"], str)
    assert pattern.get("apply_in"), f"{pattern['name']}: apply_in vacío"


# ---- 2. no ReDoS ----------------------------------------------------------

_N = 5000
_ADVERSARIAL = [
    "a" * _N,
    "0" * _N,
    "a:" * _N,
    "\\" * _N,
    ("A" * _N) + "!",
    "C:\\Users\\" + ("x" * _N),
    "\\\\" + ("h" * _N),
    "deadbeef" * _N,
    "1234:" * _N,
    "ComputerName=" + ("x" * _N),
    ("aad3b435b51404eeaad3b435b51404ee:" * _N),
]


@pytest.mark.parametrize("pattern", PATTERNS, ids=_IDS)
def test_pattern_no_redos(pattern: dict) -> None:
    rx = re.compile(pattern["regex"])
    repl = pattern["replacement"]
    for s in _ADVERSARIAL:
        # Gate de ReDoS: un patrón con backtracking catastrófico (exponencial) no
        # termina en 1s ni con inputs moderados; el timeout del hilo lo delata.
        # (No es un micro-benchmark: la lentitud cuadrática leve no es ReDoS.)
        elapsed = _run_with_budget(lambda s=s: rx.sub(repl, s), budget_s=1.0)
        assert elapsed is not None, (
            f"{pattern['name']}: parece backtracking catastrófico (>1s) "
            f"sobre input adversario de {len(s)} chars"
        )


# ---- 3. correctness -------------------------------------------------------


def test_windows_user_path_preserva_estructura() -> None:
    assert _apply(r"C:\Users\johndoe\AppData\Roaming\x") == r"C:\Users\<USER>\AppData\Roaming\x"


def test_unc_path_redacted() -> None:
    assert "<UNC_PATH>" in _apply(r"abrir \\FILESRV\share\secreto.docx ahora")


def test_hostname_labeled_conserva_etiqueta() -> None:
    assert _apply("ComputerName: WIN10-DESK01") == "ComputerName: <HOST>"
    assert _apply("Hostname=DC01") == "Hostname=<HOST>"


def test_guid_redacted() -> None:
    assert _apply("MachineGuid 1b4e28ba-2fa1-11d2-883f-0016d3cca427 fin") == "MachineGuid <GUID> fin"


def test_credential_dump_line_redacted() -> None:
    line = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
    assert _apply(line) == "<CREDENTIAL_DUMP>"


def test_ntlm_hash_redacted_md5_incluido() -> None:
    assert _apply("hash: 5f4dcc3b5aa765d61d8327deb882cf99") == "hash: <NTLM_HASH>"


def test_sha256_no_se_rompe() -> None:
    # 64 hex sin frontera de palabra interna: el {32} con \b no muerde una subcadena.
    sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert _apply(sha) == sha


def test_credenciales_tambien_en_relaxed() -> None:
    # NTLM/pwdump deben caer también en relaxed; el path de usuario (host) NO.
    assert _apply("5f4dcc3b5aa765d61d8327deb882cf99", mode="relaxed") == "<NTLM_HASH>"
    assert _apply(r"C:\Users\johndoe\x", mode="relaxed") == r"C:\Users\johndoe\x"


def _pattern(name: str) -> dict:
    for p in PATTERNS:
        if p["name"] == name:
            return p
    raise KeyError(name)


def test_preexistentes_intactas() -> None:
    assert _apply("correo a@ejemplo.com") == "correo <EMAIL>"
    assert _apply("ip 10.0.0.5 fin") == "ip <IPV4> fin"
    assert "<SID>" in _apply("owner S-1-5-21-1004336348-1177238915-682003330-512")


def test_mac_etiquetada_mac_no_ipv6() -> None:
    # Tras reordenar `mac_address` antes de `ipv6`, una MAC se etiqueta <MAC>
    # (antes la comía el patrón laxo de ipv6 y salía <IPV6>).
    assert _apply("mac AA:BB:CC:DD:EE:FF") == "mac <MAC>"
    assert _apply("00:1a:2b:3c:4d:5e") == "<MAC>"


def test_ipv6_sigue_redactada_tras_reorden() -> None:
    # El reorden no debe dejar ninguna IPv6 real sin redactar: sus bloques de
    # hasta 4 hex no los consume `mac_address` (que exige exactamente 2).
    for addr in ("fe80:0000:0000:0000:0204:61ff:fe9d:f156", "2001:db8:85a3:8a2e"):
        out = _apply(f"addr {addr} fin")
        assert addr not in out, f"IPv6 {addr} no se redactó"
        assert "<IPV6>" in out


def test_email_no_es_cuadratico_en_input_largo() -> None:
    # Con los cuantificadores acotados, el email es O(n) sobre un input largo
    # no-email; el patrón sin topes anterior habría excedido el presupuesto.
    p = _pattern("email")
    rx = re.compile(p["regex"])
    repl = p["replacement"]
    big = "a" * 100_000  # no contiene '@'
    elapsed = _run_with_budget(lambda: rx.sub(repl, big), budget_s=1.0)
    assert elapsed is not None, "email: no terminó en 1s sobre input largo no-email (O(n^2)?)"
    # Correctness intacta sobre un email válido.
    assert _apply("correo a@ejemplo.com") == "correo <EMAIL>"
