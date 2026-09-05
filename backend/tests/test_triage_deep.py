"""Triage PROFUNDO: el SO de una imagen CONTENEDOR se determina abriéndola.

El fingerprint superficial (`agentopsy.triage`) lee los BYTES del fichero
registrado. En un `.raw` eso basta. En un contenedor (EWF `.E01`, `.vmdk`,
`.qcow2`, `.vhd(x)`, `.vdi`) el disco está troceado y comprimido: los marcadores
del SO no están en claro, `family` salía `unknown`, el caso se quedaba sin
`os_profile` y había que PREGUNTARLE al perito qué SO era. `agentopsy.triage_deep`
cierra ese hueco abriendo la imagen por el maletín (ewfmount / qemu FUSE export,
solo lectura a nivel de bloque) y leyendo el directorio raíz de cada sistema de
ficheros.

Lo que se fija aquí (CLAUDE.md RULE 2 — determina por CONTENIDO, escala en
ambigüedad, jamás adivina):

- Un `.E01` cuyo disco tiene `Windows/`, `Program Files/`, `$MFT` → `windows`,
  y el caso queda enrutado sin intervención del perito.
- Un `.vmdk` cuyo disco tiene `etc/`, `usr/`, `var/`, `bin/` → `unix`, con el
  desencapsulado qemu correcto (`qemu_image` + `qemu_format`), no ewfmount.
- Empate (dual-boot / evidencia sembrada con nombres del otro SO) → `unknown`:
  ni se enruta ni se inventa; el perito ancla.
- Maletín caído / `ewfmount` ausente → el registro NO falla, el perfil queda sin
  resolver, y el motivo accionable queda en el audit log.
- Una evidencia que el pase superficial YA sabe enrutar no dispara ninguna
  ejecución: el triage profundo es para el hueco, no un peaje.
- Sin tabla de particiones (`mmls` exit≠0) se lee el FS en offset 0 — la
  determinación de `mmls`, no un reintento a ciegas (docs/bugs/001).
- Cada comando ejecutado (argv literal + exit) queda en el log encadenado
  (FORENSIC INVARIANT 4).
"""

from __future__ import annotations

import json

import pytest

from agentopsy.cases.manager import CaseManager, resolve_os_profile
from agentopsy.evidence import EvidenceManager
from agentopsy.toolkit import maletin
from agentopsy.triage import DetectedEvidence
from agentopsy.triage_deep import DEEP_TRIAGE_VENUE, deepen, probe_image

# --- salidas TSK sintéticas ------------------------------------------------ #

_MMLS_ONE_PARTITION = """DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

     Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)
"""

# Salida REAL de `mmls` sobre una imagen GPT (Windows 10, la del caso que dejó de
# enrutarse). En GPT no hay tablas anidadas, así que TSK imprime el slot SOLO
# (`000`) en vez del `tabla:slot` (`000:000`) del MBR. Reconocer solo la forma del
# MBR dejaba CERO particiones, se leía el offset 0 (donde un disco GPT solo tiene
# el MBR de protección), `fls` fallaba y la familia salía `unknown`.
_MMLS_GPT_WINDOWS = """GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  Meta      0000000001   0000000001   0000000001   GPT Header
003:  Meta      0000000002   0000000033   0000000032   Partition Table
004:  000       0000002048   0001023999   0001021952   Basic data partition
005:  001       0001024000   0001226751   0000202752   EFI system partition
006:  002       0001226752   0001259519   0000032768   Microsoft reserved partition
007:  003       0001259520   1000214527   0998955008   Basic data partition
008:  -------   1000214528   1000215215   0000000688   Unallocated
"""

# Raíz REAL de la partición de sistema de esa misma imagen. Nótese que `Windows`
# no aparece: los metaficheros NTFS y los directorios de perfil ya sostienen el
# veredicto, que es lo que hace la determinación robusta.
_FLS_GPT_WINDOWS_ROOT = """d/d 3-144-5:\tDocuments and Settings
d/d 4-144-5:\tProgramData
d/d 5-144-5:\tUsers
r/r 0-128-1:\t$MFT
r/r 1-128-1:\t$MFTMirr
r/r 2-128-1:\t$LogFile
r/r 7-128-1:\t$Boot
d/d 6-144-5:\t$Recycle.Bin
d/d 8-144-5:\tConfig.Msi
d/d 9-144-5:\tIntel
"""

_FLS_WINDOWS_ROOT = """d/d 5-144-5:\t$Extend
r/r 0-128-1:\t$MFT
r/r 2-128-1:\t$LogFile
d/d 256-144-5:\tWindows
d/d 257-144-5:\tProgram Files
d/d 258-144-5:\tUsers
r/r 259-128-1:\tpagefile.sys
"""

_FLS_UNIX_ROOT = """d/d 11:\tlost+found
d/d 12:\tetc
d/d 13:\tusr
d/d 14:\tvar
d/d 15:\tbin
d/d 16:\thome
"""

_FLS_DUAL_BOOT_ROOT = """d/d 12:\tetc
d/d 13:\tusr
d/d 14:\tvar
d/d 15:\tbin
d/d 256:\tWindows
d/d 257:\tProgram Files
r/r 258:\t$MFT
r/r 259:\tpagefile.sys
"""


class FakeMaletin:
    """Sustituye a `run_argv_in_maletin`: registra cada llamada y responde por
    binario. Ninguna prueba necesita Docker — el contrato que se fija es el que
    cruza ese canal (argv literal + modo de desencapsulado)."""

    def __init__(self, *, mmls=(0, _MMLS_ONE_PARTITION), fls=(0, _FLS_WINDOWS_ROOT)):
        self.mmls = mmls
        self.fls = fls
        self.calls: list[dict] = []

    def __call__(self, service, argv, *, timeout=None, ewf_image=None,
                 qemu_image=None, qemu_format=None, stdout_path=None):
        self.calls.append({
            "service": service,
            "argv": list(argv),
            "ewf_image": ewf_image,
            "qemu_image": qemu_image,
            "qemu_format": qemu_format,
        })
        exit_code, stdout = self.mmls if argv[0] == "mmls" else self.fls
        return exit_code, stdout, ""


@pytest.fixture
def cases(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


@pytest.fixture
def evidence(cases) -> EvidenceManager:
    return EvidenceManager(cases)


def _ewf_blob() -> bytes:
    """Cabecera EWF real + relleno. El pase superficial la clasifica
    `container_disk` con familia `unknown` — exactamente el hueco."""
    return b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 2048 + b"compressed-noise" * 64


def _vmdk_blob() -> bytes:
    """Cabecera VMDK sparse (`KDMV`) → `container_disk` / `unknown`."""
    return b"KDMV" + b"\x00" * 2048 + b"compressed-noise" * 64


def _audit(cases, case_id) -> list[dict]:
    path = cases.case_dir(case_id) / "audit.jsonl"
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


def _register(evidence, case_id, tmp_path, name, blob) -> str:
    src = tmp_path / name
    src.write_bytes(blob)
    return evidence.register(case_id, str(src)).evidence_id


# --------------------------------------------------------------------------- #
# El hueco que motiva todo: sin el pase profundo, un contenedor no enruta.
# --------------------------------------------------------------------------- #
def test_container_without_deep_pass_stays_unresolved(evidence, cases, tmp_path, monkeypatch):
    """Sin canal al maletín (el caso de estas pruebas por defecto), un `.E01` se
    registra bien pero el caso NO obtiene os_profile. Es el estado que el pase
    profundo viene a arreglar — y el que debe conservarse cuando no puede correr."""
    monkeypatch.delenv("AGENTOPSY_TOOLKIT_UNIX_URL", raising=False)
    case = cases.create(name="op", examiner="alice")
    handle = evidence.register(
        case.id, str(_write(tmp_path, "img.E01", _ewf_blob()))
    )

    assert handle.detected_kind == "container_disk"
    assert handle.detected_os == "unknown"
    assert cases.load(case.id).os_profile is None
    # El motivo queda escrito: no es un silencio, es una dependencia ausente.
    deep = [e for e in _audit(cases, case.id) if e.get("action") == "triage_deep"]
    assert len(deep) == 1
    assert deep[0]["outcome"] == "unavailable"
    assert "exec-agent" in deep[0]["reason"]


def _write(tmp_path, name, blob):
    path = tmp_path / name
    path.write_bytes(blob)
    return path


# --------------------------------------------------------------------------- #
# EWF → windows, automático
# --------------------------------------------------------------------------- #
def test_ewf_container_routes_to_windows_without_asking(
    evidence, cases, tmp_path, monkeypatch
):
    fake = FakeMaletin(fls=(0, _FLS_WINDOWS_ROOT))
    monkeypatch.setattr(maletin, "run_argv_in_maletin", fake)

    case = cases.create(name="op", examiner="alice")
    handle = evidence.register(case.id, str(_write(tmp_path, "img.E01", _ewf_blob())))

    # La determinación llega a la evidencia Y al caso: nadie preguntó el SO.
    assert handle.detected_os == "windows"
    reloaded = cases.load(case.id)
    assert reloaded.os_profile == "windows"
    assert reloaded.os_profile_source == "derived"
    assert resolve_os_profile(reloaded) == "windows"

    # El desencapsulado fue el de EWF (ewfmount), no el de qemu.
    assert all(c["ewf_image"] is not None for c in fake.calls)
    assert all(c["qemu_image"] is None for c in fake.calls)
    assert all(c["service"] == DEEP_TRIAGE_VENUE for c in fake.calls)
    # Y el token de la imagen es el que porta el argv (contrato del exec-agent).
    for call in fake.calls:
        assert call["ewf_image"] in call["argv"]


def test_ewf_deep_run_is_audited_with_literal_argv(evidence, cases, tmp_path, monkeypatch):
    monkeypatch.setattr(maletin, "run_argv_in_maletin", FakeMaletin())
    case = cases.create(name="op", examiner="alice")
    eid = _register(evidence, case.id, tmp_path, "img.E01", _ewf_blob())

    entries = _audit(cases, case.id)
    deep = [e for e in entries if e.get("action") == "triage_deep"]
    assert len(deep) == 1
    assert deep[0]["evidence_id"] == eid
    assert deep[0]["venue"] == DEEP_TRIAGE_VENUE
    assert deep[0]["family"] == "windows"
    # El argv LITERAL de cada comando, no la intención (FORENSIC INVARIANT 4).
    binaries = [run["argv"][0] for run in deep[0]["runs"]]
    assert binaries == ["mmls", "fls"]
    assert all("exit" in run for run in deep[0]["runs"])
    # Y las entradas concretas que sostienen el veredicto.
    assert any(s.startswith("root[") and "windows" in s for s in deep[0]["signals"])

    # El enrutado sigue registrándose con su decisión, como cualquier auto-set.
    routed = [e for e in entries if e.get("action") == "os_profile_routed"]
    assert routed and routed[0]["decision"] == "auto_set"


# --------------------------------------------------------------------------- #
# Contenedor qemu → unix, con el driver correcto
# --------------------------------------------------------------------------- #
def test_vmdk_container_routes_to_unix_via_qemu(evidence, cases, tmp_path, monkeypatch):
    fake = FakeMaletin(fls=(0, _FLS_UNIX_ROOT))
    monkeypatch.setattr(maletin, "run_argv_in_maletin", fake)

    case = cases.create(name="op", examiner="alice")
    handle = evidence.register(case.id, str(_write(tmp_path, "disk.vmdk", _vmdk_blob())))

    assert handle.detected_os == "unix"
    assert cases.load(case.id).os_profile == "unix"
    # Desencapsulado qemu con el driver de bloque de VMDK — nunca ewfmount.
    assert all(c["qemu_format"] == "vmdk" for c in fake.calls)
    assert all(c["ewf_image"] is None for c in fake.calls)


# --------------------------------------------------------------------------- #
# Ambigüedad: escala, no adivina
# --------------------------------------------------------------------------- #
def test_dual_boot_image_stays_unknown_and_escalates(evidence, cases, tmp_path, monkeypatch):
    """Windows y Unix en la misma raíz (dual-boot, o evidencia sembrada por un
    sospechoso para inducir un enrutado erróneo): ninguna familia domina, así que
    no se enruta. Es la garantía de RULE 2, no una carencia."""
    fake = FakeMaletin(fls=(0, _FLS_DUAL_BOOT_ROOT))
    monkeypatch.setattr(maletin, "run_argv_in_maletin", fake)

    case = cases.create(name="op", examiner="alice")
    handle = evidence.register(case.id, str(_write(tmp_path, "img.E01", _ewf_blob())))

    assert handle.detected_os == "unknown"
    assert cases.load(case.id).os_profile is None
    deep = [e for e in _audit(cases, case.id) if e.get("action") == "triage_deep"]
    assert deep[0]["outcome"] == "inconclusive"
    # Aun sin veredicto, queda registrado QUÉ se miró.
    assert any("deep:win=" in s for s in deep[0]["signals"])


def test_unreadable_image_never_invents_a_profile(evidence, cases, tmp_path, monkeypatch):
    """TSK no abre la imagen (mmls y fls fallan): sin nombres que puntuar, la
    familia sigue `unknown`. Jamás se cae en un default."""
    fake = FakeMaletin(mmls=(1, ""), fls=(1, ""))
    monkeypatch.setattr(maletin, "run_argv_in_maletin", fake)

    case = cases.create(name="op", examiner="alice")
    handle = evidence.register(case.id, str(_write(tmp_path, "img.E01", _ewf_blob())))
    assert handle.detected_os == "unknown"
    assert cases.load(case.id).os_profile is None


def test_maletin_down_does_not_break_registration(evidence, cases, tmp_path, monkeypatch):
    """El maletín caído degrada la DETERMINACIÓN, no la custodia: la evidencia
    queda registrada, hasheada y auditada; solo el perfil queda sin resolver."""
    def boom(*_a, **_k):
        raise maletin.MaletinExecError("exec-agent inalcanzable")

    monkeypatch.setattr(maletin, "run_argv_in_maletin", boom)
    case = cases.create(name="op", examiner="alice")
    handle = evidence.register(case.id, str(_write(tmp_path, "img.E01", _ewf_blob())))

    assert handle.sha256  # la puerta de hash corrió igual
    assert handle.detected_os == "unknown"
    assert cases.load(case.id).os_profile is None
    deep = [e for e in _audit(cases, case.id) if e.get("action") == "triage_deep"]
    assert deep[0]["outcome"] == "unavailable"


# --------------------------------------------------------------------------- #
# El pase profundo no es un peaje: no corre cuando no hace falta
# --------------------------------------------------------------------------- #
def test_routable_evidence_runs_no_commands(tmp_path, monkeypatch):
    called: list = []
    monkeypatch.setattr(maletin, "run_argv_in_maletin", lambda *a, **k: called.append(a))

    shallow = DetectedEvidence("windows", "disk", "header", ("ntfs_bpb",))
    record, detail, reason = deepen(shallow, tmp_path / "x.raw")

    assert record is shallow and detail is None and reason is None
    assert called == []


def test_memory_dump_runs_no_commands(tmp_path, monkeypatch):
    """Un volcado de memoria no tiene tabla de particiones ni sistema de ficheros:
    abrirlo con TSK son round-trips que no informan nada."""
    called: list = []
    monkeypatch.setattr(maletin, "run_argv_in_maletin", lambda *a, **k: called.append(a))

    shallow = DetectedEvidence("unknown", "memory", "markers", ("pe_scatter=6",))
    record, detail, _ = deepen(shallow, tmp_path / "ram.lime")

    assert record is shallow and detail is None
    assert called == []


# --------------------------------------------------------------------------- #
# Sin tabla de particiones: se lee el FS en offset 0 (docs/bugs/001)
# --------------------------------------------------------------------------- #
def test_flat_filesystem_is_read_at_offset_zero(monkeypatch):
    fake = FakeMaletin(mmls=(1, "Cannot determine partition type"), fls=(0, _FLS_UNIX_ROOT))
    monkeypatch.setattr(maletin, "run_argv_in_maletin", fake)

    result = probe_image("/cases/cases/c/evidence/e/original.raw")

    assert result.family == "unix"
    fls_call = next(c for c in fake.calls if c["argv"][0] == "fls")
    # Sin `-o`: el sistema de ficheros empieza en el sector 0.
    assert "-o" not in fls_call["argv"]
    # Y una imagen raw no se desencapsula: no es un contenedor.
    assert fls_call["ewf_image"] is None and fls_call["qemu_image"] is None


def test_partitioned_image_reads_each_partition_root(monkeypatch):
    fake = FakeMaletin(mmls=(0, _MMLS_ONE_PARTITION), fls=(0, _FLS_WINDOWS_ROOT))
    monkeypatch.setattr(maletin, "run_argv_in_maletin", fake)

    result = probe_image("/cases/cases/c/evidence/e/original.raw")

    assert result.family == "windows"
    fls_call = next(c for c in fake.calls if c["argv"][0] == "fls")
    # Solo la fila con slot `NNN:NNN` es una partición; Meta y Unallocated no.
    assert fls_call["argv"][:3] == ["fls", "-o", "2048"]


def test_gpt_disk_reads_its_partitions_instead_of_offset_zero(monkeypatch):
    """Un disco GPT es hoy el caso NORMAL (todo Windows 10/11), y era justo el que
    no se determinaba: TSK imprime el slot de GPT solo (`000`), no como el
    `tabla:slot` del MBR (`000:000`), así que no se reconocía ninguna partición, se
    caía a leer el offset 0 (donde un GPT solo tiene el MBR de protección) y la
    imagen salía `unknown` teniendo la raíz de Windows delante."""
    fake = FakeMaletin(mmls=(0, _MMLS_GPT_WINDOWS), fls=(0, _FLS_GPT_WINDOWS_ROOT))
    monkeypatch.setattr(maletin, "run_argv_in_maletin", fake)

    result = probe_image("/cases/cases/c/evidence/e/original.E01")

    assert result.family == "windows"
    offsets = [c["argv"][2] for c in fake.calls if c["argv"][0] == "fls"]
    # Las CUATRO particiones reales de la tabla, en su orden, y ninguna más:
    # las filas `Meta` (tabla de particiones, cabecera GPT) y las `-------`
    # (espacio no asignado) no son sistemas de ficheros.
    assert offsets == ["2048", "1024000", "1226752", "1259520"]
    # Y nunca se leyó el offset 0, que es lo que hacía el pase roto.
    assert all("-o" in c["argv"] for c in fake.calls if c["argv"][0] == "fls")


# --------------------------------------------------------------------------- #
# Re-determinación bajo demanda (el maletín estaba caído al registrar)
# --------------------------------------------------------------------------- #
def test_redetect_os_resolves_a_case_registered_while_maletin_was_down(
    evidence, cases, tmp_path, monkeypatch
):
    def boom(*_a, **_k):
        raise maletin.MaletinExecError("exec-agent inalcanzable")

    monkeypatch.setattr(maletin, "run_argv_in_maletin", boom)
    case = cases.create(name="op", examiner="alice")
    eid = _register(evidence, case.id, tmp_path, "img.E01", _ewf_blob())
    assert cases.load(case.id).os_profile is None

    # El maletín vuelve. La re-determinación cierra el caso sin preguntar nada.
    monkeypatch.setattr(maletin, "run_argv_in_maletin", FakeMaletin())
    handle = evidence.redetect_os(case.id, eid)

    assert handle.detected_os == "windows"
    assert cases.load(case.id).os_profile == "windows"
    # Y la custodia no se tocó: el baseline sigue siendo el mismo hash.
    assert evidence.verify(case.id, eid) is True
