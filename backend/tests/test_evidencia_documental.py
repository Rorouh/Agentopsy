"""Ficheros APORTADOS como evidencia: documentos, imágenes, correo, artefactos.

Un caso no siempre trae un disco entero o una RAM. Muchas veces trae lo que
alguien entregó: el PDF de un contrato, el Word de una carta de despido, la foto
que se envió por mensajería, el CSV que exportó una aplicación, el ``.evtx`` que
mandó el cliente sin su disco, la muestra de malware. Todo eso es evidencia y
entra por el MISMO hash-gate y la MISMA cadena de custodia.

Lo que este fichero fija son las tres cosas que cambian, y sólo esas tres:

1. **El triage lo clasifica ``kind=document``** leyendo sus BYTES, no su
   extensión. Una foto renombrada a ``.txt`` sigue siendo un JPEG, y renombrar es
   lo primero que hace quien esconde algo.
2. **Un documento NUNCA fija el ``os_profile`` del caso.** Es lo más importante
   de aquí. El PDF de un informe sobre un incidente de Windows está lleno de
   cadenas de Windows; si puntuasen, un documento enrutaría el caso y, peor,
   entraría en conflicto con el perfil que determina el disco de verdad, dejando
   el caso SIN enrutar. Un fichero aportado no es el sistema investigado.
3. **La bandeja lo acepta**, y lo que no reconoce lo rechaza nombrando por dónde
   entra igualmente (la carpeta ``./evidence`` del host), nunca con un «formato
   no soportado» que deja al perito sin salida.

La cadena de custodia en sí (hash-gate, copia inmutable, log encadenado) no se
re-prueba aquí: es la misma de siempre y la cubre ``test_evidence*``. Lo que sí
se comprueba es que un documento la recorre entera igual que una imagen.
"""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from agentopsy.i18n import _LANG_ACTUAL, set_current_lang
from agentopsy.cases.manager import CaseManager
from agentopsy.evidence import (
    EvidenceManager,
    is_registrable_evidence_ext,
    is_uploadable_evidence_ext,
    save_uploaded_source,
)
from agentopsy.reports.material import naturaleza
from agentopsy.triage import DetectedEvidence, fingerprint_evidence, routable_profile


@pytest.fixture
def cases(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


@pytest.fixture
def manager(cases: CaseManager) -> EvidenceManager:
    return EvidenceManager(cases)


@pytest.fixture
def case(cases: CaseManager):
    return cases.create(name="Documental", examiner="perito")


def _docx_bytes() -> bytes:
    """Un OOXML real: un ZIP cuya primera entrada vive bajo ``word/``."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:p>carta</w:p>")
    return buf.getvalue()


def _xlsx_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("xl/workbook.xml", "<workbook/>")
    return buf.getvalue()


# ── 1 · El triage reconoce el fichero por sus BYTES ──────────────────────────


class TestTriageDeUnFicheroAportado:
    @pytest.mark.parametrize(
        ("name", "payload", "signal"),
        [
            ("contrato.pdf", b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n" + b"0" * 500, "pdf"),
            ("foto.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 500, "jpeg"),
            ("captura.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 500, "png"),
            ("carta.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512, "ole2_office"),
            ("nota.rtf", b"{\\rtf1\\ansi hola}" + b" " * 100, "rtf"),
            ("eventos.evtx", b"ElfFile\x00" + b"\x00" * 500, "evtx"),
            ("SYSTEM", b"regf" + b"\x00" * 500, "registry_hive"),
            ("red.pcap", b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 100, "pcap"),
            ("base.sqlite", b"SQLite format 3\x00" + b"\x00" * 500, "sqlite"),
            ("muestra.bin", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 200, "elf"),
            ("entrega.7z", b"7z\xbc\xaf\x27\x1c" + b"\x00" * 100, "7z"),
        ],
    )
    def test_una_firma_conocida_es_un_fichero_aportado(
        self, tmp_path, name, payload, signal
    ):
        path = tmp_path / name
        path.write_bytes(payload)
        record = fingerprint_evidence(path)
        assert record.kind == "document"
        assert record.confidence == "header"
        assert signal in record.signals

    @pytest.mark.parametrize(
        ("name", "payload", "signal"),
        [
            ("carta.docx", _docx_bytes(), "ooxml_word"),
            ("cuentas.xlsx", _xlsx_bytes(), "ooxml_excel"),
        ],
    )
    def test_un_ooxml_se_distingue_del_zip_que_lo_envuelve(
        self, tmp_path, name, payload, signal
    ):
        # Un .docx y un .zip comparten la firma ``PK\x03\x04``. Qué hay dentro se
        # decide leyendo el nombre de las primeras entradas, que el ZIP guarda en
        # claro al principio del fichero.
        path = tmp_path / name
        path.write_bytes(payload)
        record = fingerprint_evidence(path)
        assert record.kind == "document"
        assert signal in record.signals

    @pytest.mark.parametrize(
        ("name", "text"),
        [
            ("notas.txt", "Reunión del 3 de marzo. Se acordó el traspaso.\n"),
            ("acceso.log", "2026-01-01T00:00:00Z sshd: Accepted password for root\n" * 40),
            ("export.csv", "fecha;usuario;accion\n2026-01-01;jperez;login\n" * 40),
            ("config.json", '{"servidor": "10.0.0.5", "puerto": 22}\n' * 40),
        ],
    )
    def test_el_texto_plano_no_tiene_firma_y_aun_asi_se_reconoce(
        self, tmp_path, name, text
    ):
        # Un .txt, un .log o un .csv no tienen magic ninguno: lo que los
        # identifica es que TODO lo que hay dentro es texto.
        path = tmp_path / name
        path.write_bytes(text.encode("utf-8"))
        record = fingerprint_evidence(path)
        assert record.kind == "document"
        assert "text_utf8" in record.signals

    def test_un_log_en_latin_1_tambien_es_texto(self, tmp_path):
        # Lo que exporta media herramienta de Windows en español. No decodifica
        # como UTF-8, pero es texto y hay que reconocerlo como tal.
        path = tmp_path / "sistema.log"
        path.write_bytes("Sesión iniciada por josé\n".encode("latin-1") * 60)
        record = fingerprint_evidence(path)
        assert record.kind == "document"
        assert "text_8bit" in record.signals

    def test_la_extension_no_manda_sobre_el_contenido(self, tmp_path):
        # Una foto renombrada a .txt sigue siendo un JPEG. Es exactamente lo que
        # hace quien esconde algo, y el triage lee bytes, no nombres.
        path = tmp_path / "inocente.txt"
        path.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 500)
        record = fingerprint_evidence(path)
        assert record.kind == "document"
        assert "jpeg" in record.signals

    def test_un_ejecutable_de_windows_necesita_las_dos_condiciones(self, tmp_path):
        # ``MZ`` suelto son dos bytes corrientes: hace falta además la cabecera
        # ``PE\0\0`` en el offset que el propio fichero declara.
        pe = bytearray(b"MZ" + b"\x00" * 62 + b"PE\x00\x00" + b"\x00" * 200)
        pe[60:64] = (64).to_bytes(4, "little")
        real = tmp_path / "muestra.exe"
        real.write_bytes(bytes(pe))
        assert "pe_executable" in fingerprint_evidence(real).signals

        falso = tmp_path / "falso.bin"
        falso.write_bytes(b"MZ" + b"\x00" * 4000)
        assert "pe_executable" not in fingerprint_evidence(falso).signals


# ── 2 · Un documento NUNCA enruta el caso ────────────────────────────────────


class TestUnDocumentoNoDeterminaElSistemaOperativo:
    def test_un_pdf_lleno_de_cadenas_de_windows_no_enruta(self, tmp_path):
        # El corazón del asunto. Este PDF nombra Windows por todas partes, que es
        # lo normal en un informe pericial sobre un incidente de Windows. Si esas
        # cadenas puntuasen, el DOCUMENTO fijaría el perfil del caso.
        marcadores = (
            b"Microsoft Windows\n\\Windows\\System32\n\\Program Files\n"
            b"NTUSER.DAT\nSOFTWARE\\Microsoft\nSYSTEM\\CurrentControlSet\n"
            b"\\Users\\Default\nWindows NT\nBOOTMGR\n"
        )
        path = tmp_path / "informe.pdf"
        path.write_bytes(b"%PDF-1.7\n" + marcadores * 20)

        record = fingerprint_evidence(path)
        assert record.kind == "document"
        assert record.family == "unknown"
        assert routable_profile(record) is None

    def test_un_log_de_linux_tampoco_enruta(self, tmp_path):
        path = tmp_path / "auth.log"
        path.write_text(
            "Linux version 5.15\n/etc/passwd\n/etc/shadow\n/bin/bash\n"
            "/usr/bin/sudo\n/var/log/auth.log\n/sbin/init\n" * 30,
            encoding="utf-8",
        )
        record = fingerprint_evidence(path)
        assert record.kind == "document"
        assert record.family == "unknown"
        assert routable_profile(record) is None

    def test_un_registro_construido_a_mano_tampoco_cuela(self):
        # ``fingerprint_evidence`` ya devuelve family=unknown para un documento y
        # con eso bastaría. Esta comprobación es la que hace que siga siendo
        # verdad si alguien construye el registro por otra vía: un test, una
        # migración, un backfill de baseline.json.
        forzado = DetectedEvidence("windows", "document", "header", ("pdf",))
        assert routable_profile(forzado) is None

    def test_un_documento_no_estropea_el_perfil_que_fijo_una_imagen(
        self, manager: EvidenceManager, cases: CaseManager, case, tmp_path
    ):
        # El escenario real: un disco Windows y, además, el PDF del contrato. El
        # perfil lo fija el DISCO, y registrar el documento después no lo mueve
        # ni lo pone en conflicto (que dejaría el caso sin enrutar, o sea sin
        # agente).
        disco = tmp_path / "equipo.raw"
        marcadores = (
            b"Microsoft Windows\n\\Windows\\System32\n\\Program Files\n"
            b"NTUSER.DAT\nSOFTWARE\\Microsoft\nSYSTEM\\CurrentControlSet\n"
        )
        mbr = bytearray(b"\x00" * 512)
        mbr[446 + 4] = 0x07  # tipo de partición NTFS
        mbr[446 + 8 : 446 + 12] = (2048).to_bytes(4, "little")
        mbr[446 + 12 : 446 + 16] = (4096).to_bytes(4, "little")
        mbr[510:512] = b"\x55\xaa"
        disco.write_bytes(bytes(mbr) + marcadores * 40)
        manager.register(case.id, str(disco))
        assert cases.load(case.id).os_profile == "windows"

        doc = tmp_path / "contrato.pdf"
        doc.write_bytes(b"%PDF-1.7\n" + b"/etc/passwd\n/bin/bash\n/usr/bin/\n" * 40)
        manager.register(case.id, str(doc))

        despues = cases.load(case.id)
        assert despues.os_profile == "windows"
        assert despues.os_profile_source == "derived"


# ── 3 · La bandeja y el registro ─────────────────────────────────────────────


class TestBandejaDeMaterialAportado:
    @pytest.fixture
    def inbox(self, tmp_path, monkeypatch):
        root = tmp_path / "inbox"
        root.mkdir()
        monkeypatch.setenv("AGENTOPSY_EVIDENCE_DIR", str(root))
        return root

    @pytest.mark.parametrize(
        "name",
        [
            "contrato.pdf",
            "carta.docx",
            "cuentas.xlsx",
            "foto.jpg",
            "captura.png",
            "mensaje.eml",
            "eventos.evtx",
            "red.pcap",
            "entrega.zip",
            "muestra.exe",
            "notas.txt",
            "acceso.log",
            "syslog",
        ],
    )
    def test_el_material_aportado_se_sube_y_se_registra(self, inbox, name):
        assert is_uploadable_evidence_ext("." + name.split(".")[-1] if "." in name else "")
        assert is_registrable_evidence_ext("." + name.split(".")[-1] if "." in name else "")
        entry = save_uploaded_source(name, io.BytesIO(b"contenido"))
        assert (inbox / name).read_bytes() == b"contenido"
        assert entry["name"] == name

    def test_un_documento_recorre_el_hash_gate_como_una_imagen(
        self, manager: EvidenceManager, cases: CaseManager, case, tmp_path
    ):
        # Cadena de custodia idéntica: hash baseline, copia inmutable en el
        # directorio del caso, y el evento en el log encadenado. Un documento no
        # es evidencia de segunda.
        src = tmp_path / "contrato.pdf"
        payload = b"%PDF-1.7\nclausula de confidencialidad\n"
        src.write_bytes(payload)

        handle = manager.register(case.id, str(src))

        assert handle.detected_kind == "document"
        assert handle.original_path.read_bytes() == payload
        assert handle.original_path.parent != src.parent
        assert manager.verify(case.id, handle.evidence_id) is True

        audit = (cases.case_dir(case.id) / "audit.jsonl").read_text(encoding="utf-8")
        eventos = [json.loads(line) for line in audit.splitlines() if line.strip()]
        registro = [e for e in eventos if e.get("action") == "evidence_register"]
        assert len(registro) == 1
        assert registro[0]["sha256"] == handle.sha256

    def test_el_pase_profundo_no_abre_un_documento(
        self, manager: EvidenceManager, cases: CaseManager, case, tmp_path, monkeypatch
    ):
        # El pase profundo abre imágenes de disco por el maletín con ``mmls``. Un
        # PDF no tiene tabla de particiones: llamar ahí sería gastar una ida y
        # vuelta al maletín para que TSK falle.
        import agentopsy.evidence as evidence_mod

        def _nunca(*args, **kwargs):
            raise AssertionError("el pase profundo no debe tocar un documento")

        monkeypatch.setattr(evidence_mod, "deepen_triage", _nunca)
        src = tmp_path / "foto.png"
        src.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 500)
        assert manager.register(case.id, str(src)).detected_kind == "document"


# ── 4 · Cómo se nombra en el informe ─────────────────────────────────────────


class TestNaturalezaEnElInforme:
    @pytest.mark.parametrize(
        ("name", "esperado"),
        [
            ("original.pdf", "documento PDF"),
            ("original.docx", "documento de texto"),
            ("original.xlsx", "hoja de cálculo"),
            ("original.jpg", "imagen fotográfica"),
            ("original.eml", "mensaje de correo electrónico"),
            ("original.evtx", "registro de eventos de Windows"),
            ("original.pcap", "captura de tráfico de red"),
            ("original.exe", "ejecutable de Windows"),
            ("original.qqq", "fichero aportado"),
        ],
    )
    def test_un_informe_escribe_la_naturaleza_en_castellano(
        self, tmp_path, name, esperado
    ):
        # Un informe pericial dice «documento PDF», no «document». Y lo que no se
        # reconoce se queda en la categoría general: no se adivina (RULE 2).
        # La naturaleza se escribe en el idioma del INFORME, así que el caso
        # castellano se comprueba fijando esa lengua.
        class _Handle:
            detected_kind = "document"
            original_path = tmp_path / name

        token = set_current_lang("es")
        try:
            assert naturaleza(_Handle()) == esperado
        finally:
            _LANG_ACTUAL.reset(token)
