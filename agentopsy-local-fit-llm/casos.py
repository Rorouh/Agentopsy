"""Casos: el mismo directorio por caso que usa el api, para que la web vea lo mismo
hable con el backend que hable.

    <AGENTOPSY_HOME>/cases/<case_id>/
        case.json          identidad del caso (formato del api)
        evidence/<id>/     baseline.json (+ original.* si lo copió el api)
        audit.jsonl        registro encadenado (custodia/registro.py)
        findings.jsonl     hallazgos (formato del api)
        artifacts/<run>/   salida cruda de cada ejecución
        chats/<sesion>.jsonl
        agente/<sesion>/   estado del agente: tareas, pasos, rondas

Este módulo solo sabe de `case.json` y de resolver rutas. No hay «caso por
defecto»: quien no da un `case_id` válido recibe un KeyError con el motivo.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from configuracion import Ajustes, ajustes

_ID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")
_SESION_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
PERFILES = ("unix", "windows")
KINDS = ("memory", "disk", "container", "document")


def ahora_iso_ms() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def validar_id(case_id: str) -> str:
    if not isinstance(case_id, str) or not _ID_RE.match(case_id):
        raise ValueError(f"case_id inválido: {case_id!r} (se espera un UUID)")
    return case_id


def validar_sesion(sesion: str) -> str:
    if not isinstance(sesion, str) or not _SESION_RE.match(sesion):
        raise ValueError(f"session_id inválido: {sesion!r}")
    return sesion


class Casos:
    def __init__(self, cfg: Ajustes = ajustes) -> None:
        self._cfg = cfg

    @property
    def raiz(self) -> Path:
        return self._cfg.dir_casos

    def dir_caso(self, case_id: str) -> Path:
        validar_id(case_id)
        ruta = self.raiz / case_id
        if not (ruta / "case.json").is_file():
            raise KeyError(f"caso desconocido: {case_id} (no existe {ruta / 'case.json'})")
        return ruta

    def cargar(self, case_id: str) -> dict[str, Any]:
        return json.loads((self.dir_caso(case_id) / "case.json").read_text(encoding="utf-8"))

    def listar(self) -> list[dict[str, Any]]:
        if not self.raiz.is_dir():
            return []
        salida = []
        for hijo in sorted(self.raiz.iterdir()):
            fichero = hijo / "case.json"
            if fichero.is_file():
                try:
                    salida.append(json.loads(fichero.read_text(encoding="utf-8")))
                except (OSError, ValueError):
                    continue
        return salida

    def crear(self, nombre: str, perito: str, notas: str = "") -> dict[str, Any]:
        nombre = (nombre or "").strip()
        perito = (perito or "").strip()
        if not nombre:
            raise ValueError("el caso necesita un nombre")
        if not perito:
            raise ValueError("el caso necesita el nombre del perito (examiner)")
        case_id = str(uuid.uuid4())
        ruta = self.raiz / case_id
        for sub in ("evidence", "artifacts", "chats", "documents", "graphs", "reports", "agente"):
            (ruta / sub).mkdir(parents=True, exist_ok=True)
        caso = {
            "id": case_id,
            "name": nombre,
            "examiner": perito,
            "created_at": ahora_iso_ms(),
            "os_profile": None,
            "os_profile_source": None,
            "status": "active",
            "notes": notas or "",
        }
        (ruta / "case.json").write_text(json.dumps(caso, indent=2, sort_keys=True), encoding="utf-8")
        return caso

    def fijar_perfil(self, case_id: str, perfil: str, origen: str = "operator") -> dict[str, Any]:
        if perfil not in PERFILES:
            raise ValueError(f"os_profile inválido: {perfil!r} (unix | windows)")
        caso = self.cargar(case_id)
        caso["os_profile"] = perfil
        caso["os_profile_source"] = origen
        (self.dir_caso(case_id) / "case.json").write_text(
            json.dumps(caso, indent=2, sort_keys=True), encoding="utf-8"
        )
        return caso

    def perfil(self, case_id: str) -> str:
        """El maletín que atiende al caso. Sin perfil no hay maletín: se pide al
        operador que lo ancle, nunca se adivina."""
        caso = self.cargar(case_id)
        perfil = caso.get("os_profile")
        if perfil not in PERFILES:
            raise ValueError(
                f"el caso {case_id} no tiene os_profile anclado; fíjalo (unix | windows) "
                "con POST /api-local/cases/{id}/os-profile o al ingestar la evidencia"
            )
        return perfil

    # -- subdirectorios --------------------------------------------------------------
    def dir_agente(self, case_id: str, sesion: str) -> Path:
        ruta = self.dir_caso(case_id) / "agente" / validar_sesion(sesion)
        ruta.mkdir(parents=True, exist_ok=True)
        return ruta

    def ruta_registro(self, case_id: str) -> Path:
        return self.dir_caso(case_id) / "audit.jsonl"


casos = Casos()
