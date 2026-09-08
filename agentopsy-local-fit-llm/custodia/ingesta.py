"""Ingesta de evidencia (RC-1, RC-2) y resolución de la evidencia de un caso.

Orden obligatorio: hash SHA-256 por bloques del fichero **antes** de que nada
lo lea, `baseline.json` con el hash, evento `evidence_register` en la cadena,
y solo entonces la evidencia existe para el motor.

Solo lectura (RC-2): la evidencia se queda en la bandeja, que el maletín y este
servicio montan `:ro` en el compose. Además se intenta `chmod 0444` (nivel
«fs», el mismo que declara el api). No se copia: copiar un volcado de 1 GB
duplica disco y tiempo sin añadir custodia.

Compatibilidad: una evidencia registrada por el api (que sí copia a
`evidence/<id>/original.<ext>`) se resuelve igual, leyendo su `baseline.json`.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from casos import KINDS, PERFILES, Casos, ahora_iso_ms, casos
from configuracion import Ajustes, ajustes
from custodia.registro import Registro, sha256_fichero
from custodia.rutas import confinar


@dataclass(frozen=True)
class Evidencia:
    evidence_id: str
    case_id: str
    ruta_local: Path        # cómo la ve este proceso
    ruta_maletin: str       # cómo la ve el maletín (la que va en el argv)
    sha256: str
    tamano: int
    kind: str
    nombre: str
    registrada_en: str

    def puntero(self) -> dict[str, Any]:
        """Referencia, no contenido: lo que entra en el prompt."""
        return {
            "evidence_id": self.evidence_id,
            "nombre": self.nombre,
            "kind": self.kind,
            "tamano_mb": round(self.tamano / (1024 * 1024), 1),
            "sha256": self.sha256[:16] + "…",
        }


class Ingesta:
    def __init__(self, cfg: Ajustes = ajustes, cs: Casos = casos) -> None:
        self._cfg = cfg
        self._casos = cs

    def registrar(
        self,
        case_id: str,
        origen: str,
        kind: str,
        os_profile: str | None = None,
    ) -> Evidencia:
        """Registra `origen` (nombre de fichero dentro de la bandeja o ruta bajo ella)."""
        if kind not in KINDS:
            raise ValueError(f"kind inválido: {kind!r} (uno de {list(KINDS)})")
        dir_caso = self._casos.dir_caso(case_id)
        bandeja = self._cfg.dir_evidencias
        candidata = Path(origen) if os.path.isabs(origen) else bandeja / origen
        ruta = confinar(candidata, bandeja)
        if not ruta.is_file():
            raise FileNotFoundError(f"no existe la evidencia {ruta} en la bandeja {bandeja}")

        # RC-1: el hash se calcula ANTES de que ningún componente lea la evidencia.
        sha, tamano = sha256_fichero(ruta)

        # RC-2: solo lectura a nivel fs (best-effort: el montaje :ro es la garantía real).
        nivel = "fs"
        try:
            os.chmod(ruta, 0o444)
        except OSError:
            nivel = "mount"

        evidence_id = str(uuid.uuid4())
        dir_ev = dir_caso / "evidence" / evidence_id
        dir_ev.mkdir(parents=True, exist_ok=False)
        registrada = ahora_iso_ms()
        ruta_maletin = self._cfg.a_ruta_maletin(ruta)
        baseline = {
            "sha256": sha,
            "size": tamano,
            "original_basename": ruta.name,
            "source_path": ruta_maletin,
            "path_maletin": ruta_maletin,
            "detected_kind": kind,
            "detected_os": os_profile,
            "registered_at": registrada,
            "read_only_level": nivel,
            "ingested_by": "local-fit-llm",
        }
        (dir_ev / "baseline.json").write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")

        if os_profile is not None:
            if os_profile not in PERFILES:
                raise ValueError(f"os_profile inválido: {os_profile!r}")
            self._casos.fijar_perfil(case_id, os_profile, origen="operator")

        Registro(self._casos.ruta_registro(case_id)).anotar({
            "action": "evidence_register",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "sha256": sha,
            "size": tamano,
            "source_path": ruta_maletin,
            "original_basename": ruta.name,
            "detected_kind": kind,
            "detected_os": os_profile,
            "read_only_level": nivel,
            "engine": "local-fit-llm",
        })
        return self.obtener(case_id, evidence_id)

    def obtener(self, case_id: str, evidence_id: str) -> Evidencia:
        dir_caso = self._casos.dir_caso(case_id)
        if not isinstance(evidence_id, str) or "/" in evidence_id or ".." in evidence_id:
            raise ValueError(f"evidence_id inválido: {evidence_id!r}")
        dir_ev = dir_caso / "evidence" / evidence_id
        fichero = dir_ev / "baseline.json"
        if not fichero.is_file():
            raise KeyError(f"evidencia desconocida en el caso {case_id}: {evidence_id}")
        base = json.loads(fichero.read_text(encoding="utf-8"))
        # Evidencia copiada por el api: original.<ext> junto al baseline.
        copias = [p for p in dir_ev.iterdir() if p.name.startswith("original.")]
        if copias:
            ruta_local = copias[0]
            ruta_maletin = self._cfg.a_ruta_maletin(ruta_local)
        else:
            ruta_maletin = base.get("path_maletin") or base.get("source_path")
            if not ruta_maletin:
                raise KeyError(f"baseline.json de {evidence_id} no dice dónde está la evidencia")
            ruta_local = self._cfg.de_ruta_maletin(ruta_maletin)
        return Evidencia(
            evidence_id=evidence_id,
            case_id=case_id,
            ruta_local=ruta_local,
            ruta_maletin=ruta_maletin,
            sha256=base["sha256"],
            tamano=int(base.get("size") or 0),
            kind=base.get("detected_kind") or "unknown",
            nombre=base.get("original_basename") or ruta_local.name,
            registrada_en=base.get("registered_at") or "",
        )

    def listar(self, case_id: str) -> list[Evidencia]:
        dir_caso = self._casos.dir_caso(case_id)
        raiz = dir_caso / "evidence"
        if not raiz.is_dir():
            return []
        salida = []
        for hijo in sorted(raiz.iterdir()):
            if (hijo / "baseline.json").is_file():
                try:
                    salida.append(self.obtener(case_id, hijo.name))
                except (KeyError, ValueError):
                    continue
        return salida

    def verificar(self, case_id: str, evidence_id: str) -> dict[str, Any]:
        """Re-hash contra el baseline (comprobación de integridad). Se anota en la cadena."""
        ev = self.obtener(case_id, evidence_id)
        sha, tamano = sha256_fichero(ev.ruta_local)
        ok = sha == ev.sha256 and tamano == ev.tamano
        Registro(self._casos.ruta_registro(case_id)).anotar({
            "action": "evidence_verify",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "baseline_sha256": ev.sha256,
            "sha256": sha,
            "ok": ok,
            "engine": "local-fit-llm",
        })
        return {"ok": ok, "sha256": sha, "baseline_sha256": ev.sha256, "size": tamano}


ingesta = Ingesta()
