"""Hallazgos: `findings.jsonl` con el mismo esquema que `backend/agentopsy/findings`,
para que la vista de Hallazgos de la web los pinte vengan del motor que vengan.

Regla anti-alucinación heredada: un hallazgo afirmativo exige `run_id` (la
ejecución que lo sostiene) y ese run tiene que existir en el caso; un
`descarte` (una vía que no aportó) queda exento. `mitre_hints` se acepta solo
si hay semilla ATT&CK a mano; sin ella se descarta con aviso, nunca se inventa.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from custodia.registro import Registro

SEVERIDADES = ("low", "medium", "high", "critical")
_TRADUCCION_SEV = {"baja": "low", "media": "medium", "alta": "high", "critica": "critical", "crítica": "critical"}
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{3,4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_TECNICA_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _ahora() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _observado_en(valor: Any) -> str | None:
    if valor is None or valor == "":
        return None
    if not isinstance(valor, str):
        raise ValueError("observed_at debe ser texto ISO-8601 con zona explícita (p. ej. 2015-09-02T12:00:00Z)")
    texto = valor.strip()
    candidato = texto[:-1] + "+00:00" if texto.endswith(("Z", "z")) else texto
    try:
        parsed = datetime.fromisoformat(candidato)
    except ValueError as exc:
        raise ValueError(f"observed_at no es ISO-8601: {texto!r}; usa p. ej. 2015-09-02T12:00:00Z o déjalo vacío") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"observed_at {texto!r} no lleva zona horaria; añade Z u offset, o déjalo vacío")
    return texto


class Hallazgos:
    def __init__(self, dir_caso: Path, case_id: str) -> None:
        self.dir = Path(dir_caso)
        self.case_id = case_id
        self.ruta = self.dir / "findings.jsonl"

    def registrar(self, datos: dict[str, Any], *, evidence_id: str | None, agente: str) -> dict[str, Any]:
        titulo = str(datos.get("titulo") or datos.get("title") or "").strip()
        resumen = str(datos.get("resumen") or datos.get("summary") or datos.get("justificacion") or "").strip()
        sev = str(datos.get("severidad") or datos.get("severity") or "").strip().lower()
        sev = _TRADUCCION_SEV.get(sev, sev)
        if not titulo or len(titulo) > 200:
            raise ValueError("titulo obligatorio (≤ 200 caracteres)")
        if not resumen or len(resumen) > 4000:
            raise ValueError("resumen obligatorio (≤ 4000 caracteres): qué se observó y por qué importa")
        if sev not in SEVERIDADES:
            raise ValueError(f"severidad debe ser una de {list(SEVERIDADES)}")
        kind = str(datos.get("tipo") or datos.get("finding_kind") or "afirmacion").strip().lower()
        if kind not in {"afirmacion", "descarte"}:
            raise ValueError("tipo debe ser 'afirmacion' o 'descarte'")
        run_id = datos.get("run_id")
        if run_id is not None and run_id != "":
            if not isinstance(run_id, str) or not _UUID_RE.match(run_id):
                raise ValueError("run_id debe ser el id de una ejecución de este caso")
            if not (self.dir / "artifacts" / run_id / "manifest.json").is_file():
                raise ValueError(f"run_id {run_id} no corresponde a ninguna ejecución de este caso; usa listar_artefactos()")
        else:
            run_id = None
        if kind == "afirmacion" and not run_id:
            raise ValueError("un hallazgo afirmativo necesita run_id: la ejecución cuya salida lo sostiene")
        tool_id = None
        artifact_sha = None
        if run_id:
            m = json.loads((self.dir / "artifacts" / run_id / "manifest.json").read_text(encoding="utf-8"))
            tool_id = m.get("tool_id")
            artifact_sha = m.get("stdout_sha256")
        confianza = datos.get("confianza", datos.get("confidence"))
        if confianza is not None:
            try:
                confianza = float(confianza)
            except (TypeError, ValueError) as exc:
                raise ValueError("confianza debe ser un número entre 0 y 1") from exc
            if not 0.0 <= confianza <= 1.0:
                raise ValueError("confianza debe estar entre 0 y 1")
        observado = _observado_en(datos.get("observado_en", datos.get("observed_at")))
        tecnicas = datos.get("mitre_hints") or datos.get("tecnicas") or []
        if isinstance(tecnicas, str):
            tecnicas = [t.strip() for t in tecnicas.split(",") if t.strip()]
        tecnicas = [t for t in tecnicas if isinstance(t, str) and _TECNICA_RE.match(t.strip())]

        hallazgo = {
            "id": str(uuid.uuid4()),
            "case_id": self.case_id,
            "title": titulo,
            "summary": resumen,
            "severity": sev,
            "evidence_id": evidence_id,
            "tool_id": tool_id,
            "run_id": run_id,
            "created_at": _ahora(),
            "mitre_hints": tecnicas,
            "confidence": confianza,
            "observed_at": observado,
            "artifact_sha256": artifact_sha,
            "finding_kind": kind,
        }
        with self.ruta.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(hallazgo, sort_keys=True, ensure_ascii=False) + "\n")
        Registro(self.dir / "audit.jsonl").anotar({
            "action": "finding_recorded",
            "case_id": self.case_id,
            "finding_id": hallazgo["id"],
            "run_id": run_id,
            "severity": sev,
            "title": titulo,
            "agent": agente,
            "engine": "local-fit-llm",
        })
        return hallazgo

    def listar(self) -> list[dict[str, Any]]:
        if not self.ruta.is_file():
            return []
        salida = []
        for linea in self.ruta.read_text(encoding="utf-8").splitlines():
            if linea.strip():
                try:
                    salida.append(json.loads(linea))
                except ValueError:
                    continue
        return salida

    def texto_compacto(self, tope: int = 20) -> str:
        filas = self.listar()
        if not filas:
            return "(ninguno)"
        lineas = [f"- [{h['severity']}] {h['title']} (run {str(h.get('run_id') or '')[:8]})" for h in filas[-tope:]]
        if len(filas) > tope:
            lineas.insert(0, f"(… {len(filas) - tope} anteriores)")
        return "\n".join(lineas)
