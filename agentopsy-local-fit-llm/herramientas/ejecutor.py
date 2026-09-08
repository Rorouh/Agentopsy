"""Ejecuta una herramienta forense con toda la custodia alrededor.

    argv literal → run abierto → `tool_run_start` en la cadena → POST /exec en el
    maletín → salida cruda persistida y hasheada → `tool_run_finish` (cierra la
    cadena, RC-7) → resumen acotado para el modelo.

El modelo nunca ve la ruta de la evidencia ni la de salida: se inyectan aquí.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from artefactos.almacen import Almacen, Manifiesto
from configuracion import Ajustes, ajustes
from custodia.ingesta import Evidencia
from custodia.registro import Registro
from herramientas.forenses import Herramienta, ParametrosInvalidos, resolver
from maletin import Maletin, MaletinError
import trazas

TOPE_LINEAS_RESUMEN = 25
TOPE_CHARS_RESUMEN = 1600
TOPE_CHARS_STDERR = 500


@dataclass
class Resultado:
    tool_id: str
    run_id: str | None
    argv: list[str] | None
    estado: str              # ok | nonzero | error | refused
    exit_code: int | None
    resumen: str             # lo que ve el modelo
    detalle: dict[str, Any]  # lo que ve el operador (evento tool_result)


class Ejecutor:
    def __init__(
        self,
        *,
        case_id: str,
        dir_caso: Path,
        evidencia: Evidencia,
        perfil: str,
        cfg: Ajustes = ajustes,
        maletin: Maletin | None = None,
        agente: str = "investigador",
    ) -> None:
        self.case_id = case_id
        self.dir_caso = Path(dir_caso)
        self.evidencia = evidencia
        self.perfil = perfil
        self._cfg = cfg
        self.maletin = maletin or Maletin(cfg.url_maletin(perfil), cfg.token_maletin)
        self.almacen = Almacen(self.dir_caso)
        self.registro = Registro(self.dir_caso / "audit.jsonl")
        self.agente = agente
        self._versiones: dict[str, str] | None = None
        self._versiones_preguntadas: dict[str, str] = {}

    # -- versiones reales (RC-3) ---------------------------------------------------
    def version(self, binario: str) -> str:
        if self._versiones is None:
            self._versiones = self.maletin.versiones()
        v = self._versiones.get(binario)
        if v:
            return v
        # El manifiesto del maletín solo cubre las herramientas del catálogo, y la
        # terminal usa un binario del sistema (`bash`). RC-3 pide la versión REAL, no
        # que esté en una lista: se le pregunta al propio binario, una vez por corrida,
        # y esa cadena es la que queda en el registro.
        preguntada = self._versiones_preguntadas.get(binario)
        if preguntada:
            return preguntada
        try:
            resp = self.maletin.ejecutar([binario, "--version"], timeout=30)
        except MaletinError as exc:
            raise MaletinError(
                f"no se pudo obtener la versión de {binario!r} en el maletín "
                f"{self.maletin.base_url}: {exc}; sin versión real no hay registro (RC-3)"
            ) from exc
        linea = (str(resp.get("stdout") or "").strip().splitlines() or [""])[0].strip()
        if resp.get("exit") != 0 or not linea:
            raise MaletinError(
                f"el binario {binario!r} no respondió a --version en el maletín "
                f"{self.maletin.base_url}; sin versión real no hay registro de custodia (RC-3)"
            )
        self._versiones_preguntadas[binario] = linea
        return linea

    # -- ejecución -------------------------------------------------------------------
    @trazas.trazable(name="herramienta forense", run_type="tool")
    def ejecutar(self, tool_id: str, params: dict[str, Any] | None) -> Resultado:
        params = dict(params or {})
        try:
            h = resolver(tool_id, permitir_shell=self._cfg.shell)
        except KeyError as exc:
            return Resultado(tool_id, None, None, "refused", None, f"RECHAZADA: {exc}", {"reason": str(exc)})
        if self.evidencia.kind not in h.kinds:
            motivo = (f"{tool_id} no aplica a evidencia de tipo {self.evidencia.kind!r} "
                      f"(aplica a {', '.join(h.kinds)})")
            return Resultado(tool_id, None, None, "refused", None, f"RECHAZADA: {motivo}", {"reason": motivo})

        # Rutas: las pone el sistema, en la vista del maletín (RC-6).
        run_placeholder = "__RUN__"
        try:
            argv_plantilla = h.construir(
                params, self.evidencia.ruta_maletin,
                self._cfg.a_ruta_maletin(self.almacen.raiz / run_placeholder / "out"),
                self._cfg.a_ruta_maletin(self.almacen.raiz),
            )
        except ParametrosInvalidos as exc:
            motivo = f"parámetros inválidos para {tool_id}: {exc}"
            return Resultado(tool_id, None, None, "refused", None, f"RECHAZADA: {motivo}", {"reason": motivo})

        try:
            version = self.version(h.binario)
        except MaletinError as exc:
            return Resultado(tool_id, None, None, "error", None, f"ERROR: {exc}", {"reason": str(exc)})

        # Abrimos el run para conocer su id y fijar el argv literal con las rutas reales.
        m = self.almacen.abrir(
            self.case_id, self.evidencia.evidence_id, tool_id, argv_plantilla,
            baseline_sha256=self.evidencia.sha256, tool_version=version, agente=self.agente,
        )
        argv = [a.replace(run_placeholder, m.run_id) for a in argv_plantilla]
        m.argv = argv
        stdout_path = None
        if h.stdout_a_fichero:
            stdout_path = self._cfg.a_ruta_maletin(self.almacen.ruta_stdout(m.run_id))

        self.registro.anotar({
            "action": "tool_run_start",
            "case_id": self.case_id,
            "evidence_id": self.evidencia.evidence_id,
            "baseline_sha256": self.evidencia.sha256,
            "run_id": m.run_id,
            "tool_id": tool_id,
            "tool_version": version,
            "argv": argv,
            "params": _params_auditables(params),
            "maletin": self.maletin.base_url,
            "agent": self.agente,
            "engine": "local-fit-llm",
        })

        try:
            resp = self.maletin.ejecutar(argv, timeout=self._cfg.timeout_herramienta, stdout_path=stdout_path)
        except MaletinError as exc:
            self.almacen.fallar(m, "MaletinError", str(exc))
            self.registro.anotar({
                "action": "tool_run_finish", "case_id": self.case_id, "run_id": m.run_id,
                "tool_id": tool_id, "status": "error", "error": str(exc), "engine": "local-fit-llm",
            })
            return Resultado(tool_id, m.run_id, argv, "error", None, f"ERROR de ejecución: {exc}", {"reason": str(exc)})

        exit_code = int(resp.get("exit", -1))
        stderr = str(resp.get("stderr") or "")
        stdout_texto = None if stdout_path is not None else str(resp.get("stdout") or "")
        m = self.almacen.cerrar(m, exit_code=exit_code, timed_out=bool(resp.get("timed_out")),
                                stdout_texto=stdout_texto, stderr_texto=stderr)
        if stdout_path is not None and resp.get("stdout_sha256") and resp["stdout_sha256"] != m.stdout_sha256:
            self.almacen.fallar(m, "HashMismatch", "el hash del stdout no coincide con el que declaró el maletín")
            motivo = "el stdout que dejó el maletín no coincide con su hash declarado"
            self.registro.anotar({
                "action": "tool_run_finish", "case_id": self.case_id, "run_id": m.run_id,
                "tool_id": tool_id, "status": "error", "error": motivo, "engine": "local-fit-llm",
            })
            return Resultado(tool_id, m.run_id, argv, "error", exit_code, f"ERROR: {motivo}", {"reason": motivo})

        # RC-3/RC-4: se cierra la cadena en el instante en que la herramienta termina.
        self.registro.anotar({
            "action": "tool_run_finish",
            "case_id": self.case_id,
            "evidence_id": self.evidencia.evidence_id,
            "baseline_sha256": self.evidencia.sha256,
            "run_id": m.run_id,
            "tool_id": tool_id,
            "tool_version": version,
            "exit_code": exit_code,
            "timed_out": m.timed_out,
            "status": m.status,
            "stdout_sha256": m.stdout_sha256,
            "stderr_sha256": m.stderr_sha256,
            "stdout_size": m.stdout_size,
            "output_files_count": len(m.output_files),
            "output_files": [{"relpath": f["relpath"], "sha256": f["sha256"], "size": f["size"]} for f in m.output_files],
            "engine": "local-fit-llm",
        })

        resumen = self.resumir(h, m, stderr)
        estado = "ok" if exit_code == 0 else "nonzero"
        return Resultado(tool_id, m.run_id, argv, estado, exit_code, resumen, {
            "exit_code": exit_code, "stdout_lines": m.stdout_lines, "stdout_size": m.stdout_size,
            "output_files": len(m.output_files), "timed_out": m.timed_out,
        })

    # -- resumen acotado -------------------------------------------------------------
    def resumir(self, h: Herramienta, m: Manifiesto, stderr: str) -> str:
        partes = [f"{h.id} → exit {m.exit_code}, run_id {m.run_id}, stdout {m.stdout_lines} líneas / {m.stdout_size} bytes"]
        if m.exit_code != 0:
            pista = h.pista(stderr, m.exit_code or 0)
            if pista:
                partes.append(f"PISTA: {pista}")
        if stderr.strip():
            partes.append("stderr: " + _recortar(stderr.strip(), TOPE_CHARS_STDERR))
        if m.output_files:
            partes.append("ficheros en out/: " + ", ".join(
                f"{f['relpath']} ({f['size']} B)" for f in m.output_files[:30]
            ) + (" …" if len(m.output_files) > 30 else ""))
            partes.append(self._resumen_bulk(m) if h.id == "bulk_extractor" else "")
        cabeza = self._cabeza_stdout(m)
        if cabeza:
            partes.append("stdout (inicio):\n" + cabeza)
        if (m.stdout_lines or 0) > TOPE_LINEAS_RESUMEN:
            partes.append(f"(hay {m.stdout_lines} líneas; leer_artefacto('{m.run_id}', desde, n) o buscar('texto') para el resto)")
        return "\n".join(p for p in partes if p)

    def _cabeza_stdout(self, m: Manifiesto) -> str:
        ruta = self.almacen.ruta_stdout(m.run_id)
        if not ruta.is_file() or (m.stdout_size or 0) == 0:
            return ""
        if m.tool_id == "volatility3":
            return _resumen_vol(ruta)
        lineas: list[str] = []
        usados = 0
        with ruta.open("r", encoding="utf-8", errors="replace") as fh:
            for linea in fh:
                linea = linea.rstrip("\n")
                if len(linea) > 160:
                    linea = linea[:160] + "…"
                if len(lineas) >= TOPE_LINEAS_RESUMEN or usados + len(linea) > TOPE_CHARS_RESUMEN:
                    break
                lineas.append(linea)
                usados += len(linea) + 1
        return "\n".join(lineas)

    def _resumen_bulk(self, m: Manifiesto) -> str:
        """bulk_extractor: cuántas features por fichero y las 5 más frecuentes de cada histograma."""
        out = self.almacen.ruta_out(m.run_id)
        lineas = []
        for f in m.output_files:
            rel = f["relpath"]
            if not rel.endswith("_histogram.txt") or f["size"] == 0:
                continue
            top = []
            with (out / rel).open("r", encoding="utf-8", errors="replace") as fh:
                for linea in fh:
                    if linea.startswith("#") or not linea.strip():
                        continue
                    top.append(linea.strip()[:100])
                    if len(top) >= 5:
                        break
            lineas.append(f"{rel}: " + " | ".join(top))
        return "\n".join(lineas[:8])


def _resumen_vol(ruta: Path) -> str:
    """Volatility -r json: nº de filas, columnas y unas pocas filas, nunca el array entero."""
    try:
        texto = ruta.read_text(encoding="utf-8", errors="replace")
        filas = json.loads(texto)
    except ValueError:
        return _recortar(ruta.read_text(encoding="utf-8", errors="replace"), TOPE_CHARS_RESUMEN)
    if not isinstance(filas, list):
        return _recortar(json.dumps(filas)[:TOPE_CHARS_RESUMEN], TOPE_CHARS_RESUMEN)
    columnas = sorted(filas[0].keys()) if filas and isinstance(filas[0], dict) else []
    muestra = [json.dumps(f, ensure_ascii=False)[:200] for f in filas[:8]]
    return f"{len(filas)} filas; columnas {columnas}\n" + "\n".join(muestra)


def _recortar(texto: str, tope: int) -> str:
    return texto if len(texto) <= tope else texto[:tope] + "…"


def _params_auditables(params: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in params.items() if isinstance(v, (str, int, float, bool, list, dict))}
