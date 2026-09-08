"""Cliente HTTP del maletín (`exec_agent.py`): /health, /versions, /which, /exec.

Los maletines no se tocan (RE-3): este cliente habla el contrato que ya
exponen. Toda respuesta de /exec trae `executed_argv`; se compara token a token
con el argv pedido, como hace el api: un maletín que ejecutara otra cosa
rompería la cadena (FORENSIC INVARIANT 4) y aquí se detecta.

Solo stdlib (urllib): cero dependencias para hablar con el maletín.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

# Techo del exec-agent (`_MAX_TIMEOUT_S`). Esperamos siempre más que él para que sea
# el maletín quien mate al hijo, hashee y responda: nunca el cliente antes.
TECHO_MALETIN_S = 1800.0
MARGEN_HTTP_S = 30.0
TIMEOUT_SONDA_S = 5.0


class MaletinError(RuntimeError):
    """El maletín no está, no responde o devolvió algo que no es un resultado."""


class Maletin:
    def __init__(self, base_url: str, token: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token

    def _peticion(self, metodo: str, ruta: str, cuerpo: dict | None, timeout: float) -> tuple[int, Any]:
        datos = None
        cabeceras = {"Accept": "application/json"}
        if cuerpo is not None:
            datos = json.dumps(cuerpo).encode("utf-8")
            cabeceras["Content-Type"] = "application/json"
        if self._token:
            cabeceras["X-Agentopsy-Exec-Token"] = self._token
        req = urllib.request.Request(self.base_url + ruta, data=datos, method=metodo, headers=cabeceras)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8") or "null")
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read().decode("utf-8") or "null")
            except ValueError:
                return exc.code, {"error": f"HTTP {exc.code}"}
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise MaletinError(f"no se pudo hablar con el maletín {self.base_url}{ruta}: {exc}") from exc

    def salud(self) -> dict[str, Any]:
        estado, cuerpo = self._peticion("GET", "/health", None, TIMEOUT_SONDA_S)
        if estado != 200 or not isinstance(cuerpo, dict) or not cuerpo.get("ok"):
            raise MaletinError(f"maletín {self.base_url} no sano: HTTP {estado} {cuerpo}")
        return cuerpo

    def versiones(self) -> dict[str, str]:
        estado, cuerpo = self._peticion("GET", "/versions", None, TIMEOUT_SONDA_S)
        if estado != 200 or not isinstance(cuerpo, dict) or not isinstance(cuerpo.get("versions"), dict):
            detalle = cuerpo.get("error") if isinstance(cuerpo, dict) else cuerpo
            raise MaletinError(f"el maletín {self.base_url} no sirve su manifiesto de versiones: {detalle}")
        return {str(k): str(v) for k, v in cuerpo["versions"].items()}

    def presentes(self, binarios: list[str]) -> set[str]:
        estado, cuerpo = self._peticion("POST", "/which", {"binaries": binarios}, TIMEOUT_SONDA_S)
        if estado != 200 or not isinstance(cuerpo, dict):
            raise MaletinError(f"/which falló en {self.base_url}: HTTP {estado} {cuerpo}")
        return set(cuerpo.get("present") or [])

    def ejecutar(
        self,
        argv: list[str],
        *,
        timeout: float | None,
        stdout_path: str | None = None,
    ) -> dict[str, Any]:
        """POST /exec. Devuelve el dict del exec-agent (exit, stdout|stdout_file, stderr,
        timed_out, executed_argv). Con `stdout_path` el stdout va crudo a ese fichero
        (canal binario-seguro) y el maletín responde con su SHA-256 y tamaño."""
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            raise MaletinError("argv debe ser una lista de cadenas no vacía")
        efectivo = TECHO_MALETIN_S if timeout is None else min(float(timeout), TECHO_MALETIN_S)
        cuerpo: dict[str, Any] = {"argv": argv, "timeout": timeout}
        if stdout_path is not None:
            cuerpo["stdout_path"] = stdout_path
        estado, resp = self._peticion("POST", "/exec", cuerpo, efectivo + MARGEN_HTTP_S)
        if estado != 200 or not isinstance(resp, dict) or "exit" not in resp:
            detalle = resp.get("error") if isinstance(resp, dict) else resp
            raise MaletinError(f"/exec en {self.base_url} respondió HTTP {estado}: {detalle}")
        ejecutado = resp.get("executed_argv")
        if ejecutado != argv:
            raise MaletinError(
                f"el maletín {self.base_url} ejecutó un argv distinto del auditado: "
                f"pedido={argv!r} ejecutado={ejecutado!r}"
            )
        return resp
