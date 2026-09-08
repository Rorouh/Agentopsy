"""Dobles de prueba: un modelo con guion y un maletín en proceso.

Sin Ollama y sin contenedores: aquí se prueba el bucle, la custodia y las
herramientas de contexto. El modelo real se mide con `cli.py turno`.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

RAIZ = Path(__file__).resolve().parent.parent
if str(RAIZ) not in sys.path:
    sys.path.insert(0, str(RAIZ))

from configuracion import Ajustes  # noqa: E402
from modelo import Respuesta  # noqa: E402


class MaletinFalso:
    """Ejecuta el argv en este proceso (sin shell) sobre el sistema de ficheros local."""

    base_url = "http://maletin-falso"

    def __init__(self, versiones: dict[str, str] | None = None) -> None:
        self._versiones = versiones or {
            "file": "file 5.x-test", "xxd": "xxd test", "strings": "binutils test",
            "vol": "volatility3 test", "bulk_extractor": "be test", "hashdeep": "hashdeep test",
        }
        self.ejecutados: list[list[str]] = []

    def salud(self) -> dict[str, Any]:
        return {"ok": True, "stage": "test"}

    def versiones(self) -> dict[str, str]:
        return dict(self._versiones)

    def ejecutar(self, argv: list[str], *, timeout: float | None, stdout_path: str | None = None) -> dict[str, Any]:
        import hashlib
        import subprocess

        self.ejecutados.append(list(argv))
        binario = argv[0]
        if binario == "vol":
            # Simula el fallo real por falta de símbolos.
            return {"exit": 1, "stdout": "", "stderr": "Unable to validate the plugin requirements: ['plugins.Info.kernel.layer_name']",
                    "timed_out": False, "executed_argv": list(argv)}
        if binario == "xxd":
            # Volcado hex en proceso: el host de pruebas no tiene xxd.
            n, skip = int(argv[argv.index("-l") + 1]), int(argv[argv.index("-s") + 1])
            with open(argv[-1], "rb") as fh:
                fh.seek(skip)
                datos = fh.read(n)
            lineas = []
            for i in range(0, len(datos), 16):
                trozo = datos[i:i + 16]
                hexs = " ".join(trozo[j:j + 2].hex() for j in range(0, len(trozo), 2))
                asc = "".join(chr(b) if 32 <= b < 127 else "." for b in trozo)
                lineas.append(f"{skip + i:08x}: {hexs:<39}  {asc}")
            return {"exit": 0, "stdout": "\n".join(lineas) + "\n", "stderr": "", "timed_out": False, "executed_argv": list(argv)}
        if binario == "hashdeep":
            return {"exit": 0, "stdout": "%%%% HASHDEEP-1.0\n%%%% size,sha256,filename\n1,abc,x\n", "stderr": "",
                    "timed_out": False, "executed_argv": list(argv)}
        if binario == "bulk_extractor":
            out = Path(argv[argv.index("-o") + 1])
            out.mkdir(parents=True, exist_ok=True)
            (out / "email.txt").write_text("# BANNER\n123\tadmin@example.com\n456\tbob@evil.org\n", encoding="utf-8")
            (out / "email_histogram.txt").write_text("# BANNER\nn=2\tadmin@example.com\nn=1\tbob@evil.org\n", encoding="utf-8")
            texto = "email: 2 features\n"
        else:
            try:
                proc = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout or 60, shell=False)
            except FileNotFoundError:
                return {"exit": 127, "stdout": "", "stderr": f"{binario}: not found", "timed_out": False, "executed_argv": list(argv)}
            if stdout_path is None:
                return {"exit": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "timed_out": False, "executed_argv": list(argv)}
            texto = proc.stdout
        if stdout_path is not None:
            Path(stdout_path).write_text(texto, encoding="utf-8")
            sha = hashlib.sha256(texto.encode("utf-8")).hexdigest()
            return {"exit": 0, "stdout_file": stdout_path, "stdout_sha256": sha, "stdout_size": len(texto.encode("utf-8")),
                    "stderr": "", "timed_out": False, "executed_argv": list(argv)}
        return {"exit": 0, "stdout": texto, "stderr": "", "timed_out": False, "executed_argv": list(argv)}


class ModeloGuion:
    """Devuelve las respuestas de un guion, en orden. Registra los prompts recibidos."""

    def __init__(self, guion: list[dict[str, Any]], ratio: float = 4.0, prompt_max: int = 3600) -> None:
        self.guion = list(guion)
        self.prompts: list[tuple[str, str]] = []
        self._ratio = ratio
        self._prompt_max = prompt_max

    def estimar_tokens(self, texto: str, modelo: str | None = None) -> int:
        return int(len(texto) / self._ratio) + 1

    def comprobar_ventana(self, system: str, user: str, ventana=None) -> int:
        from modelo import PromptDemasiadoLargo

        maximo = ventana.prompt_max if ventana is not None else self._prompt_max
        est = self.estimar_tokens(system) + self.estimar_tokens(user)
        if est > maximo:
            raise PromptDemasiadoLargo(est, maximo)
        return est

    def preguntar(self, system: str, user: str, **kw: Any) -> Respuesta:
        self.prompts.append((system, user))
        if not self.guion:
            raise AssertionError("el guion del modelo se agotó")
        datos = self.guion.pop(0)
        texto = json.dumps(datos, ensure_ascii=False)
        return Respuesta(texto=texto, prompt_tokens=self.estimar_tokens(system + user), tokens_generados=len(texto) // 4,
                         segundos=0.01, segundos_prefill=0.0, segundos_generacion=0.0, modelo="guion",
                         prompt_chars=len(system) + len(user))

    def disponible(self) -> tuple[bool, str]:
        return True, "guion"


@pytest.fixture
def entorno(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """AGENTOPSY_HOME y bandeja temporales con una evidencia pequeña ya creada."""
    home = tmp_path / "home"
    bandeja = tmp_path / "evidence"
    home.mkdir()
    bandeja.mkdir()
    evidencia = bandeja / "mini.mem"
    evidencia.write_bytes(b"\x00" * 64 + b"WIN-TESTHOST Administrator sqlmap/1.0 phpshell.php " + b"\x00" * 64
                          + b"http://10.20.0.5/dvwa/login.php " + b"\x00" * 512)
    variables = {
        "AGENTOPSY_HOME": str(home),
        "AGENTOPSY_EVIDENCE_DIR": str(bandeja),
        "AGENTOPSY_TOOLKIT_UNIX_URL": "http://maletin-falso",
        "AGENTOPSY_TOOLKIT_WINDOWS_URL": "http://maletin-falso",
        "OLLAMA_HOST": "http://ollama-falso",
        "LOCALFIT_MODEL": "guion",
        "LOCALFIT_MEMORIA": "estructurada",
        "LOCALFIT_MAX_PASOS": "8",
        "LOCALFIT_MAX_PASOS_ORDEN": "3",
        "LOCALFIT_MAX_RONDAS_REVISION": "1",
        # Los tests del bucle libre fijan el reparto antiguo; el invertido tiene su test.
        "LOCALFIT_REPARTO": "investigador",
    }
    for k, v in variables.items():
        monkeypatch.setenv(k, v)
    import casos as mod_casos
    import custodia.ingesta as mod_ingesta

    cfg = Ajustes(dict(os.environ))
    cs = mod_casos.Casos(cfg)
    ing = mod_ingesta.Ingesta(cfg, cs)
    caso = cs.crear("caso test", "perito test")
    ev = ing.registrar(caso["id"], "mini.mem", "memory", "windows")
    return {"cfg": cfg, "casos": cs, "ingesta": ing, "caso": caso, "evidencia": ev, "home": home, "bandeja": bandeja}
