#!/usr/bin/env python3
"""Lanza una investigación real: pasa el prompt de agente a un CLI (o modelo) y
guarda TODA la salida en un fichero con nombre característico.

Una sola instrucción, el CLI como parámetro, salida autoguardada. Pensado para
automatizar la Vía 2 (análisis real de evidencia) sin fallos humanos y para que
luego sea fácil de integrar en el proyecto.

Ejemplos:
    # 1) ya tienes el prompt en un .txt (de build_agent_prompt.py):
    python run_investigation.py --motor gemini --model gemini-2.5-pro \
        --prompt-file agente-win.txt \
        --evidence "....\\evidence-corpus\\lonewolf-2018\\memdump.mem" --yes

    # 2) que ensamble el prompt él mismo (memory/disk) y lo ejecute:
    python run_investigation.py --motor codex \
        --type memory --evidence "....\\lonewolf-2018\\memdump.mem" --yes

Config de motores: reutiliza motors.yaml (mismo que el harness). Cada motor declara
argv + prompt_via (stdin | arg | file) + default_model.

SOUNDNESS / seguridad (léelo):
- El CLI se ejecuta en modo AUTÓNOMO: puede correr comandos en tu máquina. Úsalo
  SOLO sobre una COPIA de la evidencia y con imágenes de laboratorio (LoneWolf).
- El script fija el cwd a la carpeta de la evidencia para que el CLI encuentre las
  herramientas y el fichero. No dejes que ninguna tool escriba en la imagen.
- Exige --yes para ejecutar (evita lanzamientos accidentales, RULE 2).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("Falta PyYAML: pip install pyyaml")

HERE = Path(__file__).resolve().parent
PKG = HERE.parents[1]                      # agentes/forensia-windows
PROMPTS = PKG / "prompts"
MOTORS_YAML = HERE / "motors.yaml"
OUT_DIR = HERE / "results" / "investigations"

TASKS = {
    "memory": (
        "TAREA: Analiza el volcado de memoria Windows indicado. Investiga procesos "
        "(incl. ocultos), inyeccion, conexiones de red, lineas de comando y "
        "credenciales. Usa Volatility 3 (windows.info, pslist, pstree, psscan, "
        "malfind, netscan, cmdline). Registra cada hallazgo con su herramienta y "
        "artefacto. No inventes."
    ),
    "disk": (
        "TAREA: Analiza la imagen de disco Windows indicada (seccion A del playbook): "
        "mmls, fls, $MFT, hives (icat -> RegRipper), EVTX (icat -> EvtxECmd/Hayabusa). "
        "Investiga persistencia, ejecucion, cuentas, USB y actividad sospechosa. "
        "Registra cada hallazgo con su herramienta y artefacto. No montes el FS en "
        "escritura ni pases la imagen cruda a una tool de contenedor."
    ),
}

# En MODO AUTÓNOMO se antepone este override: el CLI ejecuta las herramientas él
# mismo (a diferencia del contrato Agentopsy, que asume el motor). Solo para
# laboratorio, sobre una COPIA y con imágenes públicas (LoneWolf).
# NOTA: se usa una variable _BAR + f-strings a propósito. Escribir "...\n" "=" * 78
# concatena los literales adyacentes ANTES de multiplicar y repite todo x78 (bug).
_BAR = "=" * 78
AUTONOMOUS_OVERRIDE = (
    f"{_BAR}\n"
    "MODO AUTÓNOMO DE LABORATORIO — LEE ESTO PRIMERO (tiene prioridad):\n"
    f"{_BAR}\n"
    "A DIFERENCIA de la regla 1 de las reglas de sistema de abajo (que asume el motor\n"
    "Agentopsy y te prohíbe ejecutar comandos), en ESTA prueba de laboratorio TÚ tienes\n"
    "las herramientas instaladas (Volatility 3 como `vol`, y si aplica The Sleuth Kit)\n"
    "y acceso de shell. DEBES ejecutarlas tú mismo, en SOLO LECTURA, sobre la evidencia\n"
    "indicada, e interpretar sus salidas.\n\n"
    "- Traduce cada paso del playbook al comando real. Ej.: el plugin\n"
    "  `windows.pslist.PsList` -> `vol -f <EVIDENCIA> windows.pslist.PsList`;\n"
    "  `windows.malfind.Malfind`, `windows.netscan.NetScan`, `windows.cmdline.CmdLine`, etc.\n"
    "- NUNCA modifiques la evidencia: no la montes en escritura, no ejecutes comandos\n"
    "  destructivos. Solo lectura.\n"
    "- Usa el PLAYBOOK de abajo para decidir QUÉ ejecutar y en qué orden.\n"
    "- Reporta al final un informe (Resumen, Hallazgos con su herramienta+artefacto y\n"
    "  severidad, Lagunas). No inventes: si algo no concluye, dilo.\n"
    f"{_BAR}\n\n"
)


def read(path: Path) -> str:
    if not path.is_file():
        sys.exit(f"ERROR: no existe {path} (RULE 2: sin fallbacks).")
    return path.read_text(encoding="utf-8")


def build_prompt(ev_type: str, evidence: str, mode: str = "forensia") -> str:
    override = AUTONOMOUS_OVERRIDE if mode == "autonomous" else ""
    parts = [
        "=" * 78,
        "INSTRUCCIONES DEL AGENTE (Agentopsy-WIN) — compórtate según ellas:",
        "=" * 78,
        "\n## IDENTIDAD\n" + read(PROMPTS / "identity.md").strip(),
        "\n## REGLAS DE SISTEMA\n" + read(PROMPTS / "system.md").strip(),
        "\n## PLAYBOOK\n" + read(PROMPTS / "playbook.md").strip(),
        "=" * 78,
        f"{TASKS[ev_type]}\nEVIDENCIA: {evidence}",
        "=" * 78,
    ]
    return override + "\n".join(parts) + "\n"


def load_motor(name: str) -> dict:
    motors = yaml.safe_load(read(MOTORS_YAML)).get("motors", {})
    if name not in motors:
        sys.exit(f"ERROR: motor '{name}' no está en motors.yaml. Definidos: {list(motors)}")
    m = motors[name]
    if not m.get("ready", False):
        sys.exit(
            f"ERROR: motor '{name}' está ready:false en motors.yaml "
            "(instálalo/autentícalo y pon ready:true). RULE 2: sin defaults."
        )
    return m


def build_argv(motor: dict, prompt: str, model: str | None) -> tuple[list[str], str | None, Path | None]:
    """Devuelve (argv, stdin_text, tmp_file). Sustituye {model}/{prompt}/{prompt_file}."""
    mdl = model or motor.get("default_model", "")
    via = motor.get("prompt_via", "stdin")
    tmp: Path | None = None
    stdin_text: str | None = None
    argv: list[str] = []
    for tok in motor["argv"]:
        if tok == "{prompt}":
            argv.append(prompt)
        elif tok == "{prompt_file}":
            if tmp is None:
                fd = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
                fd.write(prompt)
                fd.close()
                tmp = Path(fd.name)
            argv.append(str(tmp))
        elif tok == "{model}":
            argv.append(mdl)
        else:
            argv.append(tok)
    if via == "stdin":
        stdin_text = prompt
    return argv, stdin_text, tmp


def main() -> None:
    ap = argparse.ArgumentParser(description="Investigación automática con un CLI/modelo.")
    ap.add_argument("--motor", required=True, help="nombre en motors.yaml (ollama, gemini, codex...)")
    ap.add_argument("--model", help="override del modelo (si el motor usa {model})")
    ap.add_argument("--prompt-file", help="prompt de agente ya ensamblado (.txt)")
    ap.add_argument("--type", choices=sorted(TASKS), help="si no das --prompt-file, ensambla este tipo")
    ap.add_argument("--mode", choices=["forensia", "autonomous"], default="forensia",
                    help="forensia = contrato {tool_id,params} (mide decisión); "
                         "autonomous = el CLI ejecuta las tools él mismo (análisis real, laboratorio)")
    ap.add_argument("--evidence", required=True, help="ruta a la evidencia (COPIA, solo lectura)")
    ap.add_argument("--workdir", help="cwd para el CLI (por defecto: carpeta de la evidencia)")
    ap.add_argument("--timeout", type=int, default=3600, help="segundos (por defecto 3600)")
    ap.add_argument("--yes", action="store_true", help="confirma ejecución autónoma del CLI")
    args = ap.parse_args()

    if not args.yes:
        sys.exit("Aborta: ejecución autónoma de un CLI. Añade --yes cuando trabajes sobre una COPIA.")

    if args.prompt_file:
        prompt = read(Path(args.prompt_file))
    elif args.type:
        prompt = build_prompt(args.type, args.evidence, args.mode)
    else:
        sys.exit("ERROR: da --prompt-file o --type.")

    motor = load_motor(args.motor)
    argv, stdin_text, tmp = build_argv(motor, prompt, args.model)

    ev = Path(args.evidence)
    workdir = Path(args.workdir) if args.workdir else (ev.parent if ev.parent.exists() else Path.cwd())
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    mdl = (args.model or motor.get("default_model", "modelo")).replace(":", "-").replace("/", "-")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / f"{args.motor}__{mdl}__{ev.stem}__{ts}.md"

    # Resolver el ejecutable real. En Windows, los CLI de npm son shims (codex.cmd /
    # codex.ps1) que CreateProcess no lanza directamente con el nombre pelado
    # (WinError 5 "Acceso denegado" / 193). shutil.which respeta PATHEXT y da el path
    # completo; los .cmd/.bat se ejecutan vía `cmd /c`.
    exe = shutil.which(argv[0])
    if exe is None:
        msg = f"ERROR: '{argv[0]}' no está en PATH. Instálalo o corrige su argv en motors.yaml."
        out.write_text(f"# Investigación Agentopsy-WIN\n- motor: {args.motor}\n\n{msg}\n",
                       encoding="utf-8")
        sys.exit(msg)
    if exe.lower().endswith((".cmd", ".bat")):
        argv = ["cmd", "/c", exe] + argv[1:]
    else:
        argv = [exe] + argv[1:]

    print(f"Ejecutando {args.motor} en {workdir} ... (salida -> {out})")
    _t0 = time.monotonic()
    try:
        proc = subprocess.run(
            argv, input=stdin_text, cwd=str(workdir), capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=args.timeout, shell=False,
        )
        body = f"## STDOUT\n\n{proc.stdout}\n\n## STDERR\n\n{proc.stderr}\n\n(exit={proc.returncode})\n"
    except FileNotFoundError:
        body = f"ERROR: no encuentro el ejecutable '{argv[0]}'. ¿Está instalado y en PATH?\n"
    except PermissionError as e:
        body = (f"ERROR: Windows denegó lanzar '{argv[0]}' ({e}). Suele ser antivirus/EDR "
                "bloqueando el spawn, un shim .cmd/.ps1, o el binario en actualización. "
                "Reintenta; si persiste, ejecútalo desde una terminal con permisos o revisa Defender.\n")
    except OSError as e:
        body = f"ERROR: no se pudo lanzar '{argv[0]}': {e}\n"
    except subprocess.TimeoutExpired:
        body = f"ERROR: timeout tras {args.timeout}s.\n"
    finally:
        if tmp and tmp.exists():
            tmp.unlink()

    # Duración de pared del análisis del agente (para estimar tiempos por motor /
    # tipo de evidencia y hacer cálculos de coste). Medida alrededor de la llamada
    # al CLI, así que incluye el análisis completo del agente (no el arranque de este
    # script). `duracion_s` es parseable; `duracion` es H:MM:SS legible.
    elapsed_s = time.monotonic() - _t0
    elapsed_h = str(_dt.timedelta(seconds=round(elapsed_s)))

    header = (
        f"# Investigación Agentopsy-WIN\n"
        f"- motor: {args.motor}\n- modelo: {args.model or motor.get('default_model','')}\n"
        f"- evidencia: {args.evidence}\n- tipo: {args.type or 'prompt-file'}\n"
        f"- cwd: {workdir}\n- comando: {argv}\n- fecha: {ts}\n"
        f"- duracion_s: {elapsed_s:.1f}\n- duracion: {elapsed_h}\n\n"
        f"{'='*78}\n\n"
    )

    out.write_text(header + body, encoding="utf-8")
    print(f"OK: guardado en {out}  (duracion {elapsed_s:.1f}s / {elapsed_h})")


if __name__ == "__main__":
    main()
