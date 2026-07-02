#!/usr/bin/env python3
"""Ensambla el "prompt de agente" FORENSIA-WIN para pegarlo en un CLI agéntico.

NO ejecuta herramientas ni el CLI: solo concatena los prompts del paquete
(system + identity + playbook) y añade una tarea concreta según el tipo de
evidencia. La salida va a stdout; rediríjela a un fichero y pégala en
codex / gemini / claude para que ellos conduzcan la investigación real.

Uso:
    python build_agent_prompt.py --type memory --evidence RUTA
    python build_agent_prompt.py --type disk   --evidence RUTA --out mi-prompt.txt

Escribe el prompt en un fichero UTF-8 (por defecto agente-win.txt) — no uses el
redireccionamiento '>' de PowerShell, que re-codifica y rompe los caracteres.

Soundness: este script NO toca la evidencia. Cuando el CLI ejecute herramientas,
trabaja sobre una COPIA en solo lectura y no dejes que ninguna tool escriba en la
imagen (Volatility sobre memoria es read-only; TSK lee sin montar el FS).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Los prompts del paquete están dos niveles por encima de este fichero:
#   agentes/forensia-windows/prompts/{system,identity,playbook}.md
PKG = Path(__file__).resolve().parents[2]        # -> agentes/forensia-windows
PROMPTS = PKG / "prompts"

TASKS = {
    "memory": (
        "TAREA: Analiza el volcado de memoria Windows en la ruta indicada. Investiga "
        "procesos (incluidos ocultos), inyección de código, conexiones de red, líneas "
        "de comando y credenciales residentes. Usa Volatility 3 (windows.info, pslist, "
        "pstree, psscan, malfind, netscan, cmdline). Registra cada hallazgo con la "
        "herramienta y el artefacto que lo sostiene. No inventes: si no hay evidencia, "
        "dilo. Al final, lista los hallazgos en el esquema de finding del system prompt."
    ),
    "disk": (
        "TAREA: Analiza la imagen de disco Windows en la ruta indicada. Sigue la "
        "seccion A del playbook: particiones (mmls), sistema de ficheros (fls), $MFT, "
        "hives de registro (extraidos con icat -> RegRipper), EVTX (extraidos -> "
        "EvtxECmd/Hayabusa). Investiga persistencia, ejecucion, cuentas, USB y "
        "actividad sospechosa. Registra cada hallazgo con su herramienta y artefacto. "
        "No montes el FS en escritura ni pases la imagen cruda a una tool de contenedor."
    ),
}


def read(path: Path) -> str:
    if not path.is_file():
        sys.exit(f"ERROR: no encuentro {path} (RULE 2: sin fallbacks).")
    return path.read_text(encoding="utf-8").strip()


def main() -> None:
    ap = argparse.ArgumentParser(description="Ensambla el prompt de agente FORENSIA-WIN.")
    ap.add_argument("--type", required=True, choices=sorted(TASKS), help="tipo de evidencia")
    ap.add_argument("--evidence", required=True, help="ruta a la evidencia (copia, solo lectura)")
    ap.add_argument("--out", default="agente-win.txt", help="fichero de salida (UTF-8)")
    args = ap.parse_args()

    system = read(PROMPTS / "system.md")
    identity = read(PROMPTS / "identity.md")
    playbook = read(PROMPTS / "playbook.md")
    task = TASKS[args.type]

    bar = "=" * 78
    text = (
        f"{bar}\n"
        "INSTRUCCIONES DEL AGENTE (FORENSIA-WIN) — compórtate según ellas:\n"
        f"{bar}\n"
        f"\n## IDENTIDAD\n{identity}\n"
        f"\n## REGLAS DE SISTEMA\n{system}\n"
        f"\n## PLAYBOOK\n{playbook}\n"
        f"\n{bar}\n"
        f"{task}\nEVIDENCIA: {args.evidence}\n"
        f"{bar}\n"
    )

    # Escribir en UTF-8 desde Python evita el UnicodeEncodeError de cp1252 y la
    # re-codificación del redireccionamiento '>' de PowerShell (RULE 2: sin sorpresas).
    out = Path(args.out)
    out.write_text(text, encoding="utf-8")
    print(f"OK: prompt de agente escrito en {out.resolve()} ({len(text)} chars, UTF-8)")


if __name__ == "__main__":
    main()
