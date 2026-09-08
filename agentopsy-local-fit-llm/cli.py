"""Línea de comandos para probar y medir sin la web.

    python cli.py caso "nombre" "perito"
    python cli.py ingestar <case_id> memdump.mem memory --os-profile windows
    python cli.py turno <case_id> <evidence_id> "Analiza la evidencia" [--sesion main]
    python cli.py estado <case_id> [--sesion main]
    python cli.py verificar <case_id>
    python cli.py capacidades

`turno` imprime cada evento según ocurre y, al final, las métricas del turno
(pasos, llamadas al modelo, tokens, segundos): son los números que el spike
tiene que medir (RP-1, RP-3, criterios 2 a 5).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

from casos import casos
from configuracion import ajustes
from custodia.ingesta import ingesta
from custodia.registro import Registro
from estado import Estado
from maletin import Maletin, MaletinError
from modelo import Modelo
from runner import Corrida


def _imprimir_evento(e: dict[str, Any]) -> None:
    t = e.get("type")
    ag = e.get("agent", "")
    if t == "reasoning":
        print(f"  [{ag}] piensa: {e.get('text', '')[:200]}")
    elif t == "tool_call":
        print(f"  [{ag}] → {e.get('tool_id')} {json.dumps(e.get('params') or {}, ensure_ascii=False)[:160]}")
    elif t == "tool_result":
        print(f"  [{ag}] ← {e.get('tool_id')} {e.get('status')} exit={e.get('exit_code')} run={str(e.get('run_id') or '')[:8]} "
              f"({e.get('seconds')}s modelo)")
        for linea in (e.get("summary") or "").splitlines()[:6]:
            print(f"        {linea[:140]}")
    elif t == "finding":
        print(f"  [{ag}] HALLAZGO [{e.get('severity')}] {e.get('title')}")
    elif t == "tareas":
        print(f"  [{ag}] tareas: " + " | ".join(f"{x['estado'][:1]}:{x['texto'][:40]}" for x in e.get("tareas") or []))
    elif t == "revision":
        print(f"  [revisor] {'APRUEBA' if e.get('approved') else 'PIDE REVISIÓN'}: {e.get('text', '')[:200]}")
    elif t == "orden":
        print(f"  [revisor] ORDEN: {e.get('text')}")
    elif t == "final":
        print(f"  [{ag}] informe{' (agotado)' if e.get('exhausted') else ''}: {e.get('text', '')[:300]}")
    sys.stdout.flush()


def cmd_caso(a: argparse.Namespace) -> None:
    print(json.dumps(casos.crear(a.nombre, a.perito), indent=2, ensure_ascii=False))


def cmd_ingestar(a: argparse.Namespace) -> None:
    inicio = time.monotonic()
    ev = ingesta.registrar(a.case_id, a.fichero, a.kind, a.os_profile)
    print(json.dumps(ev.puntero() | {"sha256": ev.sha256, "path": ev.ruta_maletin,
                                     "segundos_hash": round(time.monotonic() - inicio, 1)}, indent=2, ensure_ascii=False))


def cmd_turno(a: argparse.Namespace) -> None:
    corrida = Corrida(case_id=a.case_id, evidence_id=a.evidence_id, sesion=a.sesion, prompt=a.prompt,
                      emitir=_imprimir_evento)
    print(f"modelo={ajustes.get('LOCALFIT_MODEL')} memoria={ajustes.get('LOCALFIT_MEMORIA')} ventana={ajustes.ventana}")
    inicio = time.monotonic()
    r = corrida.ejecutar()
    print("\n=== RESPUESTA AL PERITO ===\n" + r["reply"])
    print("\n=== MÉTRICAS ===")
    m = dict(r["metrics"])
    m["segundos_reloj"] = round(time.monotonic() - inicio, 1)
    print(json.dumps(m, indent=2, ensure_ascii=False))
    print("tareas finales:", json.dumps(r["tasks"], ensure_ascii=False))
    if r.get("error"):
        print("ERROR:", r["error"])


def cmd_estado(a: argparse.Namespace) -> None:
    print(json.dumps(Estado(casos.dir_agente(a.case_id, a.sesion)).vista(), indent=2, ensure_ascii=False))


def cmd_verificar(a: argparse.Namespace) -> None:
    reg = Registro(casos.ruta_registro(a.case_id))
    ok, motivo = reg.verificar()
    print(json.dumps({"ok": ok, "reason": motivo, "entries": len(reg.entradas())}))


def cmd_capacidades(_: argparse.Namespace) -> None:
    salida: dict[str, Any] = {"config": ajustes.resumen()}
    try:
        salida["modelo"] = Modelo(ajustes).disponible()
    except KeyError as exc:
        salida["modelo"] = (False, str(exc))
    for perfil in ("unix", "windows"):
        try:
            m = Maletin(ajustes.url_maletin(perfil), ajustes.token_maletin)
            salida[perfil] = m.salud() | {"versiones": {k: v for k, v in m.versiones().items()
                                                        if k in {"file", "xxd", "strings", "vol", "bulk_extractor", "hashdeep"}}}
        except (KeyError, MaletinError) as exc:
            salida[perfil] = {"error": str(exc)}
    print(json.dumps(salida, indent=2, ensure_ascii=False, default=str))


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="agentopsy-local-fit-llm")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("caso"); s.add_argument("nombre"); s.add_argument("perito"); s.set_defaults(f=cmd_caso)
    s = sub.add_parser("ingestar"); s.add_argument("case_id"); s.add_argument("fichero"); s.add_argument("kind")
    s.add_argument("--os-profile", dest="os_profile", default=None); s.set_defaults(f=cmd_ingestar)
    s = sub.add_parser("turno"); s.add_argument("case_id"); s.add_argument("evidence_id"); s.add_argument("prompt")
    s.add_argument("--sesion", default="main"); s.set_defaults(f=cmd_turno)
    s = sub.add_parser("estado"); s.add_argument("case_id"); s.add_argument("--sesion", default="main"); s.set_defaults(f=cmd_estado)
    s = sub.add_parser("verificar"); s.add_argument("case_id"); s.set_defaults(f=cmd_verificar)
    s = sub.add_parser("capacidades"); s.set_defaults(f=cmd_capacidades)
    a = p.parse_args(argv)
    a.f(a)


if __name__ == "__main__":
    main()
