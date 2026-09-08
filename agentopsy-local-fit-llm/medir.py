"""El spike: mismo caso, misma pregunta, varias configuraciones, y una tabla.

    python medir.py <case_id> <evidence_id> "Analiza la evidencia" \
        --config agentopsy-local-q25-3b:estructurada \
        --config agentopsy-local-q25-3b:embeddings \
        --config agentopsy-local-q25-7b:estructurada

Cada configuración corre en una sesión nueva (`medida-<n>`), así el estado del
agente empieza de cero y la comparación es justa (RA-9, RE-2). Se miden reloj
de pared, pasos, llamadas al modelo, tokens, herramientas ejecutadas y
hallazgos registrados. Sale un JSON en `mediciones/` y una tabla en pantalla.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from casos import casos
from configuracion import Ajustes
from hallazgos import Hallazgos
from runner import Corrida


def medir(case_id: str, evidence_id: str, prompt: str, modelo: str, memoria: str, indice: int,
          embed: str | None) -> dict:
    entorno = dict(os.environ)
    # "investigador+revisor" permite un modelo distinto por agente.
    inv, _, rev = modelo.partition("+")
    entorno["LOCALFIT_MODEL"] = inv
    if rev:
        entorno["LOCALFIT_MODEL_REVISOR"] = rev
    else:
        entorno.pop("LOCALFIT_MODEL_REVISOR", None)
    entorno["LOCALFIT_MEMORIA"] = memoria
    if embed:
        entorno["LOCALFIT_EMBED_MODEL"] = embed
    cfg = Ajustes(entorno)
    sesion = f"medida-{indice}-{int(time.time())}"
    antes = len(Hallazgos(casos.dir_caso(case_id), case_id).listar())
    inicio = time.monotonic()
    error = None
    try:
        corrida = Corrida(case_id=case_id, evidence_id=evidence_id, sesion=sesion, prompt=prompt, cfg=cfg,
                          emitir=lambda e: print(f"    {e['type']:12} {e.get('tool_id') or (e.get('text') or '')[:70]}", flush=True))
        r = corrida.ejecutar()
        metricas = r["metrics"]
        respuesta = r["reply"]
        error = r.get("error")
    except Exception as exc:  # noqa: BLE001 — la medición sigue con la siguiente configuración
        metricas, respuesta, error = {}, "", f"{type(exc).__name__}: {exc}"
    segundos = round(time.monotonic() - inicio, 1)
    despues = len(Hallazgos(casos.dir_caso(case_id), case_id).listar())
    return {
        "modelo": modelo, "memoria": memoria, "sesion": sesion, "segundos": segundos,
        "hallazgos_nuevos": despues - antes, "error": error, "respuesta": respuesta[:2000], **metricas,
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("case_id")
    p.add_argument("evidence_id")
    p.add_argument("prompt")
    p.add_argument("--config", action="append", required=True, help="modelo[+modelo_revisor]:memoria")
    p.add_argument("--embed", default=None, help="modelo de embeddings para el camino B")
    a = p.parse_args()
    filas = []
    for i, conf in enumerate(a.config, start=1):
        modelo, _, memoria = conf.partition(":")
        memoria = memoria or "estructurada"
        print(f"\n=== [{i}/{len(a.config)}] {modelo} · {memoria}", flush=True)
        filas.append(medir(a.case_id, a.evidence_id, a.prompt, modelo, memoria, i, a.embed))
    salida = Path(__file__).parent / "mediciones"
    salida.mkdir(exist_ok=True)
    fichero = salida / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json")
    fichero.write_text(json.dumps({"prompt": a.prompt, "case_id": a.case_id, "filas": filas}, indent=2, ensure_ascii=False))
    print("\n| modelo | memoria | segundos | pasos | llamadas | tokens prompt | herramientas | hallazgos | error |")
    print("|---|---|---|---|---|---|---|---|---|")
    for f in filas:
        print(f"| {f['modelo']} | {f['memoria']} | {f['segundos']} | {f.get('pasos', '')} | {f.get('llamadas_modelo', '')} | "
              f"{f.get('prompt_tokens', '')} | {f.get('herramientas', '')} | {f['hallazgos_nuevos']} | {f['error'] or ''} |")
    print(f"\nguardado en {fichero}")


if __name__ == "__main__":
    main()
