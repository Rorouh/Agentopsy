#!/usr/bin/env python3
"""Harness single-shot AGNÓSTICO DE MOTOR para la DECISIÓN del sub-agente windows.

Mide qué decide el agente (qué tools planifica + qué findings propone) frente a
la traza dorada de un `case-win-*.yaml`, con CUALQUIER motor declarado en
`motors.yaml` (Ollama local o un CLI: claude/codex/gemini). NO ejecuta
herramientas forenses reales, NO toca el motor del backend y NO lee evidencia:
usa un dispatcher implícito de "una sola tirada" (single-shot) — el modelo
responde el plan + findings de golpe y el harness lo puntúa.

Añadir un motor nuevo = un bloque en `motors.yaml`. Cero cambios aquí.

Uso:
    python run_eval.py --motor ollama --model qwen2.5:3b --cases 002,005,010
    python run_eval.py --motor claude --cases 002

Reglas de diseño respetadas:
    - subprocess SIEMPRE con shell=False y argv en lista (gate 4).
    - Sin fallbacks silenciosos (RULE 2): motor no listo / caso inexistente /
      JSON no parseable => error/mark explícito, nunca un default inventado.
    - No lee ni ejecuta evidencia real.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path

import yaml

# --- Rutas del paquete (todo relativo a este fichero) ------------------------
_HARNESS_DIR = Path(__file__).resolve().parent
_EVALS_DIR = _HARNESS_DIR.parent                      # .../evals
_PKG_DIR = _EVALS_DIR.parent                          # .../forensia-windows
_PROMPTS_DIR = _PKG_DIR / "prompts"
_POLICY_TOOLS = _PKG_DIR / "policy" / "tools.yaml"
_MOTORS_YAML = _HARNESS_DIR / "motors.yaml"
_RESULTS_DIR = _HARNESS_DIR / "results"
_MITRE_SEED = (
    _PKG_DIR.parent / "_orchestrator" / "knowledge" / "mitre_attack_seed.md"
)

_DISK_EXT = {".raw", ".e01", ".vmdk", ".dd", ".img"}
_MEM_EXT = {".mem", ".dmp", ".vmem", ".lime"}


# =========================================================================== #
#  Carga del paquete: prompts, allowlist de tools, semilla MITRE               #
# =========================================================================== #

def load_agent_prompts() -> str:
    """Concatena system + identity + playbook: el cerebro que ve el modelo."""
    parts = []
    for name in ("system.md", "identity.md", "playbook.md"):
        p = _PROMPTS_DIR / name
        if not p.exists():
            raise FileNotFoundError(f"prompt ausente del paquete: {p}")
        parts.append(f"===== {name} =====\n{p.read_text(encoding='utf-8')}")
    return "\n\n".join(parts)


def load_tool_schema() -> tuple[list[str], str]:
    """Devuelve (ids permitidos, texto compacto 'id: descripción') desde tools.yaml.

    La descripción sale del comentario en línea de cada entrada del allowlist.
    """
    data = yaml.safe_load(_POLICY_TOOLS.read_text(encoding="utf-8"))
    allowed = list(data.get("allowed", []))
    # Descripción = comentario en línea `  - id   # desc` del propio YAML.
    desc: dict[str, str] = {}
    for line in _POLICY_TOOLS.read_text(encoding="utf-8").splitlines():
        m = re.match(r"\s*-\s*([A-Za-z0-9_]+)\s*#\s*(.+)$", line)
        if m:
            desc[m.group(1)] = m.group(2).strip()
    lines = [f"- {tid}: {desc.get(tid, '(sin descripción)')}" for tid in allowed]
    return allowed, "\n".join(lines)


def load_mitre_seed_ids() -> set[str]:
    """Enum CERRADA de technique_ids válidos (los de la semilla)."""
    if not _MITRE_SEED.exists():
        raise FileNotFoundError(f"semilla MITRE ausente: {_MITRE_SEED}")
    text = _MITRE_SEED.read_text(encoding="utf-8")
    return set(re.findall(r"T\d{4}(?:\.\d{3})?", text))


def load_case(case_id: str) -> dict:
    """Carga case-win-<id>.yaml. Falla en seco si no existe (RULE 2)."""
    path = _EVALS_DIR / f"case-win-{case_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(
            f"caso inexistente: {path.name}. Casos disponibles: "
            + ", ".join(sorted(p.stem for p in _EVALS_DIR.glob('case-win-*.yaml')))
        )
    return yaml.safe_load(path.read_text(encoding="utf-8"))


# =========================================================================== #
#  Prompt de escenario (neutro; NUNCA incluye expected_findings)               #
# =========================================================================== #

def evidence_kind(fixture: str) -> str:
    ext = Path(fixture).suffix.lower()
    if ext in _MEM_EXT:
        return "memory"
    if ext in _DISK_EXT:
        return "disk"
    return "unknown"


_SCENARIO = {
    "disk": (
        "Contexto de evidencia: detected_os = windows, kind = disk (imagen de "
        "disco Windows).\n"
        "Tarea: investiga PERSISTENCIA, EJECUCIÓN, CUENTAS y ACTIVIDAD "
        "SOSPECHOSA en esta imagen de disco Windows."
    ),
    "memory": (
        "Contexto de evidencia: detected_os = windows, kind = memory (volcado de "
        "memoria Windows).\n"
        "Tarea: investiga PROCESOS, INYECCIÓN de código y CONEXIONES sospechosas "
        "en este volcado de memoria Windows."
    ),
    "unknown": (
        "Contexto de evidencia: detected_os = windows, kind = unknown.\n"
        "Tarea: haz un único probe diagnóstico y luego propón el plan forense."
    ),
}

_OUTPUT_CONTRACT = """\
Responde EXCLUSIVAMENTE con UN bloque de código JSON (```json ... ```), sin
prosa antes ni después, con EXACTAMENTE esta forma:

```json
{
  "plan": [
    {"tool_id": "<id de la allowlist>", "params": {}, "why": "por qué"}
  ],
  "findings": [
    {"title": "frase corta", "severity": "low|medium|high|critical",
     "provenance_tool": "<id de la allowlist>", "mitre": ["T1547.001"]}
  ]
}
```

Reglas: cada `tool_id` y cada `provenance_tool` DEBEN estar en la allowlist de
arriba. Cada `mitre` es una lista de technique_ids (formato T####[.###]). No
inventes tools ni técnicas. No incluyas rutas de evidencia."""


def build_prompt(brain: str, tools_txt: str, kind: str) -> str:
    return (
        f"{brain}\n\n"
        f"===== ALLOWLIST DE TOOLS (id: descripción) =====\n{tools_txt}\n\n"
        f"===== ESCENARIO =====\n{_SCENARIO[kind]}\n\n"
        f"===== FORMATO DE SALIDA (OBLIGATORIO) =====\n{_OUTPUT_CONTRACT}\n"
    )


# =========================================================================== #
#  Invocación del motor (pluggable, shell-free)                                #
# =========================================================================== #

def resolve_motor(name: str) -> dict:
    reg = yaml.safe_load(_MOTORS_YAML.read_text(encoding="utf-8"))
    motors = reg.get("motors", {})
    if name not in motors:
        raise SystemExit(
            f"[error] motor '{name}' no está en motors.yaml. "
            f"Definidos: {', '.join(sorted(motors))}"
        )
    m = motors[name]
    if not m.get("ready", False):
        raise SystemExit(
            f"[error] motor '{name}' está marcado ready:false en motors.yaml "
            f"(no verificado en esta máquina). {m.get('note', '')}".strip()
        )
    if "argv" not in m or "prompt_via" not in m:
        raise SystemExit(f"[error] motor '{name}' incompleto: falta argv/prompt_via")
    if m["prompt_via"] not in ("stdin", "arg", "file"):
        raise SystemExit(
            f"[error] prompt_via inválido en '{name}': {m['prompt_via']} "
            "(usa stdin|arg|file)"
        )
    return m


def run_motor(motor: dict, model: str, prompt: str, timeout_s: int) -> str:
    """Ejecuta el motor con el prompt y devuelve stdout. shell=False, argv lista."""
    via = motor["prompt_via"]
    tmp_path: Path | None = None
    stdin_data: str | None = None

    def _subst(tok: str) -> str:
        tok = tok.replace("{model}", model)
        if via == "arg":
            tok = tok.replace("{prompt}", prompt)
        if via == "file" and tmp_path is not None:
            tok = tok.replace("{prompt_file}", str(tmp_path))
        return tok

    if via == "file":
        fd = tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8"
        )
        fd.write(prompt)
        fd.close()
        tmp_path = Path(fd.name)
    elif via == "stdin":
        stdin_data = prompt

    argv = [_subst(a) for a in motor["argv"]]
    try:
        proc = subprocess.run(
            argv,
            input=stdin_data,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,               # gate 4: nunca shell
            timeout=timeout_s,
        )
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)
    if proc.returncode != 0:
        # Fail loud: no se enmascara el fallo del motor (RULE 2).
        raise RuntimeError(
            f"motor devolvió exit {proc.returncode}. stderr:\n{proc.stderr[:1000]}"
        )
    return proc.stdout


# =========================================================================== #
#  Extracción robusta del JSON de la respuesta                                 #
# =========================================================================== #

# Controles C0 residuales (salvo \t,\n,\r) que dejaría un escape no reconocido.
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_LEAD_DIGITS = re.compile(r"\d+")


def _render_terminal(text: str) -> str:
    """Emula un terminal para el subconjunto de escapes que usan los CLI al hacer
    word-wrap en streaming (ollama, etc.): NO basta con BORRAR los escapes.

    ollama imprime una palabra parcial, luego mueve el cursor a la izquierda
    (`ESC[<n>D`) y borra hasta el fin de línea (`ESC[K`) para RE-imprimir la
    palabra completa en la línea siguiente. Si solo se borran los escapes, el
    stream conserva restos (un `"` duplicado, un salto en medio de un valor) que
    invalidan el JSON. Aplicando los movimientos sobre un buffer de línea se
    reconstruye EXACTAMENTE el texto visible —que es el JSON limpio.
    """
    line: list[str] = []
    out: list[str] = []
    cur = 0
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "\x1b" and i + 1 < n and text[i + 1] == "[":  # CSI ESC[
            j = i + 2
            while j < n and text[j] in "0123456789;?":
                j += 1
            while j < n and 0x20 <= ord(text[j]) <= 0x2F:      # bytes intermedios
                j += 1
            final = text[j] if j < n else ""
            params = text[i + 2:j]
            m = _LEAD_DIGITS.match(params)
            num = int(m.group()) if m else 1
            if final == "D":                    # cursor N a la izquierda
                cur = max(0, cur - num)
            elif final == "C":                  # cursor N a la derecha
                cur = min(len(line), cur + num)
            elif final in ("K", "J"):           # borrar hasta fin de línea
                del line[cur:]
            elif final in ("G", "H", "f"):      # a columna/origen
                cur = 0
            # otros finals (m=color, etc.) se ignoran
            i = j + 1
            continue
        if c == "\r":
            cur = 0
        elif c == "\n":
            out.append("".join(line))
            line, cur = [], 0
        elif c == "\b":
            cur = max(0, cur - 1)
        else:
            if cur < len(line):
                line[cur] = c
            else:
                line.append(c)
            cur += 1
        i += 1
    out.append("".join(line))
    return _CTRL_RE.sub("", "\n".join(out))


def _escape_ctrl_in_strings(text: str) -> str:
    """Colapsa saltos de línea/tabs CRUDOS que caen DENTRO de un string JSON.

    Los CLI con word-wrap (ollama, entre otros) parten una línea larga e insertan
    un `\\n` real en mitad del valor de una cadena; tras quitar los escapes ANSI
    queda un control sin escapar dentro del string, que invalida `json.loads`. Se
    reemplazan por un espacio (solo dentro de strings; fuera son estructurales)."""
    out: list[str] = []
    in_str = esc = False
    for c in text:
        if in_str:
            if esc:
                out.append(c)
                esc = False
            elif c == "\\":
                out.append(c)
                esc = True
            elif c == '"':
                out.append(c)
                in_str = False
            elif c in "\n\r\t":
                out.append(" ")
            else:
                out.append(c)
        else:
            out.append(c)
            if c == '"':
                in_str = True
    return "".join(out)


def extract_json(text: str) -> dict | None:
    """Extrae el primer objeto JSON válido, tolerando texto/fences alrededor.

    Limpia primero el ruido de terminal (escapes ANSI que meten los CLI) y luego
    localiza el objeto por CONTEO DE LLAVES (no por regex perezoso, que se comería
    el `{}` interno de un `params`). Si hay fence ```json se acota a su interior.
    """
    text = _escape_ctrl_in_strings(_render_terminal(text))
    # Si hay un fence ```json ... ```, trabaja sobre su interior (más limpio).
    fence = re.search(r"```(?:json)?\s*(.+?)```", text, re.DOTALL)
    if fence:
        obj = _scan_balanced(fence.group(1))
        if obj is not None:
            return obj
    # Sobre el texto completo (o si el fence no cerró por truncado del modelo).
    return _scan_balanced(text)


def _scan_balanced(text: str) -> dict | None:
    """Primer objeto `{...}` balanceado que CONTENGA plan/findings.

    Exigir esas claves evita devolver un `{}` interno (p.ej. un `params: {}`)
    cuando el objeto externo quedó sin cerrar por truncado del modelo: en ese
    caso es un fallo de parseo honesto (json SIN-JSON), no un plan vacío.
    """
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            c = text[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            else:
                if c == '"':
                    in_str = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        obj = _try_load(text[start:i + 1])
                        if obj is not None and ("plan" in obj or "findings" in obj):
                            return obj
                        break
        start = text.find("{", start + 1)
    return None


def _try_load(s: str) -> dict | None:
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


# =========================================================================== #
#  Scoring contra la traza dorada (el modelo NO la ve)                         #
# =========================================================================== #

def _norm_ids(values) -> list[str]:
    return [str(v).strip() for v in (values or []) if str(v).strip()]


def score(parsed: dict | None, case: dict, allowed: set[str],
          seed: set[str]) -> dict:
    plan = (parsed or {}).get("plan", []) or []
    findings = (parsed or {}).get("findings", []) or []

    plan_tools = _norm_ids(p.get("tool_id") for p in plan if isinstance(p, dict))
    find_tools = _norm_ids(
        f.get("provenance_tool") for f in findings if isinstance(f, dict)
    )
    emitted_tools = plan_tools + find_tools

    # tool_recall: provenance_tool esperados presentes en el PLAN
    exp_tools = {
        str(f["provenance_tool"]).strip()
        for f in case.get("expected_findings", [])
        if f.get("provenance_tool")
    }
    tool_hits = {t for t in exp_tools if t in set(plan_tools)}
    tool_recall = len(tool_hits) / len(exp_tools) if exp_tools else None

    # allowlist_violations: cualquier id emitido fuera de la allowlist
    violations = sorted({t for t in emitted_tools if t not in allowed})

    # findings por title_glob (cada expected es 'globA|globB|...')
    exp_globs = [
        str(f.get("title_glob", "")) for f in case.get("expected_findings", [])
    ]
    emitted_titles = [
        str(f.get("title", "")).lower() for f in findings if isinstance(f, dict)
    ]

    def _title_matches(glob_field: str, title: str) -> bool:
        for alt in glob_field.split("|"):
            alt = alt.strip().lower()
            if alt and fnmatch(title, alt):
                return True
        return False

    matched_exp = sum(
        1 for g in exp_globs if any(_title_matches(g, t) for t in emitted_titles)
    )
    findings_recall = matched_exp / len(exp_globs) if exp_globs else None
    matched_emitted = sum(
        1 for t in emitted_titles if any(_title_matches(g, t) for g in exp_globs)
    )
    findings_precision = (
        matched_emitted / len(emitted_titles) if emitted_titles else None
    )

    # MITRE: recall sobre expected + validez de enum cerrada (semilla)
    exp_mitre = {
        str(m["technique_id"]).strip()
        for m in case.get("expected_mitre", [])
        if m.get("technique_id")
    }
    emitted_mitre = set()
    for f in findings:
        if isinstance(f, dict):
            emitted_mitre.update(_norm_ids(f.get("mitre")))
    mitre_hits = exp_mitre & emitted_mitre
    mitre_recall = len(mitre_hits) / len(exp_mitre) if exp_mitre else None
    mitre_out_of_seed = sorted(emitted_mitre - seed)   # técnicas inventadas
    mitre_correctness = (
        len(mitre_hits) / len(emitted_mitre) if emitted_mitre else None
    )

    return {
        "plan_tools": plan_tools,
        "emitted_findings": len(findings),
        "tool_recall": tool_recall,
        "allowlist_violations": violations,
        "findings_recall": findings_recall,
        "findings_precision": findings_precision,
        "mitre_recall": mitre_recall,
        "mitre_correctness": mitre_correctness,
        "mitre_out_of_seed": mitre_out_of_seed,
        "expected_tools": sorted(exp_tools),
        "expected_mitre": sorted(exp_mitre),
        "emitted_mitre": sorted(emitted_mitre),
        # single-shot: 1 iteración; tokens los reportaría el motor (n/a aquí).
        "iterations": 1,
        "tokens": None,
    }


# =========================================================================== #
#  Salida: JSON por corrida + tabla resumen comparativa                        #
# =========================================================================== #

def _fmt(x) -> str:
    if x is None:
        return "n/a"
    if isinstance(x, float):
        return f"{x:.2f}"
    if isinstance(x, list):
        return "—" if not x else ",".join(map(str, x))
    return str(x)


def write_result(motor_name: str, model: str, case_id: str, sc: dict,
                 raw: str, parsed_ok: bool) -> Path:
    _RESULTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = _RESULTS_DIR / f"{motor_name}-{model.replace(':', '_')}-{case_id}-{ts}.json"
    out.write_text(
        json.dumps(
            {
                "motor": motor_name,
                "model": model,
                "case": f"case-win-{case_id}",
                "timestamp": ts,
                "json_parsed": parsed_ok,
                "scores": sc,
                "raw_stdout": raw,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return out


_SUMMARY_HEADER = (
    "| motor | modelo | caso | json | tool_recall | find_recall | "
    "find_prec | mitre_recall | mitre_ok | fuera_semilla | allowlist_viol | iters | tokens |\n"
    "|---|---|---|---|---|---|---|---|---|---|---|---|---|\n"
)


def append_summary(motor_name: str, model: str, case_id: str, sc: dict,
                   parsed_ok: bool) -> None:
    _RESULTS_DIR.mkdir(exist_ok=True)
    summary = _RESULTS_DIR / "summary.md"
    if not summary.exists():
        summary.write_text(
            "# Resumen comparativo del harness (single-shot)\n\n"
            "Una fila por (motor, modelo, caso). Permite comparar VARIOS motores "
            "lado a lado. `mitre_ok` = fracción de técnicas emitidas correctas; "
            "`fuera_semilla` = técnicas inventadas (deben ser —).\n\n"
            + _SUMMARY_HEADER,
            encoding="utf-8",
        )
    row = (
        f"| {motor_name} | {model} | {case_id} | {'ok' if parsed_ok else 'FALLO'} "
        f"| {_fmt(sc['tool_recall'])} | {_fmt(sc['findings_recall'])} "
        f"| {_fmt(sc['findings_precision'])} | {_fmt(sc['mitre_recall'])} "
        f"| {_fmt(sc['mitre_correctness'])} | {_fmt(sc['mitre_out_of_seed'])} "
        f"| {_fmt(sc['allowlist_violations'])} | {_fmt(sc['iterations'])} "
        f"| {_fmt(sc['tokens'])} |\n"
    )
    with summary.open("a", encoding="utf-8") as fh:
        fh.write(row)


# =========================================================================== #
#  Main                                                                        #
# =========================================================================== #

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Harness single-shot agnóstico de motor.")
    ap.add_argument("--motor", required=True, help="nombre en motors.yaml")
    ap.add_argument("--model", default=None, help="id de modelo (o default del motor)")
    ap.add_argument("--cases", required=True, help="lista separada por comas, p.ej. 002,005,010")
    ap.add_argument("--timeout", type=int, default=300, help="timeout por corrida (s)")
    args = ap.parse_args(argv)

    motor = resolve_motor(args.motor)
    model = args.model or motor.get("default_model")
    if not model and any("{model}" in a for a in motor["argv"]):
        raise SystemExit(
            f"[error] el motor '{args.motor}' usa {{model}} pero no diste --model "
            "ni tiene default_model (RULE 2: sin defaults silenciosos)."
        )
    model = model or "-"

    brain = load_agent_prompts()
    allowed_list, tools_txt = load_tool_schema()
    allowed = set(allowed_list)
    seed = load_mitre_seed_ids()

    case_ids = [c.strip() for c in args.cases.split(",") if c.strip()]
    print(f"[harness] motor={args.motor} model={model} casos={case_ids}")

    for cid in case_ids:
        case = load_case(cid)
        kind = evidence_kind(case.get("evidence_fixture", ""))
        prompt = build_prompt(brain, tools_txt, kind)
        print(f"[harness] === case-win-{cid} (kind={kind}) — invocando motor…")
        try:
            raw = run_motor(motor, model, prompt, args.timeout)
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            print(f"[harness] motor FALLÓ en {cid}: {exc}")
            sc = score(None, case, allowed, seed)
            out = write_result(args.motor, model, cid, sc, str(exc), False)
            append_summary(args.motor, model, cid, sc, False)
            print(f"[harness]   -> {out.name} (json FALLO)")
            continue

        parsed = extract_json(raw)
        sc = score(parsed, case, allowed, seed)
        out = write_result(args.motor, model, cid, sc, raw, parsed is not None)
        append_summary(args.motor, model, cid, sc, parsed is not None)
        ok = "ok" if parsed is not None else "SIN-JSON"
        print(
            f"[harness]   -> {out.name} (json {ok}) "
            f"tool_recall={_fmt(sc['tool_recall'])} "
            f"find_recall={_fmt(sc['findings_recall'])} "
            f"mitre_recall={_fmt(sc['mitre_recall'])} "
            f"viol={_fmt(sc['allowlist_violations'])}"
        )

    print(f"[harness] resumen actualizado: {(_RESULTS_DIR / 'summary.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
