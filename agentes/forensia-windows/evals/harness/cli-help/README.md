# Salidas `--help` de los CLI agénticos (referencia del harness)

Volcados literales de la ayuda de cada CLI usado como *motor* en `motors.yaml`.
Sirven para justificar por qué cada bloque de `motors.yaml` tiene la forma que
tiene (invocador no interactivo, cómo entra el prompt, flags de sandbox/approvals).

Regenerar cuando actualices un CLI (la superficie de flags cambia entre versiones):

    codex exec --help   > cli-help/codex-exec-help.txt
    claude --help       > cli-help/claude-help.txt
    gemini --help       > cli-help/gemini-help.txt

- `codex-exec-help.txt` — capturado 2026-07-03 (Windows/PowerShell).
- `claude-help.txt` — PENDIENTE: pega la salida de `claude --help`.
- `gemini-help.txt` — PENDIENTE: pega la salida de `gemini --help`.
