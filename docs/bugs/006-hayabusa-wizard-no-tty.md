# Bug 006 — hayabusa panica sin TTY: falta `--no-wizard` en el wrapper

- **Severidad:** alta (la tool no ejecuta por el dispatcher)
- **Estado:** ✅ **resuelto** (2026-07-04)
- **Componente:** `backend/forensia/toolkit/wrappers/hayabusa.py`
- **Detectado:** 2026-07-04, al ejecutar hayabusa por el dispatcher

## Síntoma

`execute("hayabusa", …)` → **exit 101** (panic de Rust), `parsed=None`. stderr:
```
thread 'main' panicked: called `Result::unwrap()` on an `Err` value:
  IO(Custom { kind: NotConnected, error: "not a terminal" })
```
Directo en el maletín con `-w -q` funcionaba; por el dispatcher no.

## Causa raíz

Sin `-w/--no-wizard`, hayabusa lanza un **"Scan wizard" interactivo** que lee opciones del
**terminal**. El exec-agent ejecuta las tools **sin TTY** (`subprocess`, sin pty), así que el
wizard hace `unwrap()` sobre un stdin no-terminal → panic (exit 101). El wrapper solo ponía
`--no-color`, no `-w`.

## Fix aplicado

El wrapper añade **`-w`** (`--no-wizard`, escanea todo sin preguntar) y **`-q`** (silencia el
banner) al argv de `csv-timeline`. Tras el fix: exit 0, 129 detecciones.

## Lección (reusable)

Las tools **interactivas por defecto** (wizards, prompts, TUIs) hay que forzarlas a modo
**no-interactivo** en su wrapper, porque el exec-agent no da TTY. Revisar el mismo patrón en
cualquier tool nueva con modo interactivo (algunos CLIs de EZ Tools, chainsaw en ciertos
modos, etc.). Relacionado con Bug 004 (el exec-agent y la salida de las tools).
