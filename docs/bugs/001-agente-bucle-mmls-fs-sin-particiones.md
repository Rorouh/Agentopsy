# Bug 001 — El agente entra en bucle con `tsk_mmls` en imágenes de FS sin tabla de particiones

- **Severidad:** media (no corrompe datos ni evidencia; degrada la usabilidad y quema iteraciones/coste)
- **Estado:** mitigado (guardrail de reintentos) — causa raíz (prompt) aún abierta
- **Componente:** paquete de agente `agentes/forensia-unix/prompts/` (prompt), no el cableado de ejecución
- **Detectado:** 2026-07-04, sesión de prueba con la evidencia `dvwa-disk.raw` (rootfs de contenedor Docker → ext4 **sin** tabla de particiones)

## Síntoma

Al pedirle al agente algo tan simple como *"lista los directorios de la raíz del disco"*
sobre una imagen que es un **sistema de ficheros plano** (ext4 en offset 0, sin MBR/GPT),
el agente **no termina**: agota el `max_iterations` (18) y responde *"Se alcanzó el máximo
de iteraciones sin respuesta final"*. Solo produce una respuesta correcta si el operador
le da la pista a mano (*"no hay tabla de particiones, usa tsk_fls directamente"*).

Se reprodujo con **los cuatro caminos de modelo**: Ollama (`qwen2.5:7b`) y Claude Code
(`claude -p`) igual — luego **no es una limitación del LLM**, es el prompt.

## Reproducción

1. Registrar como evidencia una imagen de FS sin tabla de particiones (p. ej. un `.raw`
   creado con `mkfs.ext4` directo, o el rootfs de un contenedor). Triage: `kind=disk`,
   `os=unix`.
2. En Investigación, seleccionar un ejecutor y pedir *"lista los directorios de la raíz"*.
3. Observar el `audit.jsonl` del caso: el agente llama `tsk_mmls` una y otra vez
   (variando flags: `-t gpt`, `-i raw`…), cada una con **exit 1**
   (`Cannot determine partition type`), sin pasar nunca a `tsk_fls`.

Evidencia del audit (sesión real, últimas llamadas antes de agotar iteraciones):

```
tsk_mmls  ['mmls', '-t', 'gpt', '/cases/.../original.raw']   exit 1
tsk_mmls  ['mmls', '-i', 'raw', '/cases/.../original.raw']   exit 1
tsk_mmls  ['mmls', '-t', 'gpt', '/cases/.../original.raw']   exit 1
... (~10 reintentos de mmls) ...
tsk_fls   ['fls', '/cases/.../original.raw']                 exit 0   ← solo tras la pista manual
```

## Causa raíz

Está **en el system prompt / playbook** del paquete `forensia-unix`, no en el código. Tres
instrucciones se contradicen y no cubren el caso "FS plano":

1. **`prompts/playbook.md` §A.2** manda particiones primero:
   > *"2. **Particiones.** `tsk_mmls` → tabla de particiones, offsets…"*
   y la descripción de la tool refuerza *"Run this first to discover the partition layout."*
   → el modelo **siempre** arranca con `mmls`.

2. **Bloque "Cuando un tool falle"** (system prompt) da una pista **equivocada** para este
   caso:
   > *"si `tsk_mmls` falla con 'Cannot determine partition type', la evidencia probablemente
   > NO es una imagen de disco — prueba `volatility3` con `linux.pslist.PsList`…"*
   → empuja hacia **Volatility (memoria)**, no hacia `tsk_fls`. Pero la evidencia **sí** es
   un disco (un FS sin particiones), así que Volatility también falla.

3. **Contradicción**: el mismo prompt, en *"## Ruta del playbook — DISK IMAGE"*, dice
   *"no llames a plugins `windows.*`/`linux.*` de Volatility"*.

Resultado: no hay ninguna regla que diga *"mmls sin particiones + kind=disk → usa `fls` en
offset 0"*. El modelo rebota entre `mmls` y (según el hint) `volatility`, y nunca aterriza
en `fls`. Los modelos pequeños se atascan del todo; los grandes (Claude) acaban probando
`fls` pero desperdiciando iteraciones.

## Impacto

- Imágenes de **FS sin tabla de particiones** y **rootfs de contenedor** (`.dockerenv`,
  imágenes exportadas de Docker, particiones sueltas volcadas) → el flujo básico de listar
  ficheros no responde sin intervención manual.
- Coste/latencia: hasta 18 llamadas al ejecutor por una consulta trivial. Con ejecutores
  cloud (`claude -p`) esto es tiempo y tokens desperdiciados; con Ollama, minutos de CPU.

## Fix propuesto (no aplicado)

Editar `agentes/forensia-unix/prompts/` (playbook y/o el bloque "Cuando un tool falle")
para cubrir el caso explícitamente, algo como:

> *"Si `tsk_mmls` falla con 'Cannot determine partition type' y `detected_kind = disk`: la
> imagen es un **sistema de ficheros sin tabla de particiones** (o el rootfs de un
> contenedor). Llama a `tsk_fls` directamente **sin** `partition_offset` (offset 0). NO
> reintentes `mmls` ni saltes a Volatility."*

Y resolver la contradicción del hint de Volatility (que solo aplica a `kind=memory`).

## Mitigación aplicada (guardrail de reintentos)

Se añadió un tope en el loop del agente (`backend/forensia/agent/agent.py`): una tool que
**falla** (exit≠0 o error de ejecución) no se reintenta más de **`max_attempts` veces por
sesión** (default 3, override `FORENSIA_MAX_TOOL_ATTEMPTS`). Al superar el tope, el loop
**bloquea** nuevas llamadas a ese `tool_id` y le devuelve al modelo un mensaje pidiéndole
que cambie de herramienta o cierre. Solo cuenta fallos: una tool que va bien puede llamarse
cuantas veces haga falta (p. ej. `tsk_icat` por inodo). Tests:
`backend/tests/test_agent_loop.py`.

Esto **acota el desperdicio** (de ~10-18 reintentos a 3) pero **no resuelve la causa
raíz**: el modelo sigue empezando por `mmls` y sigue sin saber que debe usar `fls` en un FS
plano. El fix de fondo (editar el playbook) sigue pendiente.

## Notas

- El **cableado de ejecución** (dispatcher → exec-agent → maletín) funciona correctamente:
  cuando el modelo elige `tsk_fls`, se ejecuta y devuelve el resultado real. El bug es
  puramente de **orquestación guiada por el prompt**.
- Al ser declarativo el paquete de agente, el fix es solo edición de Markdown en
  `agentes/forensia-unix/` — sin tocar código ni reconstruir imágenes.
