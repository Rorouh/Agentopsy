# Bugs conocidos

Registro de fallos observados en Agentopsy que **aún no están corregidos**. Un fichero
por bug (`NNN-slug.md`), numerados por orden de descubrimiento. Cuando uno se arregle,
marca su estado como `resuelto` y enlaza el commit/PR; no borres la entrada (el histórico
de por qué falló es útil).

No confundir con [`operacion/proximos-pasos.md`](../operacion/proximos-pasos.md), que es
deuda técnica y trabajo *planificado*. Aquí van **fallos de comportamiento** concretos,
con su reproducción y causa raíz.

| # | Título | Severidad | Estado |
|---|--------|-----------|--------|
| [001](001-agente-bucle-mmls-fs-sin-particiones.md) | El agente entra en bucle con `tsk_mmls` en imágenes de FS sin tabla de particiones | media | mitigado |
| [002](002-tsk-fls-parser-recursivo-subcuenta.md) | El parser de `tsk_fls` recursivo subcuenta (14.234 → 22) por el prefijo de profundidad | media | abierto |
| [003](003-tools-stub-sin-wrapper.md) | Tools stub sin wrapper (las 6 integradas: hashdeep/foremost/tsk_icat/plaso*/qemu_nbd) | alta | resuelto |
| [004](004-exec-agent-utf8-crash.md) | El exec-agent crashea con salida no-UTF-8 (RemoteDisconnected) — `errors="replace"` | alta | resuelto |
| [005](005-hayabusa-glibc-gnu-build.md) | hayabusa (build gnu) no arranca en Ubuntu 22.04 (`GLIBC_2.38`) — usar build musl | alta | resuelto |
| [006](006-hayabusa-wizard-no-tty.md) | hayabusa panica sin TTY (`not a terminal`, exit 101) — falta `--no-wizard` en el wrapper | alta | resuelto |
| [007](007-chainsaw-parser-lee-stdout-no-stderr.md) | El parser de `chainsaw` leía stdout, pero chainsaw resume por stderr (parsed=0 con artefacto correcto) — dispatcher pasa stderr por aridad | media | resuelto |
| [008](008-consumo-tokens-executor-stateless-volatility.md) | Un volcado de Volatility funde ~50 % del presupuesto de tokens en una pasada — executores stateless re-facturan el prefijo fijo (playbook 21.9 KB + specs) × `max_iterations` sin caché | alta | mitigado |
