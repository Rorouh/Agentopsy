# Bugs conocidos

Registro de fallos observados en FORENSIA que **aún no están corregidos**. Un fichero
por bug (`NNN-slug.md`), numerados por orden de descubrimiento. Cuando uno se arregle,
marca su estado como `resuelto` y enlaza el commit/PR; no borres la entrada (el histórico
de por qué falló es útil).

No confundir con [`operacion/proximos-pasos.md`](../operacion/proximos-pasos.md), que es
deuda técnica y trabajo *planificado*. Aquí van **fallos de comportamiento** concretos,
con su reproducción y causa raíz.

| # | Título | Severidad | Estado |
|---|--------|-----------|--------|
| [001](001-agente-bucle-mmls-fs-sin-particiones.md) | El agente entra en bucle con `tsk_mmls` en imágenes de FS sin tabla de particiones | media | abierto |
