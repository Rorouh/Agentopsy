# `tsk_mactime` — sobre `metasploitable2-linux/Metasploitable.raw`

- **Grupo:** B · **Imagen:** Metasploitable 2 (disco particionado real) · **Estado:** ✅ eficaz (destapó **Bug 004**, ya resuelto)
- **Binario:** `mactime` (Sleuthkit) · **Maletín:** `toolkit-unix`
- **run_ids:** bodyfile `5fbb427c` · mactime `d7c124aa`
- **Entrada:** bodyfile de `tsk_fls -m` sobre la raíz (offset 482397), 63.052 líneas.

## Objetivo (máxima expresión)

Timeline MAC(b) de un **sistema usado de verdad** — a diferencia del Grupo A (rootfs fabricado
de una vez), aquí debería haber **ventanas de actividad reales** (instalación, uso, apagado).

## 🐛 Destapó el Bug 004 (crash del exec-agent con no-UTF-8)

Primer intento por el dispatcher: falló con `RemoteDisconnected` (el maletín seguía healthy).
Causa: el exec-agent hacía `subprocess.run(text=True)` con **UTF-8 estricto**, y mactime
imprime **nombres de fichero no-UTF-8** de un disco real → `UnicodeDecodeError` → el hilo del
agente moría. Confirmado (`byte 0x9e`).

**Fix (regla de sesión):** `errors="replace"` en `exec_agent.py`; maletines reconstruidos.
Tras el fix, exit 0. Documentado en [Bug 004](../../../bugs/004-exec-agent-utf8-crash.md).
(Es un caso que el Grupo A no destapó: `strings`/`bulk_extractor` daban salida ASCII válida.)

## Resultado obtenido — exit 0

- **228.514 filas** de timeline.
- **Ventanas de actividad reales:**
  - `2008-03` → paquetes base **Ubuntu 8.04 (Hardy)**.
  - `2010-04-28` → **24.798 eventos** (gran ráfaga de setup del sistema).
  - `2012-05-20` → actividad del **build final de la VM** (clusters de miles; última marca
    `19:56:57` en `/var/lib/urandom/random-seed` = arranque/apagado).
  - `0000-00-00` → **60.923 eventos** con timestamp nulo (típico en ext: inodos sin todos los
    tiempos).

Esto es un sistema **con historia**, no fabricado de golpe — contraste directo con el DVWA
(una sola ráfaga de creación).

## Veredicto de eficacia

- **Muy eficaz** una vez resuelto el Bug 004: timeline completo con ventanas interpretables.
- Reveló una **fragilidad real de infraestructura** (Bug 004) que solo aparece con evidencia
  de disco real — justo el valor de probar el Grupo B.

## Lecciones para entrenar al agente

1. **`fls -m` → `mactime`** también aquí (mactime no lee la imagen).
2. **Interpreta las ventanas**: separa instalación (fechas antiguas homogéneas) de uso real
   (clusters posteriores) y del último evento (apagado). Ancla los hallazgos a esas marcas.
3. **`0000-00-00` no es un error**: son inodos sin timestamp completo; no los cuentes como
   actividad.
4. La salida de mactime puede ser **enorme** (24 MB / 228k filas): trátala como artefacto y
   acótala con `date_range` o `jq`/grep por ventana.

## Registro en el caso

- **Finding:** `7a422af2` — "Timeline de sistema usado: Hardy 2008 → setup 2010-04-28 → build 2012-05-20" (low), run `d7c124aa`.
- **Evidencia recopilada:** [`tsk_mactime/timeline-resumen.txt`](tsk_mactime/timeline-resumen.txt). CSV completo (228k filas) en el `ArtifactRun` `d7c124aa`.
