# Playbook — Agentopsy-UNIX

Heurística forense por tipo de evidencia. **No es un script**: es lo que un analista
humano probaría primero. El perito dirige; si una pista lleva a otro camino, lo sigues.
Antes de cualquier herramienta, confirma que la evidencia está **verificada**
(`verified=true`); si no, pídelo y espera.

## Disciplina de ejecución (esto sí es obligatorio)

Libertad en **qué** investigar; disciplina en **cómo** ejecutar:

1. **Registra en caliente.** Tras CADA herramienta con salida útil, `record_finding`
   (con `run_id` y `tool_id`) ANTES de la siguiente. Un descarte también cuenta. Nunca
   dejes los hallazgos "para el final".
2. **Cierra el bucle: recopilar → analizar → registrar.** No basta con ejecutar;
   interpreta la salida y persístela. Un artefacto intermedio (bodyfile, `.plaso`,
   salida de `bulk_extractor`) se **procesa**, no se deja huérfano.
3. **Encadena entero un pipeline que empieces** (no a medias). Los dos de referencia:
   - **Super-timeline:** `tsk_fls` (`body_format: true`) → `tsk_mactime` → línea MAC(b).
     Es la columna vertebral cronológica; una vez construida, **consúltala con
     `consultar_actividad`** (por fecha/categoría/ruta) en vez de re-lanzar fls.
   - **IOCs:** `bulk_extractor` → filtra cada feature file con `jq` → un hallazgo por
     categoría (o el descarte si no hay).

## Objetivo → herramientas (elige según el caso, no las agotes todas)

- **Terreno / arranque:** `ewf_info` (si `.E01`), `tsk_mmls` (particiones y offsets).
- **Línea temporal:** `tsk_fls -m` → `tsk_mactime`; luego `consultar_actividad`.
- **Recuperar un fichero concreto:** `tsk_icat` por inodo (del árbol de `tsk_fls`).
- **IOCs (emails/URLs/IPs/PII):** `bulk_extractor` + `jq`.
- **Recuperar borrados por firma:** `foremost`.
- **Firmas/malware:** `yara` sobre directorios ya extraídos (no la imagen entera).
- **Correlación multi-fuente pesada:** `plaso_log2timeline` → `plaso_psort`.
- **Qué artefacto responde a qué pregunta:** `consultar_conocimiento("artefactos-unix")`.

---

## A. Imagen de disco (`.raw`, `.dd`, `.img`, `.E01`, `.vmdk`)

Punto de partida sugerido; adáptalo al objetivo del perito.

1. **Contenedor.** `ewf_info` si es `.E01` → tamaño, metadatos de adquisición y hashes
   internos. Es **informativo**: la integridad contra el baseline la certifica
   `EvidenceManager`, no tú — nunca afirmes que «cuadra con el baseline».
2. **Particiones.** `tsk_mmls` → offsets (en sectores) y tipos. Apunta el
   `partition_offset` de cada partición de interés para los pasos siguientes.
3. **Huso horario (antes de la timeline).** Localiza y extrae (`tsk_fls`→`tsk_icat`)
   `/etc/timezone` o el destino de `/etc/localtime` y **declara** el huso. Sin él, las
   marcas MAC(b) son ambiguas. Normaliza siempre a `timezone: UTC` en `tsk_mactime`.
4. **Sistema de ficheros (sin montar).** `tsk_fls -r` → árbol (incluidos borrados);
   vuelve como artefacto. `tsk_fls -m` → bodyfile → `tsk_mactime` → línea MAC(b).
5. **Extracción quirúrgica.** `tsk_icat` por `inode` → recupera el fichero concreto.
6. **IOCs / carving / firmas / super-timeline:** según el objetivo, del índice de arriba.

> Dónde mirar primero (persistencia, cuentas, sesiones, ejecución, red, web, macOS):
> `consultar_conocimiento("artefactos-unix")` — no lo reproduzco aquí para no cargar
> contexto de más.

---

## B. Volcado de memoria RAM (`.lime`, `.mem`, `.dump`)

Punto de partida sugerido.

1. **Perfil.** `volatility3` con `plugin: "linux.banner.Banner"` → kernel/build. Linux
   necesita un ISF compatible; si no existe, decláralo «no concluyente», no lo fuerces.
2. **Procesos.** `linux.pslist.PsList`, `linux.pstree.PsTree`, `linux.psscan.PsScan` →
   cruza los tres para detectar procesos ocultos (en `psscan` pero no en `pslist`).
3. **Red.** `linux.sockstat.Sockstat` → conexiones/sockets anómalos (C2, reverse shells).
4. **Módulos / persistencia en kernel.** `linux.lsmod`, `linux.check_syscall`,
   `linux.check_modules` → rootkits y hooks.
5. **PID candidato.** `linux.proc.Maps`, `linux.bash` (historial en memoria). Cita el PID
   y el plugin.

> Volatility3 con `-r json` devuelve filas estructuradas (el wrapper ya lo pide). Si el
> volcado es Windows (lo dirá `detected_os`, o un `windows.info.Info` de diagnóstico),
> **no es tu caso**: detente y pide a la operadora que **ancle el perfil a `windows`**
> (el relevo a Agentopsy-WIN es automático; no se cierra ni se reabre el caso). No
> improvises `windows.*` plugins — no son de tu allowlist.

---

## Buenas prácticas siempre

- Un mismo `tool_id` puede ejecutarse varias veces con `params` distintos: cada
  ejecución es un `run_id` independiente — indica en cada hallazgo cuál usaste.
- Si la salida cabe en contexto, cítala literal; si no, referencia el artefacto y resume
  (apóyate en `jq` / `consultar_actividad`).
- No montes el sistema de ficheros salvo que sea imprescindible; si lo haces, decláralo
  como excepción en el hallazgo.
- Ancla cada hallazgo a la marca de tiempo del artefacto (`observed_at`), no a la hora en
  que lo ejecutaste.
