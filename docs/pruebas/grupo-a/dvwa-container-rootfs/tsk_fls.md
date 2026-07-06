# `tsk_fls` — sobre `dvwa-container-rootfs/dvwa-disk.raw`

- **Grupo:** A · **Imagen:** DVWA docker rootfs (ext4 plano) · **Estado:** ✅ eficaz; ⚠️ **bug de parser** (ver Bug 002)
- **Binario:** `fls` (Sleuthkit) · **Maletín:** `toolkit-unix` (Cross)
- **run_ids:** recursivo `ddee03ec-1611-4c04-a19f-a927c69fd264` · borrados `ece39dab-acad-4ff7-a120-a6b9c2b3a6f2` · bodyfile `4ff7bdf2-eae2-4727-afed-0f387488d287`

## Objetivo (máxima expresión)

`fls` lista ficheros/directorios **sin montar** el FS (lectura a nivel de metadatos). Quería
exprimir sus tres capacidades clave: (1) el **árbol completo** recursivo, (2) los **ficheros
borrados** (recuperación / anti-forense), y (3) el **bodyfile** que alimenta el timeline
MAC(b) de `tsk_mactime`.

## Cómo la usé (3 pasadas)

| Pasada | Params | argv |
|--------|--------|------|
| Árbol completo | `recursive=true` | `fls -r <img>` |
| Solo borrados | `recursive=true, deleted_only=true` | `fls -r -d <img>` |
| Bodyfile (timeline) | `recursive=true, body_format=true` | `fls -m / -r <img>` |

## Resultado obtenido — exit 0 en las tres

- **Árbol completo:** el artefacto tiene **14.234 entradas** reales (`wc -l`). Inodes de
  interés localizados: `config.inc.php` (**inode 13552**, credenciales DVWA), `main.sh`
  (**1030**, entrypoint), `/etc/passwd` (**375**), `/etc/shadow` (**726**). → objetivos para
  `tsk_icat`.
- **Solo borrados:** **0 entradas**. Coherente: es un rootfs de contenedor exportado limpio,
  no un disco usado; no hay recuperación por metadatos aquí.
- **Bodyfile:** **14.234 líneas** en formato body → listo para `tsk_mactime`.

## ⚠️ Hallazgo de producto: el parser subcuenta (Bug 002)

`parsed.entries_count` de la pasada recursiva dio **22** (solo la raíz), no 14.234. Causa: el
regex del wrapper ancla el tipo al inicio de línea, y la salida recursiva de TSK prefija cada
línea con la profundidad (`+ r/r 14: bash`, `++++ r/r 13552: config.inc.php`). Solo casan las
~22 líneas de la raíz. **Documentado en [Bug 002](../../../bugs/002-tsk-fls-parser-recursivo-subcuenta.md).**

## Veredicto de eficacia

- **La herramienta es muy eficaz**: mapea el FS entero, localiza inodes de alto valor y
  produce el bodyfile del timeline, todo sin montar (cadena de custodia intacta).
- **El wrapper miente en el recuento recursivo** (Bug 002): el agente que se fíe de
  `entries_count` creerá que el sistema tiene 22 ficheros. Grave para el razonamiento.

## Lecciones para entrenar al agente

1. **No te fíes de `entries_count` en modo recursivo** (Bug 002): usa el `body_format:true`
   (`parsed.lines`) o `wc -l` del artefacto para el total real.
2. **Flujo canónico de disco:** `tsk_fls -r` para mapear + localizar inodes → `tsk_icat` por
   inode para extraer los ficheros de interés → `tsk_mactime` sobre el bodyfile para el
   timeline. No intentes volcar el árbol entero al contexto (14k líneas): trabájalo como
   artefacto y extrae inodes.
3. **`deleted_only` = 0 no es "no pasó nada"**: en un rootfs de contenedor es lo esperado; en
   un **disco usado** (Metasploitable/CFReDS) ahí aparecen los borrados recuperables — es una
   de las señales más valiosas.
4. **Genera el bodyfile pronto** (`body_format:true`): es la columna vertebral cronológica y
   lo consume `tsk_mactime` directamente.

## Registro en el caso

- **Findings:** `f0321b3c` (14.234 entradas + inodes clave, low) · `61fbc187` (sin borrados, low).
- **Evidencia recopilada:**
  - [`tsk_fls/bodyfile.txt`](tsk_fls/bodyfile.txt) — 14.234 líneas, alimenta `tsk_mactime`.
  - [`tsk_fls/inodes-clave.txt`](tsk_fls/inodes-clave.txt) — inodes de alto valor para `tsk_icat`.
