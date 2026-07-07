# Catálogo del maletín forense — FORENSIA

Inventario de herramientas contenedorizadas, agrupadas como en el documento de
alcance (sección 4.3). Todas son CLI gratuitas. Los contenedores son **Linux**;
analizan evidencias de Windows y de Unix-like sin ejecutar un SO Windows.

**Todas las herramientas se invocan igual**, lanzando el comando dentro del
maletín correspondiente:

```
docker compose exec <maletín> <herramienta> [argumentos]
#   <maletín>     = toolkit-windows  |  toolkit-unix
#   /evidence     = evidencias (solo lectura)
#   /cases        = proyectos y salidas (escritura)
```

Notas que aplican a los ejemplos:

- Las herramientas **Cross** existen en los dos maletines; abajo se muestran
  sobre `toolkit-windows`, pero funcionan idénticas en `toolkit-unix`.
- Cuando un ejemplo usa redirección `>`, se envuelve en `sh -c "..."` para que
  el fichero se escriba **dentro** del contenedor (en `/cases`) y no en el host.
- `qemu-nbd` y `guestmount` necesitan privilegios de montaje; el `docker-compose.yml`
  ya añade `SYS_ADMIN` y `/dev/fuse` a los servicios.

## Comunes (Cross) — presentes en ambos maletines

| Categoría | Herramienta | Comando(s) | Para qué |
|---|---|---|---|
| Imagen y montaje | libewf-tools (GIFT) | `ewfinfo`, `ewfmount` | Leer/montar imágenes E01 (EWF) |
| Imagen y montaje | QEMU | `qemu-nbd` | Exponer .vmdk/.qcow2/.raw como dispositivo de bloque |
| Imagen y montaje | libguestfs | `guestmount` | Montar los sistemas de ficheros de la imagen en solo lectura |
| Integridad / hashing | coreutils | `sha256sum` | Hash de integridad (cadena de custodia) |
| Integridad / hashing | md5deep | `hashdeep` | Hashing recursivo y verificación de conjuntos |
| Sistema de ficheros | The Sleuth Kit | `fls`, `icat`, `mmls`, `mactime` | Listar ficheros, extraer por inodo, particiones, timeline MAC |
| Carving | bulk_extractor | `bulk_extractor` | Extracción de features (correos, tarjetas, URLs...) |
| Carving | foremost | `foremost` | Recuperación de ficheros por cabeceras |
| Línea temporal | plaso | `log2timeline.py`, `psort.py` | Supertimeline forense |
| Memoria RAM | Volatility 3 | `vol` | Análisis de volcados de memoria |

Ejemplos (uno por herramienta):

```bash
# ewfinfo — metadatos de una imagen E01
docker compose exec toolkit-windows ewfinfo /evidence/disco.E01

# ewfmount — montar una E01 como /cases/raw/ewf1 (solo lectura)
docker compose exec toolkit-windows sh -c "mkdir -p /cases/raw && ewfmount /evidence/disco.E01 /cases/raw"

# qemu-nbd — exponer un .vmdk en solo lectura como /dev/nbd0
docker compose exec toolkit-windows qemu-nbd --read-only --connect=/dev/nbd0 /evidence/disco.vmdk

# guestmount — montar el FS de la imagen (inspección automática) en solo lectura
docker compose exec toolkit-windows sh -c "mkdir -p /cases/mnt && guestmount -a /evidence/disco.raw -i --ro /cases/mnt"

# sha256sum — hash de integridad de la evidencia
docker compose exec toolkit-windows sha256sum /evidence/disco.raw

# hashdeep — hashing recursivo SHA-256 de un árbol ya montado
docker compose exec toolkit-windows hashdeep -r -c sha256 /cases/mnt

# fls — listar ficheros (recursivo, con rutas)
docker compose exec toolkit-windows fls -r -p /evidence/disco.raw

# mmls — tabla de particiones de la imagen
docker compose exec toolkit-windows mmls /evidence/disco.raw

# icat — extraer un fichero por su inodo (ej. inodo 12345) a /cases
docker compose exec toolkit-windows sh -c "icat /evidence/disco.raw 12345 > /cases/fichero.bin"

# mactime — timeline MAC a partir de un bodyfile generado con fls -m
docker compose exec toolkit-windows sh -c "fls -r -m C: /evidence/disco.raw > /cases/bodyfile && mactime -b /cases/bodyfile -d > /cases/timeline_mac.csv"

# bulk_extractor — extraer features a /cases/be_out
docker compose exec toolkit-windows bulk_extractor -o /cases/be_out /evidence/disco.raw

# foremost — recuperar ficheros por carving a /cases/foremost_out
docker compose exec toolkit-windows foremost -i /evidence/disco.raw -o /cases/foremost_out

# log2timeline.py — generar la supertimeline (almacén .plaso)
docker compose exec toolkit-windows log2timeline.py --storage-file /cases/caso.plaso /evidence/disco.raw

# psort.py — exportar la timeline a CSV
docker compose exec toolkit-windows psort.py -o l2tcsv -w /cases/timeline.csv /cases/caso.plaso

# vol — listar procesos de un volcado de memoria Windows
docker compose exec toolkit-windows vol -f /evidence/memoria.raw windows.pslist
```

> *scalpel* se relega a extra: en Ubuntu se solapa con *foremost* (mismo
> propósito) y no siempre está empaquetado. Se puede añadir si se necesita.

## Artefactos Windows — maletín `toolkit-windows`

| Herramienta | Comando | Para qué | Reglas/datos |
|---|---|---|---|
| RegRipper 3.0 | `rip.pl` (alias `regripper`) | Parseo del registro con plugins | Plugins en `/opt/regripper/plugins` |
| hayabusa | `hayabusa` | Timeline y detección Sigma sobre EVTX | Reglas en `$HAYABUSA_RULES` |
| chainsaw | `chainsaw` | Búsqueda/hunt sobre EVTX + Sigma | Reglas `$CHAINSAW_RULES`, mapping `$CHAINSAW_MAPPING` |
| python-evtx | `evtx_dump` | Volcado de .evtx a XML | — |
| LnkParse3 | `lnkparse` | Parser de accesos directos .lnk | — |
| regipy | `regipy-dump` | Volcado/análisis del registro | — |
| windowsprefetch | `prefetch.py` | Parser de Prefetch (.pf) | — |
| pyhindsight | `hindsight.py` | Forense de navegadores Chromium/Chrome | — |

Ejemplos (uno por herramienta):

```bash
# rip.pl (RegRipper) — procesar la colmena SOFTWARE
docker compose exec toolkit-windows sh -c "rip.pl -r /evidence/Windows/System32/config/SOFTWARE -f software > /cases/software.txt"

# hayabusa — timeline de eventos con reglas Sigma a CSV
docker compose exec toolkit-windows hayabusa csv-timeline -d /evidence/Windows/System32/winevt/Logs -o /cases/hayabusa.csv -w

# chainsaw — hunt sobre EVTX con reglas + mapping Sigma
docker compose exec toolkit-windows chainsaw hunt /evidence/Logs -s "$CHAINSAW_RULES" --mapping "$CHAINSAW_MAPPING"

# evtx_dump — volcar un .evtx a XML
docker compose exec toolkit-windows sh -c "evtx_dump /evidence/Logs/Security.evtx > /cases/security.xml"

# lnkparse — analizar un acceso directo .lnk
docker compose exec toolkit-windows lnkparse /evidence/Users/jdoe/Recent/informe.lnk

# regipy-dump — volcar una colmena del registro a JSON
docker compose exec toolkit-windows sh -c "regipy-dump /evidence/Windows/System32/config/SYSTEM > /cases/system.json"

# prefetch.py — parsear un fichero Prefetch en formato CSV
docker compose exec toolkit-windows prefetch.py -c -f /evidence/Windows/Prefetch/CMD.EXE-12345678.pf

# hindsight.py — forense del navegador (perfil de Chrome montado)
docker compose exec toolkit-windows hindsight.py -i "/cases/mnt/Users/jdoe/AppData/Local/Google/Chrome/User Data/Default" -o /cases/hindsight
```

> **Defectos del self-test 2026-07-01 — CORREGIDOS y revalidados en Linux el
> 2026-07-04 (retest 0 FAIL con evidencia Win7):** `evtx_dump` (el wheel de PyPI
> `python-evtx==0.8.1` referencia un módulo `scripts` que no empaqueta) se
> sustituyó por un wrapper vendorizado en el Dockerfile sobre la librería
> `Evtx`; `hayabusa` (el binario gnu `v3.9.0` requiere GLIBC ≥ 2.38 y
> `ubuntu:22.04` trae 2.35) se cambió al build **musl** estático de la misma
> versión; y `hindsight.py` (`pyhindsight` importa `ccl_chromium_reader`, no
> publicado en PyPI) se resolvió instalando esa dependencia desde su repo git
> fijada por commit, lo que a su vez exigió actualizar pip en la imagen (el
> pip 22.0.2 de Ubuntu siembra el build-isolation con setuptools 59.6,
> anterior a PEP 621, y los paquetes solo-`pyproject.toml` construían como
> `UNKNOWN`).

## Artefactos Unix-like — maletín `toolkit-unix`

| Herramienta | Comando | Para qué |
|---|---|---|
| The Sleuth Kit (EXT/XFS) | `fls`, `icat`, `mmls` | Análisis de sistemas de ficheros Linux |
| journald | `journalctl --file=...` | Lectura de journals del sistema exportados |
| lnav | `lnav` | Navegación/análisis de `/var/log` |
| Texto plano | `rg`, `jq`, `less` | Búsqueda en logs, bash history, configuración |
| plaso / Volatility | `log2timeline.py`, `vol` | Timeline y memoria (comunes) |

Ejemplos (uno por herramienta):

```bash
# fls — listar ficheros de una imagen EXT/XFS
docker compose exec toolkit-unix fls -r -p /evidence/linux.raw

# journalctl — leer un journal exportado de la evidencia
docker compose exec toolkit-unix journalctl --file=/evidence/var/log/journal/SYSTEM.journal --no-pager

# lnav — analizar de forma no interactiva /var/log montado
docker compose exec toolkit-unix lnav -n /evidence/var/log

# rg — buscar autenticaciones fallidas/aceptadas en auth.log
docker compose exec toolkit-unix rg -n "Failed password|Accepted password" /evidence/var/log/auth.log

# jq — filtrar un log en formato JSON
docker compose exec toolkit-unix sh -c "jq '.[] | select(.level==\"error\")' /evidence/var/log/app.json"

# less — inspeccionar el historial de bash de un usuario
docker compose exec toolkit-unix less /evidence/home/jdoe/.bash_history

# log2timeline.py — supertimeline de la imagen Linux
docker compose exec toolkit-unix log2timeline.py --storage-file /cases/linux.plaso /evidence/linux.raw

# vol — análisis de memoria Linux (perfil por banner)
docker compose exec toolkit-unix vol -f /evidence/memoria_linux.lime linux.pslist
```

## Versiones fijadas

| Componente | Versión | Origen |
|---|---|---|
| Ubuntu (base) | 22.04 | imagen oficial |
| plaso / TSK / bulk_extractor / libewf | PPA `gift/stable` | repositorio GIFT |
| Volatility 3 | 2.28.0 | PyPI |
| hayabusa | 3.9.0 (build musl) | release GitHub (Yamato-Security) |
| chainsaw | 2.16.0 | release GitHub (WithSecureLabs) |
| pip (dentro de la imagen) | 26.1.2 | PyPI (sustituye al 22.0.2 de Ubuntu) |
| ccl_chromium_reader | commit `b51a01c` | repo git (cclgroupltd, sin tags) |

Las versiones de hayabusa, chainsaw y Volatility se pasan como `--build-arg`
desde `docker-compose.yml`; los binarios descargados se verifican por SHA-256
en el Dockerfile.
