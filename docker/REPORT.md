# Self-test del maletín forense contenedorizado — FORENSIA

**Fecha:** 2026-07-01
**Evidencia:** colección KAPE real de Windows, montada en solo lectura desde
`F:/forense/gkape/D` → `/evidence/D` en ambos contenedores (override de compose,
sin tocar `docker-compose.yml` base).
**Imágenes:**

```
forensia/toolkit-unix:1.0      1a4900c2c6b5   1.08GB (reciente)
forensia/toolkit-windows:1.0   7d28431e4d5b   1.4GB  (reciente)
```

**Metodología:** cada comando se ejecutó con `docker compose exec -T` (sin TTY)
para capturar exit code y salida real. Cuando un flag fallaba se consultó el
`--help`/`help <subcomando>` de la propia herramienta y se reintentó **una vez**
con el flag corregido antes de marcar FAIL. La evidencia nunca se modificó (bind
`:ro`); toda salida se escribió en `/cases/_selftest` (`docker/projects/_selftest`
en el host).

> **Nota de entorno (host Windows):** el primer arranque falló porque
> `/evidence` ya es un bind-mount `:ro` de nivel superior y el runtime no puede
> crear el mountpoint `/evidence/D` dentro de un mount de solo lectura. Se
> resolvió pre-creando el directorio vacío `docker/evidence/D` en el host
> (mountpoint físico) antes del `up`. Además, `docker compose exec` vía Git Bash
> reescribe rutas POSIX absolutas (`/cases/...`) a rutas de Windows (MSYS path
> conversion); todos los comandos de este self-test se ejecutaron con
> `MSYS_NO_PATHCONV=1` para evitarlo.

## `forensia-info` — toolkit-windows

```
==================== FORENSIA — Maletín forense ====================
Stage: windows
-------------------------------------------------------------------
Herramientas comunes (Cross):
  sleuthkit (fls/icat/mmls/mactime) : /usr/bin/fls
  bulk_extractor                    : /usr/bin/bulk_extractor
  foremost                          : /usr/bin/foremost
  ewfmount (libewf)                 : /usr/bin/ewfmount
  qemu-nbd                          : /usr/bin/qemu-nbd
  guestmount                        : /usr/bin/guestmount
  hashdeep                          : /usr/bin/hashdeep
  sha256sum                         : /usr/bin/sha256sum
  log2timeline (plaso)              : /usr/bin/log2timeline.py
  psort (plaso)                     : /usr/bin/psort.py
  volatility3                       : /usr/local/bin/vol
Artefactos Windows:
  rip.pl (RegRipper)              : /usr/local/bin/rip.pl
  hayabusa                        : /usr/local/bin/hayabusa
  chainsaw                        : /usr/local/bin/chainsaw
  evtx_dump (python-evtx)         : /usr/local/bin/evtx_dump
  lnkparse (LnkParse3)            : /usr/local/bin/lnkparse
  regipy                          : /usr/local/bin/regipy-dump
  hindsight (navegadores)         : /usr/local/bin/hindsight.py
====================================================================
```

## `forensia-info` — toolkit-unix

```
==================== FORENSIA — Maletín forense ====================
Stage: unix
-------------------------------------------------------------------
Herramientas comunes (Cross):
  sleuthkit (fls/icat/mmls/mactime) : /usr/bin/fls
  bulk_extractor                    : /usr/bin/bulk_extractor
  foremost                          : /usr/bin/foremost
  ewfmount (libewf)                 : /usr/bin/ewfmount
  qemu-nbd                          : /usr/bin/qemu-nbd
  guestmount                        : /usr/bin/guestmount
  hashdeep                          : /usr/bin/hashdeep
  sha256sum                         : /usr/bin/sha256sum
  log2timeline (plaso)              : /usr/bin/log2timeline.py
  psort (plaso)                     : /usr/bin/psort.py
  volatility3                       : /usr/local/bin/vol
Artefactos Unix-like:
  journalctl                      : /usr/bin/journalctl
  lnav                            : /usr/bin/lnav
  TSK sobre EXT/XFS               : fls/icat (soporte EXT/XFS)
====================================================================
```

> **Importante:** `forensia-info` solo comprueba `command -v` (presencia en
> PATH). En este self-test, `evtx_dump` y `hindsight.py` aparecen como
> presentes pero **fallan al ejecutarse** (dependencias rotas — ver sección
> Fallos). `forensia-info` no detecta esto: es una comprobación de
> disponibilidad, no de funcionalidad. Recomendación para el equipo: considerar
> un smoke-test funcional (`--help`/`--version` con exit-code check) en el
> arranque del contenedor, no solo `command -v`.

---

## Tabla de resultados

| # | Herramienta | Maletín | Comando ejecutado | Exit | Resultado | Nota |
|---|---|---|---|---|---|---|
| 1 | sha256sum, hashdeep, fls, icat, mmls, mactime, bulk_extractor, foremost, ewfinfo, ewfmount, qemu-nbd, guestmount, log2timeline.py, psort.py, vol | ambos | `command -v <bin>` × 15 | 0 | **PASS** | Las 15 herramientas cross presentes en ambos maletines |
| 2 | rip.pl, hayabusa, chainsaw, evtx_dump, lnkparse, regipy-dump, prefetch.py, hindsight.py | windows | `command -v <bin>` × 8 | 0 | **PASS** | Las 8 presentes (disponibilidad únicamente, ver funcional abajo) |
| 3 | journalctl, lnav, rg, jq, less | unix | `command -v <bin>` × 5 | 0 | **PASS** | |
| 4 | sha256sum $MFT | unix | `sha256sum '/evidence/D/$MFT'` | 0 | **PASS** | `e62992590fead70208f2d445f023d318dc98b1c49d30746fc3179565696cc6bf` |
| 5 | sha256sum SYSTEM | unix | `sha256sum /evidence/D/Windows/System32/config/SYSTEM` | 0 | **PASS** | `ae0f03df5ed5961aed98cadc59fb85ddb47c1d89e08be7e16445f6e080c6b676` |
| 6 | hashdeep -r -c sha256 | unix | `hashdeep -r -c sha256 /evidence/D/Windows/System32/config > config_hashes.txt` | 0 | **PASS** | 23 ficheros hasheados |
| 7 | RegRipper (SYSTEM) | windows | `rip.pl -r .../SYSTEM -f system` | 0 | **PASS** | 4997 líneas; 2 avisos de plugin no encontrado (ver Fallos, no bloqueante) |
| 8 | RegRipper (SOFTWARE) | windows | `rip.pl -r .../SOFTWARE -f software` | 0 | **PASS** | 31430 líneas |
| 9 | RegRipper (Amcache) | windows | `rip.pl -r .../Amcache.hve -f amcache` | 0 | **PASS** | 777 líneas, InventoryApplicationFile parseado limpio |
| 10 | regipy-dump (SYSTEM) | windows | `regipy-dump /evidence/D/Windows/System32/config/SYSTEM` | 0 | **PASS** | Corregido durante el self-test (ver Fallos-corregidos); 22.6 MB de JSON |
| 11 | evtx_dump (Security.evtx) | windows | `evtx_dump .../Security.evtx` | 1 | **FAIL** | Defecto de empaquetado upstream de `python-evtx` 0.8.1 (ver Fallos) |
| 12 | hayabusa csv-timeline | windows | `hayabusa csv-timeline -d .../Logs -o .../hayabusa.csv` | — | **FAIL** | Binario no arranca: falta GLIBC 2.38/2.39 en Ubuntu 22.04 (ver Fallos) |
| 13 | chainsaw hunt | windows | `chainsaw hunt /opt/chainsaw-src/rules /evidence/D/Windows/System32/winevt/Logs -o /cases/_selftest/chainsaw --csv` | 0 | **PASS** | Flags corregidos (ver Fallos); 138 detecciones sobre 138 artefactos, 5 CSV generados |
| 14 | lnkparse (LNK con datos) | windows | `lnkparse 'CLIENTES DEL BANCO.xls.lnk'` | 0 | **PASS** | Metadatos completos (timestamps, target ID list) |
| 15 | prefetch.py | windows | `prefetch.py -c -f CMD.EXE-89305D47.pf` | 0 | **PASS** | CSV con RunCount=35 |
| 16 | hindsight.py --help | windows | `hindsight.py --help` | 1 | **FAIL** | Escalado desde SKIP planeado: crashea por dependencia no publicada en PyPI (ver Fallos) |
| 17 | bulk_extractor | unix | `bulk_extractor -o be_out2 /evidence/D/Windows/System32/config/SOFTWARE` | 0 | **PASS** | 23 emails, dominios extraídos |
| 18 | foremost | unix | `foremost -i .../SOFTWARE -o foremost_out2` | 0 | **PASS** | Ejecución correcta, 0 ficheros (esperado sobre una colmena de registro) |
| 19 | log2timeline.py | unix | `log2timeline.py --parsers 'winevtx,winreg,prefetch,lnk,mft' --storage-file case.plaso /evidence/D` | 0 | **PASS** | 9m08s, 3,339,441 eventos, storage 1.09 GB, 11 avisos no bloqueantes |
| 20 | psort.py | unix | `psort.py -o l2tcsv -w timeline.csv case.plaso` | 0 | **PASS** | 1,998,624 filas de timeline CSV |
| 21 | mmls -V / fls -V / icat -V / mactime -V / ewfinfo -V / vol -h | unix | disponibilidad | 0 | **PASS** | Los 6 binarios cargan correctamente |
| 22 | TSK smoke test (FIXTURE sintética) | unix | `dd` + `mkfs.ext4` + `fls -r` + `fls -r -m / \| mactime` + `icat` | 0 | **PASS** | Fixture ext4 de 16MB, no es evidencia real — ver nota |
| 23 | volatility3 (windows.info) | unix | *pendiente de evidencia* | — | **SKIP** | No hay memdump `.raw` en esta colección |
| 24 | mmls / fls -r -p (imagen real) | unix | *pendiente de evidencia* | — | **SKIP** | No hay imagen `.raw`/`.E01`; esta evidencia es un árbol de ficheros KAPE, no una imagen de disco |
| 25 | ewfinfo (E01 real) | unix | *pendiente de evidencia* | — | **SKIP** | No hay `.E01` en esta colección |

**Resumen:** 20 PASS · 3 FAIL · 3 SKIP (documentado) sobre 25 filas de la matriz
(las filas 1–3 agregan 28 binarios individuales, todos PASS).

---

## Fallos

### FAIL 1 — `evtx_dump` (python-evtx 0.8.1): defecto de empaquetado upstream

```
$ evtx_dump /evidence/D/Windows/System32/winevt/Logs/Security.evtx
Traceback (most recent call last):
  File "/usr/local/bin/evtx_dump", line 5, in <module>
    from scripts.evtx_dump import main
ModuleNotFoundError: No module named 'scripts'
```

**Causa raíz:** el wheel de PyPI `python-evtx==0.8.1` instala los
`console_scripts` (`evtx_dump`, `evtx_dump_json`, `evtx_info`, etc.) apuntando a
un paquete `scripts.*` que **no se incluye en el wheel** (solo se empaqueta la
librería `Evtx/`). Se probaron los 2 entrypoints alternativos
(`evtx_dump_json`) con idéntico fallo. No es un problema de flags: los
entrypoints están rotos de origen.
**Remediación recomendada:** o bien vendorizar el script `scripts/evtx_dump.py`
del repo de GitHub de Willi Ballenthin (como ya se hace con hayabusa/chainsaw),
o sustituir por un wrapper propio de ~10 líneas sobre `Evtx.Views`. Requiere
decisión de diseño — no se aplicó en este self-test.

### FAIL 2 — `hayabusa`: binario requiere GLIBC más reciente que la base

```
$ hayabusa help csv-timeline
hayabusa: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found (required by hayabusa)
hayabusa: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.39' not found (required by hayabusa)
```

**Causa raíz:** el release `hayabusa-3.9.0-lin-x64-gnu` está enlazado contra
GLIBC ≥ 2.39. La imagen base es `ubuntu:22.04` (GLIBC 2.35 — confirmado con
`ldd --version`). Incompatibilidad de versión pura, no relacionada con montaje
de evidencia ni con flags.
**Remediación recomendada:** el equipo debe decidir entre (a) fijar
`HAYABUSA_VERSION` a un release anterior compatible con GLIBC 2.35 (verificar
SHA256 del release elegido), o (b) subir `UBUNTU_VERSION` del stage `windows` a
`24.04` (GLIBC 2.39) — evaluando el impacto sobre el resto de paquetes
`apt`/PPA GIFT de ese stage. No se aplicó en este self-test por ser una
decisión de arquitectura.

### FAIL 3 — `hindsight.py`: dependencia no publicada en PyPI

```
$ hindsight.py --help
Traceback (most recent call last):
  File "/usr/local/bin/hindsight.py", line 21, in <module>
    from pyhindsight.analysis import AnalysisSession
  ...
  File "/usr/local/lib/python3.10/dist-packages/pyhindsight/browsers/chrome.py", line 18, in <module>
    import ccl_chromium_reader
ModuleNotFoundError: No module named 'ccl_chromium_reader'
```

**Causa raíz:** `pyhindsight-20260430` (versión "nightly" con fecha en el
nombre) importa `ccl_chromium_reader`, que **no está publicado en PyPI**
(comprobado `ccl_chromium_reader` y `ccl-chromium-reader`, ambos "No matching
distribution"). Tampoco está declarado en `Requires` del paquete
(`bottle, keyring, protobuf, puremagic, pycryptodomex, rich, tzdata,
xlsxwriter` — sin `ccl_chromium_reader`). El plan original era marcar esta
herramienta SKIP (sin artefactos de navegador en la evidencia), pero ni
siquiera `--help` arranca, así que se reclasifica como FAIL de disponibilidad
real.
**Remediación recomendada:** instalar `ccl_chromium_reader` desde su
repositorio git (`pip install git+https://github.com/cclgroupltd/ccl_chromium_reader@<tag>`)
o fijar una versión de `pyhindsight` anterior a que introdujera esa dependencia.
Decisión de diseño — no aplicada en este self-test.

---

## Fallos encontrados y corregidos durante el self-test

Estos 3 defectos bloqueaban por completo el arranque o varias herramientas del
maletín; se corrigieron en `docker/docker/forensic-toolkit/Dockerfile` y
`requirements-windows.txt` porque eran correcciones de una línea, verificables
con rebuild + retest, sin implicar decisiones de diseño:

1. **CRLF en los heredocs del Dockerfile → `forensia-info`, `forensia-hash` y
   el wrapper `rip.pl` rotos de raíz** (`exec: no such file or directory`,
   causado por `#!/bin/sh\r`). Origen: `core.autocrlf=true` en este host
   Windows reescribe el propio `Dockerfile` a CRLF al hacer checkout, y los
   heredocs (`cat > file <<'EOF'`) copian esos bytes literalmente al script
   generado. Corrección: `sed -i 's/\r$//'` tras cada heredoc, antes de
   `chmod +x`. Esto bloqueaba el 100% del self-test hasta corregirse.
2. **`regipy-dump` fallaba con `ModuleNotFoundError: No module named
   'tabulate'`** — dependencia real de `regipy.cli` no declarada en su
   metadata de PyPI (`Requires: construct, inflection, pytz`, sin
   `tabulate`). Corrección: se añadió `tabulate` a `requirements-windows.txt`.
3. **`hindsight.py` con permiso denegado (exit 126)** — pip instaló el script
   de `pyhindsight` sin bit `+x` (`-rw-r--r--`). Corrección:
   `chmod +x /usr/local/bin/hindsight.py` tras el `pip install`. (Tras este
   fix apareció el FAIL 3, más profundo — ver arriba.)

## Otros hallazgos no bloqueantes

- **RegRipper (SYSTEM):** 2 avisos `Can't locate .../plugins/crashcontrol.pl` y
  `.../printer_settings.pl` — plugins referenciados en la lista de RegRipper
  3.0 que no están presentes en el clon `--depth 1` del repo (probablemente
  renombrados/eliminados aguas arriba). No afecta al exit code ni al resto de
  plugins; documentado por completitud.
- **`chainsaw hunt`:** el flag sugerido inicialmente (`--csv
  /cases/_selftest/chainsaw`) es incorrecto — `--csv` es un flag booleano, no
  admite valor; el directorio de salida es `-o/--output`. Además el orden
  posicional es `[RULES] [PATH]...` (reglas primero, evidencia después), al
  revés de lo intuitivo. Con `-s "$CHAINSAW_RULES" --mapping
  "$CHAINSAW_MAPPING"` (reglas Sigma + mapping) no se encontraron reglas
  válidas porque `$CHAINSAW_RULES` apunta a las reglas **nativas** de chainsaw
  (formato propio, en `rules/evtx/*`), no a reglas Sigma — el repo clonado no
  trae un set de reglas Sigma independiente. Comando que funciona:
  `chainsaw hunt /opt/chainsaw-src/rules <PATH> -o <OUT> --csv`.

## Pendiente de evidencia

La colección KAPE usada es un **árbol de ficheros** (artefactos extraídos), no
una imagen de disco ni un volcado de memoria. Quedan SKIP funcional estos
comandos, listos para ejecutar en cuanto se disponga del insumo:

```bash
# Memoria (requiere un memdump .raw/.lime/.vmem)
docker compose exec -T toolkit-unix vol -f /evidence/<memdump>.raw windows.info

# Imagen de disco cruda (requiere .raw/.dd de un disco completo, no un árbol KAPE)
docker compose exec -T toolkit-unix mmls /evidence/<imagen>.raw
docker compose exec -T toolkit-unix fls -r -p /evidence/<imagen>.raw

# Imagen EWF/E01 (requiere un .E01 real)
docker compose exec -T toolkit-unix ewfinfo /evidence/<imagen>.E01
```

El smoke test sintético de TSK (`synth.raw`, ext4 de 16 MB creado con
`dd`+`mkfs.ext4`) confirma que la cadena `fls → bodyfile → mactime → icat`
funciona end-to-end sobre una imagen real montable — **no sustituye** la
validación contra una imagen/memdump de evidencia real.

---

## Artefactos generados

Todos en `docker/projects/_selftest/` (host) / `/cases/_selftest/` (contenedor):
`config_hashes.txt`, `rr_system.txt`, `rr_software.txt`, `rr_amcache.txt`,
`system.json` (regipy), `security.xml` (vacío, FAIL evtx_dump), `chainsaw/*.csv`,
`lnk.txt`, `prefetch.csv`, `hindsight_help.txt` (traceback), `be_out2/*`,
`foremost_out2/audit.txt`, `case.plaso` (1.09 GB), `timeline.csv` (1.16 GB,
1,998,624 filas), `synth.raw` + `bodyfile` + `synth_timeline.csv` +
`synth_icat.bin` (fixture TSK).

---

# Revalidación en Linux — 2026-07-04

**Entorno:** host Linux (kernel 6.1, Debian), Docker Engine **nativo** 29.5.2
(contexto `default`). La migración desde el host Windows del self-test original
motivó dos correcciones de entorno y la resolución de los 3 FAIL pendientes.

**Evidencia:** imagen de disco VMDK de Windows 7 (`IE11-Win7-VMWare-disk1.vmdk`)
servida en solo lectura con `qemu-nbd --read-only` y montada en `/mnt/vmdk`
(fuseblk `ro`); montada en los contenedores vía `FORENSIA_EVIDENCE_DIR=/mnt/vmdk`
→ `/evidence:ro`. **Integridad cruzada verificada:** el SHA-256 del hive
`SYSTEM` (`ae0f03df5ed5961aed98cadc59fb85ddb47c1d89e08be7e16445f6e080c6b676`)
coincide exactamente con el de la fila 5 del self-test original en Windows —
misma evidencia origen, sin alteración entre hosts. El bind es efectivamente
inmutable (`touch /evidence/test` → `Read-only file system`).

## Cambios aplicados y por qué

1. **Carpeta de evidencia configurable (diseño "carpeta única elegida por el
   usuario").** `docker-compose.yml` ahora monta
   `${FORENSIA_EVIDENCE_DIR:-./evidence}` en `/evidence:ro` y
   `${FORENSIA_CASES_DIR:-./projects}` en `/cases`. Se **eliminó**
   `docker-compose.override.yml`, que fijaba la ruta Windows absoluta
   `F:/forense/gkape/D` — inservible en Linux y contraria al diseño. La ruta
   del caso se define por variable de entorno o `.env` (ignorado por git).
2. **FAIL 1 — `evtx_dump`:** los entrypoints del wheel PyPI `python-evtx`
   apuntan a un paquete `scripts.*` que el wheel no incluye. Se eliminan los
   entrypoints rotos (`rm /usr/local/bin/evtx_*`) y se vendoriza en el
   Dockerfile un wrapper equivalente sobre la librería `Evtx` (sí empaquetada),
   como recomendaba este reporte.
3. **FAIL 2 — `hayabusa`:** se sustituye el binario `lin-x64-gnu` (exige
   GLIBC ≥ 2.38; `ubuntu:22.04` trae 2.35) por el build **`lin-x64-musl`**
   (enlazado estático, independiente de la libc de la base) de la **misma
   versión 3.9.0**, con nuevo SHA-256 verificado en el build
   (`c2fa65e4f255db17615c7c9d0acc9030c27db73f27b097499718930a48e420a3`).
   No hizo falta subir la base a 24.04 ni degradar la versión.
4. **FAIL 3 — `hindsight.py`:** `pyhindsight` declara `ccl_chromium_reader`
   como dependencia git directa en su `requirements.txt`, forma no publicable
   en la metadata de PyPI → pip nunca la instalaba. Se añade a
   `requirements-windows.txt` desde el repo oficial fijada por commit
   (`b51a01c`, 2026-06-08; el proyecto no publica tags); arrastra
   `ccl_simplesnappy` (también git).
5. **Causa raíz adicional descubierta al aplicar (4):** el `pip 22.0.2` de
   Ubuntu 22.04 (parcheado por Debian) siembra el *build isolation* con el
   `setuptools 59.6` del sistema (`/usr/share/python-wheels`), anterior a
   PEP 621: cualquier paquete que declare su metadata solo en `[project]` de
   `pyproject.toml` (caso de `ccl_chromium_reader`) construye como
   `UNKNOWN-0.0.0` y pip lo rechaza con el críptico
   `ccl-chromium-reader (unavailable) (from versions: none)`. Corrección:
   la imagen instala `pip==26.1.2` (ARG `PIP_VERSION`) antes de cualquier
   `pip install`.
6. **Notas de entorno Windows que ya no aplican en Linux:** ni MSYS path
   conversion ni pre-crear el mountpoint. El `sed 's/\r$//'` de los heredocs
   se conserva: protege los builds hechos desde un checkout con
   `core.autocrlf=true`.
7. **Advertencia operativa (Linux):** con Docker Desktop instalado junto al
   engine nativo, usar el contexto `default`. Docker Desktop también en Linux
   ejecuta los contenedores en una VM con file-sharing intermedio: rompe el
   invariante de soundness para montar evidencia y no cubre rutas fuera de
   `$HOME` (p. ej. `/mnt`). Documentado en `docker/README.md`.

## Resultados del retest (imágenes reconstruidas el 2026-07-04)

| # | Herramienta | Antes | Ahora | Verificación sobre la evidencia Win7 |
|---|---|---|---|---|
| 11 | evtx_dump (Security.evtx) | FAIL | **PASS** | exit 0; 282.742 líneas de XML (`/cases/_selftest_linux/security.xml`) |
| 12 | hayabusa csv-timeline | FAIL | **PASS** | `help` exit 0; timeline real: 1.033 filas CSV (493,7 KiB) en 7,1 s sobre `winevt/Logs` (comando validado: `csv-timeline -d <dir> -o <csv> -w`) |
| 16 | hindsight.py | FAIL | **PASS** | `--help` exit 0 con banner; `import ccl_chromium_reader, pyhindsight` OK (2026.04) |
| — | forensia-info (windows) | PASS | PASS | 18 herramientas resueltas en PATH |
| 7 | RegRipper (SYSTEM) | PASS | PASS | 4.997 líneas — mismo recuento que el self-test original |
| 10 | regipy-dump (SYSTEM) | PASS | PASS | 22,6 MB de JSON |
| 13 | chainsaw hunt | PASS | PASS | 138 detecciones sobre 138 artefactos |
| 15 | prefetch.py | PASS | PASS | CSV correcto (`AS_BASE.EXE`, RunCount=1) |
| 4/5 | forensia-hash / sha256sum | PASS | PASS | hash de SYSTEM idéntico al self-test original (integridad entre hosts) |
| 21 | vol / log2timeline / psort | PASS | PASS | `vol -h` OK; plaso 20240308 |
| 24 | mmls / fls -r -p (imagen real) | SKIP | **PASS** | ver abajo — SKIP cerrado con copia `.raw` de la evidencia |

**Fila 24 cerrada (antes SKIP por falta de imagen de disco):** se generó una
copia de trabajo `.raw` desde el `.vmdk` (`qemu-img convert -O raw`, la
evidencia original nunca se tocó) en `docker/evidence/win7.raw` (40 GiB
lógicos / 20,4 GiB de datos, fichero sparse, carpeta ignorada por git).
Cadena aplicada dentro de `toolkit-unix` sobre bind `:ro`:

```
forensia-hash /evidence/win7.raw   → 79b351b3be9c7170ffeb43b682800356896edfad71009e3a738dc98ef1c9bcac (baseline)
mmls  /evidence/win7.raw           → exit 0; tabla DOS, NTFS en sector 2048 (0x07, 83.881.984 sectores)
fls -o 2048 -r -p /evidence/win7.raw → exit 0; 281.902 entradas (17.943 bajo Windows/System32)
```

Quedan SKIP solo las filas 23 (memdump) y 25 (`.E01`), pendientes de insumo.

**Resumen tras la revalidación: 0 FAIL.**

Artefactos del retest en `docker/projects/_selftest_linux/` (host) /
`/cases/_selftest_linux/` (contenedor): `security.xml`, `hayabusa.csv`,
`chainsaw/*.csv`, `hindsight_help.txt`, `fls_win7.txt`.
