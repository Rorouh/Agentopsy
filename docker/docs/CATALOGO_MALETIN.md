# Catálogo del maletín forense — Agentopsy

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
  ya añade `SYS_ADMIN` y `/dev/fuse` a los servicios. Los dos son de uso MANUAL:
  el agente no los puede pedir (ver «Dos ejes» más arriba).

## Dos ejes: estar en el maletín no es estar en el catálogo

Este documento inventaria lo que las imágenes **instalan**. Es un eje distinto de
lo que el **agente puede pedir**, que es el catálogo del backend
(`backend/forensia/toolkit/catalog.py`, hoy 32 tools). Un binario puede estar
instalado y no expuesto, y eso casi siempre es deliberado.

Para que una tool sea pedible por el agente hacen falta cuatro piezas, y si falta
una la tool es invisible aunque el binario esté en la imagen: entrada en
`catalog.py`, envoltorio en `toolkit/wrappers/`, schema Pydantic en
`mcp/schemas.py` y JSON Schema en `agent/tool_schemas.py`.
`tests/test_catalog_integrity.py` lo fija: una tool permitida sin schema falla el
CI en vez de desaparecer en silencio.

### Instalado y NO expuesto, a propósito

La lista canónica, con una línea de motivo por binario, vive en el bloque de
comentario **«INSTALADO EN EL MALETÍN Y FUERA DEL CATÁLOGO, A PROPÓSITO»** de
`catalog.py`, junto a la definición del catálogo. Resumen:

| Binario(s) | Motivo de la exclusión |
|---|---|
| `guestmount` | Monta el sistema de ficheros de la evidencia: viola el invariante forense 3 |
| `guestfish`, los ~25 `virt-*` | Peor: `virt-copy-in`, `virt-customize` y `virt-sysprep` ESCRIBEN en la imagen. Los arrastra `libguestfs-tools` |
| `ewfmount`, `qemu-storage-daemon` | Son el mecanismo interno de `forensia.triage_deep`; exponerlos abriría la imagen fuera del control de `EvidenceManager` |
| `sha256sum` | El hash-gate lo hace `EvidenceManager` en proceso |
| `evtx_dump` | Redunda con `evtxecmd` (EvtxECmd, que además aplica sus `Maps/`) |
| `lnkparse` | Redunda con `lecmd` (LECmd) |
| `regipy-*` | Redunda con `recmd` (RECmd) y `regripper` |
| `md5deep`, `sha1deep`, `sha256deep`... | Mismo binario que `hashdeep` con otro nombre |
| `psteal.py` | log2timeline + psort en un paso; ya cubierto y menos controlable |
| `bstrings` | En Linux solo procesa por stdin, y el exec-agent ejecuta argv sin shell (invariante de seguridad 4) |
| `rg`, `less`, `lnav`, `journalctl`, `qemu-img`, `dumpe2fs`, `debugfs`, `xfs_db`, `volshell`, `yarac` | Utilidad de operador, interactivas o sin valor pericial propio |
| `qemu-nbd` | SÍ está en el catálogo, pero `side_effecting` y sin schema: conecta dispositivos de bloque y se opera a mano |

Reconocidas como deuda, no como exclusión: `fsstat` (tipo de sistema de ficheros,
tamaño de sector y clúster, número de serie del volumen, última vez montado),
`ewfverify` (contrasta el hash interno del EWF con el que escribió quien
adquirió), y `ntfsundelete` / `usnjls` / `ils` para borrados.

## Comunes (Cross) — presentes en ambos maletines

| Categoría | Herramienta | Comando(s) | Para qué |
|---|---|---|---|
| Imagen y montaje | libewf-tools (GIFT) | `ewfinfo`, `ewfmount` | Leer/montar imágenes E01 (EWF) |
| Imagen y montaje | FTK Imager CLI (AccessData) | `ftkimager` | Crear/convertir imágenes raw↔E01/SMART con verificación MD5/SHA1 (también en el catálogo del backend — invocable por el agente) |
| Imagen y montaje | aff4imager (Velocidex c-aff4) | `aff4imager` | Volúmenes AFF4 (volcados WinPmem 3.x/linpmem): listar streams y exportarlos a raw para Volatility3 (también en el catálogo del backend). WinPmem en sí NO se empaqueta: es adquisición en vivo |
| Imagen y montaje | QEMU | `qemu-nbd` | Exponer .vmdk/.qcow2/.raw como dispositivo de bloque |
| Imagen y montaje | libguestfs | `guestmount` | Montar los sistemas de ficheros de la imagen en solo lectura |
| Integridad / hashing | coreutils | `sha256sum` | Hash de integridad (cadena de custodia) |
| Integridad / hashing | md5deep | `hashdeep` | Hashing recursivo y verificación de conjuntos |
| Sistema de ficheros | The Sleuth Kit | `fls`, `icat`, `mmls`, `mactime`, `tsk_recover` | Listar ficheros, extraer por inodo, particiones, timeline MAC, y recuperar un ÁRBOL de ficheros completo |
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

# ftkimager — convertir una imagen E01 a raw (dd) con verificación de hash
#   (la fuente puede ser dispositivo, imagen soportada o `-` para stdin; sin
#    destino, el raw sale por stdout. --print-info muestra los metadatos.)
docker compose exec toolkit-windows ftkimager /evidence/disco.E01 /cases/disco_raw --verify

# ftkimager — empaquetar una imagen raw como E01 comprimido con metadatos de caso
docker compose exec toolkit-windows ftkimager /evidence/disco.raw /cases/disco --e01 --compress 6 --case-number CASO-001 --evidence-number E-01 --examiner "Perito" --verify

# aff4imager — listar los streams de un volcado AFF4 (p. ej. de WinPmem 3.x)…
docker compose exec toolkit-windows aff4imager -l /evidence/mem.aff4
# …y exportar el stream de memoria física (URN del listado) a raw para Volatility3
docker compose exec toolkit-windows aff4imager -e "aff4://<uuid>/PhysicalMemory" -D /cases /evidence/mem.aff4

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

# tsk_recover — recuperar un DIRECTORIO entero (no un fichero) preservando el árbol.
# OJO al -d: `fls` imprime el directorio como `d/d 68-144-6:`, pero tsk_recover quiere
# SOLO el número. Con la forma completa recupera CERO ficheros y sale con 0, o sea un
# vacío silencioso (medido sobre 2020JimmyWilson.E01: 0 frente a los 27 reales).
docker compose exec toolkit-unix tsk_recover -o 65664 -a -d 68 /evidence/disco.raw /cases/perfil

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
| pyhindsight | `hindsight.py` | Forense de navegadores Chromium/Chrome | **En el catálogo desde 2026-09-03: `hindsight`, invocable por el agente** |

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

# hindsight.py — forense del navegador sobre un perfil YA EXTRAÍDO
# (el mismo argv que compone el envoltorio del catálogo: `-l` y `--temp_dir` van
#  fijados porque por defecto hindsight los escribe junto a su propio script, en
#  /usr/local/bin/, o sea fuera del caso)
docker compose exec toolkit-windows hindsight.py \
  -i /cases/<caso>/artifacts/<run>/out/recovered \
  -o /cases/<caso>/artifacts/<run>/out/navegacion -f sqlite \
  -l /cases/<caso>/artifacts/<run>/out/hindsight.log \
  --temp_dir /cases/<caso>/artifacts/<run>/out/hindsight-temp
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

### `hindsight`, la primera tool de navegador del catálogo (2026-09-03)

`hindsight.py` llevaba en el maletín desde el principio y estaba fuera del
catálogo, así que el agente no tenía NINGUNA herramienta de navegador: el ejemplo
canónico del encargo, «recopila toda la información de navegación web del usuario
entre dos fechas», no se podía resolver. Ahora sí.

Consume un DIRECTORIO de perfil, no un fichero, y su parámetro de ruta es
`DERIVED_INPUT` **y solo eso**: llega como `ArtifactRef` de una corrida previa que
el dispatcher resuelve y **re-hashea entero** antes de ejecutar. Nunca una ruta
libre. Su productor es `tsk_recover`. La cadena completa:

```
tsk_mmls                      -> offset de la partición
tsk_fls    -o <off> -r        -> localiza el perfil y su inodo
tsk_recover -o <off> -d <ino> -> el ÁRBOL, en out/recovered/
hindsight  profile_dir={run_id, relpath}
```

Verificada de punta a punta sobre `2020JimmyWilson.E01`: 27 ficheros recuperados
del perfil Firefox de «Jimmy Wilson» y 16 URLs visitadas con su marca de tiempo,
13 marcadores y 109 preferencias.

**La custodia de un árbol derivado.** El manifiesto del artifact-store es por
FICHERO, así que un directorio no es una entrada suya: es el prefijo común de
varias. `ArtifactStore.resolve_output_dir` re-hashea TODAS las entradas bajo el
prefijo, las compara una a una con el manifiesto y devuelve un digest DEL
SUBÁRBOL (SHA-256 de los pares ruta + hash ordenados), que es lo que viaja al log
encadenado. El dispatcher elige fichero o directorio por el `PathKind` que el
catálogo DECLARA, nunca probando uno y cayendo al otro (RULE 2).

Tres banderas las fija el envoltorio en vez de exponerlas, y las tres se midieron
contra hindsight 2026.06 dentro del maletín:

- `-l` (log). A su aire escribe `/usr/local/bin/hindsight.log`, junto a su propio
  script: fuera del caso, fuera del log encadenado y en una ruta que el
  artifact-store no hashea. Se fija dentro del `out/` de la corrida.
- `--temp_dir`. Mismo defecto y mismo sitio (`/usr/local/bin/hindsight-temp`), y
  pesa más: hindsight COPIA el perfil antes de abrirlo, así que ese directorio
  tiene los bytes que de verdad se parsean. También se fija dentro del `out/`.
- `--nocopy` NO se ofrece. Es la bandera que apaga esa copia protectora, y abrir
  en su sitio una base SQLite de Chromium puede reproducir su WAL y ESCRIBIR en
  el fichero: sobre un artefacto derivado eso rompe el hash que el dispatcher
  acaba de verificar.

Quedan fuera además `-d/--decrypt`, cuya propia ayuda llama «buggy» a sus dos
modos y que solo tiene sentido ejecutando en la misma máquina de la que salieron
los datos (nunca un contenedor post-mortem), y `-t/--timezone`, que solo mueve
las marcas de DISPLAY del xlsx: los hallazgos llevan `observed_at` en UTC con
desfase explícito, y dejar que el modelo elija una zona de presentación aquí
invita a una conversión equivocada que no se ve desde el artefacto.

El formato por defecto es **`sqlite`**, y el motivo está medido, no es de estilo:
sobre el perfil Firefox real, el escritor `jsonl` emitió 123 filas y **ninguna era
de navegación**, mientras que el `sqlite` traía las 16 URLs visitadas con su marca
de tiempo en la tabla `timeline`. Con `jsonl` por defecto la herramienta habría
parecido funcionar tirando justo lo que existe para producir.

**pyhindsight y Python 3.10.** La versión 2026.06 usa `datetime.UTC` en once
sitios, y esa constante existe a partir de Python 3.11; la base del maletín es
Ubuntu 22.04, que trae 3.10. El paquete declara `requires-python >=3.9`, así que
pip lo instala sin protestar y REVIENTA al fechar el primer registro, con
`--help` respondiendo y `capabilities` dándolo por disponible: no parsea ni una
fila de navegación. El Dockerfile repone el alias con un `.pth` condicionado: en
CPython `datetime.UTC` **es** `datetime.timezone.utc` (el mismo objeto), así que
no cambia comportamiento, y en una base con 3.11+ queda en no-op. Es un `.pth` y
no un `sitecustomize.py` porque Ubuntu ya trae el suyo (el hook de apport), que
ganaría el import y dejaría el nuestro muerto sin avisar.

## EZ Tools (herramientas de los *Modules* de KAPE) — maletín `toolkit-windows`

Suite de Eric Zimmerman (.NET, builds `net9` del CDN oficial
`download.ericzimmermanstools.com`): los parsers que los *Modules* de KAPE
ejecutan sobre artefactos ya extraídos. Cada zip se despliega en
`/opt/eztools/<Tool>/` conservando su estructura interna (`Maps/` de EvtxECmd,
`BatchExamples/` de RECmd) y se envuelve en un wrapper en minúsculas en el
PATH; `EvtxECmd` y `MFTECmd` conservan además el nombre capitalizado que
resuelve el catálogo del backend. El SHA-256 de cada zip y la versión
desplegada quedan registrados en la imagen (`/opt/eztools/VERSIONS.txt`) y
pinneados como `ARG *_SHA256` en el Dockerfile (el build falla en claro si el
CDN publica una versión nueva — re-pinnear, igual que hayabusa/chainsaw).

> **Fuera de alcance — adquisición:** `KAPE.exe` y los *Targets* (recolección)
> NO se incluyen: son adquisición en vivo y Agentopsy es post-mortem; solo
> entran los parsers que consumen artefactos ya extraídos.
>
> **Excluidas por plataforma (verificado 2026-07-07, build 2026.5.0):**
> **PECmd** y **SrumECmd** abortan al arrancar en Linux («Non-Windows platforms
> not supported due to the need to load decompression|ESI specific Windows
> libraries!») porque cargan librerías nativas de Windows (descompresión
> Xpress vía ntdll / motor ESENT). No se despliegan en el maletín; sus
> artefactos siguen cubiertos: **Prefetch** → `prefetch.py` (windowsprefetch)
> y **SRUDB.dat** → el parser `srum` de plaso (`log2timeline.py`).
>
> **Catálogo del backend:** las once están en el maletín para uso manual; ocho
> (`lecmd`, `jlecmd`, `recmd`, `amcacheparser`, `appcompatcacheparser`,
> `sbecmd`, `wxtcmd`, `rbcmd`) están además en el catálogo del backend
> (`backend/forensia/toolkit/catalog.py`, tier extended) y son invocables por
> el agente — igual que `evtxecmd`/`mftecmd` (core). **`bstrings` queda fuera
> del catálogo**: en Linux solo procesa por stdin y el canal exec-agent
> ejecuta argv sin shell (sin tuberías) — herramienta de uso manual.

| Herramienta | Comando | Artefacto |
|---|---|---|
| MFTECmd | `mftecmd` (alias `MFTECmd`) | `$MFT`, `$J` ($UsnJrnl), `$Boot`, `$SDS` |
| EvtxECmd | `evtxecmd` (alias `EvtxECmd`) | `winevt/Logs/*.evtx` (con sus `Maps/`) |
| LECmd | `lecmd` | Accesos directos `*.lnk` |
| JLECmd | `jlecmd` | Jump Lists (`*Destinations-ms` de `Recent/`) |
| RECmd | `recmd` | Hives del registro (batch en `BatchExamples/`) |
| AmcacheParser | `amcacheparser` | `Amcache.hve` |
| AppCompatCacheParser | `appcompatcacheparser` | ShimCache (hive `SYSTEM`) |
| SBECmd | `sbecmd` | ShellBags (`UsrClass.dat` / `NTUSER.DAT`) |
| WxTCmd | `wxtcmd` | `ActivitiesCache.db` (Windows Timeline) |
| RBCmd | `rbcmd` | `$Recycle.Bin` (ficheros `$I`) |
| bstrings | `bstrings` (input por **stdin** en Linux) | strings avanzado (regex predefinidas) sobre cualquier fichero |

Ejemplos (uno por herramienta, sobre una colección KAPE montada en
`/evidence/D`; las salidas CSV van a `/cases`):

```bash
# mftecmd — parsear la $MFT a CSV (comillas: el $ va escapado dentro del sh -c)
docker compose exec toolkit-windows sh -c 'mftecmd -f "/evidence/D/\$MFT" --csv /cases --csvf mft.csv'

# evtxecmd — parsear un EVTX a CSV (aplica sus Maps/ automáticamente)
docker compose exec toolkit-windows sh -c 'evtxecmd -f /evidence/D/Windows/System32/winevt/Logs/Security.evtx --csv /cases --csvf security.csv'

# lecmd — analizar un acceso directo .lnk
docker compose exec toolkit-windows lecmd -f "/evidence/D/Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent/CLIENTES DEL BANCO.xls.lnk"

# jlecmd — Jump Lists (Automatic/CustomDestinations) de la carpeta Recent del usuario
docker compose exec toolkit-windows jlecmd -d /evidence/D/Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent --csv /cases

# recmd — hives del registro con un batch de ejemplo (Kroll)
docker compose exec toolkit-windows recmd --bn /opt/eztools/RECmd/RECmd/BatchExamples/Kroll_Batch.reb -f /evidence/D/Windows/System32/config/SOFTWARE --csv /cases

# amcacheparser — Amcache.hve (con -i incluye entradas de ficheros de programas)
docker compose exec toolkit-windows amcacheparser -f /evidence/D/Windows/AppCompat/Programs/Amcache.hve --csv /cases -i

# appcompatcacheparser — ShimCache desde el hive SYSTEM
docker compose exec toolkit-windows appcompatcacheparser -f /evidence/D/Windows/System32/config/SYSTEM --csv /cases

# sbecmd — ShellBags de las UsrClass.dat/NTUSER.DAT que haya bajo el directorio
docker compose exec toolkit-windows sbecmd -d /evidence/D/Users/IEUser/AppData/Local/Microsoft/Windows --csv /cases

# wxtcmd — Windows Timeline (ActivitiesCache.db; Win10 1803+ — no existe en Win7)
docker compose exec toolkit-windows wxtcmd -f "/evidence/D/Users/IEUser/AppData/Local/ConnectedDevicesPlatform/L.IEUser/ActivitiesCache.db" --csv /cases

# rbcmd — papelera de reciclaje: ficheros $I del volumen
docker compose exec toolkit-windows sh -c 'rbcmd -d "/evidence/D/\$Recycle.Bin" --csv /cases'

# bstrings — strings avanzado con regex predefinida (URLs) sobre un artefacto.
# En Linux el fichero entra por stdin: los modos -f/-d del build 2026.5.0 no
# procesan en no-Windows (imprimen "input from stdin or file" y salen con 0).
docker compose exec toolkit-windows sh -c 'cat /evidence/D/Windows/System32/config/SYSTEM | bstrings --lr url3986 -o /cases/system_urls.txt'
```

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
| FTK Imager CLI | 3.1.1 ubuntu64 (último CLI publicado para Linux; freeware, se descarga en el build — sin redistribución) | CDN oficial AccessData (CloudFront), SHA-256 pinneado |
| aff4imager | 1.0.rc1 (último binario Linux publicado por Velocidex; casi estático) | release GitHub (Velocidex/c-aff4), SHA-256 pinneado |
| .NET runtime (stage `windows`) | canal 9.0 (`dotnet-install.sh`) | dot.net (Microsoft) |
| EZ Tools (suite Eric Zimmerman, 11 tools) | 2026.5.0 (builds net9 «latest» del CDN; SHA-256 pinneado por `ARG` y registrado con la versión en `/opt/eztools/VERSIONS.txt`) | download.ericzimmermanstools.com |

Las versiones de hayabusa, chainsaw y Volatility se pasan como `--build-arg`
desde `docker-compose.yml`; los binarios descargados (hayabusa, chainsaw y los
zips de las EZ Tools) se verifican por SHA-256 en el Dockerfile.
