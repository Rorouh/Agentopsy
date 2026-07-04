# Prompt para Claude Code — Self-test del maletín forense (docker/)

> Copia TODO el bloque de abajo y pégalo en Claude Code, con el repositorio
> FORENSIA abierto. Está pensado para el enfoque `docker/` (compose +
> `toolkit-windows` / `toolkit-unix`).
>
> Evidencia de prueba: colección **KAPE** (árbol de ficheros ya extraído de un
> Windows 10, usuarios `IEUser` / `sshd_server`) en `F:\forense\gkape\D`.
> **No hay imagen `.raw`/`.E01` ni volcado de memoria**, así que las tools de
> imagen/memoria se prueban solo a nivel de disponibilidad + un smoke test
> sintético; las de artefactos Windows se prueban con rutas reales.

---

```
Actúa como ingeniero de forense/DevOps. Vas a hacer un SELF-TEST completo del
maletín forense contenedorizado que vive en la carpeta `docker/` de este repo
(enfoque compose: servicios `toolkit-windows` y `toolkit-unix`). El objetivo es
comprobar, HERRAMIENTA POR HERRAMIENTA y por comando real, que el maletín está
bien construido, usando como evidencia una colección KAPE real de Windows.

## Reglas duras
- NO modifiques la evidencia. Se monta en SOLO LECTURA. Toda salida va a `/cases`
  (carpeta `docker/projects` en el host).
- Ejecuta los comandos con `docker compose exec -T` (sin TTY) para poder capturar
  exit codes y salida.
- Para cada test registra: comando, exit code, y las primeras ~15 líneas de salida
  (o el error). Clasifica cada tool como PASS / FAIL / SKIP(con motivo).
- Si un flag falla, ejecuta el `--help`/`help <subcomando>` de esa tool, corrige
  el flag y reintenta UNA vez antes de marcar FAIL.
- Ojo con el shell: las rutas con `$` (p. ej. `$MFT`, `$Extend/$J`) y con espacios
  deben ir entre comillas SIMPLES para que el shell del contenedor no expanda
  variables. Las variables de entorno de reglas (`$HAYABUSA_RULES`,
  `$CHAINSAW_RULES`, `$CHAINSAW_MAPPING`) sí deben resolverse DENTRO del
  contenedor: úsalas dentro de `sh -c '...'`.

## Paso 0 — Prerrequisitos y arranque
1. Comprueba `docker --version` y `docker compose version`. Si falta alguno, para
   y dímelo.
2. Sitúate en la carpeta `docker/` del repo.
3. Monta la evidencia en solo lectura SIN tocar el compose base: define la
   variable `FORENSIA_EVIDENCE_DIR` apuntando a la carpeta de evidencia del
   caso (el compose la monta en `/evidence:ro`). Nada de rutas absolutas
   hardcodeadas en ficheros versionados.

   ```bash
   # variable puntual…
   FORENSIA_EVIDENCE_DIR=/ruta/a/la/evidencia docker compose up -d
   # …o fichero .env junto al docker-compose.yml (ignorado por git)
   echo 'FORENSIA_EVIDENCE_DIR=/ruta/a/la/evidencia' > .env
   ```

   (En Linux usa el Docker Engine nativo — contexto `default` —, no Docker
   Desktop; ver README. Si el bind falla, cópiame la evidencia a
   `docker/evidence/` y usa `/evidence` igualmente.)
4. Construye y levanta: `docker compose up --build -d`. El primer build tarda
   (compila plaso, descarga hayabusa/chainsaw). Espera a que ambos servicios estén
   `running`.
5. Sanity del maletín:
   - `docker compose exec -T toolkit-windows forensia-info`
   - `docker compose exec -T toolkit-unix    forensia-info`
   Anota qué herramientas salen como "NO" (no encontradas) — esas ya son un FAIL
   de disponibilidad.

## Rutas reales de la evidencia (verifícalas con `ls` antes de usarlas)
Usa esta base dentro del contenedor: `EVID=/evidence/D`
- $MFT:            '/evidence/D/$MFT'
- UsnJrnl ($J):    '/evidence/D/$Extend/$J'
- Hive SYSTEM:     /evidence/D/Windows/System32/config/SYSTEM
- Hive SOFTWARE:   /evidence/D/Windows/System32/config/SOFTWARE
- Hive SAM:        /evidence/D/Windows/System32/config/SAM
- Hive SECURITY:   /evidence/D/Windows/System32/config/SECURITY
- NTUSER (IEUser): /evidence/D/Users/IEUser/NTUSER.DAT
- UsrClass:        /evidence/D/Users/IEUser/AppData/Local/Microsoft/Windows/UsrClass.dat
- Amcache:         /evidence/D/Windows/AppCompat/Programs/Amcache.hve
- Carpeta EVTX:    /evidence/D/Windows/System32/winevt/Logs   (138 logs)
- Security.evtx:   /evidence/D/Windows/System32/winevt/Logs/Security.evtx
- System.evtx:     /evidence/D/Windows/System32/winevt/Logs/System.evtx
- PowerShell log:  '/evidence/D/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx'
- Carpeta Prefetch:/evidence/D/Windows/Prefetch     (112 .pf)
- Un Prefetch:     /evidence/D/Windows/Prefetch/CMD.EXE-89305D47.pf
- LNK (limpio):    '/evidence/D/Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent/Documents.lnk'
- LNK (con datos): '/evidence/D/Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent/CLIENTES DEL BANCO.xls.lnk'

Si alguno de estos ficheros no existe, elige otro equivalente del mismo directorio
(p. ej. otro `.pf` o `.lnk`) y anótalo.

## Paso 1 — Matriz de DISPONIBILIDAD (todas las tools)
Para cada binario, `docker compose exec -T <maletín> command -v <bin>` y marca
presente/ausente. Lista mínima a comprobar:
- Cross (windows y unix): sha256sum, hashdeep, fls, icat, mmls, mactime,
  bulk_extractor, foremost, ewfinfo, ewfmount, qemu-nbd, guestmount,
  log2timeline.py, psort.py, vol
- toolkit-windows: rip.pl (regripper), hayabusa, chainsaw, evtx_dump, lnkparse,
  regipy-dump, prefetch.py, hindsight.py
- toolkit-unix: journalctl, lnav, rg, jq, less

## Paso 2 — Integridad / cadena de custodia (Cross)
- `sha256sum` de la colmena SYSTEM y del `$MFT` (con comillas simples por el `$`).
- `hashdeep -r -c sha256` de `/evidence/D/Windows/System32/config` → guarda el
  set en `/cases/_selftest/config_hashes.txt`.

## Paso 3 — Artefactos Windows (rutas REALES) → maletín `toolkit-windows`
Ejecuta y verifica (exit 0 + salida no vacía). Envía salidas a `/cases/_selftest/`.
- RegRipper (SYSTEM):   sh -c 'rip.pl -r /evidence/D/Windows/System32/config/SYSTEM -f system > /cases/_selftest/rr_system.txt'
- RegRipper (SOFTWARE): sh -c 'rip.pl -r /evidence/D/Windows/System32/config/SOFTWARE -f software > /cases/_selftest/rr_software.txt'
- RegRipper (Amcache):  sh -c 'rip.pl -r /evidence/D/Windows/AppCompat/Programs/Amcache.hve -f amcache > /cases/_selftest/rr_amcache.txt'  (si el plugin no existe, prueba `-f amcache_app` o márcalo)
- regipy-dump (SYSTEM): sh -c 'regipy-dump /evidence/D/Windows/System32/config/SYSTEM > /cases/_selftest/system.json'
- evtx_dump (Security): sh -c 'evtx_dump /evidence/D/Windows/System32/winevt/Logs/Security.evtx > /cases/_selftest/security.xml'  (comprueba tamaño > 0)
- hayabusa: sh -c 'hayabusa csv-timeline -d /evidence/D/Windows/System32/winevt/Logs -o /cases/_selftest/hayabusa.csv'  (añade flags no-interactivos que veas en `hayabusa help csv-timeline`, p. ej. saltarse el wizard/quiet; usa `$HAYABUSA_RULES` si pide reglas)
- chainsaw: sh -c 'chainsaw hunt /evidence/D/Windows/System32/winevt/Logs -s "$CHAINSAW_RULES" --mapping "$CHAINSAW_MAPPING" --csv /cases/_selftest/chainsaw'  (ajusta flags con `chainsaw hunt --help`)
- lnkparse:  lnkparse '/evidence/D/Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent/CLIENTES DEL BANCO.xls.lnk'
- prefetch.py: prefetch.py -c -f /evidence/D/Windows/Prefetch/CMD.EXE-89305D47.pf   (si `-c/-f` no son válidos, mira `prefetch.py -h`)
- hindsight.py: en esta evidencia NO hay perfil de Chrome/Edge con `History`.
  Márcalo SKIP (motivo: sin artefactos de navegador) pero confirma disponibilidad
  con `hindsight.py --help`.

## Paso 4 — Cross sobre ficheros que SÍ tenemos
- bulk_extractor: `bulk_extractor -o /cases/_selftest/be_out /evidence/D/Windows/System32/config/SOFTWARE`  (funciona sobre cualquier fichero; revisa `be_out/*.txt`)
- foremost:       `sh -c 'foremost -i /evidence/D/Windows/System32/config/SOFTWARE -o /cases/_selftest/foremost_out'`
- plaso (integración real sobre el árbol):
  - `log2timeline.py --parsers 'winevtx,winreg,prefetch,lnk,mft' --storage-file /cases/_selftest/case.plaso /evidence/D`  (puede tardar varios minutos; si tarda demasiado, limita con `--parsers 'winevtx,prefetch,lnk'`)
  - `psort.py -o l2tcsv -w /cases/_selftest/timeline.csv /cases/_selftest/case.plaso` y cuenta líneas del CSV (debe ser > 1).

## Paso 5 — Imagen/memoria: SIN diana real en este triage
Esta evidencia es un árbol de ficheros, no una imagen. Por tanto:
- Disponibilidad: `mmls -V`, `fls -V`, `icat -V`, `mactime -V`, `ewfinfo -V`,
  `vol -h` (confirma que el binario carga).
- Smoke test SINTÉTICO de TSK (etiquétalo claramente como FIXTURE, no evidencia):
  en `toolkit-unix`, `sh -c 'dd if=/dev/zero of=/cases/_selftest/synth.raw bs=1M count=16 && mkfs.ext4 -F /cases/_selftest/synth.raw'`, luego
  `fls -r /cases/_selftest/synth.raw`,
  `sh -c "fls -r -m / /cases/_selftest/synth.raw > /cases/_selftest/bodyfile && mactime -b /cases/_selftest/bodyfile -d > /cases/_selftest/synth_timeline.csv"`,
  y un `icat` sobre algún inodo que devuelva `fls`.
- Volatility y mmls (tabla de particiones) → SKIP funcional. Motivo: se necesita
  un `.raw`/`.E01`/memdump. Deja escritos, listos para usar, los comandos reales:
  - `vol -f /evidence/<memdump>.raw windows.info`
  - `mmls /evidence/<imagen>.raw`  /  `fls -r -p /evidence/<imagen>.raw`
  - `ewfinfo /evidence/<imagen>.E01`

## Paso 6 — Informe
Escribe `docker/projects/_selftest/REPORT.md` con:
- Fecha, versión de imágenes (`docker image ls | grep forensia`), y salida de los
  dos `forensia-info`.
- Una TABLA: herramienta | maletín | comando ejecutado | exit | PASS/FAIL/SKIP | nota.
- Sección "Fallos" con el stderr recortado de cada FAIL.
- Sección "Pendiente de evidencia" listando lo que quedó SKIP por falta de
  imagen raw / memdump, con el comando exacto a usar cuando se disponga de ella.
Al final, imprime en el chat un resumen: nº de PASS/FAIL/SKIP y los FAIL primero.

## Cierre
No borres `docker/projects/_selftest/` (es la prueba). Deja el maletín levantado.
Si algún build falló, muéstrame el log del build de esa imagen.
```
