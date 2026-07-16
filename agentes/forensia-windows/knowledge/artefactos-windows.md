# Artefactos Windows — dónde mirar y con qué

Referencia de consulta bajo demanda. En disco se recupera **sin montar**: localiza el
fichero/hive con `tsk_fls` y extrae con `tsk_icat` (o `mftecmd` sobre `$MFT`); luego el
parser específico. Cada extracción es un artefacto hasheado; ancla el hallazgo a su
`run_id`.

## Registro (hives → `regripper`)
- `SYSTEM`: servicios (`ControlSet\Services`), `Run`/`RunOnce` de máquina, orden de
  arranque, huso horario (`TimeZoneInformation`), red.
- `SOFTWARE`: `Run`/`RunOnce`, `Uninstall`, versión de SO, `NetworkList` (SSIDs/redes).
- `SAM`: cuentas locales y su último login (nunca afirmes hashes «crackeados»).
- `SECURITY`: política, secretos LSA.
- `NTUSER.DAT` (por usuario): `RunMRU`, `TypedPaths`, `UserAssist` (ejecución GUI),
  `RecentDocs`, `WordWheelQuery` (búsquedas).
- `Amcache.hve`: `amcacheparser`/`regripper` → ejecutables vistos (hash SHA1, rutas).

## Ejecución de programas
- **Prefetch** (`C:\Windows\Prefetch\*.pf`, `pecmd`): qué se ejecutó, cuántas veces,
  primera/última vez, ficheros referenciados.
- **Amcache / ShimCache** (AppCompatCache en `SYSTEM`): presencia y rutas de binarios.
- **SRUM** (`sru.db`): uso de recursos y red por app (bytes por proceso).
- **UserAssist** (`NTUSER.DAT`): programas lanzados desde el shell (ROT13).

## Eventos (EVTX → `evtxecmd` / `hayabusa` / `chainsaw`)
- `Security.evtx`: 4624 (logon ok, mira LogonType — 3 red, 10 RDP), 4625 (fallido),
  4634/4647 (logoff), 4688 (creación de proceso), 4672 (privilegios), 4720/4726
  (alta/baja de cuenta), 4732 (añadido a grupo).
- `System.evtx`: 7045 (servicio nuevo — persistencia), 7034/7035.
- `Microsoft-Windows-Sysmon/Operational.evtx`: 1 (proceso), 3 (red), 11 (fichero),
  13 (registro) — oro si Sysmon estaba desplegado.
- `hayabusa`/`chainsaw`: reglas Sigma sobre los EVTX → detecciones ya priorizadas.
  Recuerda: algunas emiten el resumen por **stderr**.

## Sistema de ficheros y actividad
- `$MFT` (`mftecmd`): timeline MAC(b) NTFS, ficheros borrados, ADS.
- `$UsnJrnl:$J` (`mftecmd`): cambios recientes (creación/borrado/rename).
- `$LogFile`: transacciones NTFS.

## Actividad de usuario (parsers KAPE / EZ Tools)
- **LNK** (`lecmd`): ficheros abiertos, con ruta origen y volumen.
- **Jump Lists** (`jlecmd`, `AutomaticDestinations`): apps y ficheros recientes.
- **ShellBags** (`sbecmd`, en `NTUSER`/`UsrClass.dat`): carpetas navegadas (incluidas
  ya inexistentes/extraíbles).
- **Windows Timeline** (`ActivitiesCache.db`).
- **Papelera** (`$Recycle.Bin\$I*`): ficheros borrados con ruta y fecha originales.

## Persistencia (dónde suele esconderse)
- Registro: `Run`/`RunOnce` (máquina y usuario), `Services` (7045 en System.evtx),
  `Winlogon\Shell`/`Userinit`, `Image File Execution Options` (debugger hijack).
- Tareas programadas: `C:\Windows\System32\Tasks\*` (XML), evento 106/200.
- Carpetas Startup: `…\Start Menu\Programs\Startup`.
- WMI: suscripciones de eventos (`OBJECTS.DATA`).

## Web / navegadores
- Historial y descargas en el perfil del usuario (`AppData`): Chrome/Edge
  (`History` SQLite), Firefox (`places.sqlite`). Extrae el SQLite y parsea.
- Artefactos web servidos: `C:\inetpub\wwwroot\` (webshells `.asp`/`.aspx`).

## Nota de huso horario
El huso está en `SYSTEM\...\TimeZoneInformation`. Declara y normaliza a UTC antes de
correlacionar EVTX con la timeline del `$MFT`.
