# Playbook — FORENSIA-WIN

Heurística forense por tipo de evidencia. **No es un script**: es la secuencia que
un analista humano probaría primero. Antes de cualquier herramienta, confirma que
la evidencia está **verificada** (`verified=true`).

> **Regla de oro de custodia:** las herramientas de contenedor (`regripper`,
> `evtxecmd`, `mftecmd`) **nunca** reciben la imagen cruda. Siempre:
> `tsk_fls` (localizar) → `tsk_icat` (extraer el artefacto vía handle read-only)
> → procesar **solo** ese fichero derivado.

---

## A. Imagen de disco Windows (`.raw`, `.E01`, `.vmdk`)

1. **Contenedor.** `ewf_info` si es `.E01` → metadatos y hash interno; cuádralo
   con el baseline del caso.
2. **Particiones.** `tsk_mmls` → offsets y tipos. Apunta el `partition_offset` de
   la partición del sistema (NTFS).
3. **Sistema de ficheros (sin montar).**
   - `tsk_fls` con `recursive: true` → árbol completo, incluidos borrados.
   - `tsk_mactime` (bodyfile) → línea temporal MAC(b): tu columna vertebral.
4. **`$MFT`.** Localiza la `$MFT` con `tsk_fls`, extráela con `tsk_icat`, y
   procésala con `mftecmd` → CSV de creación/modificación/acceso. Cruza con la
   timeline para detectar *timestomping* (creación posterior a modificación, o
   `$STANDARD_INFORMATION` vs `$FILE_NAME` inconsistentes).
5. **Registro.** Extrae los hives (`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`,
   `NTUSER.DAT`, `UsrClass.dat`) con `tsk_icat` y procésalos con `regripper`.
   Busca: persistencia (`Run`/`RunOnce`, `Services`, `Scheduled Tasks`), ejecución
   (`Amcache`, `ShimCache`/AppCompatCache), USB, cuentas (`SAM`), `ShellBags`.
6. **Eventos (EVTX).** Extrae `Security.evtx`, `System.evtx`, `Application.evtx`,
   `Microsoft-Windows-Sysmon%4Operational.evtx` con `tsk_icat`. Procésalos con:
   - `evtxecmd` → CSV normalizado (consulta puntual de IDs: 4624/4625 logon,
     4688 process creation, 7045 service install, 4720 user created).
   - `hayabusa` y `chainsaw` → detecciones **Sigma** (barrido de amenazas).
7. **IOCs.** `bulk_extractor` sobre la imagen → emails, URLs, IPs, PII en
   no-asignado. Lento: anúncialo. Filtra con `jq`.
8. **Firmas / malware.** `yara` sobre directorios sospechosos extraídos
   (`%TEMP%`, `%APPDATA%`, `C:\Windows\Tasks`, perfiles de usuario).
9. **Super-timeline (opcional, pesado).** `plaso_log2timeline` → `.plaso`;
   `plaso_psort` para acotar por rango y exportar CSV.

---

## B. Volcado de memoria RAM Windows (`.mem`, `.dmp`)

> Antes de empezar, confirma que `detected_os` del bloque «Contexto de
> evidencia» dice `windows` (o que un probe diagnóstico ya lo confirmó). Si el
> volcado es UNIX, **no es tu caso**: detente y pide reabrir con perfil
> `unix` (lo lleva FORENSIA-UNIX). Ver regla 9 del system prompt.

1. **Perfil.** `volatility3` con `plugin: "windows.info.Info"` → build y perfil.
2. **Procesos.** `windows.pslist.PsList`, `windows.pstree.PsTree`,
   `windows.psscan.PsScan` → cruza para detectar ocultos.
3. **Inyección.** `windows.malfind.Malfind` (regiones RWX/anómalas),
   `windows.hollowprocesses` cuando sospeches *process hollowing*.
4. **Red.** `windows.netscan.NetScan` → conexiones y puertos (C2, shells inversas).
5. **Registro residente.** `windows.registry.hivelist.HiveList` +
   `windows.registry.printkey.PrintKey` → persistencia viva en memoria.
6. **Comando/credenciales.** `windows.cmdline.CmdLine`, líneas de comando de
   procesos sospechosos; vuelca regiones de un PID candidato si procede.

---

## Buenas prácticas siempre

- Un mismo `tool_id` puede repetirse con `params` distintos: **cada ejecución es
  un `artifact_id`** — indícalo en cada hallazgo.
- Cruza fuentes: una persistencia en `Run` (registro) gana fuerza si hay un 4688
  (EVTX) y una entrada en `Amcache`/Prefetch a la misma hora. Correlación = más
  confianza.
- Ancla cada hallazgo a la marca de tiempo del **artefacto** (`observed_at`), no a
  la hora de ejecución.
- Si la salida cabe en contexto, cítala literal; si no, referencia el
  `artifact_id` y resume (apóyate en `jq`).
