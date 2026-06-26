# Playbook — Sample Unix Analyst

Heurísticas por tipo de evidencia. **No es un script**: es la secuencia que un
analista humano probaría primero. Si una pista lleva a otro camino, lo sigues.

## Paso 0 — SIEMPRE, sea cual sea el tipo de evidencia

Caracteriza el archivo ANTES de invocar herramientas forenses específicas:

1. **`file_info`** → libmagic. Si devuelve algo concreto (`DOS/MBR boot sector`,
   `Linux core dump`, `Microsoft Disk Image`), salta al bloque correspondiente
   abajo. Si devuelve `data` o `application/octet-stream`, **no te rindas** —
   sigue con el paso 2.
2. **`xxd_head`** con `bytes=64` → los primeros 32-64 bytes en hex. Magic numbers
   conocidos:
   - `45 56 46 09` → EWF/E01
   - `4B 44 4D 56` → VMware VMDK
   - `4C 69 4D 45` ("LiME") → memdump LiME
   - `EE...` o `45 4D...` → Windows hibernate
   - `7F 45 4C 46` → ELF
   - `4D 5A` → PE/EXE
   - `55 AA` al offset 0x1FE → MBR
   - Todos ceros / patrón repetitivo → sparse o memdump sin cabecera
3. **`strings_head`** con `min_len=8` → vendor markers (`vmware`, `EnCase`,
   `Linux version`, `Windows NT`, `KDBG`, etc.). Si aparece "Linux version
   X.Y.Z" es un memdump Linux. Si aparece "Windows" + "kernel" + "NT" es
   memdump Windows.
4. **Solo después** de los pasos 1-3, decide qué tool especializada usar:
   - hint disco → `tsk_mmls` / `ewf_info`
   - hint memdump Linux → `volatility3` con plugin `linux.banner` (auto-probe)
   - hint memdump Windows → `volatility3` con plugin `windows.info` (auto-probe)
   - sin hint claro → `bulk_extractor` (extrae IOCs de cualquier blob)

**Importante con Volatility**: usa SIEMPRE `windows.info` o `linux.banner` como
primer plugin — auto-detectan el perfil. NO empieces con `linux.pslist.PsList`
ni `windows.pslist.PsList` (esos requieren que el perfil ya esté resuelto).

## Imagen de disco (`.raw`, `.vmdk`, `.E01`)

1. `ewf_info` → metadatos del contenedor (tamaño, hash interno, particiones).
2. `tsk_mmls` → tabla de particiones, offsets, tipos.
3. Por cada partición de interés:
   - `tsk_fls -r` → árbol de ficheros (incluyendo borrados).
   - `tsk_mactime` → bodyfile → timeline cronológica.
4. `bulk_extractor` sobre la imagen completa → IOCs (emails, urls, ips, cards).
   Tarda. Avísalo antes de lanzarlo.
5. `yara` con reglas relevantes (malware, ransomware, persistencia) sobre la
   imagen o sobre directorios concretos extraídos.

## Volcado de RAM (`.mem`, `.dump`)

1. `volatility3` con plugin `windows.info` / `linux.banner` para identificar perfil.
   *(Para Linux: confirmar que existe el ISF compatible antes de seguir.)*
2. Procesos: `pslist`, `pstree`, `psscan` — cruzar para procesos ocultos.
3. Red: `sockets`, `netstat` — buscar conexiones a IPs/dominios sospechosos.
4. Drivers / módulos cargados.
5. Cadenas y dumps (`pstrings`, `memmap`) cuando hay un PID candidato.

## Buenas prácticas siempre

- Antes de cualquier wrapper, asegúrate de que la evidencia tiene `verified=true`
  (`/api/cases/{id}/evidence/{ev}/verify`).
- Un mismo `tool_id` puede ejecutarse varias veces con `params` distintos: cada
  ejecución genera su propio `artifact_id` — apunta en la respuesta cuál usaste.
- Si la salida cabe en contexto, la citas literal con bloque de código; si no,
  referencias el `artifact_id` y resumes los puntos clave.
