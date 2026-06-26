# Playbook — Sample Unix Analyst

Heurísticas por tipo de evidencia. **No es un script**: es la secuencia que un
analista humano probaría primero. Si una pista lleva a otro camino, lo sigues.

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
