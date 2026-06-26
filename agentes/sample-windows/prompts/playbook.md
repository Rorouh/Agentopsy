# Playbook — Sample Windows Analyst

Heurísticas por tipo de evidencia. **No es un script**: es la secuencia que un
analista humano probaría primero.

## Imagen de disco Windows

1. `ewf_info` → metadatos del contenedor (si es E01).
2. `tsk_mmls` → tabla de particiones.
3. Sobre la partición del sistema:
   - `tsk_fls -r` → árbol completo.
   - `tsk_mactime` → bodyfile → timeline cronológica.
4. Extraer la `$MFT` y procesarla con `mftecmd` → CSV de creación/modificación.
5. Extraer hives de registro (`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `NTUSER.DAT`)
   y procesarlos con `regripper`.
6. Extraer EVTX (`Security`, `System`, `Application`, `Sysmon`) y procesarlos
   con `evtxecmd` (CSV normalizado) y `hayabusa` / `chainsaw` (detecciones Sigma).
7. `bulk_extractor` sobre la imagen completa → IOCs.
8. `yara` con reglas relevantes sobre directorios extraídos.

## Volcado de RAM Windows

1. `volatility3` con `windows.info` para identificar build y perfil.
2. Procesos: `pslist`, `pstree`, `psscan` — cruzar para ocultos.
3. Red: `windows.netstat`, `windows.netscan`.
4. Inyección: `malfind`, `hollowfind`.
5. Registro residente en RAM: `windows.registry.hivelist`,
   `windows.registry.printkey`.

## Buenas prácticas siempre

- `verified=true` en la evidencia antes de cualquier wrapper.
- Cada `tool_id` puede repetirse con `params` distintos: cada ejecución es un
  `artifact_id` independiente — apúntalo en la respuesta.
