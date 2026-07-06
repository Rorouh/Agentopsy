# Imagen: `dvwa-container-rootfs` (DVWA docker rootfs)

Bitácora de pruebas de tools sobre esta imagen. Una carpeta hermana `<tool>.md` por
herramienta probada.

## Identidad de la evidencia

| Campo | Valor |
|-------|-------|
| Fichero (bandeja) | `evidence/dvwa-container-rootfs/dvwa-disk.raw` |
| Qué es | rootfs del contenedor `vulnerables/web-dvwa` volcado a `.raw` |
| Sistema de ficheros | **ext4**, volumen `DVWA`, UUID `b632c5f5-a170-4dec-990e-c17ae97874af` |
| Tabla de particiones | **ninguna** (FS plano en offset 0) → `tsk_mmls` no aplica |
| Tamaño | 1 189 085 184 B (~1,1 GB) |
| SHA-256 baseline | `d9d08eabe8008bccc1c6252364fff6c5f2685257f727d12e2dfa2bdda609f8f9` |
| Caso | `8c944918-7791-4e09-9e58-7d414c5be9be` ("Prueba", perfil `unix`) |
| evidence_id | `0948aadd-a962-47c3-9f93-2c373f2fe502` |
| Ruta interna (api/maletín) | `/cases/cases/8c944918-…/evidence/0948aadd-…/original.raw` |

## Metodología

- Cada tool se ejecuta por el **dispatcher** anclado al caso:
  `execute(tool_id, params, case_id=…, os_profile='unix')`. Esto la corre por el
  exec-agent dentro de `toolkit-unix`, deja un `run_id`, un `ArtifactRun` y entradas
  `tool_run_start/finish` en el `audit.jsonl` (cadena de custodia), y suma al panel Tools.
- Para cada tool se prueba su **máxima expresión** (flags/params que le sacan el jugo),
  no la invocación mínima.
- Se documenta: objetivo → cómo → resultado → veredicto → lecciones para el agente.

## Checklist de tools

| Tool | Estado | Veredicto corto |
|------|--------|-----------------|
| [`file_info`](file_info.md) | ✅ | Útil en modo descripción (identifica ext4+volumen); `also_mime` es una trampa en imágenes de disco |
| [`strings_head`](strings_head.md) | ✅ | Extrajo credenciales DVWA (`root`/`p@ssw0rd`) + versiones; artefacto 99 MB → hay que **cribar**, no leer el head; no capta UTF-16 |
| [`tsk_fls`](tsk_fls.md) | ✅ | Mapeó 14.234 entradas + inodes clave (config.inc.php 13552, main.sh 1030) + bodyfile; **Bug 002**: `entries_count` recursivo subcuenta (→22) |
| [`tsk_icat`](tsk_icat.md) | ✅ | **Integrada** (fix Bug 003); extrae por inode (config.inc.php→app/vulnerables, main.sh, passwd/shadow); trampa: no elegir inode por nombre |
| [`tsk_mactime`](tsk_mactime.md) | ✅ | 43.604 eventos; ráfaga de creación 2026-07-03 (mkfs) vs instalación 2018; matiz: histograma agrupa por segundo con ISO |
| [`hashdeep`](hashdeep.md) | ✅ | **Integrada** (wrapper implementado, fix Bug 003); SHA-256 de la imagen **== baseline FORENSIA** (integridad OK) + hash set estructurado |
| [`foremost`](foremost.md) | ✅ | **Integrada** (fix Bug 003); carveó 277 ficheros por firma (160 png/111 gif/5 jpg/1 pdf) = assets embebidos; el resumen está en audit.txt, no en `parsed` |
| [`bulk_extractor`](bulk_extractor.md) | ✅ | 87k dominios/70k emails/16k URLs (provenencia de software, no actividad); trampa: `url` no es escáner válido en BE 2.1.0 (exit 5) |
| [`jq`](jq.md) | ✅ | Filtró `baseline.json` → campos de custodia; utilidad *downstream* (brilla con JSON grande de volatility/plaso); sin finding |
| [`xxd_head`](xxd_head.md) | ✅ | **Desbloqueada** (instalado `xxd`); hex del superbloque → magic ext4 `53ef` en 0x430 |
| [`yara`](yara.md) | ✅ | **Desbloqueada** (instalado `yara` 4.1.3); regla propia matchea credenciales DVWA (parse estructurado) |
