# Grupo C — artefactos Windows (EVTX + registro)

Tercer grupo: tools **Windows** sobre artefactos reales traídos de fuentes públicas (sin
imágenes de 8 GB). A diferencia de los grupos A/B (disco Linux), aquí la evidencia son
**ficheros de artefacto** — logs de eventos y hives de registro.

Caso: **Windows-artefactos** (`42f06083-5fff-41d0-affa-434dcc65c331`, perfil `windows`).
Plan general: [`../matriz-tools-evidencia.md`](../matriz-tools-evidencia.md).

## Evidencia (traída con `gh`/git, gitignorada)

| Carpeta | Qué | Para |
|---------|-----|------|
| `evidence/windows-evtx-hayabusa-samples/` | 16 `.evtx` mapeados a MITRE (Yamato-Security) | `hayabusa`, `chainsaw` |
| `evidence/windows-registry-hives-ericzimmerman/` | 5 hives (SAM/SECURITY/SOFTWARE/SYSTEM/NTUSER) | `regripper` |
| `evidence/windows7-x64-ram-dump/` | volcado de RAM de 5 GB (Win7 SP1 x64) | `volatility3` |

## Tools de este grupo

| Tool | Estado | Nota |
|------|--------|------|
| [`hayabusa`](windows-evtx-hayabusa-samples/hayabusa.md) | ✅ | **129 detecciones Sigma** (1 crit, 17 high) → cadena de ataque MITRE real; 2 fixes (Bug 005 musl + Bug 006 wizard) |
| [`chainsaw`](windows-evtx-hayabusa-samples/chainsaw.md) | ✅ | **56 detecciones** (148 filas) segmentadas por categoría; Kerberoasting + borrado de logs + RDP externo; 1 fix (Bug 007 parser stderr) |
| [`regripper`](windows-registry-hives-ericzimmerman/regripper.md) | ✅ | 7 plugins sobre las 5 hives → host **HAXOR4** (Win7 SP1), USB **SAMSUNG mass-storage**, cuentas; realineado al maletín (`rip`→`rip.pl`, sin legacy container) |
| [`volatility3`](windows7-x64-ram-dump/volatility3.md) | ✅ | 6 plugins sobre 5 GB de RAM (Win7 SP1 x64) → **keylogger `key.exe`** en el Escritorio, **código inyectado RWX** en explorer, hMailServer/OpenSSH expuestos; sin fixes (ya cableado) |
| `evtxecmd` / `mftecmd` | ⛔ | .NET sin absorber en el maletín |

## Notas de infraestructura descubiertas aquí

- **Bug 005**: `hayabusa` gnu no arranca en Ubuntu 22.04 (glibc 2.35 < 2.38) → se pasó al
  build **musl** (static-pie). `chainsaw` no sufre esto.
- **Bug 007**: `chainsaw` resume por **stderr** y escribe las tablas a **ficheros**, no a
  stdout → el parser reportaba 0 con el artefacto correcto. El dispatcher ahora pasa `stderr`
  a los `parse` que lo aceptan (por aridad). Patrón a vigilar en toda CLI que use `--output`.
