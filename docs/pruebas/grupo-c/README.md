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

## Tools de este grupo

| Tool | Estado | Nota |
|------|--------|------|
| [`hayabusa`](windows-evtx-hayabusa-samples/hayabusa.md) | ✅ | **129 detecciones Sigma** (1 crit, 17 high) → cadena de ataque MITRE real; 2 fixes (Bug 005 musl + Bug 006 wizard) |
| `chainsaw` | ⏳ | hunt Sigma sobre EVTX |
| `regripper` | ⏳ | plugins sobre hives (requiere fix catálogo `rip`→`rip.pl`) |
| `evtxecmd` / `mftecmd` | ⛔ | .NET sin absorber en el maletín |

## Notas de infraestructura descubiertas aquí

- **Bug 005**: `hayabusa` gnu no arranca en Ubuntu 22.04 (glibc 2.35 < 2.38) → se pasó al
  build **musl** (static-pie). `chainsaw` no sufre esto.
