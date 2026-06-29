# Maletín forense — catálogo y estado de vendoring

Cada herramienta del catálogo (`backend/forensia/toolkit/catalog.py`) declara su
**delivery** por host OS (CLAUDE.md RULE 1). Dos vías de entrega:

- **bundled** — Python tools (Volatility 3, Plaso) empaquetadas por PyInstaller dentro del
  sidecar; binarios nativos vendoreados a `vendor/<tool>/<os>-<arch>/<binary>` con
  `scripts/bundle-tool.mjs` en la máquina de build.
- **container** — imagen OCI ejecutada contra el runtime del host (docker / podman /
  nerdctl). Para herramientas sin build nativo viable en algún OS (.NET, Perl, libguestfs).

El `resolver` (`toolkit/resolver.py`) elige según lo declarado:
`env → bundled (vendor / sidecar) → container → host PATH`.

## CORE TIER — kit "primeros 30 minutos"

13 herramientas requeridas para el MVP. Ver `docs/maletin/inventario-tools.md` para el razonamiento.

| id | binario | vía | linux | mac | windows | win-x64 | linux-x64 | mac-arm64 | mac-x64 |
|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `tsk_mmls` | `mmls` | bundled | bundled | bundled | bundled | ☐ | ☐ | ☐ | ☐ |
| `tsk_fls` | `fls` | bundled | bundled | bundled | bundled | ☐ | ☐ | ☐ | ☐ |
| `tsk_mactime` | `mactime` | bundled | bundled | bundled | bundled | ☐ | ☐ | ☐ | ☐ |
| `ewf_info` | `ewfinfo` | bundled | bundled | bundled | bundled | ☐ | ☐ | ☐ | ☐ |
| `bulk_extractor` | `bulk_extractor` | bundled | bundled | bundled | bundled | ☐ | ☐ | ☐ | ☐ |
| `yara` | `yara` | bundled | bundled | bundled | bundled | ☐ | ☐ | ☐ | ☐ |
| `volatility3` | `vol` | sidecar | bundled | bundled | bundled | ✅* | ✅* | ✅* | ✅* |
| `hayabusa` | `hayabusa` | bundled | bundled | bundled | bundled | ☐ | ☐ | ☐ | ☐ |
| `chainsaw` | `chainsaw` | bundled | bundled | bundled | bundled | ☐ | ☐ | ☐ | ☐ |
| `evtxecmd` | `EvtxECmd` | bundled+container | container | container | bundled | ☐ | 🐳 | 🐳 | 🐳 |
| `mftecmd` | `MFTECmd` | bundled+container | container | container | bundled | ☐ | 🐳 | 🐳 | 🐳 |
| `regripper` | `rip` | container | container | container | container | 🐳 | 🐳 | 🐳 | 🐳 |
| `jq` | `jq` | bundled | bundled | bundled | bundled | ☐ | ☐ | ☐ | ☐ |

## EXTENDED TIER — añadidas tras estabilizar el core

| id | binario | vía | linux | mac | windows | win-x64 | linux-x64 | mac-arm64 | mac-x64 |
|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `tsk_icat` | `icat` | bundled | bundled | bundled | bundled | ☐ | ☐ | ☐ | ☐ |
| `plaso_log2timeline` | `log2timeline.py` | sidecar | bundled | bundled | bundled | ✅* | ✅* | ✅* | ✅* |
| `plaso_psort` | `psort.py` | sidecar | bundled | bundled | bundled | ✅* | ✅* | ✅* | ✅* |
| `hashdeep` | `hashdeep` | bundled | bundled | bundled | bundled | ☐ | ☐ | ☐ | ☐ |
| `foremost` | `foremost` | bundled | bundled | bundled | — | — | ☐ | ☐ | ☐ |
| `qemu_nbd` | `qemu-nbd` | bundled | bundled | bundled | — | — | ☐ | ☐ | ☐ |

Leyenda:
- `✅*` = entra vía sidecar una vez fijada la versión en `pyproject [forensics]`.
- `🐳` = entregada vía contenedor; no requiere vendoring de binario nativo en esa plataforma.
- `☐` = pendiente de vendorizar.
- `—` = no aplica en esa plataforma (el tool no tiene build nativo viable allí; ver columna `delivery`).

## Notas de vendoring (las ásperas)

- **EvtxECmd / MFTECmd** (.NET): en Windows se bundlea el `.exe` self-contained; en Linux/Mac
  se entrega vía imagen `forensia/evtxecmd:latest` / `forensia/mftecmd:latest` (pendiente de
  build pipeline).
- **RegRipper** (`rip.pl`) es Perl 5 + módulos CPAN — bundlearlo cross-OS exige Perl portable
  o PAR::Packer. Decisión: entregar **siempre por contenedor** (`forensia/regripper:latest`).
- **plaso** nativo en Windows es delicado; preferimos vía sidecar (PyInstaller) y validar.
- **macOS**: binarios con dylibs propias necesitan `dylibbundler` para relocalizar.
- Tras vendorizar, **comprobar firma/quarantine** en el `.dmg`/instalador real, no en dev.
- Si `container_runtime()` devuelve `None` (no hay docker/podman/nerdctl), las filas con
  `delivery=container` se marcan automáticamente como no disponibles en `/api/capabilities`
  y la UI degrada esas herramientas (el resto sigue funcionando).

> Este árbol está en `.gitignore` (binarios grandes, repo público). La máquina de build los
> produce; los usuarios los reciben en el instalador.
