# Maletín forense — catálogo y estado de vendoring

Cada herramienta del catálogo (`backend/forensia/toolkit/catalog.py`) viaja **dentro del
binario compilado** (CLAUDE.md RULE 1). Dos vías de entrega:

- **sidecar** — herramienta Python; la empaqueta PyInstaller dentro del sidecar. No requiere
  vendoring nativo.
- **vendored** — binario nativo; se copia a `vendor/<tool>/<os>-<arch>/<binary>` con
  `scripts/bundle-tool.mjs` en la máquina de build. El usuario lo recibe en el bundle.

El `resolver` (`toolkit/resolver.py`) busca: `env → vendored/bundled → PATH`. **Sin Docker.**

Layout esperado: `vendor/<tool>/{win-x64,linux-x64,mac-arm64,mac-x64}/<binary>`

| id (Tool) | binario | vía | OS | win-x64 | linux-x64 | mac-arm64 | mac-x64 |
|---|---|---|---|:---:|:---:|:---:|:---:|
| tsk_fls / icat / mmls / mactime | `fls`… | vendored | cross | ☐ | ☐ | ☐ | ☐ |
| bulk_extractor | `bulk_extractor` | vendored | cross | ☐ | ☐ | ☐ | ☐ |
| foremost | `foremost` | vendored | unix | — | ☐ | ☐ | ☐ |
| ewf_info | `ewfinfo` | vendored | cross | ☐ | ☐ | ☐ | ☐ |
| qemu_nbd | `qemu-nbd` | vendored | unix | — | ☐ | ☐ | ☐ |
| hashdeep | `hashdeep` | vendored | cross | ☐ | ☐ | ☐ | ☐ |
| plaso_log2timeline / psort | `*.py` | **sidecar** | cross | ✅* | ✅* | ✅* | ✅* |
| volatility3 | `vol` | **sidecar** | cross | ✅* | ✅* | ✅* | ✅* |
| regripper | `rip` | vendored (Perl) | windows | ☐ | — | — | — |
| hayabusa | `hayabusa` | vendored | windows | ☐ | ☐ | ☐ | ☐ |
| chainsaw | `chainsaw` | vendored | windows | ☐ | ☐ | ☐ | ☐ |

`✅*` = entra vía sidecar una vez fijada la versión en `pyproject [forensics]`.
`☐` = pendiente de vendorizar.  `—` = no aplica a esa plataforma.

## Notas de vendoring (las ásperas)

- **RegRipper** es Perl → hay que bundlear un Perl portable o compilar a binario (PAR::Packer).
- **plaso** nativo en Windows es delicado; preferir la vía sidecar (PyInstaller) y validar.
- **macOS**: binarios con dylibs propias necesitan `dylibbundler` para relocalizar (ver fractia/QEMU).
- Tras vendorizar, **comprobar la firma/quarantine** en el `.dmg`/instalador real, no en dev.

> Este árbol está en `.gitignore` (binarios grandes, repo público). La máquina de build los
> produce; los usuarios los reciben en el instalador.
