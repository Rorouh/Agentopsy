# FORENSIA — Inventario de herramientas (maletín extendido)

Catálogo candidato de herramientas forenses CLI evaluadas para el maletín de FORENSIA,
agrupadas por dominio. La selección final de las que se integran en las imágenes de los
maletines del compose (`toolkit-windows` / `toolkit-unix` — único mecanismo de entrega,
RULE 1) vive en `backend/forensia/toolkit/catalog.py`; la construcción de las imágenes,
con versiones pineadas, en los Dockerfiles de `docker/`. Este documento es la lista
larga; aquellas son las cortas.

> **Dónde vive cada tool del catálogo.** Desde 2026-07-03 cada entrada de `catalog.py`
> declara su maletín (`toolkits=`: los del stage `base` en ambos maletines; los artefactos
> Windows solo en `toolkit-windows`), y `forensia.toolkit.maletin` sondea los contenedores
> para que `/api/capabilities` reporte cada tool con disponible/no + razón (servicio
> caído, binario ausente) — sin sustituciones entre maletines (RULE 2). La "Estado local"
> de abajo es una foto del host de dev; para el usuario final la verdad es la del sondeo a
> los maletines. Los maletines se fijan a `linux/amd64` (el PPA GIFT no tiene arm64: en
> Apple Silicon corren bajo emulación) — ver `docker/README.md`.

> Probe ejecutado el **2026-06-26 en macOS (arm64)**, host del desarrollador. La columna
> "Estado local" refleja la presencia en `PATH` del sistema + el venv `backend/.venv`.
> "Nativo en" indica los OS donde la herramienta tiene un build nativo viable; los huecos
> (p. ej. `journalctl` en Win/Mac, EvtxECmd sin .NET en Linux/Mac) son exactamente lo que
> resuelven los maletines contenedorizados (RULE 1): al ser imágenes **Linux**, .NET Core,
> Perl o systemd-utils se instalan una vez en la imagen y valen para los tres SOs del host.

---

## 1. Adquisición, procesamiento de imágenes de disco y sistemas de archivos

| Herramienta | Nativo en | Necesita | Estado local |
|---|---|---|---|
| `tsk_loaddb` (The Sleuth Kit) | Linux / macOS / Windows | — | Instalado |
| `fls` (The Sleuth Kit) | Linux / macOS / Windows | — | Instalado |
| `icat` (The Sleuth Kit) | Linux / macOS / Windows | — | Instalado |
| `ils` (The Sleuth Kit) | Linux / macOS / Windows | — | Instalado |
| `img_stat` (The Sleuth Kit) | Linux / macOS / Windows | — | Instalado |
| `istat` (The Sleuth Kit) | Linux / macOS / Windows | — | Instalado |
| `mmstat` (The Sleuth Kit) | Linux / macOS / Windows | — | Instalado |
| `blkcalc` / `blkls` / `blkcat` (The Sleuth Kit) | Linux / macOS / Windows | — | Instalado |
| `guestfish` (libguestfs) | Linux | libguestfs + QEMU | No instalado |
| `guestmount` (libguestfs) | Linux | libguestfs + QEMU + FUSE | No instalado |
| `ewfinfo` (libewf) | Linux / macOS / Windows | — | Instalado |
| `ewfexport` (libewf) | Linux / macOS / Windows | — | Instalado |
| `ewfverify` (libewf) | Linux / macOS / Windows | — | Instalado |
| `vmdkinfo` (libvmdk) | Linux / macOS / Windows | — | No instalado |
| `vmdkmount` (libvmdk) | Linux / macOS / Windows | FUSE | No instalado |
| `affuse` (afflib) | Linux / macOS | FUSE | Instalado |
| `affstats` (afflib) | Linux / macOS | — | Instalado |
| `bulk_extractor` | Linux / macOS / Windows | — | No instalado |
| `bitlocker-dump` / `dislocker-find` | Linux (compilable en macOS) | FUSE | No instalado |
| `7z` (p7zip) | Linux / macOS / Windows | — | No instalado |
| `hfsutils` (artefactos heredados de macOS) | Linux | — | No instalado |

## 2. Artefactos, registros y telemetría de Windows (offline / parsers)

| Herramienta | Nativo en | Necesita | Estado local |
|---|---|---|---|
| `log2timeline.py` (Plaso) | Linux / macOS (Win delicado) | Python ≥3.10 + libyal | No instalado |
| `psort.py` (Plaso) | Linux / macOS (Win delicado) | Python ≥3.10 | No instalado |
| `image_export.py` (Plaso) | Linux / macOS (Win delicado) | Python ≥3.10 | No instalado |
| `hayabusa-cli` (Rust, multi-arch) | Linux / macOS / Windows | — | No instalado |
| `chainsaw` (Rust, multi-arch) | Linux / macOS / Windows | — | No instalado |
| `rip.pl` (RegRipper 3.0) | Linux / macOS / Windows | Perl 5 + módulos CPAN | No instalado |
| `EvtxECmd` (Eric Zimmerman) | Windows | .NET ≥6 (cross via .NET Core) | No instalado |
| `MFTECmd` (Eric Zimmerman) | Windows | .NET ≥6 (cross via .NET Core) | No instalado |
| `RECmd` (Eric Zimmerman) | Windows | .NET ≥6 (cross via .NET Core) | No instalado |
| `AmcacheParser` (Eric Zimmerman) | Windows | .NET ≥6 (cross via .NET Core) | No instalado |
| `LECmd` (Eric Zimmerman) | Windows | .NET ≥6 (cross via .NET Core) | No instalado |
| `JLECmd` (Eric Zimmerman) | Windows | .NET ≥6 (cross via .NET Core) | No instalado |
| `ShellBagsExplorer` (CLI) | Windows | .NET ≥6 (cross via .NET Core) | No instalado |
| `fred` (Forensic Registry Editor CLI) | Linux | Qt 5 base | No instalado |
| `hivexget` / `hivexml` / `hivexsh` (libhivex) | Linux | libhivex | No instalado |
| `evtx_dump` (rust-evtx) | Linux / macOS / Windows | — | No instalado |
| `reglookup` (python-registry / reglookup) | Linux / macOS | Python pkg o binario C | No instalado |
| `srch_strings` (binutils) | Linux / macOS | — | Instalado |
| `prefetch-parser` (Python / Rust) | Cross | Python o binario Rust | No instalado |
| `srum-parser` | Cross | Python ≥3.8 | No instalado |
| `scca` (Shim Cache Parser) | Cross | Python ≥3.8 | No instalado |

## 3. Artefactos, logs y auditoría de sistemas Unix-like (Linux / macOS)

| Herramienta | Nativo en | Necesita | Estado local |
|---|---|---|---|
| `uac` (Unix Artifact Collector) | Linux / macOS / *BSD / Solaris | Bash / sh POSIX | No instalado |
| `ausearch` (Auditd) | Linux | audit-utils | No instalado |
| `aureport` (Auditd) | Linux | audit-utils | No instalado |
| `utmpdump` (wtmp / btmp) | Linux | util-linux | No instalado |
| `journalctl` (systemd) | Linux | systemd montado | No instalado |
| `logcheck` | Linux / Unix | Perl | No instalado |
| `logwatch` | Linux / Unix | Perl | No instalado |
| `linenum.sh` | Cross-Unix | Bash | No instalado |
| `lynis` (módulo forense) | Linux / macOS / *BSD | Bash | No instalado |
| `chkrootkit` | Linux / macOS / *BSD | — | No instalado |
| `rkhunter` | Linux / macOS / *BSD | Perl | No instalado |
| `dumpe2fs` (e2fsprogs) | Linux | e2fsprogs | No instalado |
| `debugfs` (e2fsprogs) | Linux | e2fsprogs | No instalado |
| `find` / `stat` / `file` | POSIX (Linux / macOS) | coreutils | Instalado (`find`, `stat`, `file`) |
| `maclookup` (lookup OUI) | Cross | DB OUI IEEE | No instalado |

## 4. Análisis de memoria RAM volátil

| Herramienta | Nativo en | Necesita | Estado local |
|---|---|---|---|
| `vol` (Volatility 3 Framework) | Linux / macOS / Windows | Python ≥3.8 + symbol packs | Instalado |
| `vol.py` (Volatility 2 legacy) | Linux / macOS / Windows | Python 2.7 (legacy) | No instalado |
| `dwarf2json` (firmas ISF kernels Linux) | Linux / macOS / Windows | Go runtime para build; binario standalone | No instalado |
| `rekall` | Linux / macOS / Windows | Python (proyecto descontinuado) | No instalado |
| `lime-res` (parser LiME) | Linux | Python | No instalado |
| `vmem_parse` | Linux | Python | No instalado |

## 5. Análisis de malware, ingeniería inversa estática y firmas

| Herramienta | Nativo en | Necesita | Estado local |
|---|---|---|---|
| `yara` (CLI multi-OS) | Linux / macOS / Windows | reglas YARA | No instalado |
| `capa` (FLARE) | Linux / macOS / Windows | Python ≥3.10 + reglas capa | No instalado |
| `floss` (FLARE) | Linux / macOS / Windows | Python ≥3.10 | No instalado |
| `clamscan` (ClamAV) | Linux / macOS / Windows | firmas ClamAV (freshclam) | No instalado |
| `pecheck` | Cross | Python + pefile | No instalado |
| `readelf` (binutils) | Linux / *BSD | binutils | No instalado (en macOS solo `objdump`) |
| `ldd` | Linux | glibc | No instalado (macOS usa `otool -L`) |
| `objdump` (binutils) | Linux / macOS / Windows | binutils | Instalado |
| `signcheck` (Sysinternals / equiv. Py/Go) | Windows (Py/Go cross) | .NET o Python | No instalado |
| `trid` (identificador de formato) | Linux / macOS / Windows | DB de definiciones | No instalado |
| `ssdeep` (fuzzy hash) | Linux / macOS / Windows | — | No instalado |
| `tlsh` (LSH de Trend Micro) | Linux / macOS / Windows | libtlsh | No instalado |

## 6. Correlación de datos, líneas de tiempo y helpers para la IA

| Herramienta | Nativo en | Necesita | Estado local |
|---|---|---|---|
| `sqlite3` | Linux / macOS / Windows | — | Instalado |
| `jq` | Linux / macOS / Windows | — | Instalado |
| `csvkit` (`csvlook`, `csvformat`, `csvgrep`) | Cross | Python ≥3.8 | No instalado |
| `timesketch-cli` | Cross | Python ≥3.8 + servidor Timesketch | No instalado |
| `grep` / `egrep` / `fgrep` | POSIX | — | Instalado |
| `awk` | POSIX | — | Instalado |
| `sed` | POSIX | — | Instalado |
| `datamash` (GNU) | Linux / macOS | — | No instalado |
| `diff` / `colordiff` | POSIX / cross | — | `diff` instalado, `colordiff` no |

---

## Resumen del estado local

| Sección | Instaladas | Total | Cobertura |
|---|---:|---:|---:|
| 1. Imágenes y FS | 14 | 21 | 67 % |
| 2. Windows offline | 1 | 21 | 5 % |
| 3. Unix-like | 1 | 15 | 7 % |
| 4. Memoria RAM | 1 | 6 | 17 % |
| 5. Malware / RE | 1 | 12 | 8 % |
| 6. Correlación IA | 7 | 9 | 78 % |
| **Total** | **25** | **84** | **30 %** |

La cobertura alta en secciones 1 y 6 viene de Homebrew (`sleuthkit`, `libewf`, `afflib`,
`jq`, `sqlite3`) y herramientas POSIX. Las secciones 2 (Windows offline) y 3 (Unix logs
remotos) son las que más se benefician del maletín contenedorizado (RULE 1) — sin .NET ni
systemd locales, EvtxECmd y `journalctl` no son alcanzables nativamente desde un Mac;
dentro de la imagen Linux del maletín, sí. El estado local del host es irrelevante para
el usuario final: todas las tools le llegan por las imágenes del compose.
