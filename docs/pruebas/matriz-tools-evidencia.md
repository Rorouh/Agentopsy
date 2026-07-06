# Matriz de pruebas: tools × evidencia real

Plan para probar **cada herramienta del maletín en su máxima expresión**, una por una,
con la evidencia real adecuada. La evidencia se descarga **según se necesite por tool**
(las URLs están abajo). Dos ejes que se cruzan: la **tool** y la **evidencia** que
consume; a la hora de ejecutar van juntas.

- Estado `✅` = corre ya sobre el disco DVWA que tenemos (`./evidence/dvwa-disk.raw`).
- Estado `📥` = necesita evidencia externa (descargar de la URL).
- Estado `⛔` = **no arranca hoy** (binario ausente / no absorbido / desajuste de catálogo) — hay que resolverlo antes de probar. Ver "Bloqueos".

Convención de rutas: la evidencia va a `./evidence/` del repo (se monta `ro` en los
maletines en `/evidence`). Los ficheros derivados (hives, `$MFT`, `.evtx`) se extraen de
una imagen con `tsk_icat`/`tsk_fls` o se descargan sueltos.

---

## Tabla principal

| Tool | Maletín | Máxima expresión (qué exprimir) | Evidencia necesaria | Fuente real (URL) | Estado |
|------|---------|--------------------------------|---------------------|-------------------|--------|
| `file_info` | ambos | tipo + MIME por *magic* de un fichero/imagen | cualquier fichero o imagen | usar uno extraído del DVWA, o cualquier sample de abajo | ✅ |
| `strings_head` | ambos | strings imprimibles (ASCII/UTF-16) de un binario | cualquier binario/fichero | fichero del DVWA (`icat`) o binario de sistema | ✅ |
| `tsk_fls` | ambos | listado recursivo `-r`, borrados `-d`, bodyfile `-m` | imagen de disco (mejor con borrados) | DVWA (básico) · disco particionado (rico) → CFReDS / Digital Corpora | ✅ / 📥 |
| `tsk_icat` | ambos | extracción de fichero por `inode` (incl. borrado) | imagen de disco + un inode de interés | DVWA (`main.sh` inode 1030) · CFReDS | ✅ |
| `tsk_mactime` | ambos | timeline MAC(b) desde bodyfile (`fls -m`) | bodyfile de `tsk_fls -m` | derivado de cualquier disco (DVWA sirve) | ✅ |
| `tsk_mmls` | ambos | tabla de particiones DOS/GPT, offsets, tipos | disco **con tabla de particiones** (DVWA falla) | CFReDS Hacking Case (E01 NTFS) · Digital Corpora `nps-2009-canon2` | 📥 |
| `ewf_info` | ambos | metadatos EWF + hashes de adquisición | imagen **.E01/.Ex01** | CFReDS Hacking Case (.E01) · o convertir raw→E01 con `ewfacquire` | 📥 |
| `bulk_extractor` | ambos | scanners: email/url/ip/ccn/exif sobre no asignado | imagen de disco con PII real | Digital Corpora `govdocs1` / escenario M57-Patents | 📥 |
| `foremost` | ambos | carving por cabecera/pie desde espacio no asignado | imagen con ficheros borrados/no asignado | Digital Corpora `nps-2009-canon2` (SD FAT, con borrados) | 📥 |
| `hashdeep` | ambos | hashing recursivo + audit contra set conocido | cualquier fichero/dir | ficheros extraídos del DVWA, o NSRL set | ✅ |
| `qemu_nbd` | ambos | exponer raw/qcow2 como block device (helper de montaje) | imagen `.raw`/`.qcow2` | DVWA (raw) · o qcow2 de abajo | ✅ |
| `volatility3` | ambos | plugins de memoria: pslist/pstree/psscan/netscan/malfind/… | **volcado de RAM** + ISF/símbolos del kernel | Volatility Memory Samples (Windows) — ver URL | ✅ |
| `hayabusa` | windows | EVTX → detecciones Sigma + timeline (`csv-timeline`) | logs `.evtx` de Windows | hayabusa-sample-evtx · EVTX-ATTACK-SAMPLES | 📥 |
| `chainsaw` | windows | hunt Sigma sobre EVTX/MFT/registro (`hunt`) | logs `.evtx` (y opcional `$MFT`/hives) | EVTX-ATTACK-SAMPLES | ✅ |
| `plaso_log2timeline` | ambos | super-timeline multi-fuente (disco/EVTX/registro) → `.plaso` | imagen de disco o artefactos | CFReDS Hacking Case · o `test_data` de plaso | 📥 |
| `plaso_psort` | ambos | post-proceso `.plaso` → CSV/l2tcsv, filtros por rango | un `.plaso` de `log2timeline` | derivado del paso anterior | 📥 |
| `regripper` | windows | plugins sobre hives (SYSTEM/SOFTWARE/NTUSER) | hives de registro de Windows | extraer de CFReDS con `icat`, o samples | ✅ |
| `evtxecmd` | windows | EVTX → CSV/JSON estructurado (Eric Zimmerman) | logs `.evtx` | EVTX-ATTACK-SAMPLES | ✅ |
| `mftecmd` | windows | `$MFT` → timeline NTFS (creación/mod, ADS) | fichero `$MFT` de un NTFS | extraer de CFReDS NTFS con `icat`, o sample | ✅ |
| `yara` | ambos | match de reglas (webshells/malware/persistencia) | reglas YARA + fichero objetivo | signature-base + fichero de test (EICAR) | ⛔ (binario ausente) |
| `xxd_head` | ambos | hex dump de la cabecera (magic bytes) | cualquier fichero | cualquiera | ⛔ (binario ausente) |
| `jq` | ambos | filtrar el JSON de salida de otra tool (top-N, por campo) | un artefacto JSON (p. ej. `vol -r json`) | derivado de otra tool — sin descarga | ✅ |

---

## Fuentes de evidencia real (URLs)

### Discos (raw / dd / E01)
- **NIST CFReDS** (índice): https://cfreds.nist.gov/
- **CFReDS — Hacking Case** (imagen `.E01`, NTFS; ideal para `ewf_info`, `mmls`, `fls`, `icat`, `mftecmd`, hives→`regripper`, `plaso`): https://cfreds.nist.gov/all/NIST/HackingCase
- **CFReDS — Data Leakage Case**: https://cfreds.nist.gov/all/NIST/DataLeakageCase
- **Digital Corpora — disk images** (índice): https://digitalcorpora.org/corpora/disk-images/
- **Digital Corpora — `nps-2009-canon2`** (SD FAT pequeña, con borrados; buena para `fls`/`icat`/`foremost`/`mmls`): https://digitalcorpora.org/corpora/scenarios/nps-2009-canon2/
- **Digital Corpora — `govdocs1`** (documentos con PII; buena para `bulk_extractor`): https://digitalcorpora.org/corpora/files/govdocs1/
- **Digital Corpora — M57-Patents scenario** (disco+RAM+red de un caso completo): https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/

### Volcados de memoria (Volatility 3)
- **Volatility — Memory Samples** (lista con URLs de descarga; usar muestras **Windows**, que Vol3 soporta out-of-the-box): https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples
- **Símbolos/ISF de Volatility 3** (si el volcado es Linux/Mac, hace falta el ISF del kernel): https://github.com/Abyss-W4tcher/volatility3-symbols

### Logs de eventos Windows (.evtx)
- **hayabusa-sample-evtx** (muestras oficiales para probar hayabusa): https://github.com/Yamato-Security/hayabusa-sample-evtx
- **EVTX-ATTACK-SAMPLES** (miles de `.evtx` por técnica ATT&CK; para hayabusa/chainsaw): https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

### Registro / $MFT
- Se **extraen de una imagen NTFS** (CFReDS Hacking Case) con `tsk_icat` sobre los inodes de `C:\Windows\System32\config\{SYSTEM,SOFTWARE,SAM}` y `$MFT` (inode 0 en NTFS). No suele haber "hives sueltos" oficiales — el flujo forense correcto es extraerlos de la imagen.

### YARA
- **Reglas — signature-base (Neo23x0)**: https://github.com/Neo23x0/signature-base
- **Reglas — YARA-Rules**: https://github.com/Yara-Rules/rules
- **Fichero objetivo de test (EICAR, inofensivo)**: https://secure.eicar.org/eicar.com.txt

---

## Bloqueos a resolver antes de probar (hallazgos del propio ejercicio)

Probar destapa lo que no está cableado. Cinco tools no arrancan hoy:

| Tool | Causa | Arreglo |
|------|-------|---------|
| ~~`yara`~~ ✅ | ~~binario no instalado~~ **RESUELTO**: `yara` 4.1.3 añadido al Dockerfile; probado (match sobre DVWA) | — |
| ~~`xxd_head`~~ ✅ | ~~binario no instalado~~ **RESUELTO**: `xxd` añadido al Dockerfile; probado (magic ext4) | — |
| ~~`evtxecmd`~~ ✅ | **resuelto (2026-07-04)**: absorbido runtime .NET 9 + build net9 en el stage `windows`; realineado al maletín | — |
| ~~`mftecmd`~~ ✅ | **resuelto (2026-07-04)**: mismo bloque .NET; probado con el `$MFT` de la NIST Hacking Case | — |
| ~~`regripper`~~ ✅ | **resuelto (2026-07-04)**: desajuste de catálogo `rip`→`rip.pl` + realineado al maletín (retirado `delivery`/`container_image`/`host_mounts` legacy) | — |

> Nota: `evtxecmd`/`mftecmd` son .NET; su ausencia coincide con "absorber las últimas
> tools Windows en los Dockerfiles" (proximos-pasos §A). `chainsaw` cubre parte de su
> función mientras tanto.

Había **6 tools *stub* de catálogo** (sin `build_argv`/`parse` → `NotImplementedError`). **Las
6 ya integradas** ✅ (`hashdeep`, `foremost`, `tsk_icat`, `plaso_*`, `qemu_nbd`) — Bug 003
**resuelto**. `qemu_nbd` tiene wrapper pero su runtime (nbd+privilegios) no está en el compose
(documentado). Ver [Bug 003](../bugs/003-tools-stub-sin-wrapper.md).

---

## Orden sugerido de ejecución

1. **Grupo A (ya, sobre DVWA):** `file_info` → `strings_head` → `tsk_fls` (`-r`/`-d`/`-m`) → `tsk_icat` (extraer `main.sh`) → `tsk_mactime` → `hashdeep` → `foremost` → `bulk_extractor` → `jq` (sobre un JSON de estos). Cierra 9 tools sin descargas.
2. **Disco particionado + E01 (CFReDS Hacking Case):** desbloquea `tsk_mmls`, `ewf_info`, y enriquece `fls`/`icat`/`foremost`/`plaso`.
3. **Memoria (muestra Windows de Volatility):** `volatility3` (pslist/pstree/psscan/netscan/malfind) + `jq` sobre su salida JSON.
4. **EVTX (hayabusa-sample-evtx / EVTX-ATTACK-SAMPLES):** `hayabusa`, `chainsaw`.
5. **Resolver bloqueos** y probar `yara`, `xxd_head`, `regripper`, `evtxecmd`, `mftecmd`.
6. **Plaso** como cierre (super-timeline sobre el disco de CFReDS).

Cada prueba deja constancia: `run_id` + artefacto + entrada en el `audit.jsonl` del caso
(cadena de custodia). Se registra por tool: comando, exit code, y si el resultado es el
esperado ("eficacia").
