# `mftecmd` — sobre `windows-ntfs-mft-nist` (`$MFT` de la NIST Hacking Case)

- **Grupo:** C (Windows) · **Estado:** ✅ (tras **absorber .NET + realinear al maletín**)
- **Binario:** `MFTECmd` (Eric Zimmerman, .NET net9 sobre runtime en el maletín) · **Maletín:** `toolkit-windows`
- **run_id:** `e0e96164-10c8-4cd0-9b1f-1aa2c5d183e8`
- **Evidencia:** `nist-hacking-case.mft` (~12,6 MB) — `$MFT` real de la **NIST CFReDS Hacking Case**

## Objetivo (máxima expresión)

Parsear la **`$MFT`** (Master File Table, el índice maestro de todo NTFS) → un CSV con **cada
registro de fichero**: ruta, tamaño, si es directorio, timestamps `$STANDARD_INFORMATION` vs
`$FILE_NAME`, ADS (`HasAds`) y si está en uso o **borrado** (`InUse`). Es **la fuente de verdad
del sistema de ficheros NTFS**, sin montar la imagen.

## Qué hizo falta para arrancarla (el bloque .NET)

Mismo trabajo que `evtxecmd` (van juntos, comparten runtime): runtime **.NET 9** + build **net9**
de MFTECmd en el maletín (SHA pinneado), `ENV DOTNET_EnableWriteXorExecute=0` (segfault bajo
QEMU), y realineado de catálogo/wrapper al modelo maletín (`-f <mft>`, `--csv <out>`, sin
`/in/mft`·`/out` ni `host_mounts`). Ver detalles en [`evtxecmd.md`](../windows-evtx-hayabusa-samples/evtxecmd.md).

Para la evidencia no hizo falta `icat`: se usó un **`$MFT` ya extraído** de la NIST Hacking Case
(repo `msuhanov/dfir_ntfs`), que empieza por el magic `FILE0` de un registro MFT.

## Cómo la usé (params + argv)

```
execute("mftecmd", {"mft_path": "/evidence/windows-ntfs-mft-nist/nist-hacking-case.mft"},
        case_id=…, os_profile="windows")   # output_dir lo inyecta el dispatcher
argv = MFTECmd -f <$MFT> --csv <out_dir> --csvf mft.csv   →   exit 0, run e0e96164
```

## Resultado obtenido — exit 0

**12.181 registros** de la MFT → CSV con `EntryNumber, ParentPath, FileName, FileSize,
IsDirectory, HasAds, InUse` + timestamps. Señales:

- **Árbol NTFS reconstruido:** 12.181 entradas con su ruta padre y tamaño, sin montar la imagen.
- **3 entradas borradas** (`InUse=false`): `OBJECTS.MAP`, `INDEX.MAP`, `ROLL_FORWARD` del
  repositorio **WMI** (`WINDOWS\system32\wbem\Repository\FS`).
- **2 con ADS** (`HasAds=true`): `$BadClus` y `$Secure` — metaficheros NTFS de sistema con streams
  nombrados (`$Bad`, `$SDS`); esperados, no maliciosos, pero demuestran la detección de ADS.

## Veredicto / lecciones para el agente

- **La MFT es el catálogo maestro de NTFS:** una sola pasada da el árbol completo + metadatos, y
  aún sobreviven entradas **borradas** (los ficheros ya no están, pero su registro sí).
- **Caza timestomping:** MFTECmd expone `$SI` y `$FN` por separado; si `$SI` (lo que ve el usuario)
  es anterior a `$FN` (lo que fija NTFS al crear), hay manipulación de fechas.
- **`HasAds` señala dónde mirar ADS** (Alternate Data Streams), escondite clásico de malware —
  aquí solo salen los de sistema, pero el flag es el que dispara la revisión.
- **El `$MFT` va pre-extraído** (aquí ya lo estaba; en general `icat -o <offset> <img> 0`, la MFT es
  el inode 0 de NTFS) y se pasa por su ruta real bajo `/evidence`.

## Registro en el caso

- **Findings:** `87cc8538` (12.181 registros MFT + borrados/ADS — low).
- **Evidencia recopilada:** [`mftecmd/mft.csv`](mftecmd/mft.csv) (muestra representativa;
  el CSV completo de 12.181 filas queda en el artifact store del caso, run `e0e96164`).
