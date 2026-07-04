# Catálogo de tools instaladas

Referencia rápida de **qué hace cada herramienta** del maletín que **ya está instalada y
probada**, agrupada por fase forense. La columna **Ficha** enlaza al documento de prueba
(objetivo / params / resultado / veredicto / lecciones) de cada tool.

> **Mantener en sync (RULE 4):** este fichero cubre **solo las tools instaladas y operativas**.
> Cada vez que se **añada, quite o modifique** una tool del maletín (`catalog.py` + su wrapper),
> hay que **actualizar esta tabla**: alta/baja de fila, cambio de descripción y enlace a su ficha.
> No listar aquí una tool que no arranque todavía.

Estado: **20/22** tools del catálogo instaladas y probadas. Las 2 restantes
(`evtxecmd`, `mftecmd`) **aún no están operativas** (ver [pendientes](#pendientes-de-instalar))
y por eso no aparecen en las tablas.

---

## 🔎 Triage / identificar ficheros

| Tool | Para qué sirve | Estado | Ficha |
|------|----------------|:------:|-------|
| `file_info` | Te dice **qué es** un fichero por sus *magic bytes* (MIME real), sin fiarte de la extensión | ✅ | [ver](../pruebas/grupo-a/dvwa-container-rootfs/file_info.md) |
| `strings_head` | Saca el **texto imprimible** de un binario (URLs, IPs, comandos incrustados) | ✅ | [ver](../pruebas/grupo-a/dvwa-container-rootfs/strings_head.md) |
| `xxd_head` | **Hex dump** de la cabecera — ver los magic bytes crudos byte a byte | ✅ | [ver](../pruebas/grupo-a/dvwa-container-rootfs/xxd_head.md) |
| `jq` | **Filtrar/consultar** el JSON que produce otra tool (top-N, por campo) | ✅ | [ver](../pruebas/grupo-a/dvwa-container-rootfs/jq.md) |

## 💽 Sistema de ficheros y disco (The Sleuth Kit + carving)

| Tool | Para qué sirve | Estado | Ficha |
|------|----------------|:------:|-------|
| `tsk_mmls` | Lee la **tabla de particiones** (dónde empieza cada una, tipo) | ✅ | [ver](../pruebas/grupo-b/metasploitable2-linux/tsk_mmls.md) |
| `tsk_fls` | **Lista ficheros** de una imagen, incluidos los **borrados**; genera *bodyfile* | ✅ | [A](../pruebas/grupo-a/dvwa-container-rootfs/tsk_fls.md) · [B](../pruebas/grupo-b/metasploitable2-linux/tsk_fls.md) |
| `tsk_icat` | **Extrae un fichero** concreto por su `inode` (aunque esté borrado) | ✅ | [A](../pruebas/grupo-a/dvwa-container-rootfs/tsk_icat.md) · [B](../pruebas/grupo-b/metasploitable2-linux/tsk_icat.md) |
| `tsk_mactime` | Construye la **línea temporal MAC** (cuándo se creó/modificó/accedió cada fichero) | ✅ | [A](../pruebas/grupo-a/dvwa-container-rootfs/tsk_mactime.md) · [B](../pruebas/grupo-b/metasploitable2-linux/tsk_mactime.md) |
| `foremost` | **File carving**: recupera ficheros por cabecera/pie del espacio **no asignado** (sin FS) | ✅ | [A](../pruebas/grupo-a/dvwa-container-rootfs/foremost.md) · [B](../pruebas/grupo-b/metasploitable2-linux/foremost.md) |
| `hashdeep` | **Hashea recursivamente** y coteja contra un set conocido → separa conocido/sospechoso | ✅ | [ver](../pruebas/grupo-a/dvwa-container-rootfs/hashdeep.md) |
| `qemu_nbd` | Expone una imagen `.raw`/`.qcow2` como **dispositivo de bloque** (helper de montaje) | ✅ | [ver](../pruebas/grupo-b/metasploitable2-linux/qemu_nbd.md) |

## 🗄️ Imagen forense e integridad

| Tool | Para qué sirve | Estado | Ficha |
|------|----------------|:------:|-------|
| `ewf_info` | **Metadatos y hashes** de una imagen `.E01` (formato EnCase) | ✅ | [ver](../pruebas/grupo-b/metasploitable2-linux/ewf_info.md) |

## 🕵️ Búsqueda de IOCs / malware

| Tool | Para qué sirve | Estado | Ficha |
|------|----------------|:------:|-------|
| `bulk_extractor` | Escanea **toda** la imagen (incl. no asignado) buscando **emails, URLs, IPs, tarjetas, EXIF** | ✅ | [A](../pruebas/grupo-a/dvwa-container-rootfs/bulk_extractor.md) · [B](../pruebas/grupo-b/metasploitable2-linux/bulk_extractor.md) |
| `yara` | Aplica **reglas/firmas** (webshells, malware, persistencia) a ficheros | ✅ | [ver](../pruebas/grupo-a/dvwa-container-rootfs/yara.md) |

## 🧠 Memoria RAM

| Tool | Para qué sirve | Estado | Ficha |
|------|----------------|:------:|-------|
| `volatility3` | Análisis de un **volcado de RAM** (procesos y árbol padre/hijo, líneas de comando, conexiones de red, **código inyectado**) | ✅ | [ver](../pruebas/grupo-c/windows7-x64-ram-dump/volatility3.md) |

## 🪟 Windows: eventos, registro, timeline

| Tool | Para qué sirve | Estado | Ficha |
|------|----------------|:------:|-------|
| `hayabusa` | EVTX → **detecciones Sigma** + timeline, mapeadas a MITRE (**alerta**) | ✅ | [ver](../pruebas/grupo-c/windows-evtx-hayabusa-samples/hayabusa.md) |
| `chainsaw` | **Hunt** sobre EVTX, agrupando hits **por tipo de ataque** (**alerta**) | ✅ | [ver](../pruebas/grupo-c/windows-evtx-hayabusa-samples/chainsaw.md) |
| `regripper` | Plugins sobre **hives del registro** (cuentas, USB, persistencia, ejecución) | ✅ | [ver](../pruebas/grupo-c/windows-registry-hives-ericzimmerman/regripper.md) |
| `plaso_log2timeline` | **Super-timeline**: fusiona disco+EVTX+registro+navegador en un `.plaso` | ✅ | [ver](../pruebas/grupo-b/metasploitable2-linux/plaso.md) |
| `plaso_psort` | Post-procesa el `.plaso` → CSV filtrable por rango de fechas | ✅ | [ver](../pruebas/grupo-b/metasploitable2-linux/plaso.md) |

---

## Pendientes de instalar

No están en las tablas de arriba porque **aún no arrancan** en el maletín. Se listan aquí solo
como recordatorio; se moverán a la tabla que les corresponda cuando queden operativos.

| Tool | Para qué sirve | Bloqueo |
|------|----------------|---------|
| `evtxecmd` | EVTX → **CSV/JSON normalizado** (todos los eventos crudos, no alertas) — Eric Zimmerman | .NET sin absorber en el Dockerfile del maletín |
| `mftecmd` | Parsea el **`$MFT`** de NTFS → timeline, timestomping, ADS, borrados residentes — Eric Zimmerman | .NET sin absorber en el Dockerfile del maletín |
