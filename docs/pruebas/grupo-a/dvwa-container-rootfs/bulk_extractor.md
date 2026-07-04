# `bulk_extractor` — sobre `dvwa-container-rootfs/dvwa-disk.raw`

- **Grupo:** A · **Imagen:** DVWA docker rootfs (ext4 plano) · **Estado:** ✅ muy eficaz (tras corregir nombres de escáner)
- **Binario:** `bulk_extractor` **2.1.0** · **Maletín:** `toolkit-unix` (Cross)
- **run_ids:** `e8c33548` (falló, exit 5) · `6fc0d77b-50ad-4baa-bf34-d17eca2cc787` (OK, exit 0)

## Objetivo (máxima expresión)

`bulk_extractor` escanea la imagen **byte a byte** (incluido espacio no asignado) con escáneres
paralelos y extrae *features*: emails, URLs, dominios, IPs, tarjetas/PII, teléfonos, EXIF,
artefactos Windows… Es el harvester de IOCs. Quería el barrido completo del rootfs.

## Cómo la usé — y el primer fallo (lección de compatibilidad)

**Intento 1 (exit 5, FALLÓ):** `enable_scanners=['email','url','accts']` →
`argv: bulk_extractor -o <out> -E email -e url -e accts <img>`.
`stderr: no such scanner: url`. En **BE 2.1.0 no existe un escáner `url`**: la salida
`url.txt` la produce el escáner **`email`**. Los nombres de escáner cambiaron entre versiones.

**Escáneres válidos en 2.1.0** (de `bulk_extractor -h`):
`accts aes base64 elf email evtx exif facebook find gps gzip httplogs json kml_carved msxml net
ntfsindx ntfslogfile ntfsmft ntfsusn pdf rar sqlite utmp vcard_carved windirs winlnk winpe
winprefetch zip`.

**Intento 2 (exit 0, OK):** sin `enable_scanners` → todos los escáneres por defecto
(`argv: bulk_extractor -o <out> <img>`). Máxima cobertura y sin depender de nombres.

## Resultado obtenido — exit 0

Feature files con contenido (líneas útiles):

| Feature | Nº | Feature | Nº |
|---------|----|---------|----|
| domain.txt | 86.960 | telephone.txt | 30 |
| email.txt | 69.731 | httplogs.txt | 27 |
| url.txt | 16.038 | ether.txt (MAC) | 5 |
| rfc822.txt | 14.397 | winlnk.txt | 2 |
| elf.txt | 1.243 | json.txt | 131 |

**Interpretación forense:** top dominios `mariadb.com`, `php.net`, `gnu.org`,
`bugs.debian.org`; emails tipo `…@compuserve.com`, `…@gnu.org`. **No son actividad de
usuario**: proceden de la **documentación/changelogs de los paquetes** instalados en el
rootfs. Es lo esperable en una imagen de contenedor recién construida — no hay tráfico ni
correos reales. En un **disco usado** (Metasploitable/CFReDS) estos mismos escáneres sacarían
IOCs reales (correos, historiales de navegación, tarjetas).

## Veredicto de eficacia

- **Muy eficaz y potente**: 87k dominios / 70k emails / 16k URLs de una pasada, incluido
  espacio no asignado.
- **Trampa de nombres de escáner por versión** (exit 5): el wrapper no valida los nombres
  contra la versión instalada.
- El volumen es enorme: hay que trabajar por **histogramas** (`*_histogram.txt`), no por el
  feature file crudo.

## Lecciones para entrenar al agente

1. **No hardcodees nombres de escáner:** varían por versión (`url` no existe en BE 2.x). O
   corre **por defecto** (todos), o consulta primero `-H`/`-h`. Un `-e <nombre_malo>` aborta
   todo con exit 5.
2. **Lee los histogramas, no los feature files crudos:** `email_histogram.txt` /
   `domain_histogram.txt` te dan el top ordenado; el `email.txt` de 70k líneas no cabe en
   contexto.
3. **Contextualiza los IOCs:** en una imagen fresca, dominios/emails son *provenencia de
   software* (docs de paquetes), no indicadores. Distingue "IOC del sistema" de "IOC de
   actividad" antes de escalar la severidad.
4. **Es lento** (minutos en imágenes grandes, más bajo emulación): anúncialo y, si acotas,
   habilita escáneres concretos **con nombres válidos**.

## Acciones de mejora sugeridas (producto)

- **Validar `enable_scanners` contra la versión** (o mapear alias como `url`→`email`) para no
  abortar con exit 5.
- Exponer un modo "solo histogramas" para no materializar los feature files gigantes.

## Registro en el caso

- **Finding:** `efb3c09e` — "bulk_extractor: 87k dominios, 70k emails, 16k URLs (provenencia de
  software)" (low), procedencia `bulk_extractor` / run `6fc0d77b`.
- **Evidencia recopilada:** [`bulk_extractor/ioc-resumen.txt`](bulk_extractor/ioc-resumen.txt)
  (top dominios/emails + teléfonos + MACs). Feature files completos en el `ArtifactRun`
  `6fc0d77b/out/`.
