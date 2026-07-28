# strings — nube / webmail / IP externa (legible + leads) · P4

Cruda: [`raw.txt`](raw.txt) (1951 líneas que casan con el filtro). Tool: `strings` (ASCII +
UTF‑16LE) sobre `ram.raw`, filtrado por IP externa y dominios de nube/webmail.

## Resultado

| Búsqueda | Resultado | Lectura |
|---|---|---|
| **`200.228.36.6`** (la IP CLOSED de netscan) | **0 coincidencias** en el texto de memoria | El resto de conexión de `03_netscan` **no está corroborado** en strings → **pierde fuerza** como destino de exfiltración. No descartado del todo (pudo no dejar texto), pero baja de prioridad. |
| **⭐ Google Drive — enlace a un fichero** | `https://drive.google.com/file/d/0B1yljg3v3iiCdzhJVXZTa3Q0Tzg/edit?usp=sharing` (repetido varias veces, vía Bing newtabredir y directo) | **Lead fuerte de P4:** se accedió a **un archivo concreto** en Google Drive (id `0B1yljg3v3iiCdzhJVXZTa3Q0Tzg`). Posible subida/descarga del documento. A confirmar en historial de navegador (disco). |
| Dominios de nube/webmail (recuento) | outlook 816, yandex 482, gmail 353, onedrive 297, dropbox 66, drive.google 64, pastebin 40, protonmail 30, wetransfer 15, mega.nz 2… | ⚠️ **En su mayoría RUIDO** de telemetría/caché de navegador (aparecen en cualquier Windows con Edge/IE). El **número no es prueba**; sirve el **artefacto concreto** (el enlace de Drive), no el conteo. |
| Otros | `log.getdropbox.com`, `wetransfer` sueltos | Contexto; sin URL de fichero concreta como la de Drive. |

## Conclusión P4 (con memoria)

- **Sí hay rastro de nube:** un **enlace directo a un fichero de Google Drive**, repetido. Es
  el mejor indicio de conexión a almacenamiento en la nube.
- **La IP externa de netscan no se sostiene** en el texto de memoria.
- **Para cerrar P4** hace falta el **historial de navegador** (disco: `hindsight`, o WebCache
  de IE/Edge) para saber si ese Drive fue **subida** (exfiltración) o simple visita, y cuándo.
