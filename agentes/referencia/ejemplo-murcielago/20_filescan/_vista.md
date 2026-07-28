# filescan + dumpfiles — ficheros en memoria (legible) · P1 + E1

Crudas: [`raw.txt`](raw.txt) (filescan, 9990 objetos de fichero) · extraídos en
[`../21_dumpfiles/`](../21_dumpfiles/).

## ⭐ Los documentos confidenciales (P1) — identificados y RECUPERADOS

| Fichero (en memoria) | Offset | Extraído | Contenido |
|---|---|---|---|
| `\Users\IEUser\Documents\Documentacion empresa\`**`CLIENTES DEL BANCO.xls`** | `0x13d0bb070` | ✅ 16 KB | **Datos de clientes bancarios** (columnas `NOMBRE`, `TIPO DE CUENTA`, `CUENTA COMPARTIDA`, `CUENTA CORRIENTE`). |
| `\Users\IEUser\Documents\Documentacion empresa\`**`Plan_de_cuentas.xls`** | `0x13d337dd0` | ✅ 72 KB | Plan contable. |
| `…\Documentacion empresa\flag2.txt` | `0x13fe38d10` | — | Fichero planta del CTF. |

→ **La "información económica confidencial" del enunciado son estos dos XLS** (clientes del
banco + plan de cuentas), y se **recuperaron de la RAM** con `dumpfiles`. P1 confirmado con
los ficheros reales, no solo con su nombre.

## E1 — la contraseña NO sale de esta RAM

| Fichero | En filescan | ¿Contenido en memoria? |
|---|---|---|
| `\Users\IEUser\Desktop\pass.txt` | sí (`0x13d6be070`) | ❌ `dumpfiles` vacío → **solo el metadato, sin páginas de datos residentes**. |
| `passwords.txt` | **no aparece** | no cacheado. |

- **Conclusión honesta:** el fichero con la contraseña existe en el Desktop, pero su
  **contenido no está en este volcado** → E1 se cierra con el **disco** (leer `pass.txt`), no
  con la RAM. Los hashes NTLM tampoco se pueden extraer con este maletín (ver
  [a6](../../REGISTRO-DECISIONES.md#a6-hives-key-cuentas)). **No se inventa la contraseña.**

## Otros

- `\Windows\Prefetch\KEY.EXE-A7310F00.pf` → **artefacto de ejecución de `key.exe`** (Prefetch).
  Confirma que key.exe se ejecutó; el `.pf` (con nº de ejecuciones y última hora) está en el
  **disco**. Refuerza P2.
