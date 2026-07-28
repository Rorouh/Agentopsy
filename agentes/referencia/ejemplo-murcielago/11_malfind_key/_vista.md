# key.exe (PID 3856/3184) — malfind + dlllist + handles (legible)

Crudas: [`raw.txt`](raw.txt) (malfind) · [`../12_dlllist_key/raw.txt`](../12_dlllist_key/raw.txt) ·
[`../13_handles_key/raw.txt`](../13_handles_key/raw.txt).

## Qué es key.exe

- Binario **`C:\Users\IEUser\Desktop\key.exe`**, arrancado **2021-03-23 19:08:10 UTC** (dos
  instancias: 3856 padre, 3184 hija).
- **DLLs cargadas** (`dlllist`): incluye **`WS2_32.dll` + `NSI.dll`** → **capacidad de red
  (Winsock)**. También USER32/GDI32 (tiene GUI), ADVAPI32, MSCTF.
- **Handles** (`handles`): abre `\Users\IEUser\Desktop` (File), y claves de registro entre
  ellas **`IMAGE FILE EXECUTION OPTIONS`** y `APPCOMPATFLAGS`. SID de IEUser confirmado
  `S-1-5-21-2213123778-2569645789-4120232176-1000`.

## malfind

- Una región **`PAGE_EXECUTE_READWRITE`** (RWX) en `0x180000` de la instancia 3184… pero
  **vacía (todo ceros)**. RWX privada es un indicio débil; sin código inyectado visible **no
  es prueba de inyección**.

## Lectura (a confirmar, NO cerrado)

- key.exe es un **ejecutable de red con GUI** puesto en el escritorio del usuario. Nombre +
  ubicación + Winsock + el hecho de arrancar justo tras la creación de `testuser` lo hacen
  **sospechoso**. Pero **no se puede afirmar qué hace** sin el binario: hay que **dumparlo**
  (`windows.pedump`/`dumpfiles`) o cogerlo del **disco** y analizarlo (hash, strings, sandbox).
- ⚠️ No llamarlo "malware" todavía. Es "ejecutable sospechoso con capacidad de red, pendiente
  de análisis".
