# regripper samparse (SAM) — cuentas del sistema (legible + leads)

Cruda: [`raw.txt`](raw.txt). Tool: `regripper` (rip.pl) `samparse v.20220921` del maletín
**windows**, sobre el hive `SAM` volcado de memoria (`../10_hivelist/registry.SAM.*.hive`).
Horas en **UTC (Z)**.

## Cuentas

| RID | Usuario | Tipo | Último login | **Pwd Fail** | Logins | Nota |
|---|---|---|---|---|---|---|
| 500 | Administrator | Admin (built-in) | 2009-07-14 | Never | 1 | **Deshabilitada** |
| 501 | Guest | Guest | Never | Never | 0 | Deshabilitada |
| 1000 | **IEUser** | **Admin** | **2021-03-23 17:15:22** | **2021-03-23 19:07:38** | 24 | El usuario del equipo (sospechoso) |
| 1001 | sshd | Custom Limited | Never | Never | 0 | Cuenta privsep de Cygwin. Deshabilitada |
| 1002 | **sshd_server** | **Admin** | 2021-03-23 17:15:46 | **2021-03-23 19:07:38** | 11 | ⚠️ Cuenta del servicio SSH **con rango de administrador** |
| 1003 | **testuser** | **Admin** | **Never** | Never | 0 | ⭐ **CREADA 2021-03-23 19:07:38** y metida en **Administradores** |

## ⭐ El evento de las 19:07:38 UTC

Tres cosas caen **en el mismo segundo**, 17 min antes del volcado (19:24:35):
1. **`testuser` se crea** y se añade al grupo **Administrators** (LastWrite del grupo Admin =
   19:07:38). → creación de cuenta = **persistencia / TTP** (MITRE T1136.001, T1098).
2. **Pwd Fail de `IEUser`** a las 19:07:38.
3. **Pwd Fail de `sshd_server`** a las 19:07:38.

32 s después (**19:08:10**) arranca **`key.exe`**. Es el inicio de la secuencia sospechosa.

## Miembros de Administrators (LastWrite 19:07:38)

IEUser(1000), sshd_server(1002), **testuser(1003)** y Administrator(500).

## Lo que ESTO responde y lo que NO

- **Aporta a E2/P2:** la creación de `testuser` es **ejecución de comandos** (probable
  `net user testuser … /add` + `net localgroup administrators testuser /add`) y un TTP claro.
- **NO da la contraseña (E1).** `samparse` lista cuentas, **no** el hash NTLM crackeable. En
  este maletín **no hay** `samdump2`/`secretsdump`/`hashdump` → el hash no se extrae aquí. Vías
  para E1: (1) SAM del **disco** + herramienta de cracking; (2) contraseña en **claro** en
  memoria (`strings`, ejec. 14) o en Sticky Notes (disco). ⚠️ **No se inventa la contraseña.**
