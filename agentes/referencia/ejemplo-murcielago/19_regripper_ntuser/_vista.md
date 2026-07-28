# regripper (NTUSER de IEUser) — documentos y programas (legible) · P1

Cruda: [`raw.txt`](raw.txt). Tool: `regripper` sobre `NTUSER.dat` de IEUser volcado de RAM
(`../10_hivelist/registry.ntuserdat.0xf8a0025e5410.hive`). Horas en **UTC**; local = UTC−7.

## P1 — Documentos abiertos (RecentDocs)

`RecentDocs` (LastWrite **2021‑03‑23 19:24:33Z**, orden MRU = más reciente primero) contiene,
entre otros:

| Documento | Relevancia |
|---|---|
| **`Documentacion empresa`** | ⭐ La **información confidencial de la empresa** — el objeto del caso (P1). |
| **`pass.txt`**, **`passwords.txt`** | ⭐ Directamente relacionados con **E1 (contraseña)**. Fueron abiertos por el usuario. |
| `flag.txt`, `flag2.txt`, `leeme.txt`, `leeme.txt.bak`, `README.txt` | Ficheros del ejercicio/CTF (planta del enunciado); `leeme` = readme. |
| `…0110d5ec.zip` (nombre tipo SHA256) | Zip sospechoso; RecentDocs\.zip LastWrite 2021‑03‑19. |
| `ram.raw`, `RAM`, `DumpIt`, `wintriage.log` | Artefactos de **adquisición** (no del sospechoso). |

- Subclave `.txt` (LastWrite **2021‑03‑23 17:54:24Z**): orden de apertura de los .txt →
  leeme, flag, passwords, pass, flag2, README.

## comdlg32 — ficheros por diálogo Abrir/Guardar

- `OpenSavePidlMRU`: **`My Computer\F:\RAM\ram.raw`** → el volcado se guardó en la **USB F:**
  (perito). `CIDSizeMRU`/`LastVisitedPidlMRU`: **MagnetRamCapture.exe**, **thunderbird.exe**.

## userassist — programas ejecutados por el usuario

- **Herramientas de adquisición forense** (del perito): `MagnetRamCapture.exe`, `DumpIt.exe`,
  `RamCapture64.exe`, `Wintriage64.exe`, `FTKImagerLite.exe`, `HashMyFiles.exe` — ejecutadas
  desde `F:\`, `E:\` y el Desktop.
- **`C:\Users\IEUser\Desktop\key.exe (3)`** → ejecutado **3 veces** por el usuario. Refuerza el
  lead de P2.
- `thunderbird.exe` (cliente de correo), `hMailAdmin.exe` (admin del servidor de correo),
  `MicrosoftEdgeSetup`, notepad, calc, etc.

## ⚠️ Interpretación honesta

- **P1 respondida:** el usuario **abrió `Documentacion empresa`** y ficheros como
  `passwords.txt`/`pass.txt`. La marca temporal fina de cada apertura (más allá del LastWrite
  de la clave) y el **contenido** de esos ficheros están en el **disco** → pendiente.
- **Mucho de lo que se ve es ADQUISICIÓN** (Magnet, DumpIt, Wintriage, FTK, HashMyFiles):
  actividad del **perito**, no del sospechoso. Separado a propósito.
- **E1:** `pass.txt`/`passwords.txt` abiertos → su **contenido** puede seguir en memoria
  (`strings`) o en el disco. Es la vía más directa a la contraseña; **no se inventa**.
