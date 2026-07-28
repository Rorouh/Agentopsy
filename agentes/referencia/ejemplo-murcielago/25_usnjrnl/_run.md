# E2 — $UsnJrnl:$J · ejecución 25
- **Tools:** TSK icat (57644-128-7) + mftecmd (maletín windows). 217.918 entradas USN.
- **Hallazgos:** firma de SDelete a las 22:55:20-23 UTC (`SDELTEMP` + `ZAP****.tmp` = borrado seguro de ESPACIO LIBRE, anti-forense). `base_library.zip` borrado 19:08:02 (key.exe = PyInstaller). XLS confidenciales renombrados a papelera 23:08:59. TODO 22:5x-23:08 es POSTERIOR al volcado de RAM (19:24).
- ⚠️ El CSV `usn.csv` y `UsnJrnl_J.bin` (1,1 GB) son derivados voluminosos; conviene borrarlos tras el análisis para no ocupar disco.
