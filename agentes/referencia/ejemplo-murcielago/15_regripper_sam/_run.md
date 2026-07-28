# regripper samparse (SAM) · murcielago · ejecución 15
- **Tool:** regripper (rip.pl) `samparse v.20220921` · imagen `forensia/toolkit-windows:1.0`
- **Comando:** `rip.pl -r /hives/registry.SAM.0xf8a002386010.hive -p samparse`
- **Entrada:** SAM volcado en `../10_hivelist/` (montado ro). **Fecha:** 2026-07-28 · Exit 0 · 6523 bytes
- **Salidas:** `raw.txt` · `_vista.md`
- **Observado:** 7 cuentas; **testuser creada 19:07:38 y admin**; pwd-fail de IEUser y sshd_server a esa hora; sshd_server es admin. NO da el hash NTLM (E1 sigue sin cerrar).
- **Nota de método:** hive volcado de RAM analizado con una tool del maletín **windows** (regripper no está en el unix). Cruzar maletines es normal; se documenta cuál se usó.
