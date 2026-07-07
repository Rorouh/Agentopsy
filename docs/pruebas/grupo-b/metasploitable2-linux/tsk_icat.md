# `tsk_icat` — sobre `metasploitable2-linux/Metasploitable.raw`

- **Grupo:** B · **Imagen:** Metasploitable 2 (disco particionado real) · **Estado:** ✅ eficaz (hallazgo de alto valor)
- **Binario:** `icat` (Sleuthkit) · **Maletín:** `toolkit-unix` (integrada — fix Bug 003)
- **run_ids:** passwd `88320b73` · shadow `c2a03534`

## Objetivo (máxima expresión)

Extraer ficheros de alto valor de la **raíz real** (dentro del LVM, offset 482397). El
objetivo estrella: `/etc/shadow` — en un sistema real hay **hashes de contraseña reales**
(a diferencia del DVWA, con cuentas bloqueadas).

## Cómo la usé (params + argv)

Encadenado `fls → icat` con el **offset del LV** (482397, ver `tsk_fls.md`). Primero navegué
`/etc` (fls) para los inodes correctos (lección del Grupo A: no elegir por nombre):
`/etc` = inode 139265 → `passwd` = 140721, `shadow` = 140720.

```
execute("tsk_icat", {"image_path": <raw>, "partition_offset": 482397, "inode": 140720}, …)
argv = icat -o 482397 <raw> 140720   →   exit 0, run c2a03534
```

## Resultado obtenido — exit 0

**`/etc/shadow` — 7 cuentas con hash MD5-crypt (`$1$`) CRACKEABLE:**
`root`, `sys`, `klog`, `msfadmin`, `postgres`, `user`, `service`.
(Metasploitable usa contraseñas débiles conocidas → crackeables con john/hashcat + rockyou.)

**`/etc/passwd`:** cuentas reales — `root` (/bin/bash), `msfadmin`, `postgres`, `user`,
`service`, cuentas de servicio (daemon, bin, sys, mail, uucp…).

**Contraste con el Grupo A (DVWA):** allí `/etc/shadow` tenía todo bloqueado (`*`), sin nada
que crackear. Aquí hay **credenciales reales recuperables** — el corazón de muchos casos.

## Veredicto de eficacia

- **Muy eficaz** y de alto valor: recuperó las credenciales del sistema por el flujo normal
  (dispatcher, offset LVM), con cadena de custodia.
- Cierra el triángulo del caso: **passwd** (quién existe) + **shadow** (sus hashes) + **utmp**
  (quién entró, de bulk_extractor).

## Lecciones para entrenar al agente

1. **`/etc/shadow` es objetivo prioritario en Linux**: hashes de contraseña. Si son `$1$`
   (MD5), `$6$` (SHA512) o DES, son crackeables — repórtalo como **hallazgo de alto valor**.
2. **Navega el directorio padre para el inode** (`/etc` → passwd/shadow); no adivines por
   nombre (lección del Grupo A).
3. **Cruza artefactos**: passwd + shadow + utmp (sesiones) + auth.log dan la historia de
   accesos completa.
4. **No inventes la contraseña**: `icat` da el hash; el crackeo (john/hashcat) es un paso
   aparte (no está en el maletín) — reporta el hash y su tipo, no un valor sin crackear.

## Registro en el caso

- **Findings:** `25bc3975` (7 hashes MD5 crackeables — **high**) · `c97c330e` (cuentas passwd).
- **Evidencia recopilada:** [`tsk_icat/shadow`](tsk_icat/shadow) · [`tsk_icat/passwd`](tsk_icat/passwd).
