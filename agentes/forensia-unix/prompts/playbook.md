# Playbook — FORENSIA-UNIX

Heurística forense por tipo de evidencia. **No es un script**: es la secuencia que
un analista humano probaría primero. Si una pista lleva a otro camino, lo sigues.
Antes de cualquier herramienta, confirma que la evidencia está **verificada**
(`verified=true`); si no, pídelo y espera.

---

## A. Imagen de disco (`.raw`, `.dd`, `.img`, `.E01`, `.vmdk`)

1. **Contenedor.** `ewf_info` si es `.E01` → tamaño, hash interno, metadatos de
   adquisición. Confirma que el hash interno cuadra con el baseline del caso.
2. **Particiones.** `tsk_mmls` → tabla de particiones, offsets (en sectores) y
   tipos. Apunta el `partition_offset` de cada partición de interés: lo necesitas
   como `params.partition_offset` en los pasos siguientes.
3. **Sistema de ficheros (sin montar).** Por cada partición relevante:
   - `tsk_fls` con `recursive: true` → árbol de ficheros, incluidos borrados
     (`*`); vuelve como artefacto (puede ser enorme).
   - `tsk_mactime` sobre el bodyfile (`tsk_fls` con `body_format: true`) →
     **línea temporal MAC(b)**. Esta es tu columna vertebral cronológica.
4. **Extracción quirúrgica.** Cuando identifiques un inodo de interés en el árbol,
   `tsk_icat` con su `inode` → recupera el fichero concreto (log, binario,
   config) como artefacto, sin montar el FS.
5. **IOCs.** `bulk_extractor` sobre la imagen → emails, URLs, IPs, tarjetas,
   PII en espacio no asignado. **Lento**: anúncialo. Filtra el resultado con `jq`.
6. **Carving.** `foremost` para recuperar ficheros por cabecera/firma desde
   espacio no asignado cuando sospeches borrado deliberado.
7. **Firmas / malware.** `yara` con reglas relevantes (webshells, ransomware,
   persistencia) sobre directorios concretos ya extraídos (no sobre la imagen
   entera salvo necesidad).
8. **Super-timeline (opcional, pesado).** `plaso_log2timeline` → `.plaso`;
   `plaso_psort` para acotar por rango temporal y exportar CSV. Úsalo cuando
   necesites correlacionar muchas fuentes; no por defecto.

### Artefactos UNIX donde mirar primero (vía `tsk_icat` sobre el árbol de `fls`)
- Persistencia: `/etc/cron*`, `/etc/systemd/system/*`, `~/.config/systemd/user/*`,
  `/etc/rc.local`, `~/.bashrc`, `~/.profile`, `/etc/ld.so.preload`.
- Cuentas/accesos: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`,
  `~/.ssh/authorized_keys`, `/var/log/auth.log`, `/var/log/secure`.
- Sesiones: `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog`.
- Ejecución / shell: `~/.bash_history`, `~/.zsh_history`, `/var/log/syslog`.
- Red/servicios: `/etc/hosts`, `/etc/resolv.conf`, configs de Apache/Nginx,
  `/var/www` (webshells).
- macOS heredado: `/private/var/log`, `~/Library/Logs`, `LaunchAgents` /
  `LaunchDaemons`, `/Library/Preferences`.

---

## B. Volcado de memoria RAM (`.lime`, `.mem`, `.dump`)

1. **Perfil.** `volatility3` con `plugin: "linux.banner.Banner"` (o el equivalente
   macOS) → identifica kernel/build. **Aviso:** Linux necesita un ISF compatible;
   si no existe, decláralo «no concluyente» en vez de forzar.
2. **Procesos.** `linux.pslist.PsList`, `linux.pstree.PsTree`,
   `linux.psscan.PsScan` → cruza los tres para detectar procesos ocultos
   (presentes en `psscan` pero no en `pslist`).
3. **Red.** `linux.sockstat.Sockstat` → conexiones/sockets; busca IPs o puertos
   anómalos (C2, shells inversas).
4. **Módulos / persistencia en kernel.** `linux.lsmod`, `linux.check_syscall`,
   `linux.check_modules` → rootkits y hooks.
5. **Profundizar en un PID candidato.** `linux.proc.Maps`, volcado de regiones,
   `linux.bash` (historial en memoria). Cita siempre el PID y el plugin.

> Volatility3 con `-r json` devuelve filas estructuradas: el wrapper ya lo pide.
> Si el volcado es Windows (lo dirá `detected_os` del bloque «Contexto de
> evidencia», o lo confirmará un `windows.info.Info` puntual de diagnóstico),
> **no es tu caso**: detente y pide a la operadora que **ancle el perfil del caso
> a `windows`** (el re-enrutado a FORENSIA-WIN es automático; no se cierra ni se
> reabre el caso). Ver la regla 8 del system prompt — no improvises `windows.*`
> plugins porque no son de tu allowlist y porque el caso debe llevarlo
> FORENSIA-WIN.

---

## Buenas prácticas siempre

- Un mismo `tool_id` puede ejecutarse varias veces con `params` distintos: **cada
  ejecución es un `artifact_id` independiente** — indica en cada hallazgo cuál
  usaste.
- Si la salida cabe en contexto, cítala literal en bloque de código; si no,
  referencia el `artifact_id` y resume los puntos clave (apóyate en `jq`).
- No montes el sistema de ficheros salvo que sea imprescindible; si lo haces,
  decláralo explícitamente como excepción en el hallazgo.
- Prioriza la **línea temporal** pronto: ancla cada hallazgo a una marca de
  tiempo del artefacto (`observed_at`), no a la hora en que lo ejecutaste.
