# Artefactos UNIX/Linux/macOS — dónde mirar y con qué

Referencia de consulta bajo demanda. Todo se recupera **sin montar** el sistema de
ficheros: localiza el inodo en el árbol de `tsk_fls` y extrae con `tsk_icat`. Cada
extracción es un artefacto hasheado; ancla el hallazgo a su `run_id`.

## Persistencia / autoarranque
- `cron`: `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.{daily,hourly,weekly,monthly}/*`,
  `/var/spool/cron/crontabs/*`.
- `systemd`: `/etc/systemd/system/*`, `/lib/systemd/system/*`, `~/.config/systemd/user/*`
  (unidades `.service`/`.timer` sospechosas: `ExecStart` a rutas raras).
- Init clásico: `/etc/rc.local`, `/etc/init.d/*`, `/etc/rc[0-6].d/*`.
- Shells de login: `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`,
  `/etc/profile`, `/etc/profile.d/*`.
- Carga de librerías: `/etc/ld.so.preload`, variable `LD_PRELOAD` en configs.

## Cuentas y accesos
- Usuarios/hashes: `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`,
  `/etc/sudoers.d/*` (nunca afirmes que una clave está «crackeada»: solo describe).
- SSH: `~/.ssh/authorized_keys` (puertas traseras), `~/.ssh/known_hosts` (a dónde se
  conectó), `~/.ssh/id_*` (material de clave), `/etc/ssh/sshd_config`.

## Sesiones y autenticación
- Binarios (no texto plano; extrae y parsea): `/var/log/wtmp` (logins),
  `/var/log/btmp` (fallidos), `/var/log/lastlog`, `/var/run/utmp`.
- Texto: `/var/log/auth.log` (Debian/Ubuntu), `/var/log/secure` (RHEL/CentOS).

## Ejecución y actividad de usuario
- Historial de shell: `~/.bash_history`, `~/.zsh_history`, `~/.local/share/fish/…`,
  `~/.python_history`, `~/.mysql_history`. Ojo: puede estar vaciado o enlazado a
  `/dev/null` (indicador anti-forense — regístralo).
- Logs de sistema: `/var/log/syslog`, `/var/log/messages`, `/var/log/journal/*`
  (journald binario: parsea con la herramienta adecuada).

## Red y servicios
- `/etc/hosts`, `/etc/resolv.conf`, `/etc/hostname`.
- Servidores web (webshells): `/var/www/`, `/srv/www/`, configs de Apache
  (`/etc/apache2`, `/etc/httpd`) y Nginx (`/etc/nginx`). Filtra por extensiones
  ejecutables (`.php`, `.jsp`, `.cgi`) en rutas servidas.

## Temporales / staging de malware
- `/tmp/`, `/var/tmp/`, `/dev/shm/` con binarios/scripts (`.sh`, `.elf`, `.py`,
  ejecutables sin extensión con bit +x): staging típico de payloads.

## macOS (heredado)
- Persistencia: `/Library/LaunchAgents`, `/Library/LaunchDaemons`,
  `~/Library/LaunchAgents`, `/System/Library/LaunchDaemons`.
- Logs y prefs: `/private/var/log`, `~/Library/Logs`, `/Library/Preferences`,
  `~/Library/Preferences` (plists — parsea, no asumas texto).
- Cuarentena / descargas: atributo extendido `com.apple.quarantine`,
  `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`.

## Huso horario (antes de cualquier timeline)
- `/etc/timezone` o el destino del symlink `/etc/localtime`. En macOS, la preferencia
  de zona del sistema. Declara el huso hallado ANTES de construir la línea MAC(b):
  sin él, las marcas son ambiguas. Normaliza siempre a `timezone: UTC` en `tsk_mactime`.
