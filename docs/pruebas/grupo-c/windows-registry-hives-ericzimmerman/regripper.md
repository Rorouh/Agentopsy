# `regripper` — sobre `windows-registry-hives-ericzimmerman` (5 hives)

- **Grupo:** C (Windows) · **Estado:** ✅ (tras **realinear al modelo maletín**)
- **Binario:** `rip.pl` v3.0 (Perl) · **Maletín:** `toolkit-windows` · plugins en `/opt/regripper/plugins`
- **Hives:** `SAM`, `SECURITY`, `SOFTWARE`, `SYSTEM`, `NTUSER.DAT` (samples de Eric Zimmerman)

## Objetivo (máxima expresión)

Extraer del **registro de Windows** el perfil del sistema, las cuentas, la actividad de
usuario y los rastros de dispositivos/persistencia — RegRipper corre **plugins** dirigidos
(uno por artefacto) sobre una hive pre-extraída, sin montar la imagen (FORENSIC_SOUNDNESS §5).

## El realineado que hizo falta (no era un bug, era deuda legacy)

regripper era el último tool con el **modelo muerto container-por-tool**: el catálogo lo
declaraba con `binary="rip"` (no existe en el maletín; es `rip.pl`), `delivery=DELIVERY_ALL_
CONTAINER`, `container_image="forensia/regripper:latest"` y `host_mounts` mapeando la hive a
`/in/hive`. El dispatcher ya **no** mira esos campos (enruta por `toolkits` + `os_profile` al
exec-agent), así que el sondeo lo veía ausente y el argv apuntaba a un mount inexistente.

**Fix (proximos-pasos §A):**
- catálogo: `binary "rip" → "rip.pl"`; retirados `delivery`/`container_image`/`host_mounts`
  (forma idéntica a hayabusa/chainsaw). Import `DELIVERY_ALL_CONTAINER` eliminado (huérfano).
- wrapper: `build_argv` referencia la **ruta real** de la hive (`-r <hive_path>`, bajo el
  `/evidence` de solo-lectura) en vez de `/in/hive`; función `host_mounts` eliminada.
- tests: aserción de `build_argv` actualizada; test de `host_mounts` sustituido por uno que
  garantiza que **ya no existe**.

## Cómo la usé (params + argv)

```
execute("regripper", {"hive_path": "/evidence/.../SAM", "plugin": "samparse"},
        case_id=…, os_profile="windows")
argv = rip.pl -r <hive_path> -p <plugin>        (o -f <profile>, o -l para listar)
```

Batería ejecutada (7 plugins, todos exit 0):

| Hive | Plugin | Señal obtenida |
|------|--------|----------------|
| SYSTEM | `compname` | equipo **HAXOR4** / hostname haxor4 |
| SOFTWARE | `winver` | **Windows 7 Pro SP1**, build 7601.18247, instalado 2013-10-10 |
| SYSTEM | `shutdown` | último apagado **2015-02-24 03:22:21Z** |
| SYSTEM | `usbstor` | **óptico MATSHITA BD** (2015-02-16) + **SAMSUNG File-Stor Gadget** (móvil, 2015-02-19) |
| SOFTWARE | `run` | única autostart: VMware Tools (benigno); RunOnce/RunServices vacíos |
| SAM | `samparse` | cuentas Administrator [500] (Login Count 0) + Guest [501] |
| NTUSER.DAT | `userassist` | ejecución GUI (UserAssist) presente |

## Resultado / hallazgos

- **Perfil del host:** HAXOR4, Win7 Pro SP1 build 7601, instalado 2013-10-10, ventana hasta
  el apagado de 2015-02-24 → acota la línea temporal del sistema.
- **USB:** un **SAMSUNG File-Stor Gadget** (teléfono en modo almacenamiento masivo, S/N
  ce0fa56b) conectado el 2015-02-19 — vector potencial de exfiltración; `usbstor` data cada
  conexión (First InstallDate / Last Arrival / Last Removal).
- **Sin persistencia por Run keys:** única autostart VMware Tools → descarta esa vía en la imagen.

## Veredicto / lecciones para el agente

- **Un plugin por pregunta.** RegRipper no "vuelca todo": eliges el plugin del artefacto que
  te interesa (`usbstor` para USB, `run` para persistencia, `samparse` para cuentas). Para un
  barrido usar `-f <profile>` (system/software/sam/ntuser), pero genera mucho ruido.
- **La hive va pre-extraída** (TSK `icat`) y se pasa por su ruta real bajo `/evidence`; el
  wrapper **ya no** monta un `/in/hive` (modelo container-por-tool retirado).
- **El binario del catálogo debe existir en el maletín** — `rip` vs `rip.pl` era la diferencia
  entre "ausente" y "funciona". Al declarar un tool, comprobar `which <binary>` en la imagen.
- **`usbstor` + `userassist` + `run` son oro para triage:** dispositivos, ejecución de usuario
  y persistencia, cada uno con sus timestamps de LastWrite.

## Registro en el caso

- **Findings:** `258dbd25` (perfil HAXOR4 — low) · `189b18f2` (USB SAMSUNG mass-storage —
  medium) · `5fa7aaf1` (cuentas + sin persistencia Run — low).
- **Evidencia recopilada:** [`regripper/`](regripper/) (7 `.txt`, una salida por plugin).
