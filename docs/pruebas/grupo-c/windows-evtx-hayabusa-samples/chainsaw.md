# `chainsaw` — sobre `windows-evtx-hayabusa-samples` (16 EVTX)

- **Grupo:** C (Windows) · **Estado:** ✅ (con **1 fix de parser**: Bug 007)
- **Binario:** `chainsaw` (Rust estático — no sufrió el glibc del Bug 005) · **Maletín:** `toolkit-windows`
- **run_id:** `e22e05f7-b57f-446a-889d-245f59ab1fc7`

## Objetivo (máxima expresión)

Hacer **hunting** con reglas de detección sobre el mismo set de EVTX que hayabusa, pero por
la vía de chainsaw: agrupa los hits **por categoría de ataque** (credential_access,
lateral_movement, log_tampering, rdp_attacks…) en CSV separados, ideal para triage dirigido.

## Reglas usadas

El maletín **no trae reglas Sigma bundle** (`/opt/chainsaw-src/sigma` vacío), así que se usan
las **127 reglas nativas de chainsaw** (`-r /opt/chainsaw-src/rules`), que **no requieren
`--mapping`** (el mapping solo hace falta para reglas Sigma de terceros). 1 regla no carga
(127 de 128) — no bloquea.

## Cómo la usé (params + argv)

```
execute("chainsaw", {"target_dir": "/evidence/windows-evtx-hayabusa-samples",
                     "rules_dir": "/opt/chainsaw-src/rules",
                     "output_format": "csv", "output_path": "/tmp/chainsaw-out"},
        case_id=…, os_profile="windows")
argv = chainsaw hunt <target_dir> -r /opt/chainsaw-src/rules --csv --output <dir>
     →  exit 0, run e22e05f7
```

## El fix que hizo falta (Bug 007)

Primera ejecución: **exit 0** y los 7 CSV escritos bien, pero `parsed = {detections: 0}`.
Causa: **chainsaw resume por stderr** (`[+] 56 Detections found`) y escribe las tablas a
**ficheros**; el dispatcher solo pasaba **stdout** (vacío) al parser. Fix: el dispatcher
pasa `stderr` a los `parse` que lo aceptan (por aridad) y `chainsaw.parse` lee el conteo de
stderr. Ver [Bug 007](../../../bugs/007-chainsaw-parser-lee-stdout-no-stderr.md).

## Resultado obtenido — exit 0

**56 detecciones** (documentos únicos) → **148 filas** repartidas en 7 CSV por categoría:

| CSV | Filas | Qué |
|-----|------:|-----|
| `credential_access.csv` | 1 | **Kerberoasting** T1558.003 (RC4 débil sobre SPN `sql101`) |
| `log_tampering.csv` | 4 | **Security Audit Logs Cleared** (EventID 1102) — anti-forense |
| `lateral_movement.csv` | 16 | Network Logon (4624 tipo 3) entre hosts |
| `rdp_attacks.csv` | 8 | RDP connect/disconnect desde IP externa |
| `rdp_events.csv` | 52 | eventos RDP (TerminalServices) |
| `microsoft_rds_events_-_rd_gateway.csv` | 62 | eventos RD Gateway |
| `powershell_engine_state.csv` | 5 | PowerShell engine (incl. downgrade T1562.010) |

**Cadena reconstruida** (DC-Server-1.labcorp.local): `Alice` pide TGS del SPN `sql101` con
cifrado Kerberos débil (Kerberoasting, 4769 desde 192.168.1.200) → `Administrator` **limpia
el Security log dos veces** (1102) justo después → accesos **RDP entrantes como Administrator
desde IP externa 219.100.37.234** sobre el host EC2 → PowerShell downgrade attack. El borrado
de logs tras el robo de credenciales = encubrimiento deliberado.

## Veredicto / lecciones para el agente

- **Complementa a hayabusa, no lo duplica.** hayabusa da una timeline única priorizada por
  nivel Sigma; chainsaw **segmenta por tipo de ataque** en CSV independientes → mejor para
  "enséñame solo el movimiento lateral" o "solo el tampering de logs".
- **Reglas nativas ≠ Sigma.** `-r rules/` (nativas) no necesita `--mapping`; `-s sigma/` sí.
  Si se quiere el catálogo Sigma completo hay que **bundlearlo en el maletín** (hoy no está).
- **La salida vive en ficheros + stderr, no en stdout** (Bug 007): al leer resultados de una
  tool, comprobar *dónde* deja el dato antes de parsear.
- **Da un directorio de `.evtx`** (`target_dir`), igual que hayabusa; recorre todos.

## Registro en el caso

- **Findings:** `ed4280f6` (56 detecciones + categorías) · `0ab7499d` (cadena
  Kerberoasting + borrado de logs + RDP externo — **critical**).
- **Evidencia recopilada:** [`chainsaw/`](chainsaw/) (7 CSV por categoría, 148 filas).
