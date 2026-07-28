# regripper (SYSTEM) — zona horaria, equipo, USB (legible) · P3 + TZ

Cruda: [`raw.txt`](raw.txt). Tool: `regripper` sobre el hive `SYSTEM` volcado de RAM
(`../10_hivelist/registry.SYSTEM.*.hive`). Horas del hive en **UTC (Z)**.

## Zona horaria ⭐ (cierra la cronología)

- **TimeZoneKeyName = `Pacific Standard Time`**, Bias 480 (UTC−8), **ActiveTimeBias 420
  (UTC−7)** → el 23‑03 estaba en **horario de verano (PDT) = UTC−7**.
- **Conversión:** hora local = UTC − 7. El volcado (19:24:35 UTC) = **12:24:35 hora local**.
- **Equipo:** `IEWIN7`. Último apagado registrado: 2021‑03‑19 11:26:23Z.

## USB (P3) — con distinción PERITO vs atacante

`USBStor` lista varios **Kingston DataTraveler**. Fechas de conexión (primer/último enchufe):

| Modelo | S/N | Conectado (UTC) | Unidad | Lectura |
|---|---|---|---|---|
| DataTraveler **2.0** | 1C1B0D01… | 2021‑03‑20 09:13:44 | — | Anterior al día del incidente. Posible USB del **usuario**. |
| DataTraveler **2.0** | 1C6F654F… | 2021‑03‑22 08:31:46 | — | Ídem, día antes. |
| DataTraveler **3.0** | 6C626D7C… | **2021‑03‑23 17:48:26** | **F:** | ⚠️ **Contiene `RAM\`, `Wintriage\`** → **es del PERITO** (adquisición). |
| DataTraveler **3.0** | E0D55E6C… | **2021‑03‑23 19:21:19** | **E:** | ⚠️ Contiene `RamCapturer\`, `Wintriage\` → **también del PERITO**. |

- **MountedDevices** confirma F: y E: mapeadas a esos USBStor; LastWrite 19:21:19Z.

## ⚠️ Interpretación honesta (clave para el informe)

- Las USB **DataTraveler 3.0 (F:, E:) del 23‑03 son casi con seguridad del INVESTIGADOR**:
  contienen el kit de adquisición (Wintriage, RamCapturer) y en `F:\RAM\` está el propio
  `ram.raw`. **No se pueden presentar como exfiltración del sospechoso.**
- Los que **sí** merecen sospecha por fecha son las **DataTraveler 2.0 del 20 y 22‑03**,
  previas a la intervención. Para saber **qué se copió** a ellas hace falta el **disco**
  (`$MFT`, LNK, shellbags) → pendiente.
- **P3 respondida en cuanto a "¿hubo USB y cuándo?": SÍ, varias**, con fechas. La atribución
  (perito vs sospechoso) queda **explicada, no forzada**.
