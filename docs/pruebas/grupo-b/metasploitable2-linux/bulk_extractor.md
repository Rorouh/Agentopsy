# `bulk_extractor` — sobre `metasploitable2-linux/Metasploitable.raw`

- **Grupo:** B · **Imagen:** Metasploitable 2 (disco particionado real) · **Estado:** ✅ muy eficaz (artefactos de sistema usado)
- **Binario:** `bulk_extractor` 2.1.0 · **Maletín:** `toolkit-unix`
- **run_id:** `9aa4cd0f-b1ac-484a-9381-50d441655f5b`

## Objetivo (máxima expresión)

IOCs de un **sistema usado** (8 GB). En el Grupo A los IOCs eran *provenencia de software*
(docs de paquetes). Aquí esperaba **artefactos de actividad real**: logs web, sesiones de
login, IPs de tráfico.

## Cómo la usé (params + argv)

Aprendida la lección del Grupo A (no hardcodear nombres de escáner → exit 5), corrí **todos
los escáneres por defecto**:
```
execute("bulk_extractor", {"image_path": <raw 8GB>}, …)   →   exit 0, run 9aa4cd0f
```
Lento (8 GB emulados, varios minutos).

## Resultado obtenido — exit 0

| Feature | Nº | Feature | Nº |
|---------|----|---------|----|
| domain | 495.816 | zip | 27.100 |
| email | 349.694 | elf | 13.482 |
| url | 106.864 | **httplogs** | **160** |
| rfc822 | 33.683 | **utmp_carved** | **91** |
| telephone | 1.131 | **ccn** | **5** |
| ether (MAC) | 127 | sin (SSN) | 846 |

**Lo valioso (vs DVWA):** aparecen **artefactos de uso real**:
- **`httplogs` (160)** — actividad del servidor web (peticiones registradas).
- **`utmp_carved` (91)** — **sesiones de login** de usuarios (quién entró y cuándo).
- **`ccn` (5)** — números de tarjeta (probable dato de test de las apps vulnerables; **ojo con
  falsos positivos**: el escáner ccn marca secuencias que pasan Luhn).

Volumen ~6× el DVWA por ser un disco usado y mayor.

## Veredicto de eficacia

- **Muy eficaz**: además del harvest masivo, destapó **httplogs + utmp** — artefactos que
  cuentan la **historia de uso** del sistema, no solo strings de paquetes.
- Confirma la lección del Grupo A al revés: en un **disco usado** los IOCs sí son señal.

## Lecciones para entrenar al agente

1. **En un disco usado, prioriza `httplogs`, `utmp_carved` y `ip`**: cuentan actividad real
   (web, logins, red). Son más accionables que los 496k dominios (mayormente ruido de docs).
2. **`ccn`/`sin` (tarjetas/SSN): verifica antes de escalar** — son propensos a falsos
   positivos; contrasta con el contexto (¿app de test? ¿dato real?).
3. **Trabaja por histogramas** (`*_histogram.txt`); 350k emails no caben en contexto.
4. **No hardcodees nombres de escáner** (lección del Grupo A: `url` no existe en BE 2.x).

## Registro en el caso

- **Findings:** `426d863f` (harvest 496k/350k/107k) · `a05e53fa` (httplogs/utmp/ccn — actividad real, medium).
- **Evidencia recopilada:** [`bulk_extractor/ioc-resumen.txt`](bulk_extractor/ioc-resumen.txt)
  (httplogs + utmp + top dominios). Feature files completos en el `ArtifactRun` `9aa4cd0f/out/`.
