# Ground-truth — `m57-patents` (2009 M57-Patents, hilo Jo / exfiltración)

Traza dorada del escenario **2009 M57-Patents** (DigitalCorpora), enfocada en la
entrada de memoria `m57-patents-jo-mem-20091124` del manifiesto
([corpus-windows.md](../corpus-windows.md)). Reglas de este fichero:
[ground-truth/README.md](README.md).

> **Derivado de fuentes PÚBLICAS, no del instructor packet cifrado** (restringido a
> faculty). La solución oficial, si el tutor la obtiene, se usará solo para
> confirmar. Nada de esta traza se inyecta al agente: es instrumento de medida
> (principio metodológico, [plan-ruta-m57.md](../plan-ruta-m57.md)).

## Metadatos

| Campo | Valor (memoria) |
|---|---|
| id de imagen | `m57-patents-jo-mem-20091124` |
| fichero | `jo-2009-11-24/jo-2009-11-24.mddramimage` |
| SHA-256 baseline | `5abe455dd05b0a8728e8e155212c49b4a78f3cf1b695c463938c0431eaf959ec` (1 071 632 384 B) |
| tipo / formato | `memory` / raw `mdd` (ManTech Memory DD) |
| SO/build | Windows XP SP3 x86 (hora de sistema del volcado: 2009-11-25 00:26 UTC) |
| fuente/URL | [2009 M57-Patents](https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/) |

## Contexto (M57 Patents)

Empresa ficticia **m57.biz** (Monterey, CA) que investiga patentes. Plantilla:
**Pat McGoo** (CEO), **Terry Johnson** (IT), **Jo Smith** y **Charlie Brown**
(investigadores de patentes). Casi todo el negocio va por email; cada empleado usa
cliente distinto — **Jo usa Outlook** (los demás Thunderbird). Hay **dos hilos
criminales entrelazados**:

1. **Exfiltración de propiedad intelectual.** Un empleado roba investigación de
   patentes propietaria y la pasa a un **contacto externo**, tomando medidas para
   ocultar rastros. El ejercicio pide determinar: quién exfiltra, **cómo** y **qué
   ítems** roba (y qué se necesita para acceder a ellos), quién es el contacto
   externo, y si hay **más de un delito**.
2. **Material ilegal (eufemismo "cat exploitation", 311.3(a)).** Aaron Greene
   compró por Craigslist/PayPal un ordenador usado vendido por **Terry Johnson**;
   el disco no se había borrado y contenía imágenes/vídeos ilegales. Ese equipo era
   el **PC antiguo de Jo** (a Jo le "reemplazaron" el hardware y el viejo se vendió).
   La orden judicial se dirige a **todos los equipos/RAM/USB de Jo Smith
   (2009-11-13 → 2009-12-12)**.

Convergencia: **Jo Smith es el sujeto central** de ambos hilos. Identidad de correo
relevante: `jo@m57.biz`.

## Fuentes de la traza dorada (públicas)

- **Diapositivas del ejercicio** `M57-Patents-Exfiltration.pdf` (docs del escenario,
  NO cifradas): plantilla, "Jo usa Outlook", preguntas del caso, set de evidencia.
- **Detective report 001** y **Search Warrant/Affidavit** (`m57-affidavit-warrant-final.pdf`):
  narrativa policial, foco en Jo, ventana 13-nov → 12-dic, delito 311.3(a).
- Página del escenario [DigitalCorpora M57-Patents](https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/).

> **No se usa** el `m57-instructor-packet.pdf` (cifrado, faculty-only). Distinción
> importante: el famoso caso "`m57biz.xls` filtrado tras spear-phishing" es
> **M57-Jean (2008)**, un escenario DISTINTO — no este.

## Alcance de la memoria vs el disco

La memoria de Jo del 11-24 puede sostener el **canal** y el **staging** de la
exfil; el **contenido de los correos** y el **contacto externo** viven en el disco
par (DBX de Outlook Express, `$MFT`, USB) y en la red (PCAP). El 11-24 está dentro
de la ventana de la orden (13-nov→12-dic) y es rico en artefactos residentes; el
ejercicio "oficial" de disco usa el día de incautación **12-11** (corrida futura
de comparación).

## Hallazgos esperados (memoria de Jo) y observado en la corrida 11-24

> Columna MITRE: `[semilla]` = ya en `mitre_attack_seed.md`; `[+añadir]` = hueco de
> semilla detectado (ver scoring abajo). «Observado» = qué surfaceó la corrida
> zero-shot `codex_auto__…__jo-2009-11-24__20260703-114606` (recall).

| hallazgo esperado | fuente pública | artefacto / `tool_id` | MITRE | observado en 11-24 (recall) |
|---|---|---|---|---|
| Jo usa **Outlook Express** como canal de correo (vector de exfil) | slides ("Jo usa Outlook") | `msimn.exe` + almacén `*.dbx` (`Outbox.dbx`) / `volatility3` `filescan`,`dumpfiles` | `T1114.001` Local Email Collection `[+añadir]` | **SÍ** — `msimn.exe`, 7 DBX incl. `Outbox.dbx`; `dumpfiles` acotado no recuperó contenido → remitido a disco |
| **Investigación de patentes robada**, staged en carpeta oculta | slides ("items stolen", "qué se necesita para acceder") | `hr_patent*.JPG` en `Desktop\Pics\Hidden` / `volatility3` `filescan` | `T1074.001` Local Data Staging + `T1005` Data from Local System `[+añadir]` | **SÍ** — 82 `hr_patent*.JPG`, 43 refs bajo `Desktop\Pics\Hidden`, 252 objetos del perfil `Jo` |
| **Segundo delito**: material ilegal (311.3(a)) en el equipo de Jo | detective report / warrant | ficheros ilegales (imágenes/vídeo), probable en `Pics\Hidden` | fuera de semilla ATT&CK (delito, no técnica) | **Parcial** — enumeró `Pics\Hidden` pero no marcó el ángulo del segundo delito |
| **Contacto externo / correos enviados** | slides ("who is the outside contact") | contenido de `Outbox.dbx` (disco), cabeceras | `T1048` Exfil Over Alternative Protocol `[+añadir]` | **No en memoria** — correcto: remitido al disco (contenido no residente) |
| Actividad de **navegador** (posible OSINT/comms) | — | `firefox.exe` + artefactos Firefox / `volatility3` | `[semilla]` n/a | **SÍ** — `firefox.exe` interactivo, 26 artefactos Firefox |
| **USB personal de Jo** (`jo-favorites-usb`) como vía física | slides (set de evidencia) | dispositivo montado / `USBSTOR` (disco) | `T1052.001` Exfil over USB `[semilla]` | **No en memoria** — es artefacto de disco/registro |
| **Red hacia el contacto externo** | inferido | conexiones salientes / `volatility3` `netscan` | `T1048`/`T1071` `[semilla T1071]` | **Laguna de build** — `NetScan`/`NetStat` → `NotImplementedError` (XP no soportado en Vol3 2.28); recuperable en disco/PCAP |

## Scoring de la corrida zero-shot 11-24 (hold-out, baseline `da209f1`)

- **Recall (alcance memoria):** alto. Surfaceó los dos ejes centrales recuperables
  en RAM — **canal de exfil** (Outlook Express + DBX) y **staging de lo robado**
  (patentes ocultas en `Pics\Hidden`) — más navegador y el proceso de adquisición
  (`mdd`). Remitió correctamente al disco lo no residente (contenido de correos,
  contacto externo, USB).
- **Precisión:** alta. Sin falsos positivos; no atribuyó exfil sin red ni contenido
  (se quedó en `medium` sin MITRE). No inventó plugins ni técnicas.
- **Miss real:** no marcó explícitamente el **segundo delito** (material ilegal en
  `Pics\Hidden`) como ángulo penal aparte; lo enumeró sin caracterizarlo.
- **Causa del "sin MITRE" en exfil = hueco de semilla, no fallo de razonamiento:**
  la semilla carece de `T1114`, `T1074`, `T1005`, `T1048`. El agente hizo bien en
  **no forzar** técnica (disciplina anti-alucinación). ⇒ próxima mejora declarativa.

## Ampliaciones de semilla propuestas (post-hold-out, para task de iteración)

`mitre_attack_seed.md`, como ampliación fechada sin duplicar ids:

- `T1114` / `T1114.001` — Email Collection / Local Email Collection (Outlook Express).
- `T1074` / `T1074.001` — Data Staged / Local Data Staging (`Pics\Hidden`).
- `T1005` — Data from Local System (recolección de ficheros de patentes).
- `T1048` — Exfiltration Over Alternative Protocol (exfil por email).
- (opcional) `T1560`/`T1027` si el material robado está **archivado/cifrado** ("qué
  se necesita para acceder" sugiere protección) — confirmar en el disco par.

## Corrida post-semilla 11-24 (`…171453`) — auditoría M5-A

Segunda corrida `codex_auto` sobre la misma RAM de Jo (2 929 líneas), tras la 3ª
tanda de semilla (`T1114/.001`, `T1074/.001`, `T1005`, `T1048`).

- **Recall (estable):** volvió a surfacer el rastro de exfil — 82 `hr_patent*.JPG`,
  almacenes Outlook Express (`msimn.exe` + DBX), y el ángulo de automatización
  `Desktop\web\patentauto.py` + `urls.txt`; actividad interactiva de Jo
  (cmd→firefox→msimn) y la adquisición `mdd_1.3.exe` fechadas.
- **MITRE de exfil: sigue "sin técnica de la semilla aplicable" — y es correcto.**
  Los 4 hallazgos de exfil van sin id; el único id emitido es `T1055` como
  hipótesis no confirmada. No forzó `T1567` nube sobre una exfil por email.
- **Causa (plumbing, no razonamiento):** `run_investigation.py` (`build_prompt`)
  inyecta al sub-agente solo `identity.md + system.md + playbook.md`, **no**
  `knowledge/mitre_attack_seed.md`. Verificado: 0 ocurrencias de los ids M57 en los
  tres ficheros. Por diseño (`diseno-fase2.md`: `mitre_hints` = pista opcional, el
  orquestador decide; `_orchestrator/mitre.md`), la correlación autoritativa es del
  **orquestador** contra la semilla; el sub-agente emite hints desde su vocabulario
  de playbook. La 3ª tanda es **inerte en este harness por diseño**.
- **Consecuencia:** M5-A no puede mejorar a este nivel de fidelidad (mide la capa
  equivocada). La validación semilla→orquestador exige un test de orquestador (aún
  pendiente). Re-encuadrar M5-C/M5-D: no meter ids de email/staging en el playbook
  para "aprobar" M5-A; si acaso, decidir por separado el vocabulario de **hints
  opcionales** del sub-agente, y solo con recurrencia (2º run: disco 12-11).
