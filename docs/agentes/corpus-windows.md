# Corpus de evidencias Windows (CTF) — manifiesto

Este documento es el **manifiesto del corpus de evidencias reales** que ancla el
trabajo del sub-agente `windows` (perfil `os_profile: windows`). Es el paso **A0**
del [plan de ruta](plan-ruta-forensia-win.md): sin imágenes reales con hallazgos
conocidos, ni los prompts/playbooks ni las evals tienen contra qué validarse.

## Para qué sirve este corpus

- **Validación cualitativa del playbook** (`agentes/forensia-windows/prompts/playbook.md`):
  se corre el flujo de análisis sobre imágenes reales, se comprueba que las tools
  del catálogo producen los artefactos esperados y que los hallazgos que el agente
  debería alcanzar tienen un artefacto que los sostiene (cadena de custodia, §3.3
  del [diseño](diseno-fase2.md)).
- **Anclaje empírico de prompts y evals**: cada imagen del corpus tiene un
  **ground-truth documentado** (la "traza dorada") en
  [`ground-truth/`](ground-truth/README.md). De ahí se derivan después los casos
  `case-win-*.yaml` verificables.

## Separación estricta frente a las fixtures de eval

**El corpus y las fixtures de eval son cosas distintas y NO se mezclan:**

| | Corpus (este documento) | Fixtures de eval (`agentes/forensia-windows/evals/`) |
|---|---|---|
| Contenido | Imágenes CTF **reales** (pueden contener datos personales del escenario) | Datos **sintéticos**, generados por el equipo |
| Uso | Validación cualitativa del playbook + fuente del ground-truth | Harness comparativo local-vs-cloud (métricas del TFM) |
| En git | **No** (tamaño/licencia) — referenciadas por URL + SHA-256 aquí | **No** (`evals/README.md`) — solo el `.yaml` se versiona |
| Regla dura | — | **NUNCA** evidencia real con datos personales ([`evals/README.md`](../../agentes/forensia-windows/evals/README.md)) |

Las imágenes del corpus **no se suben a git** por tamaño y licencia. Se guardan
fuera del árbol versionado (`evidence-corpus/`, ignorada en
[`.gitignore`](../../.gitignore)) y se referencian aquí por URL de origen y
SHA-256 baseline.

## Nota de custodia (FORENSIC INVARIANTS §2)

El **SHA-256 baseline se computa una sola vez** tras la descarga (con
[`scripts/hash-evidence.py`](../../scripts/hash-evidence.py)) y se registra en la
tabla de abajo. A partir de ahí es el ancla de integridad: se **re-verifica** al
abrir y al cerrar sesión, y **nada llega a una tool sin baseline**. Esto refleja,
a nivel de dev/documentación, la puerta de hash que en runtime posee
`forensia.evidence.EvidenceManager` (`ingest → baseline hash → set read-only a
nivel de bloque → expone handle`). El `hash-evidence.py` **no** es esa puerta: solo
reproduce el mismo digest para poder anotarlo aquí.

## Manifiesto

> Una fila por imagen. El `SHA-256 baseline` queda `<pendiente>` hasta computarlo
> con `scripts/hash-evidence.py` sobre el fichero ya descargado. Las URLs de
> descarga completas y los ficheros acompañantes están en «Detalle por imagen».
> Para añadir una imagen nueva: replica una fila, descarga a `evidence-corpus/…`
> (fuera de git) y computa su baseline con el helper.

| id | nombre | fuente/URL | licencia | tipo | formato | SO/build | tamaño | SHA-256 baseline | ruta local (fuera de git) | ground-truth |
|---|---|---|---|---|---|---|---|---|---|---|
| `lonewolf-2018-disk` | LoneWolf (Windows 10) — disco | [2018 Lone Wolf Scenario](https://digitalcorpora.org/corpora/scenarios/2018-lone-wolf-scenario/) | uso educativo/investigación (ver *Lone Wolf Scenario Copyright.pdf*) | disk | `.E01` (multi-segmento) | Windows 10 | 13 545 502 470 B (~12.62 GiB, E01–E09) | variante (a) E01: **9 segmentos verificados** (tabla por segmento en «Detalle»); variante (b) imagen única `.raw`/ZIP: `<pendiente>` | `evidence-corpus/lonewolf-2018/` | [lonewolf-2018.md](ground-truth/lonewolf-2018.md) |
| `lonewolf-2018-memory` | LoneWolf (Windows 10) — memoria RAM | [2018 Lone Wolf Scenario](https://digitalcorpora.org/corpora/scenarios/2018-lone-wolf-scenario/) | uso educativo/investigación (ver *Lone Wolf Scenario Copyright.pdf*) | memory | `.mem` (raw, Volatility3) | Windows 10 | ~17 GB | `<pendiente: computar tras descarga con scripts/hash-evidence.py>` | `evidence-corpus/lonewolf-2018/` | [lonewolf-2018.md](ground-truth/lonewolf-2018.md) |
| `m57-patents-jo-mem-20091124` | M57-Patents (Jo, Windows XP) — memoria RAM 2009-11-24 | [2009 M57-Patents](https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/) | uso educativo/investigación (solución restringida a faculty) | memory | `.mddramimage` (raw mdd, dentro de ZIP) | Windows XP | 1 071 632 384 B (~1.02 GiB) | `5abe455dd05b0a8728e8e155212c49b4a78f3cf1b695c463938c0431eaf959ec` | `evidence-corpus/m57-patents/ram/jo-2009-11-24/` | `<pendiente: ground-truth/m57-patents.md (instructor packet)>` |

### Hash de adquisición (FTK) — solo entrada de disco

La imagen de disco fue adquirida en 2018 con **FTK Imager 3.1.1.8**. El log de
adquisición (`evidence-corpus/lonewolf-2018/FTK Imager Log.txt`) registra y
**verifica** los hashes de la adquisición original del dispositivo físico
(Samsung SSD 850 PRO 512 GB, 1 000 215 216 sectores). FTK computó **MD5 y SHA-1**
(no SHA-256), por eso el `SHA-256 baseline` de arriba es un ancla **propia** e
independiente (ya computada por segmento para la variante E01; ver «Detalle»):

| Hash de adquisición (FTK Imager Log) | Valor | Estado |
|---|---|---|
| MD5 | `7af48fa65519e84246b1729e5b68f140` | verificado en el log (2018) |
| SHA-1 | `694e26624d1ea029eb50d793b198edf85be4b4fc` | verificado en el log (2018) |

> Distinción importante: el hash FTK atestigua la **adquisición original** del
> contenido del disco. El `SHA-256 baseline` de la tabla se computa sobre los
> **ficheros descargados** (los segmentos `.E01` y, por separado, `memdump.mem`)
> y es el que FORENSIA re-verifica en cada sesión.

## Detalle por imagen

### `lonewolf-2018-disk` — disco Windows 10 (FTK/E01)

- **Escenario**: [2018 Lone Wolf Scenario (DigitalCorpora)](https://digitalcorpora.org/corpora/scenarios/2018-lone-wolf-scenario/).
- **Descarga (segmentos E01)** — `LoneWolf.E01` … `LoneWolf.E09` (E01–E08 ~1.5 GB
  c/u, E09 ~0.9 GB):
  - `https://downloads.digitalcorpora.org/corpora/scenarios/2018-lonewolf/LoneWolf_Image_Files/LoneWolf.E01`
  - … hasta `LoneWolf.E09`
  - Alternativa ZIP: `https://downloads.digitalcorpora.org/corpora/scenarios/2018-lonewolf/Forensic%20Image%20Files.zip`
- **Formato**: `.E01` multi-segmento (contenedor EWF). El agente lo abre con
  `ewf_info` / `tsk_mmls` (no monta FS); ver allowlist en
  [`policy/tools.yaml`](../../agentes/forensia-windows/policy/tools.yaml).
- **Variantes de ingesta** (mismo contenido lógico, dos formas equivalentes):
  - **(a) set E01 multi-segmento** — apuntar la herramienta a `LoneWolf.E01`;
    `libewf` carga `LoneWolf.E02`–`E09` automáticamente si están en la misma
    carpeta. Es la variante nativa de la descarga por segmentos.
  - **(b) imagen única reconstruida** — el ZIP único del escenario, o el resultado
    de convertir el set E01 con `ewfexport` a `.raw`. Útil para tools que esperan
    un único fichero de imagen.
  - **Nota de hash**: el `SHA-256 baseline` se registra **por la variante que se
    use realmente** — a nivel de fichero difiere (los `.E01` segmentados, el `.raw`
    reconstruido y el ZIP tienen digests distintos), aunque el **contenido lógico
    del disco es el mismo**. Aquí la variante **(a)** está **verificada por
    segmento** (tabla abajo); la variante **(b)** sigue `<pendiente>` (no
    descargada). Los hashes FTK (MD5/SHA-1) de la tabla de arriba atestiguan esa
    adquisición lógica común y **no** cambian entre variantes.
- **Acompaña**: `FTK Imager Log.txt` (log de adquisición con MD5/SHA-1) y
  `Lone Wolf Scenario Copyright.pdf` (licencia).
- **Ground-truth**: [lonewolf-2018.md](ground-truth/lonewolf-2018.md).

#### SHA-256 baseline — variante (a) E01 segmentado (verificado)

Digests computados con [`scripts/hash-evidence.py`](../../scripts/hash-evidence.py)
sobre los segmentos descargados en `evidence-corpus/lonewolf-2018/`:

| fichero | sha256 | size (bytes) |
|---|---|---|
| `LoneWolf.E01` | `cc69942dba7dbc2c0a4760b9c28b8d6e488b748c954369e343756a34889c8fa7` | 1572704213 |
| `LoneWolf.E02` | `e375234d88d1cccdbb5a8f10fa76b4354f568ae026858b53cff1a47c881179b5` | 1572709105 |
| `LoneWolf.E03` | `e2b2ffe2705ba167be53584c85892af276384b5c1017148ad28d6d6b2408a55e` | 1572749825 |
| `LoneWolf.E04` | `05e22b246b5965338baabaecd56d3f83a3ed2648cc8089d8e67b0f418d928a87` | 1572762495 |
| `LoneWolf.E05` | `d1463822c0e2464b73ca8edb82bdc42f62270a5ff75ef1ed576f0432e0598297` | 1572678499 |
| `LoneWolf.E06` | `2e6b1e7cd25c17a297a51af25421467ae71440526242d4372119a078bc83814d` | 1572802511 |
| `LoneWolf.E07` | `821abac9b7b53e37cb5b296ef2954ea87921e75ea8b901d2823d7fc57a11252b` | 1572769343 |
| `LoneWolf.E08` | `a363c2009617798312c52ffdbd5f8b442ebaf60c1d6cb55ff53e03f9a878ac39` | 1572723308 |
| `LoneWolf.E09` | `37c980ee3ca37e779d4e260f23a5f7a23585183c89231c2825145a911e0a8280` | 963603171 |

Tamaño total verificado: 13545502470 bytes (~12.62 GiB).

> La **variante (b)** (imagen única `.raw`/ZIP) y la **entrada de memoria**
> (`memdump.mem`) siguen con `SHA-256 baseline` `<pendiente>`: aún no descargadas.
> No se computan sus hashes hasta tener los ficheros (RULE 2).

### `lonewolf-2018-memory` — memoria RAM Windows 10

- **Descarga**: `https://downloads.digitalcorpora.org/corpora/scenarios/2018-lonewolf/LoneWolf_Image_Files/memdump.mem`
- **Formato**: `.mem` raw, analizable con `volatility3` (plugins `windows.*`).
- **Acompaña**: `pagefile.sys` (~2.9 GB) en la misma carpeta.
- **Ground-truth**: [lonewolf-2018.md](ground-truth/lonewolf-2018.md) (comparte
  fichero con la entrada de disco: es el mismo escenario/host).

### `m57-patents-jo-mem-20091124` — memoria RAM Windows XP (M57-Patents, Jo)

- **Escenario**: [2009 M57-Patents (DigitalCorpora)](https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/).
  Segundo escenario del corpus: cubre exfiltración/keylogger (huecos que LoneWolf,
  insider puro, no ejercita) y aporta **memoria XP con enumeración fiable en Vol3**
  (LoneWolf-Win10 degradaba). Sirve además de **hold-out de generalización** frente
  al paquete entrenado sobre LoneWolf (ver [plan-ruta-m57.md](plan-ruta-m57.md)).
- **Descarga (serie RAM de Jo, 24 ZIP, 2009-11-16 → 2009-12-11)**:
  `aws s3 cp --no-sign-request --recursive --exclude "*" --include "jo-*" s3://digitalcorpora/corpora/scenarios/2009-m57-patents/ram/ <destino>`
  - Toda la serie de Jo está descargada en `evidence-corpus/m57-patents/ram/`.
  - Herramienta de adquisición: `mdd` (ManTech Memory DD) → `*.mddramimage`; en
    diciembre hay además copias `*.winddramimage` (win32dd) de la misma RAM.
- **Fichero analizado (M2)**: `jo-2009-11-24.mddramimage` (extraído del ZIP homónimo).
  El **2009-11-24** es el día candidato del incidente de exfiltración de `m57biz.xls`
  (**confirmar contra los detective reports / instructor packet** — no se fija por
  memoria; principio metodológico del plan de ruta).
- **Formato**: raw físico, analizable con `volatility3` (plugins `windows.*`, XP x86).
- **Baselines SHA-256** (computados sobre los ficheros descargados/extraídos):

| fichero | sha256 | size (bytes) |
|---|---|---|
| `jo-2009-11-24/jo-2009-11-24.mddramimage` (raw, corre M2) | `5abe455dd05b0a8728e8e155212c49b4a78f3cf1b695c463938c0431eaf959ec` | 1071632384 |
| `jo-2009-11-24.mddramimage.zip` (procedencia) | `5a760961f21ae1b3af3fbed4ee083428437a7a0f0c8da94b355a1fb45e6913f7` | 499046715 |

- **Ground-truth**: `<pendiente>` — `ground-truth/m57-patents.md` se monta desde la
  sección *Exfiltration* del instructor packet (restringido a faculty; solo resumen
  derivado en git, no el packet verbatim).
