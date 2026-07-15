# MITRE ATT&CK — hallazgos y deudas abiertas

> Nota de traspaso del trabajo que cableó la pestaña MITRE de punta a punta
> (rama `mitre`, 2026-07-14/15). Recoge lo que **quedó cerrado**, lo que **sigue
> abierto** y un hallazgo colateral. No es `proximos-pasos.md` (plan general) ni
> `bugs/` (fallos de comportamiento con repro): es el contexto de *por qué* la
> feature MITRE parecía nueva y no lo era, y qué deuda deja al descubierto.

## Contexto: no era una feature nueva, era deuda de contrato

La pestaña MITRE pintaba `mockMitreMatches` con un banner «⚠ Vista demo». Parecía
que había que construir la feature desde cero. **No.** La correlación MITRE ya
estaba especificada y el agente ya estaba entrenado para emitirla:

- `agentes/_orchestrator/mitre.md` — esquema de salida + reglas anti-alucinación.
- `agentes/_orchestrator/knowledge/mitre_attack_seed.md` — la **enum cerrada** real
  (45 técnicas curadas con sub-técnicas y con qué artefacto forense sostiene cada
  una).
- `agentes/*/prompts/system.md` — el «Esquema de hallazgo» ya prescribía
  `mitre_hints`.

El motor no cumplía su mitad: `record_finding` cerraba con
`additionalProperties: false`, así que el modelo **no podía emitir `mitre_hints`
aunque el prompt se lo pidiera**, y `Finding` no lo persistía. Se emitía al vacío.
Eso es lo que se cerró (ver `contrato-paquetes.md` §5.bis / §5.ter).

## Lo que quedó cerrado

- `record_finding` acepta `mitre_hints`; `Finding` los persiste; enum cerrada
  validada **en el servidor** contra la semilla (id fuera de la semilla → rechaza
  el hallazgo entero, SECURITY INVARIANT 5).
- Catálogo derivado de la semilla (una sola fuente de verdad; ampliar cobertura =
  ampliar la semilla).
- Dos ejes que no se funden: **propuesta del agente** (derivada de los hints) vs
  **dictamen del perito** (persistido, con motivo obligatorio, en el log
  hash-encadenado como `mitre_adjudicated`).
- UI real sin mocks. Celda sin color = **no evaluada**, nunca «ausente».

## Deudas abiertas (lo que NO cierra este trabajo)

### 1. La capa de síntesis del orquestador no existe

`backend/forensia/reports/` **está vacío**. El `MitreTechniqueMatch[]` con
`confidence` y `relatedFindingIds` que describe `_orchestrator/mitre.md` **no lo
produce nadie todavía**.

Lo que la UI pinta hoy son los `mitre_hints` **crudos** de los hallazgos: una
propuesta con procedencia, **no** una correlación sintetizada con nivel de
confianza. La UI lo distingue explícitamente (eje «propuesta del agente» separado
del «dictamen del perito»), pero conviene no dar por satisfecho el paquete del
orquestador: falta la pasada de síntesis que convierta hallazgos en
correlaciones con `confidence`.

- **Impacto:** medio. La matriz es real y útil, pero el `confidence` del diseño y
  de `mitre.md` no aparece porque nadie lo calcula.
- **Dónde:** implementar `forensia.reports` consumiendo `_orchestrator/mitre.md`.

### 2. Campos del esquema de hallazgo aún huérfanos en el motor

El «Esquema de hallazgo» de los prompts (`agentes/*/prompts/system.md`) promete
cuatro campos estructurados. `mitre_hints` ya está cableado; siguen sin
implementarse en el motor:

- `confidence` (0–1, calibrado),
- `provenance` (`tool_id` / `params` / `run_id` / `artifact_id` / `artifact_sha256`),
- `observed_at` (marca de tiempo del **artefacto**, no de la ejecución).

Es la **misma clase de deuda** que `mitre_hints` tenía: el prompt los pide, el
motor los descarta en silencio (`FindingStore.append` sólo lee claves conocidas
vía `data.get(...)`).

- **Impacto:** medio. `provenance` y `observed_at` en particular son cadena de
  custodia y timeline; hoy se pierden.
- **Dónde:** `backend/forensia/findings/store.py` (`Finding` + validación) y
  `record_finding` en `tool_schemas.py`, igual que se hizo con `mitre_hints`.

### 3. Selección de caso: `list[0]` auto-elige «el más reciente» (roza RULE 2)

`web/src/pages/InvestigationPage.tsx:70` hace `const newest = list[0]` — auto-elige
el caso más reciente en vez de exigir que el operador seleccione. RULE 2 prohíbe
exactamente «usar el más reciente» sin selección explícita.

Mi `MitreAttackPage` **hereda ese mismo patrón** por consistencia con la página
existente (no quise introducir una convención distinta para una sola pestaña).

- **Impacto:** bajo hoy (funciona), pero es una erosión de RULE 2 y no escala: en
  cuanto haya selección de caso real, ambas páginas deben leerla.
- **Dónde:** introducir estado de selección de caso **compartido en el App shell**
  (`web/src/App.tsx`) y que `InvestigationPage` y `MitreAttackPage` lo consuman, en
  vez de cada una resolviendo `list[0]` por su cuenta. Toca también `ContextBanner`,
  Timeline y Documentos, que hoy comen mocks.

## Export de la cobertura (hallazgo D)

El perito se lleva la cobertura ATT&CK del caso fuera de FORENSIA en dos formatos.
El formateo vive en `backend/forensia/mitre/export.py` (RULE 3); ambos derivan de
`CoverageStore.coverage` (propuestas del agente + dictámenes del perito, sin fundir los
dos ejes) y toman nombres/tácticas del **catálogo Enterprise** — nunca inventados. Un
caso con **0 técnicas evaluadas** exporta igual (CSV con sólo la cabecera; layer válido
sin celdas), nunca un error.

### CSV de cobertura

```
GET /api/cases/{case_id}/mitre/export.csv
→ 200  Content-Type: text/csv; charset=utf-8
       Content-Disposition: attachment; filename="mitre-coverage-{case_id}.csv"

technique_id,technique_name,tactic_id,tactic,agent_proposed,examiner_verdict,rationale,findings,enterprise_display_id
T1055,Process Injection,TA0005,Sigilo,true,confirmada,"RWX, shellcode",<finding-id>,T1055
```

`agent_proposed` es `true`/`false`; `examiner_verdict` queda vacío si el perito no ha
dictaminado (gris = no evaluada, no «ausente»); `findings` son los ids que sostienen la
fila (propuesta + anclados al dictamen), separados por `;`. Si el catálogo Enterprise no
está montado, `technique_name`/`tactic` degradan a vacío y el `technique_id` queda como
única referencia honesta (RULE 2).

### Layer del ATT&CK Navigator

Un *layer* válido del [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
oficial (formato de layer **4.5**, `domain: "enterprise-attack"`). Emitimos sólo
`versions.layer` — no fingimos una versión de ATT&CK ni de Navigator que no conocemos
(RULE 2).

```
GET /api/cases/{case_id}/mitre/navigator
→ 200  Content-Type: application/json; charset=utf-8
       Content-Disposition: attachment; filename="mitre-navigator-{case_id}.json"

{ "name": "FORENSIA — <caso>", "versions": { "layer": "4.5" },
  "domain": "enterprise-attack",
  "techniques": [ { "techniqueID": "T1055", "color": "#c1121f",
                    "comment": "Dictamen del perito: Confirmada — …",
                    "enabled": true, "metadata": [], "showSubtechniques": false } ],
  "legendItems": [ … ] }
```

Cada técnica se pinta en su **celda Enterprise** (la padre si es una sub-técnica). El
color lo manda el eje: rojo `#c1121f` confirmada, ámbar `#e08a00` sospechosa, gris
`#8a8f98` descartada (dictamen del perito); azul `#2f6fed` propuesta del agente sin
dictaminar. El dictamen del perito gana el color sobre la propuesta, pero ambos constan
en el `comment`. La UI ofrece **«Exportar CSV»** y **«Exportar Navigator layer»** en la
barra de la pestaña MITRE (`api.cases.exportMitreCsv` / `exportMitreNavigator`, blob
mismo-origen con el token).

## Hallazgo colateral (de la sesión de exploración, previo al trabajo MITRE)

### `bulk_extractor`: 6 corridas, 6 fallos — `no such scanner: credit_cards`

En el caso real «Prueba tools completas», el agente pidió los scanners `emails`,
`urls` y `credit_cards`; ninguno existe con ese nombre en bulk_extractor 2.1.0
(los reales son `email` singular, `accts` para tarjetas, etc.). Exit 5, 3 ms tras
el start, 6 veces.

Causa raíz: `backend/forensia/toolkit/wrappers/bulk_extractor.py:44` valida los
nombres de scanner sólo contra un regex de **forma** (`^[A-Za-z0-9_]+$`), no contra
la enum de scanners que el binario realmente trae. Cualquier nombre plausible pasa
el gate y llega a argv. No es un agujero de seguridad (el binario rechaza lo
desconocido), pero es una brecha de SECURITY INVARIANT 5 (los *valores* de flag no
están en allowlist) y le quemó al agente 6 iteraciones.

- **Impacto:** medio (funcional: agota iteraciones).
- **Fix natural:** derivar la enum de scanners del manifiesto de build del maletín
  (como ya se hace con `tool_version`) en vez de un regex de forma.
- **Nota:** merece su propia entrada en `docs/bugs/` si se decide arreglarlo.

## Estado de la rama

`mitre` (desde `tools`), commit `feat(mitre): matriz ATT&CK real de punta a punta`.
Gates locales en verde: ruff · 818 tests (18 nuevos) · typecheck + build web ·
compose config + build. Verificado en la app real sobre un caso desechable (luego
borrado; los casos reales del usuario, intactos). **Sin pushear.**
