# Plan de ruta — Herramientas disponibles con independencia del SO de la evidencia

**Rama:** `tools` · **Estado:** propuesta / en curso · **Rol coordinador:** sub-agente
windows (auditoría declarativa). **Toca varias lanes** (toolkit/backend, allowlists de
agente, docs) — marcado por fase.

> **Petición del equipo (constancia):** hoy, al subir evidencia de un SO concreto, el
> sistema limita las herramientas a las de ese SO. Se pide que **se puedan usar todas
> las herramientas aplicables con independencia del SO de la evidencia**.

Este documento es la **fuente de verdad viva** de la tarea: se actualiza en cada fase
(RULE 4) con lo hecho, lo pendiente y quién sigue. Cualquiera que retome la tarea empieza
por aquí.

---

## 1. Tensión con los invariantes (leer antes de tocar nada)

La petición, tomada al pie de la letra ("todas, sea cual sea el SO"), choca con tres cosas
del proyecto. Se documenta para que la decisión sea **consciente**, no un efecto colateral:

- **RULE 2** (`CLAUDE.md`): "un paquete por `os_profile`" y **sin fallback cross-maletín**.
  El dispatcher enruta cada tool al maletín de su perfil; no busca en el otro.
- **RULE 1**: cada tool se entrega dentro de su imagen de maletín; las tools de artefacto
  Windows solo están físicamente en `toolkit-windows`.
- **Principio metodológico #4 (por-SO, no universal)**: la especialización por `os_profile`
  es la contribución del TFM; disolverla cambia la narrativa de la tesis.
- **Soundness + coste**: correr un parser de artefactos Windows sobre evidencia no-Windows
  no aporta valor probatorio (produce nada o ruido) y consume tokens/tiempo.

**Conclusión del análisis:** el "límite" que se percibe es, en su mayoría, **inconsistencias
de scoping** (tools transversales mal adscritas o ausentes de un allowlist), no la
arquitectura. Se arreglan sin erosionar invariantes (grupos A y B). El único grupo que
exige romperlos es el C (tools específicas de Windows), y por cero beneficio forense.

---

## 2. Inventario del catálogo (auditoría, 2026-07)

Fuente: `backend/forensia/toolkit/catalog.py` (`os_profiles` + `toolkits=`) y los dos
allowlists `agentes/forensia-{windows,unix}/policy/tools.yaml`.

| grupo | tools | `os_profiles` | maletín | naturaleza |
|---|---|---|---|---|
| **A — ya transversales** | file_info, xxd_head, strings_head, tsk_mmls, tsk_fls, tsk_mactime, tsk_icat, ewf_info, bulk_extractor, yara, volatility3, plaso_log2timeline, plaso_psort, hashdeep, jq | `(unix, windows)` | `_BOTH` | agnósticas; ya aplican a ambos |
| **B — transversales mal-adscritas** | foremost, qemu_nbd | `(unix,)` | `_BOTH` | agnósticas (carving / acceso a imagen) **pero** declaradas solo unix, aun estando físicamente en ambos maletines |
| **C — específicas de Windows** | regripper, evtxecmd, mftecmd, hayabusa, chainsaw | `(windows,)` | `_WINDOWS` | parsers de registro/EVTX/MFT; solo existen en `toolkit-windows` |

**Huecos de allowlist detectados (grupo A):**

- `forensia-unix` NO incluye: `file_info`, `strings_head` (diagnósticos agnósticos) —
  y opcional `xxd_head`.
- `forensia-windows` NO incluye: `xxd_head` (verificar si es redundante con `strings_head`).

**Nota `qemu_nbd`:** no está en NINGÚN allowlist hoy. Antes de añadirlo, confirmar si es
**invocable por el agente** o **interno de `EvidenceManager`** (montaje = excepción de
soundness, FORENSIC INVARIANTS §3). Si es interno, NO va al allowlist.

---

## 3. Qué logra cada capa

- **A + B** → cada evidencia obtiene **todas las herramientas que le aplican de verdad**.
  Es el objetivo práctico del equipo, y se consigue **sin romper invariantes** (solo se
  corrigen scoping y allowlists; la arquitectura por-`os_profile` y el routing siguen).
- **C** → universalizar los parsers Windows a evidencia no-Windows. **No recomendado**:
  requiere rebuild de `toolkit-unix` (RULE 1) o relajar el dispatcher (RULE 2), contradice
  la tesis, y no aporta valor forense. **Solo con decisión explícita del equipo + tutor**,
  registrada aquí, y enmendando `CLAUDE.md` (no violarlo en silencio).

---

## 4. Plan por fases

Leyenda de lane: **[decl]** = declarativo (allowlists/prompts/docs, lane del auditor
windows) · **[be]** = backend/toolkit (otro rol; revisa el dueño del motor) ·
**[gov]** = decisión de equipo/tutor + `CLAUDE.md`.

### Fase 0 — Constancia y decisión — **[gov]**  ⬜
- Este documento. Registrar la petición, la tensión con invariantes y el alcance elegido.
- **Criterio:** el equipo confirma que el alcance es **A + B** (recomendado) o que asume C
  con sus costes. Sin esta confirmación no se pasa de fase.

### Fase 1 — Auditoría (read-only) — **[decl]**  ✅ (hecha, §2)
- Inventario A/B/C + huecos de allowlist. Ver §2.
- Pendiente menor: listar los tests que codifican el scoping por SO —
  `backend/tests/test_catalog_integrity.py`, `test_agent_registry.py`, y la validación de
  `agent/loader.py` (`_validate_tool_id`: exige que el tool declare el `os_profile` del
  agente). Cualquier cambio de allowlist/os_profiles se valida contra ellos.

### Fase 2 — Grupo A: rellenar huecos de allowlist — **[decl]**  ⬜
- `forensia-unix/policy/tools.yaml`: añadir `file_info`, `strings_head` (y `xxd_head` si se
  decide). Ya declaran `unix` → `loader` los acepta sin tocar catálogo ni imágenes.
- `forensia-windows/policy/tools.yaml`: añadir `xxd_head` si se confirma que no es redundante.
- **Criterio:** carga del paquete verde (`pytest -k "agent_registry or catalog_integrity"`),
  ids existentes en catálogo con el `os_profile` correcto, RULE 0 limpio. Riesgo: nulo.

### Fase 3 — Grupo B: ampliar tools transversales mal-adscritas — **[be] + [decl]**  ⬜
- **[be]** `catalog.py`: `foremost` → `os_profiles=("unix","windows")`. `qemu_nbd` igual
  **solo si** se confirma que es agente-invocable (si no, se deja fuera y se documenta).
- **[decl]** allowlists: añadir `foremost` a `forensia-windows`; `qemu_nbd` a ambos (si aplica).
- **[be]** tests: ajustar las aserciones de scoping que asuman `foremost`=unix-only.
- **Criterio:** tests verdes; `capabilities` reporta las tools en ambos perfiles; el dueño
  del backend valida el cambio de `os_profiles`.

### Fase 4 — Grupo C: universalizar parsers Windows — **[gov] + [be]**  ⬜ (NO recomendado)
- **Gate:** decisión explícita del equipo + tutor, registrada en este doc, y enmienda de
  `CLAUDE.md` (RULE 1/2 y principio #4). Si no se aprueba, la fase se cierra como
  "descartada" con su motivo.
- Si se aprueba: meter regripper/evtxecmd/mftecmd/hayabusa/chainsaw en la imagen
  `toolkit-unix` (Dockerfile) **o** relajar el no-fallback del dispatcher — ambas backend/infra.

### Fase 5 — Validación + doc-sync — **[decl] + [be]**  ⬜
- Tests verdes (los tres gates de CI, RULE 6). `capabilities` correcto. Una corrida que
  confirme que el agente usa el set ampliado (no solo que está disponible).
- Actualizar **toda** la doc tocada (RULE 4): `docs/agentes/contrato-paquetes.md`,
  `docs/maletin/inventario-tools.md`, `docker/docs/CATALOGO_MALETIN.md`, el racional de los
  allowlists, y este plan (marcar fases hechas).

---

## 5. Estado / handoff (actualizar en cada commit)

| fase | estado | commit | notas |
|---|---|---|---|
| 0 Constancia | ⬜ pendiente confirmación de alcance | — | esperar OK del equipo (A+B vs C) |
| 1 Auditoría | ✅ hecha | (este doc) | inventario en §2 |
| 2 Allowlist A | ⬜ | — | mi lane; primer fix, 0 riesgo |
| 3 Grupo B | ⬜ | — | necesita backend + verificar qemu_nbd |
| 4 Grupo C | ⬜ | — | gated; no recomendado |
| 5 Validación | ⬜ | — | — |

---

## 6. Disciplina de documentación (RULE 4)

En cada fase, antes del commit, se actualizan los ficheros de la sección tocada **y** la
tabla de §5 de este plan (estado + hash de commit), para que otro compañero sepa por dónde
va y cómo continuar. Ningún cambio de código/allowlist entra con la doc desincronizada.
