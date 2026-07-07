# Plan de ruta — Auto-detección de SO y enrutado por el orquestador

**Rama:** `tools` · **Estado:** propuesta / Fase 0 (decisión) · **Toca varias lanes**
(backend/triage/registry, frontend, orquestador KB, docs, gobernanza).

> **Petición del equipo (constancia):** eliminar por completo que el usuario elija el SO
> de la evidencia. El **orquestador** debe ser lo bastante inteligente en su capa para
> decidir, en cada momento, a qué sub-agente (unix / windows) lanzar según la variante de
> la evidencia.

> **Reemplaza** a `plan-ruta-tools-independientes-del-so.md`: el objetivo real no era
> "todas las tools sin límite" (eso rompía la tesis) sino **quitar la elección manual del
> SO**. Los sub-agentes siguen especializados por `os_profile`; solo se automatiza el
> enrutado. (Los arreglos menores de scoping A/B de aquel plan — `foremost` mal-adscrito,
> huecos de allowlist — pueden quedar como limpieza opcional, no son el foco.)

Este documento es la **fuente de verdad viva** de la tarea (RULE 4): se actualiza cada fase.

---

## 1. Punto de partida — lo que YA existe

`backend/forensia/triage.py` es un **fingerprint determinista** (sin LLM, sin tools
externas, Python puro sobre la copia read-only tras el hash-gate → cadena de custodia
intacta). Devuelve `DetectedEvidence(family, kind, confidence, signals)`:

- `family ∈ {unix, windows, unknown}`, `kind ∈ {disk, memory, container_disk, unknown}`.
- Árbol de decisión: cabeceras a offset fijo (LiME/crashdump/EWF/VMDK/VDI/QCOW/VHD(X)) →
  MBR `0x55AA` / GPT `EFI PART` → sectores de arranque (NTFS/ext/HFS+/APFS) → scoring de
  memoria (PE scatter + `ntoskrnl`/`hal.dll`/`linux_banner`) → hint de extensión (último
  recurso).
- Se persiste en `baseline.json` por evidencia.

**Consumidores hoy:** (1) la UI muestra un banner si `case.os_profile != evidence.family`
— *el operador decide, nunca auto-switch* (RULE 2); (2) el system prompt del agente recibe
`family`+`kind` para ir a la sección correcta del playbook.

**Enrutado hoy:** `agent/registry.py` → `get_for_profile(os_profile)` con el `os_profile`
que **el operador ancla** al crear el caso (`cases/manager.py`, `routers/cases.py` lo exigen).

**Conclusión:** la detección ya está resuelta y es robusta. El cambio es de **wiring +
salvaguardas**, no una rearquitectura.

---

## 2. Tensión con los invariantes (leer antes de tocar nada)

- **RULE 2** (`CLAUDE.md`, líneas ~60 y ~133): "el operador ancla; el orquestador nunca
  adivina el perfil; `triage` solo *sugiere*". La petición lo cambia → **hay que enmendar
  RULE 2**, no violarla en silencio.
- **Reconciliación (argumento para el tutor):** lo que RULE 2 prohíbe es *"guess from
  context / host platform"* — defaults silenciosos que ocultan bugs de configuración. La
  detección de `triage` es **por el contenido de la evidencia**, determinista y auditable:
  es una determinación forense, no un default. El **espíritu** de RULE 2 se preserva si:
  > **baja confianza / `unknown` / señales en conflicto ⇒ escalar al operador (fail loud);
  > nunca elegir en silencio.**
- **Seguridad (evidencia hostil, SECURITY INVARIANTS):** un sospechoso puede plantar firmas
  (p.ej. NTFS + ext4) para inducir un enrutado erróneo. Mitigación: `confidence` + detección
  de **conflicto** de señales → escalada. La evidencia sigue tratándose como datos (triage
  ya es Python puro, no ejecuta nada de la evidencia).
- **Auditoría (FORENSIC INVARIANT 4):** la decisión de enrutado (`family`, `confidence`,
  `signals`) se registra en el log append-only hash-encadenado.
- **Tesis por-SO (principio #4):** intacta — los sub-agentes no se tocan.

---

## 3. Modelo de enrutado propuesto

- `os_profile` deja de ser propiedad **del caso** (elegida por el operador) y pasa a
  derivarse **por-evidencia** desde `triage.family` (ya está en `baseline.json`).
- El orquestador enruta **cada evidencia** al sub-agente de su `family`. Un caso con
  evidencias de distinto SO usa **ambos** sub-agentes (mejora sobre el modelo caso-único).
- **Regla de oro (RULE 2 preservada):** si `family=unknown`, `confidence` por debajo del
  umbral, o señales en conflicto → **el operador DEBE anclar manualmente** antes de enrutar.
  Sin esa anchura no se lanza sub-agente (nada de default silencioso).
- La UI deja de pedir el SO al crear el caso; muestra el `family/kind` detectado + confianza
  + base (`signals`), y solo pide intervención cuando hay ambigüedad.

---

## 4. Plan por fases

Lane: **[be]** backend/toolkit (dueño del motor) · **[fe]** frontend · **[decl]**
declarativo (orquestador KB / docs, lane del auditor) · **[gov]** decisión equipo + tutor +
`CLAUDE.md`.

### Fase 0 — Decisión y gobernanza — **[gov]**  ⬜
- Confirmar el cambio con equipo **y tutor** (enmienda una invariante y toca soundness).
- Redactar la **enmienda de RULE 2** en `CLAUDE.md`: de "operador ancla, triage sugiere" a
  "triage determina desde el contenido; enruta cuando hay confianza; **en ambigüedad exige
  anclaje del operador**". Registrar el racional (§2). **Criterio:** OK explícito + enmienda
  redactada. Sin esto no se implementa.

### Fase 1 — Auditoría técnica (read-only) — **[decl]**  ✅ (hecha)

**Inventario de puntos de cambio** (rastreo read-only):

- **La huella ya se persiste por evidencia:** `evidence.py` guarda `detected_os` /
  `detected_kind` (de `triage`) por evidencia. El enrutado puede leer
  `evidence.detected_os` — el dato ya existe.
- **3 callers de enrutado** (hoy por `case.os_profile` / `req.os_profile`; pasarlos a la
  `family` de la evidencia): `routers/agent.py:119` `get_for_profile(req.os_profile)` —
  con un **default silencioso `= "unix"`** (línea 49) que ya contradice RULE 2 —,
  `mcp/session.py:52` y `mcp/jira_tools.py:140` `get_for_profile(case.os_profile)`.
- **Anclaje del operador (a quitar):** `routers/cases.py:27,60` + `cases/manager.py:117`
  exigen `os_profile` al crear el caso; `case.json` lo valida obligatorio
  (`manager.py:235-240`). Nuevo modelo: `case.os_profile` opcional/derivado.
- **Triage / conflicto:** `DetectedEvidence(family, kind, confidence, signals)`,
  `confidence ∈ {header, markers, extension, none}`. **No hay campo de "conflicto"**:
  `_decide_family` elige por conteo de marcadores. Predicado *enrutable* =
  `family ∈ {unix, windows}` **y** `confidence ∈ {header, markers}`; el empate (dual-boot,
  win y unix altos) exige que `_decide_family` devuelva `unknown` en empate cercano →
  pequeña mejora [be] en triage.
- **Frontend:** `ChatPage.tsx:318-329,450` elige el agente por `activeCase.os_profile` y lo
  envía; banner de mismatch `ChatPage.tsx:525-530`; tipos en `api/types.ts`; el selector de
  SO vive en el formulario de creación de caso.
- **Tests afectados:** `test_cases.py`, `test_agent_registry.py`, `test_web_surface.py`,
  `test_dispatcher_case_anchored.py`, `test_smoke.py` (14 ficheros referencian `os_profile`;
  estos codifican el anclaje/enrutado).

### Fase 2 — Enrutado por evidencia — **[be]**  ⬜
- `os_profile` pasa a derivarse de `triage.family` por evidencia; `case.os_profile` se hace
  opcional/derivado (no lo elige el operador).
- `registry.get_for_profile(triage.family)`; si `family` no es enrutable (unknown/baja
  confianza/conflicto) → error accionable que la UI convierte en "el operador debe anclar".
- Registrar la decisión de enrutado en el audit log.
- **Criterio:** tests verdes; nunca enruta en silencio ante ambigüedad; el dueño del motor
  valida (es cambio de invariante).

### Fase 3 — UI sin selector de SO — **[fe]**  ⬜
- Quitar el picker de SO al crear el caso. Mostrar `family/kind/confidence/signals`
  detectados. Cuando hay ambigüedad, pedir el anclaje manual (único caso que lo requiere).
- **Criterio:** `npm run typecheck && build` verdes; el flujo degrada explícito en ambigüedad.

### Fase 4 — Orquestador (KB/prompts) + docs — **[decl]**  ⬜
- Ajustar `agentes/_orchestrator/` (README/reporter/mitre/timeline) para reflejar el
  enrutado automático por evidencia y el caso multi-SO.
- Sincronizar (RULE 4): `docs/agentes/contrato-paquetes.md`, `docs/agentes/diseno-fase2.md`,
  `agentes/README.md`, `docs/arquitectura.md`, y `CLAUDE.md` (§ Trained-agent packages +
  RULE 2 enmendada).

### Fase 5 — Validación + doc-sync — **[be] + [decl]**  ⬜
- Corridas de prueba: disco Windows, disco Linux, memoria de cada uno, un caso **multi-SO**,
  y un caso **ambiguo** (debe exigir anclaje, no enrutar). Confirmar el registro en auditoría.
- Los tres gates de CI verdes (RULE 6). Actualizar la tabla de estado (§5-bis) y toda la doc.

---

## 5-bis. Estado / handoff (actualizar en cada commit)

| fase | estado | commit | notas |
|---|---|---|---|
| 0 Gobernanza | ✅ aprobada (equipo+tutor) | (este commit) | RULE 2 enmendada |
| 1 Auditoría | ✅ hecha | (este commit) | inventario en §Fase 1 |
| 2 Enrutado [be] | ⬜ | — | cambio de invariante; lo valida el dueño del motor |
| 3 UI [fe] | ⬜ | — | quitar selector SO |
| 4 Orquestador/docs [decl] | ⬜ | — | mi lane |
| 5 Validación | ⬜ | — | incluye caso multi-SO y caso ambiguo |

---

## 6. Reparto de responsabilidad

- **Mucho de esto es backend/frontend** (triage→routing, registry, UI) = otros roles; el
  dueño del motor valida el cambio de invariante (Fase 2).
- **Mi lane (auditor windows, declarativo):** este plan, la enmienda de RULE 2 y la doc
  (Fase 4), la KB del orquestador, y auditar cada diff contra los invariantes antes del commit.
- **Gobernanza:** la enmienda de RULE 2 y la conformidad del tutor son **precondición**
  (Fase 0) — este cambio toca una invariante de soundness, no se hace en silencio.

## 7. Disciplina de documentación (RULE 4)

En cada fase, antes del commit, se actualizan los ficheros de la sección tocada **y** la
tabla §5-bis (estado + hash), para que cualquier compañero sepa por dónde va y cómo seguir.
