# FORENSIA — Plan de entrenamiento y validación del sub-agente Windows

**Rol:** entrenamiento del sub-agente `windows` · rama `tools`
**Continuación de:** `plan-ruta-forensia-win.md` (Bloque A completo → aquí empieza
la automatización del entrenamiento y la validación).

> Objetivo final: un maletín forense que analice una imagen Windows completa
> (disco + memoria) y extraiga automáticamente todo el contenido relevante de la
> evidencia, con procedencia y correlación MITRE. Este documento explica cómo se
> **entrena** y **valida** el agente para llegar ahí.

---

## 0. Aclaración de roles (quién hace qué)

- **Tú (Maletín Windows):** el **cerebro declarativo** del agente — prompts,
  playbook, allowlist, redacción, KB/RAG, evals. Ya está hecho (Bloque A).
- **Motor / Backend / Orquestador:** ejecuta ese cerebro — `ForensicAgent.run()`
  (loop tool-use), backends de modelo (Ollama local / cloud) y el dispatcher que
  llama a las herramientas. Es la caja "Backend (Orquestador + MCPs)" del diagrama.
- **Datos/QA:** fixtures sintéticas y ground-truth.

La automatización del entrenamiento vive **entre** tu rol y el motor: tú defines
qué medir (evals + métricas) y construyes el **harness** que mide; el motor aporta
la ejecución real del agente.

---

## 1. Qué es "entrenar" aquí y qué significa "automatizarlo"

Entrenar NO es ajustar pesos de un modelo. Es **ingeniería de prompts/conocimiento
iterada contra métricas**:

```
  correr el agente sobre casos con ground-truth
        → medir (¿acertó tool? ¿encontró el hallazgo? ¿cuántos tokens?)
        → ajustar prompts/playbook/KB
        → repetir hasta que las métricas suban y se estabilicen
```

**Automatizar el entrenamiento** = tener un **harness** (un runner) que ejecute ese
ciclo solo: le das los casos, corre el agente con un motor, compara la salida
contra el ground-truth y te devuelve una **tabla de métricas**. Con eso iteras los
prompts guiándote por números, no por intuición. Y como el harness admite cambiar
solo el motor, produce la **comparativa entre motores (CLI agéntico vs Ollama
local)** que es el resultado científico del TFM.

> **Arquitectura de motor (actualizada, junio 2026).** El motor NO usa API keys.
> El agente se ejecuta a través de **dos formatos de motor**:
> - **CLI agéntico** — Codex CLI / Gemini CLI / Claude Code. Mantiene sesión y
>   **contexto** entre llamadas de herramienta (no se degrada como una API
>   stateless). Se conecta al maletín FORENSIA vía **MCP** y conduce las tools.
> - **Ollama local** — loop tool-use con el camino degradado (`{tool_id, params}`
>   parseable, ya soportado por los prompts A1).
> El paquete declarativo del agente debe servir a AMBOS. **Aviso de privacidad:**
> los CLI agénticos siguen enviando datos a la nube por debajo → la redacción
> (gate 9) SÍ aplica a los motores CLI; **solo Ollama es sin egreso** y es el
> motor privado por defecto para evidencia real (GDPR).

---

## 2. El bloqueo y cómo lo esquivamos (dos vías)

El agente completo (loop `run()` + dispatcher real sobre la imagen) **aún no se
puede ejecutar** (motor pendiente + gap B1). Pero no hace falta esperar a todo para
empezar a automatizar. Separamos en dos vías:

### Vía 1 — Harness de PROMPT (se puede construir YA, sin el motor)
Prueba **la decisión del agente**, no la ejecución forense real:
- Carga los prompts del paquete (`system`+`identity`+`playbook`) y los **schemas de
  las tools** (JSON Schema de la allowlist).
- Envía un caso sintético a un **motor** (Ollama local, o un CLI agéntico:
  Codex/Gemini/Claude Code — sin API keys) y captura **qué tool_id + params
  elige** y qué findings propone.
- Usa un **dispatcher MOCK** (devuelve salidas de herramienta pre-cocinadas del
  ground-truth) para que el modelo pueda "avanzar" sin evidencia real.
- Compara contra `expected_findings.provenance_tool` y `expected_mitre`.

Mide **tool_invocation_accuracy**, **adherencia a la allowlist**, **mapeo MITRE**,
**tokens** e **iteraciones** — todo sin tocar una imagen ni el motor. Es la parte
del entrenamiento que puedes automatizar hoy.

### Vía 2 — Harness E2E (cuando el motor tenga `run()` + dispatcher real)
Se cambia el dispatcher MOCK por el **real** y las salidas cocinadas por la
**ejecución sobre la imagen** (LoneWolf, memoria con malware). Ahí ya mides
**findings_recall / precision reales** sobre artefactos reales. Es la validación de
producto y la comparativa definitiva.

El harness es el **mismo**; solo cambia de dónde salen las observaciones (mock →
dispatcher real). Por eso construirlo ahora no es trabajo tirado.

---

## 3. Cómo se valida — definición operativa

Cada caso `case-win-*.yaml` es una **traza dorada**: `expected_findings`
(title_glob + severity + provenance_tool) + `expected_mitre` + `budget`. Validar =
comparar lo que el agente produce contra esa traza. Métricas:

| Métrica | Qué mide | Cómo se calcula |
|---|---|---|
| `tool_invocation_accuracy` | ¿eligió la tool correcta con params válidos? | tools emitidas vs `provenance_tool` esperados |
| `findings_recall` | ¿encontró los hallazgos esperados? | matches de `title_glob` / total esperado |
| `findings_precision` | ¿cuántos falsos positivos? | hallazgos no esperados / total emitido |
| `mitre_correctness` | ¿técnicas correctas y sostenidas? | `expected_mitre` vs emitidas (enum cerrada) |
| `tokens_per_case` | coste | contador del backend |
| `iterations_to_solve` | eficiencia del loop | contador del loop |
| `allowlist_violations` | ¿pidió tools fuera de la allowlist? | debe ser 0 (gate 5/6) |

**Criterio de éxito** (propuesta, se ajusta con datos): recall ≥ 0.8, precision ≥
0.9, allowlist_violations = 0, y cloud como referencia con local acercándose. La
tabla local-vs-cloud por métrica es el entregable publicable.

---

## 4. Ground-truth: el paso que hay que completar

Las métricas solo valen si la traza dorada es correcta. Para LoneWolf:
- Extraer el ground-truth real de `Forensic Outputs.zip` + write-ups públicos y
  volcarlo en `docs/agentes/ground-truth/lonewolf-2018.md` (hoy con `<verificar>`).
- Para la imagen de memoria con malware (MemLabs/cridex): documentar sus hallazgos
  conocidos (inyección, C2, credenciales) — es la que cubre las técnicas de
  intrusión que LoneWolf no tiene.
- Las fixtures de los `case-win-*` sintéticos las produce Datos/QA; su ground-truth
  ya está en el propio YAML.

---

## 5. El objetivo final — "analizar un Windows completo"

Es la validación E2E cualitativa (Vía 2 sobre la imagen entera, no casos aislados):
1. Cargar LoneWolf (disco `.E01` + `memdump.mem`) como caso en FORENSIA.
2. Lanzar la investigación: el agente recorre el playbook (partición → FS → `$MFT`
   → registro → EVTX → memoria), emitiendo findings con procedencia.
3. `[proceed-to-report]`: el orquestador redacta informe + timeline + correlación
   MITRE.
4. Contrastar el informe contra el ground-truth de LoneWolf: ¿salió lo importante
   (actividad de usuario, cuentas, USB, navegación/cloud, ejecución)? ¿sin inventar?

Eso demuestra el maletín "extrayendo todo lo relevante" de una evidencia real.

---

## 6. Roadmap ordenado (con dependencias)

| # | Paso | Depende de | Estado |
|---|---|---|---|
| B0 | Completar ground-truth LoneWolf + memoria malware | descargar imágenes + Forensic Outputs | **puedes YA** (con descargas) |
| B1-esc | Escalar el gap de inyección al motor | — | **puedes YA** (mensaje) |
| S6a | **Harness de PROMPT** (Vía 1, dispatcher mock, motor pluggable) | schemas de tools + Ollama | **puedes YA** |
| S6b | Correr S6a en Ollama, iterar prompts; añadir motor CLI | S6a + Ollama (luego CLI) | tras S6a |
| B1-fix | Motor arregla `tsk_icat→artefacto` + `run()` mínimo | rol de motor | **bloqueado** (motor) |
| S6c | **Harness E2E** (Vía 2, dispatcher real) | B1-fix + motores reales | bloqueado |
| E2E | Análisis completo de LoneWolf → informe | S6c | bloqueado |
| TFM | Tabla comparativa entre motores (CLI vs Ollama) + memoria | S6b/S6c | continuo |

**Qué puedes hacer sin esperar a nadie:** B0 (con las descargas), la escalada B1, y
**S6a — construir el harness de prompt**. Eso ya te da un ciclo de entrenamiento
automatizado real sobre la decisión del agente.

---

## 7. Requisito para automatizar YA: un motor al que llamar (CLI u Ollama)

El harness necesita un motor. En la arquitectura nueva son dos, **sin API keys**:

- **Ollama local (empezar por aquí).** Instala Ollama y baja un modelo base
  (p.ej. `llama3.1:8b` o `qwen2.5:14b`). Es **estable, local, sin egreso** y ya
  definido, así que es el objetivo más firme mientras el lado CLI/orquestador
  sigue en migración. Además es el motor por defecto del producto: mides lo que
  de verdad correrá con evidencia sensible.
- **CLI agéntico (Codex / Gemini / Claude Code).** Mantiene contexto entre tool
  calls y se conecta al maletín vía MCP. Es el segundo objetivo de la comparativa.
  Nota: su interfaz de invocación depende del motor/orquestador, que está **en
  migración** — por eso el harness se diseña con el motor **pluggable** y se añade
  el CLI cuando esa interfaz se estabilice. Recuerda: los CLI egresan a la nube →
  redacción (gate 9) aplica.

**Estrategia:** construir el harness contra **Ollama primero** (firme hoy, prompts
listos), con el "motor" como componente enchufable, y añadir el/los CLI después.
Así arrancas el ciclo de entrenamiento automatizado ya, sin perseguir una interfaz
que aún se mueve.

### Puntos de coordinación con el rol de motor
- **Enum de `model.backend` en `agent.yaml`.** Hoy es `local|cloud`. La arquitectura
  nueva pide reflejar los motores reales (p.ej. `ollama` y `cli`). Cambiar ese enum
  toca `loader.py`/`registry.py` y sus tests → es del motor; se acuerda con ellos
  antes de tocar el paquete (RULE 2).
- **Schemas MCP de las tools** (S3): necesarios para que un CLI agéntico consuma el
  maletín. Se documentan desde el rol de agentes; el servidor MCP lo expone el motor.

---

## 8. Siguiente acción concreta

Dos frentes en paralelo:
1. **Descargas** (tú): `memdump.mem` + una imagen de memoria con malware; luego
   hashes con `scripts/hash-evidence.py`.
2. **S6a — harness de prompt** (con Claude Code, guiado): construir el runner que
   carga prompts + schemas, llama a un modelo con dispatcher mock, y saca la tabla
   de métricas. Empezar por 2-3 casos y un modelo, luego escalar.

El mensaje de escalada B1 al motor se prepara aparte (es corto y desbloquea al
resto del equipo).
