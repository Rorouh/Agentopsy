# Auditoría — Loop del agente, findings y backend de modelos (Fase 2)

> Auditoría de conformidad + seguridad del código aportado por el equipo de motor
> en los commits `35a44fa` (agente LLM real con OpenAI) y `b6ea63c` (findings
> persistidos). Contraste contra `docs/FASE2_AGENTES_DISENO.md`, `CLAUDE.md`,
> `docs/THREAT_MODEL.md` (gates 1–12) y `docs/FORENSIC_SOUNDNESS.md`.
> Alcance leído: `agent/agent.py`, `agent/tool_schemas.py`, `findings/store.py`,
> `models/{cloud,local,base}.py`, `routers/agent.py`.

## Resumen ejecutivo

El loop está bien construido en lo estructural: **enforce de allowlist por
paquete**, **inyección de paths por Agentopsy** (el LLM nunca elige el path de la
evidencia), **una tool por round-trip** (audit lineal), y **selección de backend
sin default silencioso** (RULE 2). Buen trabajo de base.

Pero hay **un bloqueante de privacidad/custodia**: la **redacción declarada en
cada paquete (`policy/redaction.yaml`) nunca se aplica**, y el único backend
funcional es cloud (OpenAI) — el local es un stub. Resultado: hoy, toda ejecución
real envía bytes de evidencia **sin redactar y sin consentimiento registrado** a
un tercero. Esto rompe el gate 9 y la frontera de egreso de `FORENSIC_SOUNDNESS §5`.

> **Actualización — Slice A (F1+F2+F3) RESUELTO.** La redacción del paquete se
> aplica en el único punto de egreso, el consentimiento es por caso (sin él
> `/api/agent/query` responde `consent_required` y no sale un byte) y el egreso +
> los findings entran en el audit log encadenado. Detalle por hallazgo abajo. El
> resto (F4–F10) sigue pendiente.

| ID | Severidad | Área | Gate / Diseño |
|---|---|---|---|
| F1 | **BLOQUEANTE** | Redacción no aplicada en egreso cloud | gate 9 / SOUNDNESS §5 |
| F2 | Alta | Sin consentimiento por caso registrado (+preview) antes de cloud | gate 9 / SOUNDNESS §5 |
| F3 | Alta | Egreso cloud y decisiones del agente no entran al audit log encadenado | SOUNDNESS §3 |
| F4 | Media | Sin gate de confirmación para tools `side_effecting` (existe `qemu_nbd`) | THREAT_MODEL §B |
| F5 | Media | Procedencia del finding auto-reportada por el LLM y no verificada | Diseño §3.3 |
| F6 | Media | Allowlist ↔ `tool_schemas` desalineados (tools invisibles/stubs) | Diseño §3.2 / §6 |
| F7 | Media | `jq` inoperable en el loop (su `input_path` se elimina) | Diseño §5/§6 |
| F8 | Baja | `Finding` sin `confidence`/`observed_at`/`artifact_sha256`/`mitre_hints` | Diseño §3.3/§7 |
| F9 | Baja | Backend local (Ollama) es stub → no hay vía privada hoy (amplifica F1) | Diseño §8 |
| F10 | Baja | Demo loop dispatcha tools fuera de la allowlist del paquete (dev-only) | gate 6 (defensa) |

---

## Lo que está BIEN (no tocar)

- **Allowlist por paquete enforced** en el loop: `agent.py:187` rechaza cualquier
  `tool_id` fuera de `package.policy.allowed_tools` y deja que el modelo se
  recupere (gate 6 ✓).
- **Inyección de paths por Agentopsy**: `agent.py:199` + `_inject_runtime_paths`
  (`agent.py:312-323`) fija el path de la evidencia y **elimina** cualquier clave
  auto-inyectada que el modelo intente colar (defensa contra prompt-injection de
  paths, gate 8 ✓).
- **Sin shell / enum cerrada**: el modelo emite `tool_id`+params tipados; el
  dispatcher construye el argv (gate 5 ✓). `tool_schemas.py` usa
  `additionalProperties:false` y enums por parámetro.
- **RULE 2** en selección de backend: `routers/agent.py:148-153` exige
  `MODEL_BACKEND=cloud`+key+`MODEL_NAME`; si no, cae al demo loop. Sin default
  silencioso.
- **Audit por tool run**: cada dispatch pasa por `dispatcher.execute(case_id=...)`
  → `ArtifactRun` + `audit.jsonl` con el argv literal.

---

## Hallazgos

### F1 — BLOQUEANTE · La redacción del paquete nunca se aplica al egreso cloud
**Evidencia.** `policy/redaction.yaml` se parsea (`loader.py:212`) y vive en
`AgentPackagePolicy.redaction_patterns` (`package.py:43`), pero **ningún módulo lo
consume**: `grep redaction_patterns` solo aparece en su definición. El loop
(`agent.py`) construye `messages` con resultados de tool (`stdout_sample`,
`stderr_sample`, `parsed`, `agent.py:333-343`) y el **nombre de fichero de la
evidencia** (`agent.py:265`), y los manda a OpenAI vía `CloudBackend.next_action`
(`cloud.py:103`) **sin redactar**.
**Impacto.** Bytes de evidencia (emails/IPs de `bulk_extractor`, strings, datos de
registro, nombres de fichero con PII) salen a un tercero sin minimización. Rompe
gate 9 y `FORENSIC_SOUNDNESS §5` (RGPD + cadena de custodia). Como el backend
local es stub (F9), **es el camino por defecto de toda ejecución real**.
**Fix propuesto.** Aplicar las `redaction_patterns` del paquete a **todo** texto
que cruce a un backend con `capabilities().is_local == False`, en un único punto
de egreso (envolver `state["messages"]` antes de `next_action`, o un
`RedactingModelBackend` decorador). Redactar también el `evidence_filename`
inyectado. Añadir test: payload con email/IP → 0 ocurrencias en lo enviado.
**Estado: RESUELTO (Slice A).** `forensia.agent.redaction.redact_messages` aplica
las `redaction_patterns` del paquete a system+user+resultados de tool en el único
punto de egreso de `ForensicAgent.run` cuando `capabilities().is_local == False`;
con backend local pasa intacto. Tests en `tests/test_agent_egress.py`.

### F2 — Alta · Sin consentimiento por caso ni preview antes del egreso cloud
**Evidencia.** `cloud.py:3` documenta "recorded consent + redaction"; no hay
código. `routers/agent.py:80-93` entra al path cloud solo con el flag **global**
`MODEL_BACKEND=cloud`; no hay opt-in por caso ni registro de consentimiento.
**Impacto.** El diseño exige cloud **opt-in por caso, con consentimiento
registrado y preview de qué bytes salen**. Hoy, activar cloud una vez lo activa
para todos los casos, silenciosamente.
**Fix propuesto.** Gate de consentimiento por caso (campo en `case.json` o
endpoint `/api/cases/{id}/consent`), entrada `consent_ref` en `audit.jsonl` antes
del primer egreso (esquema ya previsto en `FORENSIC_SOUNDNESS §3`), y un preview
del payload redactado.
**Estado: RESUELTO (Slice A) — sin preview.** Consentimiento por caso en
`case.json` (`CaseManager.grant_cloud_consent` / `POST /api/cases/{id}/consent`);
sin él `/api/agent/query` devuelve `consent_required` y no se instancia el backend.
El preview de bytes en la UI queda pendiente (no bloquea el gate de egreso).
> **Actualización 2026-07-16:** el consentimiento por caso para egreso cloud se
> **eliminó**. `forensia.consent`, el campo `cloud_consent` de `case.json`,
> `grant_cloud_consent`, `POST /api/cases/{id}/consent` y `POST /api/agent/cloud-consent`
> ya no existen; `/api/agent/query` no exige consentimiento ni devuelve 403 por su
> ausencia, y `ForensicAgent.run` ya no rechaza un run cloud sin `consent_ref`. La
> redacción en el punto de egreso y la auditoría del egreso (F3) se mantienen.

### F3 — Alta · El egreso cloud y las decisiones del agente no entran al audit encadenado
**Evidencia.** `agent.py:90` recibe `audit` pero no lo usa; solo el dispatcher
audita (por tool run). Las llamadas al modelo (qué se envió a OpenAI, cuándo) y
los `record_finding` no quedan en la cadena hash.
**Impacto.** `FORENSIC_SOUNDNESS §3` pide poder responder "qué acción del agente,
a qué hora, con qué modelo". El egreso a un tercero es precisamente lo que más
interesa auditar.
**Fix propuesto.** Registrar en `audit.jsonl`: inicio de run del agente (modelo,
backend, caso, evidencia), cada egreso cloud (con `consent_ref` y hash del payload
redactado) y cada `record_finding`.
**Estado: RESUELTO (Slice A).** `ForensicAgent.run` usa el `AuditLog` del caso para
encadenar `agent_run_start`, `agent_cloud_egress` (`consent_ref` +
`redacted_payload_sha256` + `message_count`) y `agent_finding` (`finding_id`); sólo
hashes/metadatos, nunca bytes crudos. `verify()` sigue en verde.

### F4 — Media · Sin confirmación humana para tools `side_effecting`
**Evidencia.** `catalog.py:268` declara `qemu_nbd` con `side_effecting=True`. El
loop (`agent.py`) y el `dispatcher` no comprueban `tool.side_effecting` en ningún
punto; el system prompt incluso instruye "no pidas confirmación"
(`agent.py:273-279`). Hoy la allowlist lo bloquea (no está en ningún paquete),
pero no hay defensa en el dispatcher.
**Impacto.** `THREAT_MODEL §B` exige confirmación humana para tools de efecto
secundario, ligada al comando ya resuelto. Una futura allowlist con `qemu_nbd` (o
cualquier tool de montaje/red) lo ejecutaría sin confirmación.
**Fix propuesto.** Guard en el `dispatcher`: si `tool.side_effecting` y no hay un
token de confirmación explícito del operador → rechazar (defensa independiente de
la allowlist). Acotar el "no pidas confirmación" del prompt a tools de solo
lectura.

### F5 — Media · Procedencia del finding auto-reportada, no verificada
**Evidencia.** `record_finding` toma `tool_id`/`run_id` de los params del **modelo**
(`agent.py:169-185`); `findings/store.py:74-77` solo valida que `run_id` tenga
formato UUID4, no que **exista** un `ArtifactRun` con ese id en el caso. El loop
conoce el `run_id` real del último dispatch (`agent.py:226`) y no lo inyecta.
**Impacto.** Diseño §3.3: "ningún finding sin procedencia resoluble". Hoy el LLM
puede citar un `run_id` inexistente o equivocado; la cadena de custodia del
hallazgo es autodeclarada.
**Fix propuesto.** Inyectar automáticamente el `run_id`/`tool_id` del último
dispatch en `record_finding` (en vez de confiar en el modelo) y/o validar en el
store que el `run_id` existe en `artifacts/` del caso.

### F6 — Media · Allowlist ↔ `tool_schemas` desalineados
**Evidencia.** `tool_schemas.TOOL_PARAM_SCHEMAS` cubre 16 tools, pero **no**
`tsk_icat`, `foremost`, `plaso_log2timeline`, `plaso_psort`, `hashdeep`. Esos ids
sí están en mis allowlists S1 (`forensia-unix`/`forensia-windows`) y en el catálogo
(como stubs `_not_built`). `openai_tool_specs` los descarta silenciosamente
(`tool_schemas.py:355-361`) → **invisibles al LLM**.
**Impacto.** El agente no puede invocarlos aunque estén en su allowlist. En
concreto, el **workflow de pre-extracción Windows** de mi playbook (`tsk_icat` →
`regripper`/`evtxecmd`) **no es ejecutable**. _Hallazgo parcialmente auto-crítico:
mis allowlists S1 sobre-alcanzaron el toolset realmente implementado._
**Fix propuesto.** Alinear: (a) recortar las allowlists S1 a tools
implementados+con schema, dejando los extendidos como roadmap comentado; o (b)
implementar wrapper+schema de `tsk_icat` (prioritario: lo necesita el flujo
contenedor) y `plaso_*`. Recomiendo (a) ahora + (b) `tsk_icat` pronto.

### F7 — Media · `jq` inoperable en el loop
**Evidencia.** El schema de `jq` exige `input_path` al modelo
(`tool_schemas.py:252`), pero `input_path` está en `AUTO_INJECTED`
(`tool_schemas.py:27`) y el loop **elimina** las claves auto-inyectadas que el
modelo haya puesto salvo el `target_key` (`agent.py:318-322`); `jq` no tiene
`target_key` en `_EVIDENCE_INJECTION` → su `input_path` se borra y nada lo
reinyecta.
**Impacto.** `jq` es el helper de 2º nivel para filtrar artefactos grandes antes
de mandarlos al modelo (estrategia anti-tokens del diseño §5). Hoy no funciona.
**Fix propuesto.** Sacar `input_path` de `AUTO_INJECTED` (es un path de artefacto
que el modelo SÍ debe elegir, confinado a `artifacts/` del caso) y validar que
cae dentro del directorio del caso. Igual revisión para `target_path` de `yara`.

### F8 — Baja · `Finding` con procedencia parcial vs diseño §3.3
**Evidencia.** `Finding` (`store.py:33-44`) tiene `evidence_id/tool_id/run_id`
pero no `confidence`, `observed_at` (marca del artefacto, no de registro),
`artifact_sha256` ni `mitre_hints`.
**Impacto.** La UI (`InvestigationFinding`) no los exige, pero el orquestador
(timeline/MITRE) los necesita: `observed_at` para anclar la timeline y
`confidence` para calibrar correlaciones. Custody alcanzable vía `run_id`.
**Fix propuesto.** Ampliar el dataclass (campos opcionales) cuando se aborde el
orquestador (S4); no urge.

### F9 — Baja · Backend local (Ollama) es stub
**Evidencia.** `local.py:27` lanza `NotImplementedError`.
**Impacto.** No hay vía privada funcional; la única real es cloud → amplifica F1.
Es coherente con el diseño §8 (desarrollar/medir con cloud primero), pero conviene
priorizar el camino degradado local para la postura privacy-by-default y la
comparativa del TFM.
**Fix propuesto.** Implementar `LocalOllamaBackend.next_action` (prompt
estructurado + parser + allowlist + reintentos) como slice propio.

### F10 — Baja · Demo loop fuera de la allowlist del paquete
**Evidencia.** `routers/agent.py:40-51,156-164` dispatcha tools de una lista fija
sin pasar por `pkg.policy.allowed_tools`.
**Impacto.** Dev-only, solo tools read-only; pero es una vía que ignora la
allowlist. Conviene cruzarla con el paquete por coherencia (gate 6 en profundidad).
**Fix propuesto.** Filtrar `_choose_tool` por la allowlist del paquete activo.

---

## Plan de remediación (orden recomendado)

1. **Slice A (BLOQUEANTE): seguridad de egreso cloud** — F1 + F2 + F3 juntos
   (redacción aplicada + consentimiento por caso + audit del egreso). Es un bloque
   coherente y desbloquea cualquier uso real con cloud.
2. **Slice B: integridad de findings y tools** — F5 (procedencia inyectada/validada)
   + F7 (`jq` operable) + F6 (alinear allowlists/schemas).
3. **Slice C: confirmación side-effecting** — F4 (guard en dispatcher).
4. **Slice D: backend local** — F9 (camino degradado Ollama) — habilita la
   comparativa del TFM y la privacy-by-default.
5. **Diferible:** F8 (campos de `Finding`) con el orquestador; F10 (demo loop).

Cada slice se entrega como un prompt de Claude Code con criterios de aceptación y
tests; la auditoría revisa el diff antes del commit.
