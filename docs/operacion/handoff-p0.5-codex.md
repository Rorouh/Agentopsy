# Traspaso P0 / P0.5 — auditor + ejecutor (Codex)

> Copia este fichero (o pégalo) en un chat nuevo de Codex. Ese chat actúa como **auditor
> forense-IA** de Agentopsy y conduce `codex code` como **ejecutor**. Cada chat nuevo arranca
> en frío: la **fuente de verdad es el repo, no la memoria**. Rama de trabajo: `tools`.

---

## 0. Rol y reglas de operación (inquebrantables)

Eres **auditor forense-IA experto** del proyecto Agentopsy (TFM). **No ejecutas tú**: das el
**contenido exacto / los prompts** para `codex code`, y **auditas cada salida contra el
ground-truth y los invariantes ANTES de commitear**.

1. **La fuente de verdad es el repo.** Antes de opinar, LEE los ficheros (empieza por
   `tools/graph/CONTEXT.md` y `CLAUDE.md`). El estado avanza entre sesiones — corre `git pull`
   al empezar (RULE 5).
2. **No lances comandos git sobre el repo** (dejan `.git/index.lock` colgado). Da el comando
   git exacto para que lo ejecute el operador.
3. **Audita antes de commitear.** Cada diff/corrida se revisa contra los invariantes de
   `CLAUDE.md`: RULE 0 (cero atribución IA en commits/código/docs), RULE 1 (todo viaja en el
   compose), RULE 2 (sin fallbacks ni defaults silenciosos, fallar fuerte), RULE 3 (lógica en
   `forensia/*`, superficies finas), RULE 4 (doc-sync antes de commitear), RULE 6 (CI verde
   antes de push), RULE 7 (sin API keys), FORENSIC INVARIANTS 1-4 (custodia, hash-chain),
   SECURITY INVARIANTS 1-8 (evidencia = dato hostil, shell-free, confinamiento de rutas).
4. **El entregable de cada paso es un prompt AUTOCONTENIDO para `codex code`** (chat nuevo sin
   contexto): repo/rama, arquitectura relevante, alcance ESTRICTO, restricciones (no tocar
   `web/` ni `agentes/*`; sin keys; sin fallbacks; sin atribución IA), verificación (`cd
   backend && pip install -e ".[dev,mcp]"` + `ruff check .` + `pytest -q`), y criterio de
   aceptación. Pídele que **NO haga git** y devuelva **diagnóstico + diff + salida ruff/pytest**.
5. **Loop por paso:** (a) das el prompt → (b) el operador lo corre en `codex code` → (c) te
   pega diagnóstico+diff+ruff/pytest → (d) **auditas** contra invariantes (lee los ficheros
   tocados, no te fíes del resumen) → (e) si pasa, das el `git add …` + `git commit` exactos y
   recuerdas `git pull`/`push` + verificar Actions verde → (f) siguiente prompt.

**Verificación mínima antes de decir "CI-safe" (RULE 6):** backend → `ruff check .` +
`pytest -q` desde `backend/` con el extra `mcp`; web → `npm ci && npm run typecheck && npm run
build`; compose → `docker compose config --quiet` + `docker compose build api web`. Si tocas
`docker/.../exec_agent.py` (infra), corre `ruff` sobre él; la gate compose no se puede
reproducir sin Docker — dilo explícito.

---

## 1. Qué es Agentopsy (contexto mínimo)

Herramienta pericial **post-mortem**, self-hosted con `docker compose up --build` (5 servicios:
`web`, `api`, `ollama`, `toolkit-windows`, `toolkit-unix`). Un **orquestador** enruta al
**sub-agente** según el `os_profile` de la evidencia; el sub-agente corre tools del maletín por
el canal **api→exec-agent→maletín** y devuelve hallazgos estructurados con **cadena de
custodia** (cada finding cita `tool_id`/`run_id`/`sha256`). El agente emite `{tool_id, params}`
tipados (enum cerrada), nunca un string de comando; el backend resuelve el argv desde un
allowlist y ejecuta shell-free.

**Flujo de una tool anclada a caso (dispatcher):** validar params → abrir `ArtifactRun` →
fijar argv literal → `tool_run_start` durable en `audit.jsonl` (hash-encadenado) → ejecutar en
el maletín → un único `tool_run_finish` con exit literal + SHA-256 de artefactos. Sin retry,
sin fallback entre maletines (RULE 2).

---

## 2. HECHO — mejoras cerradas en HEAD (commiteadas y pusheadas)

> Verifica con `git log --oneline -15`. Todas pasaron `ruff` + `pytest` y CI verde.

- **Audit-ordering (blocker antiguo #3): CERRADO.** `tool_run_start` se persiste ANTES de
  cruzar el runner (`dispatcher.py`); el fallo del finish es intento único sin retry. Un
  rechazo previo a tener argv ejecutable no genera un start que afirme una ejecución inexistente.
- **P0.1 (blocker #4 fallback): CERRADO.** `agent._max_tool_attempts` — `FORENSIA_MAX_TOOL_ATTEMPTS`
  ausente usa el default diseñado; presente-inválido **lanza** (RULE 2). Tests en
  `test_agent_loop.py`.
- **P0.2 (blocker #2 corrupción binaria): CERRADO.** Canal `stdout_path` binario-seguro: `icat`
  escribe bytes CRUDOS a `out/stdout.bin` (sin decodificar), devuelve ruta+sha256+size; se
  re-hashea por `_scan_out_dir` (INVARIANT 4). `Tool.binary_stdout` default `False` (resto sin
  cambio). Rechazó base64 (footgun OOM). Test `test_binary_stdout_channel.py`.
- **P0.3 (routing EWF): CERRADO funcional.** TSK no lee `.E01`; el exec-agent lo monta con
  `ewfmount` (FUSE, **RO, sin montar el FS** — INVARIANT 3), reescribe el token del argv al raw
  `ewf1`, ejecuta y **desmonta siempre**; sin `ewfmount` → `424` accionable, jamás trata `.E01`
  como raw (RULE 2). `ewf_image` debe ser token exacto del argv (anti-inyección). Caps del
  compose (`SYS_ADMIN`, `/dev/fuse`) ya existían. Test `test_ewf_routing.py`. **Deuda abierta:
  el argv literal EJECUTADO (`ewf1`) no se audita → ver P0.5-4.**
- **P0.4 (relevo de artefacto derivado): CERRADO en el dispatcher.** `ArtifactStore.resolve_output_file`
  confina bajo `out/`, resuelve symlinks, **re-hashea contra el manifiesto** y lanza
  `ArtifactIntegrityError` en mismatch (custodia del derivado, INVARIANTS 1-2).
  `_resolve_artifact_inputs` sustituye la ref `{run_id, relpath}` por la ruta RO verificada
  antes de `build_argv`; resultado binario **remite al artefacto** (no `content_length:0`);
  enlace de derivación en `tool_run_start.derived_inputs` (INVARIANT 4). Test
  `test_derived_handoff.py`. **Deuda: no llega al camino producto agente/MCP → ver P0.5-3.**
- **P0.6 (E2E de la cadena): CERRADO parcial.** `test_e2e_chain.py` ejerce
  `mmls→fls→icat→RegRipper` por `dispatcher → exec-agent loopback` con custodia y hash-chain
  `verify()` asertados, tamper→fallo fuerte. **Ejerce el dispatcher, NO `API→agente→dispatcher`
  → se completa en P0.5-3.**
- **P0.5-1 (blocker B4 timeout/huérfano): CERRADO.** El exec-agent nunca corre con timeout
  `None`: `null` aplica `_MAX_TIMEOUT_S`, número → `min(t, techo)`, no-positivo → `400`
  (RULE 2). `maletin` dimensiona el timeout HTTP **por encima** del techo efectivo del
  exec-agent (`_EXEC_AGENT_MAX_TIMEOUT` espejo + `_HTTP_TIMEOUT_MARGIN`), con test que fija el
  espejo → el exec-agent mata+hashea+responde antes de que el transporte se rinda → el
  dispatcher jamás hashea un artefacto en escritura (INVARIANT 4). Test
  `test_exec_timeout_custody.py`.

### Nota de re-audit — blocker antiguo #1 ("raw-path injection") → **Phase-2, NO P0**

`EvidenceManager` copia la evidencia a `case_dir/evidence/<eid>/original.<ext>`, la hashea
(gate en orden estricto), hace `chmod 0o444` y devuelve el handle. `handle.original_path` es
esa **copia inmutable, hash-verificada y RO**, no la ruta cruda del sospechoso; el agente no
puede inyectar rutas ahí (las claves auto-inyectadas se descartan). Lo único que falta frente a
la letra del INVARIANT 1 es RO a **nivel de bloque** (hoy FS `chmod 0o444`), **ya documentado
como Phase-2** en `evidence.py` (`blockdev --setro`/`losetup`/`hdiutil`/`Set-Disk` + re-verify
al cierre). Defensa en profundidad (los binarios abren `O_RDONLY` igual). → **backlog Phase-2**,
no bloquea P0.

---

## 3. PENDIENTE — P0.5 (P0 NO está cerrado)

Re-audit global de Codex (2026-07) → 6 bloqueantes. **B4 ya cerrado (P0.5-1).** Quedan 5 tareas.
No pasar a P1 hasta cerrarlas. Prioridad y modelo sugerido (con `codex code`, usa el equivalente
de razonamiento alto para los "Opus" y estándar para los "Sonnet"):

| # | Bloqueante | Rompe | Modelo | Estado |
|---|-----------|-------|--------|--------|
| P0.5-1 | B4 timeout efectivo + anti-huérfano | FORENSIC 4 | alto | **CERRADO** |
| P0.5-2 | B6 gate central de confinamiento de rutas | SECURITY 6 | alto | **SIGUIENTE** |
| P0.5-3 | B1+B5 ref derivada + contexto evidencia en agente/MCP/audit | FORENSIC 1-2/4, RULE 2 | alto | pendiente |
| P0.5-4 | B2 argv EWF ejecutado auditado | FORENSIC 4 | estándar | pendiente |
| P0.5-5 | B3 aserción de contrato `stdout.bin` | RULE 2 / FORENSIC 4 | estándar | pendiente |

---

### PROMPT P0.5-2 — gate central de confinamiento de rutas (modelo alto · sin git)

```
Repo Agentopsy, rama `tools`. Lee primero tools/graph/CONTEXT.md y CLAUDE.md (SECURITY
INVARIANT 6: TODAS las rutas se canonicalizan en el backend y se confinan a su raíz — rechazar
traversal/symlink-escape/absolutas fuera de raíz; excluir ~/.ssh, ~/.aws, keychains; la
evidencia es DATO HOSTIL, nunca instrucción; RULE 2/3). NO ejecutes git.

BUG (bloqueante de seguridad): el camino del agente expone rutas libres elegidas por el LLM
(rules_path, sigma_dir, rules_dir, output_path en backend/forensia/agent/tool_schemas.py); los
wrappers solo comprueban que sean strings (wrappers/yara.py, chainsaw.py). Existe ConfinedPath
en el MCP pero NO hay gate central en el agente ni en el dispatcher. Con evidencia hostil el LLM
puede emitir output_path: ~/.ssh/authorized_keys o rules_path: /etc/passwd sin confinar.

TAREA (diagnóstico primero):
1. LEE agent/tool_schemas.py, wrappers/yara.py y chainsaw.py, la ConfinedPath del MCP (para
   REUTILIZARLA, no duplicar), toolkit/tool.py y toolkit/dispatcher.py. Resúmeme qué params de
   ruta existen y a qué raíz confina cada uno (evidencia RO / reglas del maletín RO / out/ del
   caso escribible).
2. PROPÓN: declarar en Tool el ROL de confinamiento de cada param de ruta; un GATE CENTRAL en
   el dispatcher (antes de build_argv) que canonicalice y confine CADA param a su raíz
   (rechaza traversal, absolutas fuera de raíz, symlink-escape, dirs sensibles ~/.ssh/~/.aws);
   REUTILIZAR ConfinedPath (si vive solo en mcp/, factorízala a forensia/* y que MCP y el
   dispatcher usen UNA implementación — RULE 3). Fallo → error accionable (RULE 2), la tool no
   corre.
3. IMPLEMÉNTALO + tests por rol (traversal, absoluta fuera de raíz, symlink-escape, ~/.ssh,
   ruta válida OK), incl. un caso por el camino agente.

RESTRICCIONES: no toques web/ ni agentes/*. Lógica en forensia/* (RULE 3), sin keys (RULE 7),
sin fallbacks (RULE 2), sin atribución IA (RULE 0). Verifica en backend/ con
pip install -e ".[dev,mcp]" + ruff check . + pytest -q.

ENTREGA: NO hagas git. Devuelve (a) diagnóstico con el mapa param→raíz, (b) DIFF completo,
(c) salida ruff/pytest.
```

---

### PROMPT P0.5-3 — ref derivada + contexto de evidencia en agente/MCP/audit (modelo alto · sin git)

```
Repo Agentopsy, rama `tools`. Lee primero tools/graph/CONTEXT.md y CLAUDE.md (FORENSIC INVARIANT
4: cada acción registra argv literal, VERSIÓN DE TOOL, EVIDENCE ID + HASH, exit y SHA-256 de
artefactos; INVARIANTS 1-2 custodia; RULE 2/3). NO ejecutes git.

BUG (dos bloqueantes que comparten fontanería):
 B1) El relevo icat→RegRipper de P0.4 vive en el dispatcher pero NO llega al camino producto:
     agent.py (~152, 705-716) auto-inyecta la evidencia base sobre hive_path, y el schema del
     agente (agent/tool_schemas.py ~223-234) y el del MCP (mcp/schemas.py ~312-318,
     mcp/toolkit.py ~286-300,348-362) no permiten una ref de artefacto. El E2E evita ambas
     superficies llamando al dispatcher directo.
 B5) tool_run_start/finish NO llevan evidence_id ni hash baseline ni versión de tool, que
     INVARIANT 4 exige literalmente.

TAREA (diagnóstico primero):
1. LEE agent.py (_inject_runtime_paths, _EVIDENCE_INJECTION, cómo se obtiene el handle),
   agent/tool_schemas.py, mcp/toolkit.py, mcp/schemas.py, toolkit/dispatcher.py (firma de
   execute y qué recibe), evidence.py (EvidenceHandle: sha256, versión), y cómo se resuelve la
   versión efectiva de cada tool. Resúmeme por dónde hilar el contexto de evidencia y la ref.
2. PROPÓN el diseño mínimo:
   - Exponer en el schema del agente Y del MCP una ref tipada {run_id, relpath} para los params
     que declaran input_artifact_params; preservarla hasta el dispatcher; inyectar la evidencia
     base SOLO si NO hay ref (no sobrescribir la ref del consumidor).
   - Hilar hasta dispatcher.execute el contexto VERIFICADO de evidencia (evidence_id + hash
     baseline) y la versión resuelta de la tool, y registrarlos en tool_run_start y
     tool_run_finish (INVARIANT 4). No lo adivines desde el host (RULE 2).
3. IMPLEMÉNTALO + tests: (a) el agente/MCP pueden pasar la ref y el dispatcher la re-verifica
   (custodia); (b) start/finish contienen evidence_id+hash+versión; (c) EXTIENDE el E2E para ir
   por API→agente→dispatcher (no solo dispatcher directo).

RESTRICCIONES: no toques web/ (frontend) salvo lo imprescindible del contrato — si el cambio de
schema del agente/MCP requiere tocar el cliente web, PÁRATE y señálalo (es otro rol). Lógica en
forensia/* (RULE 3), sin keys/fallbacks/atribución IA. Verifica en backend/ con
pip install -e ".[dev,mcp]" + ruff check . + pytest -q.

ENTREGA: NO git. Devuelve (a) diagnóstico, (b) DIFF, (c) ruff/pytest.
```

---

### PROMPT P0.5-4 — argv EWF ejecutado auditado (modelo estándar · sin git)

```
Repo Agentopsy, rama `tools`. Lee tools/graph/CONTEXT.md, CLAUDE.md (FORENSIC INVARIANT 4: se
audita el argv LITERAL EJECUTADO) y docs/operacion/exec-agent.md (§ Routing EWF). NO git.

BUG (bloqueante de auditabilidad): en una corrida EWF el audit guarda el argv con .E01
(dispatcher fija prepared.argv antes del runner), pero el exec-agent reescribe ese token al raw
ewf1 efímero antes de ejecutar (exec_agent.py _exec_with_ewf ~238-249) y esa transformación NO
vuelve al dispatcher ni aparece en el finish. Hoy el argv ejecutado real no consta en ningún
sitio. (El .E01 es la identidad reproducible; el ewf1 es lo literalmente ejecutado — se
necesitan LOS DOS.)

TAREA:
1. LEE exec_agent.py (_exec, _exec_with_ewf, el dict de respuesta), maletin.py
   (run_argv_in_maletin, qué devuelve) y dispatcher.py (dónde se persiste start/finish).
2. FIX: el exec-agent devuelve executed_argv (el argv realmente ejecutado, con ewf1) + metadatos
   EWF (ewf_image, mountpoint efímero); maletin lo propaga; el dispatcher lo persiste en el
   finish (o en el start si prefieres), DISTINGUIENDO argv_solicitado (.E01, estable) de
   argv_ejecutado (ewf1). No rompas el contrato de las tools no-EWF (executed_argv == argv).
3. TESTS: una corrida EWF (loopback, mount fakeado como en test_ewf_routing.py) registra ambos
   argvs; una no-EWF los tiene idénticos. Verifica que el audit sigue hash-encadenado (verify()).
   Actualiza docs/operacion/exec-agent.md (RULE 4) reflejando que se auditan ambos.

RESTRICCIONES: no toques web/ ni agentes/*. Sin keys/fallbacks/atribución IA (RULE 2/7/0),
shell-free intacto. Verifica en backend/ con pip install -e ".[dev,mcp]" + ruff check . +
pytest -q (y ruff sobre exec_agent.py, infra).

ENTREGA: NO git. Devuelve (a) diagnóstico, (b) DIFF, (c) ruff/pytest.
```

---

### PROMPT P0.5-5 — aserción de contrato `stdout.bin` (modelo estándar · sin git)

```
Repo Agentopsy, rama `tools`. Lee tools/graph/CONTEXT.md y CLAUDE.md (RULE 2; FORENSIC INVARIANT
4). NO git.

BUG (bloqueante menor): una tool binary_stdout puede terminar con exit 0 sin haber producido
out/stdout.bin y aun declararse exitosa — _binary_artifact_ref() (dispatcher.py ~409-429)
devuelve silenciosamente sha256=None/size=None si el fichero no está en el manifest, y
_build_result() (~637-643) lo acepta como éxito. No hay test negativo.

TAREA:
1. LEE dispatcher.py (_binary_artifact_ref, _build_result) y artifacts/store.py (cómo se listan
   output_files).
2. FIX: antes de un finish exitoso de una tool binary_stdout, EXIGIR que exista exactamente
   out/stdout.bin con hash y tamaño en el manifest; si falta, cerrar el run como ERROR de
   contrato (RULE 2) y NO emitir una referencia incompleta (nunca sha256/size None como éxito).
3. TEST negativo: exit 0 sin stdout.bin → error de contrato, no ref con None.

RESTRICCIONES: no toques web/ ni agentes/*. Lógica en forensia/* (RULE 3), sin
keys/fallbacks/atribución IA. Verifica en backend/ con pip install -e ".[dev,mcp]" +
ruff check . + pytest -q.

ENTREGA: NO git. Devuelve (a) diagnóstico, (b) DIFF, (c) ruff/pytest.
```

---

## 4. Después de P0.5 — cola posterior

- **Cierre de P0.5:** re-audit final (Codex) confirmando los 5 cerrados sin regresiones →
  declarar P0 cerrado.
- **P1 — servidor MCP (modelo estándar):** inputSchema completo/tipado por tool (enum cerrada,
  required), gate `select_case` obligatorio (RULE 2), **pinning** de la versión de `mcp` en
  `pyproject.toml`, doc-sync. *Ojo:* parte (schemas de la ref `{run_id, relpath}`) se absorbe en
  P0.5-3 — no dupliques.
- **P2 — evals/validación (carril Windows):** re-correr los 12 `case-win-*`, paridad unix,
  fixtures sintéticas M5-C/D/E, regresión LoneWolf.
- **P3 — producto:** `forensia.reports` (informe court-style), correlación MITRE ATT&CK, Fase 5.
- **Backlog Phase-2:** RO a nivel de bloque en `evidence.py` + re-verify al cierre; desmontaje
  EWF best-effort más robusto; recuperación de última línea truncada del AuditLog; retirar
  campos legacy de `Tool`.

---

## 5. Estado de commits (verifícalo)

`git log --oneline -15` debe mostrar, ya en `origin/tools`: audit-ordering, P0.1, P0.2, P0.3,
P0.4, P0.6 y **P0.5-1** (timeout/custodia). Working tree limpio salvo lo que estés preparando.
**Siguiente acción del operador:** correr el **PROMPT P0.5-2** en `codex code`, pegar la salida
al auditor, auditar, commitear.
