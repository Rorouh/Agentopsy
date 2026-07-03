# Notas de reflexión — mejora iterativa de FORENSIA-WIN (2026-07-03)

Auditoría de las corridas reales del sub-agente windows sobre LoneWolf-memoria
(`evals/harness/results/investigations/`, gitignored pero en disco) más el
historial de iteraciones y los evals automatizados, seguida de la implementación
de las mejoras para los fallos **recurrentes**. Método: extracción de señales por
corrida → clusterización across runs/apartados → una mejora por cluster
recurrente. Lo que no recurre, no se tocó.

Fuentes auditadas: 5 corridas codex (2 con inferencia real: `20260702-125643`,
`20260702-153138` de 3 047 líneas; 3 stubs de fallo de arranque), 3 corridas
gemini (las tres muertas en el lanzador), la investigación de referencia
`evidence-corpus/lonewolf-2018/investigacion-codex-memoria-v2.md`, los 5 JSON de
evals ollama (`results/summary.md`) y `plan-ruta-forensia-win.md`.

## Cambios, rankeados por (recurrencia × impacto forense)

### 1. Recuperación de ficheros en memoria — paso B.7 nuevo del playbook + eval

**Evidencia.** El hallazgo central del caso (el documento del sospechoso) no se
intentó recuperar en NINGUNA corrida de memoria: codex `153138` vio la cadena
`s3browser-win3` (PID 4260, terminado 02:32:08) → `WINWORD.EXE` (PID 12400,
arrancado 02:32:31, mismo padre explorer) y no emitió ni un `filescan` ni un
`dumpfiles`; la investigación de referencia v2 tampoco. Causa raíz: la sección B
del playbook no mencionaba esos plugins — el agente no usa lo que su playbook no
enseña.

**Cambio.** `prompts/playbook.md`: paso **B.7 «Ficheros y documentos en
memoria»** (`windows.filescan.FileScan` → artefacto + filtro `jq`;
`windows.dumpfiles.DumpFiles` acotado por `pid`/`virtaddr`, nunca el volcado
completo; laguna + remisión al disco par si el contenido no está). Credenciales
renumeradas a B.8. Eval nuevo `case-win-011` (ver #3). Sin cambio de allowlist:
los plugins son `params` del tool_id `volatility3`.

### 2. MITRE omitido o inventado — semilla +T1567/.002 y formato final con mitre_hints obligatorios

**Evidencia.** Dos caras del mismo fallo, 5 corridas: codex `153138` entregó el
informe final con **cero** técnicas MITRE (la exfil-a-nube evidente quedó sin
mapear); los modelos ollama inventaron ids fuera de la enum en 3/4 corridas
parseadas (`T1489`, `T1055.017`, `T1203` en `summary.md`). Además la técnica que
el caso pide (`T1567`, usada como hint por la investigación v2) **no existía en
la semilla**: ni queriendo se podía citar desde la enum cerrada.

**Cambio.** `knowledge/mitre_attack_seed.md`: filas **T1567** (Exfiltration Over
Web Service) y **T1567.002** (to Cloud Storage) en TA0010, con nota de ampliación
fechada (mismo formato que la ampliación anterior, sin duplicar ids — verificado).
`prompts/system.md` (formato de respuesta final): cada hallazgo lleva sus
`mitre_hints` de la semilla **o** la declaración explícita «sin técnica de la
semilla aplicable»; un informe sin mención MITRE alguna está incompleto.

### 3. Correlación exfil-cloud infra-calificada — cadena nombrada 5 + guía KB + case-win-011

**Evidencia.** 2/2 corridas de memoria con inferencia vieron los tres eslabones
(cliente cloud activo + ESTABLISHED :443 a rangos Dropbox/AWS + documento en
juego) y ninguna los correlacionó: codex lo dejó en severity low «sin
atribución»; v2 en «vector potencial no concluyente». Las 4 cadenas de
correlación nombradas del playbook eran todas de disco.

**Cambio.** `playbook.md`: cadena **5 «Exfiltración a nube (memoria)»**
(pslist/psscan + netscan + filescan/dumpfiles ⇒ T1567/T1567.002, con cautelas:
tres eslabones para subir de low; sockets sin Owner no atribuyen).
`knowledge/artefactos-windows.md`: guía nueva «Procesos de cliente cloud en
memoria» (formato fijo de la KB, con falsos positivos). Eval `case-win-011`
(RAM, espera los dos findings y T1567/T1567.002).

### 4. `pslist` vacío mal interpretado — patrón vacío-total vs ausencia-parcial + guía KB + case-win-012

**Evidencia.** 2/2 corridas de memoria: `pslist`/`pstree` = 0 filas y `psscan` =
216 procesos. La regla existente del playbook («presente en PsScan y ausente en
PsList = indicio de ocultación») aplicada a una lista TOTALMENTE vacía implica
«216 procesos ocultos» — un falso positivo de ocultación masiva. codex ancló el
informe en «enumeración rota» sin diagnosticar la causa (ignoró la anomalía
`PE TimeDateStamp 2042` que `windows.info` ya le había dado).

**Cambio.** `playbook.md` §B.2: dos patrones separados — **ausencia parcial** ⇒
indicio T1055 solo con corroboración de Malfind; **vacío total** ⇒ laguna de
entorno (símbolos/ISF), diagnóstico con `windows.info.Info`, seguir sobre
psscan/psxview y **no citar T1055**. Guía KB nueva «Enumeración de procesos en
RAM — PsList vs PsScan/PsXView». Eval `case-win-012` con `expected_mitre: []` a
propósito: emitir cualquier técnica ahí es el fallo que el caso caza.

### 5. Ángulos abandonados en silencio — laguna obligatoria en B.4/B.5 + checklist de cierre

**Evidencia.** codex `153138`: `hivelist` se generó, el filtrado de su salida
rompió (error de parseo del helper) y el ángulo de registro residente
**desapareció del informe** sin constancia; nunca corrió `printkey`. Los sockets
sin Owner se dieron por «no atribuibles» sin intentar la vía alternativa.

**Cambio.** `playbook.md` §B.5: el ángulo de registro «siempre termina en el
informe» — si la lectura falla, laguna con causa. §B.4: ante sockets sin Owner,
intentar `windows.netstat.NetStat` antes de declarar no-atribución.
`system.md` (formato final): **Lagunas es un checklist de cierre** — cada ángulo
de la sección aplicable del playbook recibe estado (hallazgo / no concluyente /
laguna con causa entorno-vs-evidencia); nada se cae en silencio.

### 6. Disciplina de coste en memoria — bullets nuevos de coste

**Evidencia.** codex `153138`: la enum de ~200 plugins volcada al contexto **6
veces** (una por cada `invalid choice`); tablas completas de `netscan` (~300
sockets, mayoría CLOSED) y `psscan` (~160 filas) traídas al razonamiento;
`dlllist`/`handles` re-ejecutados ×4 por offset (76–81 s cada uno) sobre
resultados vacíos; `malfind` repetido al final.

**Cambio.** `playbook.md` («Disciplina de coste»): filtrar `psscan`/`netscan`/
`filescan` antes de razonar (estado/extensión/ruta); **un plugin caro con 0 filas
no se relanza con variantes** sin hipótesis nueva escrita (dos vacíos = laguna);
ante `invalid choice`, máximo dos intentos y el id sale literal del
`choose from …` (cada fallo re-vuelca la enum entera).

### 7. Renombres de plugins por build — nota de deprecación en el Anexo

**Evidencia.** 6 avisos «This plugin has been renamed, please call
windows.malware.<X>» en codex `153138` (malfind ×2, hollowprocesses, psxview,
skeleton_key_check, suspicious_threads). Misma raíz que la invención de
namespaces ya parcheada en `bf84cee`/`3ad6d99`: el id lo fija el build, no el
modelo.

**Cambio.** `playbook.md` (Anexo `volatility3`): los ids listados son
orientativos, el build manda; ante el aviso de renombre se adopta el nombre nuevo
en las llamadas siguientes; ante `invalid choice`, regla del §B.8. Añadidos al
listado orientativo `netstat`, `filescan` y `dumpfiles` (usados por B.4/B.7).

### 8. Lanzador de motores no veraz — motors.yaml (gemini)

**Evidencia.** 6 de 8 ficheros de investigación son fallos de lanzador sin una
sola inferencia. Los 3 de gemini: ejecutable sin resolver ×2 (ya corregido en
`f129d10`) y «La línea de comandos es demasiado larga» ×1 — el prompt de ~27 KB
como argumento vía el shim npm `gemini.CMD` (`cmd /c`) revienta el límite de
8 191 caracteres de cmd.exe. Y `gemini: ready: true` («cuando la auth funcione»)
contradecía el esquema del propio fichero y el plan de ruta («bloqueado…
aparcado»), quemando corridas.

**Cambio.** `evals/harness/motors.yaml`: gemini pasa a `prompt_via: stdin` (el
harness ya lo soporta sin tocar código) y a **`ready: false` veraz** con nota de
qué verificar antes de reactivarlo (RULE 2). codex se queda como está: sí corrió
de verdad (se resuelve a `.EXE`, bajo el límite de CreateProcess).

## Qué NO se tocó (señales que no recurren o ya están arregladas)

- **Anti-invención Vol2/Vol3 de credenciales**: los 6 `invalid choice` de codex
  son de la corrida `153138` (15:31), ANTERIOR a los fixes `bf84cee` (16:36) y
  `3ad6d99` (17:36). Pendiente del plan de ruta: validar el antes/después con una
  corrida codex nueva — no re-arreglado aquí.
- **`redaction.yaml`**: las observaciones del plan de ruta (orden MAC/IPv6, email
  O(n²)) ya estaban corregidas en el fichero (`ae77464`).
- **Código del harness** (`run_investigation.py`, `run_eval.py`): fuera del
  alcance declarativo. Recomendaciones que quedan para su dueño: los 3 stubs de
  codex (PATH ×1, `WinError 5` AV/EDR ×2) son fragilidad de arranque ya mitigada
  en parte por `f129d10`; y en modo single-shot el `find_recall` puntúa findings
  que el modelo no puede fundamentar (sin salida de tools) — decidir si ese modo
  debe puntuar solo decisión (tools/MITRE).
- **Ground truth** (`docs/agentes/ground-truth/lonewolf-2018.md`): la tabla de
  memoria sigue `<verificar>` pese a que `investigacion-codex-memoria-v2.md` ya
  tiene datos consolidables (psscan=216, clientes cloud, netscan). Es del flujo
  del corpus, no del paquete — pendiente señalado, no editado.
- **Modelos locales pequeños** (qwen2.5:3b inventa, lse_rayo devuelve vacío): la
  decisión ya está tomada en el plan de ruta (subir a `qwen2.5:14b`); operativa,
  no de paquete.

## Verificación (2026-07-03)

- **Enum MITRE cerrada**: 39 ids en la semilla, sin duplicados; todo
  `technique_id` citado en prompts, KB y los 12 casos de eval existe en la
  semilla (script de verificación, salida completa en la sesión de revisión).
- **Allowlist**: 19/19 tool_ids de `policy/tools.yaml` existen en
  `backend/forensia/toolkit/catalog.py` y declaran `windows`; los
  `provenance_tool` de los 12 casos están en la allowlist. La allowlist **no
  cambió** en esta iteración.
- **RULE 0**: cero atribución a IA en las líneas añadidas (grep sobre el diff).
- **Carga del paquete**: `test_agent_registry.py` + `test_redaction_windows.py`
  → 59 passed. Smoke del harness: `case-win-011`/`012` cargan (kind=memory),
  `load_mitre_seed_ids()` incluye T1567/T1567.002, los prompts ensamblan
  (32 653 chars — +5 K sobre la versión anterior; vigilar si algún motor de
  contexto corto entra en la comparativa).

## Validación empírica de esta iteración (corrida codex 2026-07-03)

Corrida autónoma nueva sobre LoneWolf-memoria (`codex_auto`, gpt-5.5, modo
autónomo; transcripción en `results/investigations/`, gitignored) como
«después» frente a la corrida `153138` («antes»). El prompt entró por **stdin**
(`codex exec -`) — se verificó que el STDERR reproduce el prompt completo
(~32.6K) sin truncar, cerrando el riesgo del límite ~32K de CreateProcess.

Resultado por cluster (los 7 aplicables + credenciales, todos anclados a la
salida real):

1. **B.7 filescan** — el agente lanzó `windows.filescan.FileScan` por iniciativa
   del playbook pese a una tarea genérica; 0 filas por degradación de entorno →
   laguna declarada. Pendiente menor: no remitió el ángulo al disco par.
2. **MITRE** — cada hallazgo con id de la semilla (T1567/.002 hipótesis) o la
   declaración «sin técnica de la semilla aplicable». Cero ids inventados.
3. **Cadena 5 exfil-nube** — correlacionó cliente cloud + ESTABLISHED :443 a
   `162.125.18.133` (Dropbox) + procesos Office; subió a `medium`/hipótesis con
   las cautelas (sockets sin Owner no atribuyen). No articuló el relevo temporal
   `s3browser`→`WINWORD` (candidato a refinamiento; con filescan=0 quedarse en
   hipótesis es correcto).
4. **pslist vacío** — interpretado como limitación de símbolos (no ocultación),
   diagnosticado con `windows.info.Info` (usó la anomalía `PE TimeDateStamp
   2042`), sin citar T1055.
5. **Checklist de cierre** — Lagunas recorre los 8 ángulos RAM con estado; nada
   cae en silencio (`hivelist`=0 declarado).
6. **Coste** — filtros antes de razonar; reintentos `--pid` de malfind/cmdline
   hipótesis-guiados y de un solo intento. Ruido residual: parseo JSON con
   PowerShell en vez de `jq` (del modo autónomo, no del paquete).
7. **Renombres** — usó `windows.malware.malfind.Malfind` de inicio; reconoció el
   aviso de deprecación de psxview sin spamearlo.
- **Credenciales** — canónicos `windows.hashdump/lsadump/cachedump.*` → `invalid
  choice`; **no inventó** `.registry.*`, guardó el inventario de plugins y lo
  declaró laguna de build. El `choose from` confirma que ninguno de los tres está
  registrado (colisión de nombres del entorno), validando el hallazgo técnico.

**Constraint de corpus (no del paquete):** en este build/símbolos la imagen de
memoria está degradada (pslist/pstree/cmdline/hivelist/filescan = 0 filas; solo
pool-scanners y netscan responden). El agente se comporta bien, pero el
rendimiento probatorio es bajo. Decisión pendiente del flujo de corpus:
conseguir símbolos/ISF que casen o registrar la degradación como constraint.
