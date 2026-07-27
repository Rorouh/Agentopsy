# Apuntes — BORRADOR desechable

> Cuaderno de trabajo para ir apuntando hallazgos/observaciones **según van
> saliendo** mientras seguimos probando. **No se commitea** (fichero desechable);
> lo bueno se traslada luego a `docs/apuntes-perito-e2e.md`.

## Por revisar / probar
- [ ] **Super-timeline no maneja discos PARTICIONADOS/LVM**: `run_filesystem_timeline`
  corre `tsk_fls -m` en offset 0 → en un disco con MBR (Metasploitable.raw) falla
  "Cannot determine file system type" (fail-loud RULE 2, correcto). Debería `mmls` primero
  → `fls -m -o <offset>` por partición legible (saltando LVM, que TSK no lee).
- [ ] **Contabilidad de tokens ignora los cache tokens**: el ejecutor claude-code solo
  captura `usage.input_tokens` (constante ~2501 = parte NO cacheada); el grueso va en
  `cache_read`/`cache_creation`, no contados. El `total_cost_usd` sí es real. Debería sumar
  los cache tokens para que el "TOK" del panel refleje el throughput real.
- [ ] **libvmdk en el maletín** (RULE 1): FORENSIA declara soportar vmdk pero el TSK del
  toolkit no tiene libvmdk (`mmls -i vmdk` → Unsupported). Añadirlo al Dockerfile, o
  convertir a raw en el ingest.

## ✅ Arreglos aplicados y verificados E2E (2026-07-16)
- [x] **Auto-borrador de informe** al cerrar el análisis (Documentos ya no queda vacío;
  refresca sin apilar, no toca finales). Backend, 988 tests + verificado E2E.
- [x] **Caso activo compartido** entre todas las vistas (contexto + localStorage; selector
  en Timeline/Documentos/Chat; persiste F5). Verificado E2E.
- [x] **Botón "Anclar perfil unix/windows"** cuando el triage no determina el SO. Verificado E2E.

## 🔧 Checklist de arreglos — revisión de prompts del agente (6 agentes, 2026-07-16)

> **✅ TODO APLICADO (FIX-1 código, FIX-2 orquestador, FIX-3 sub-agentes)** — gates verdes
> (ruff + 983 tests + compose config), ambos agentes cargan sin errores, y smoke en vivo OK:
> el agente registró 2 hallazgos nuevos con `run_id`+`confidence` y sin rechazos. Sin commitear.

Revisión cruzada de los prompts (sub-agentes unix/windows, orquestador, ensamblado en
código) desde 6 lentes: rigor forense, seguridad/inyección, RULE 2/anti-alucinación,
eficacia tool-use, consistencia/drift, orquestación/síntesis. Marcado ⇒ nº de lentes que
lo señalan (más lentes = más confianza).

### 🔴 Convergentes (máxima prioridad)
- [ ] **Contradicción desajuste de perfil ⇒4 lentes**: `agent.py:628-638` inyecta "cerrar
  el caso y reabrirlo" pero los prompts + CLAUDE.md dicen "anclar → re-enrutado automático,
  sin reabrir". Unificar el `mismatch_block` con los prompts.
- [ ] **Drift del esquema de hallazgo ⇒4 lentes**: los `system.md` piden `confidence`,
  `observed_at`, `provenance{artifact_sha256}`, pero `record_finding` (`tool_schemas.py:351-397`,
  `additionalProperties:false`) los descarta. Añadirlos al schema + `Finding` (store) + handler
  + pintarlos en `reports/generator.py`. (Mismo bug ya arreglado para `mitre_hints`.)
- [ ] **Windows va por delante de UNIX ⇒3 lentes**: sincronizar allowlist de probes, "camino
  degradado" (contrato JSON para Ollama) y checklist de lagunas entre ambos paquetes.

### 🟠 Por lente
- [ ] **Rigor**: paso 0 de **huso horario** en ambos playbooks (determinar/declarar TZ, UTC
  explícito a `tsk_mactime`); reescribir `ewf_info` A.1 (el agente no tiene el hash baseline →
  no afirmar "cuadra con baseline"); versión de herramienta en la procedencia.
- [ ] **Seguridad**: `reporter/timeline/mitre.md` sin defensa anti-inyección → declarar
  `Finding[]` como datos hostiles (no obedecer órdenes en `summary`/`severity`); en `history.py`
  sacar títulos de hallazgo del rol `system` (etiquetar como no-confiable); delimitar la salida
  de tool en `agent.py:_tool_result_msg` como evidencia no confiable; regla en sub-agentes de
  que la SALIDA de tool también es hostil.
- [ ] **Anti-alucinación**: exigir procedencia (`run_id`/`tool_id`) en `record_finding` salvo
  descarte explícito; reencuadrar `agent.py:743-748` ("prueba la otra tool a ver") como probe
  único de fingerprint (RULE 2, no fallback); persistir `confidence` para no igualar descartes
  forzados con hallazgos sólidos.
- [ ] **Eficacia**: quitar el "camino degradado" de 2 claves de `windows/system.md:398-419`
  (el parser exige `{"action":"tool_call",...}`); dar schema a `tsk_icat` + param de entrada
  `artifact_ref` a EZ Tools (`mftecmd`/`evtxecmd`/`lecmd`/…); ejemplo few-shot del sobre de
  acción para Ollama.
- [ ] **Consistencia/RULE4**: allowlistar/quitar `xxd_head` (`tool_schemas.py:320-322`);
  `darwin.*`→`mac.*` (`unix/system.md:59`); cualificar `windows.hollowprocesses.HollowProcesses`;
  refs muertas a `desktop/.../domain.ts` en `timeline.md:8`/`mitre.md:9`.
- [ ] **Orquestación**: marcar `reporter/timeline/mitre.md` como "esquema objetivo, síntesis
  determinista actual" (o construir la síntesis LLM); tabla MITRE del informe con los
  `finding_id` que sostienen cada técnica, no solo el recuento; sincronizar el enum de estado de
  `mitre.md` con el doble eje real de `coverage.py`.

## ✔ Captura bien
- **[A ✅]** Timeline de investigación real: reconstruye cronología del caso desde el
  audit log (cada `tool_run` con argv+exit) + hallazgos, ordenado por UTC. Verificado
  E2E (caso Live activity: mmls exit1 → fls exit0 → hallazgo).
- **[A ✅]** Super-timeline de ficheros (MACB) bajo demanda: `tsk_fls -m` sobre la
  imagen real → 43.604 eventos (truncado a 5000 en UI). Job async, no bloquea.

## ✘ No captura / limitaciones
- **[A]** Handoff `fls → mactime` no cableado por el dispatcher (bodyfile va a stdout,
  no a `out/`); se hace la expansión MACB en proceso. Gap de los wrappers del catálogo.

## ★ Útil para el perito
- **[A+F ✅]** Zona horaria **UTC explícita** en cada marca y cabecera (F). Un perito
  necesita timestamps inequívocos; ya no hay ambigüedad de huso.

## ⚠ Carencias
- **[C ✅ cerrada]** Solo-lectura a nivel de bloque sigue pendiente (Fase 2); ahora la
  UI/acta lo declaran HONESTAMENTE (chmod 0444), no fingen block-level (RULE 2).
- (pendientes B, D, E; se van cerrando)

## Exportaciones (nuevo, D ✅)
- MITRE: "Exportar CSV" (una fila por técnica evaluada: propuesta agente + veredicto perito)
  y "Exportar Navigator layer" (JSON formato 4.5 cargable en el ATT&CK Navigator oficial).
- Timeline: "Exportar CSV" del timeline de investigación (ts_utc, kind, tool_id, argv, exit,
  title, severity, mitre_hints). Verificado E2E: los 3 botones descargan; caso sin propuestas
  MITRE → CSV con solo cabecera (honesto, RULE 2).

## Estimación previa (nuevo, E ✅)
- Antes de lanzar el análisis, el chat muestra un aviso "Estimación previa" con rangos de
  iteraciones/tokens/tiempo/coste + base (histórico del caso vs heurística) + disclaimer.
  Ancla en el histórico real del caso cuando existe; Ollama = "local, sin coste"; cloud sin
  tarifa citable = "no disponible" (RULE 2, no inventa precios). Verificado E2E.

## Informe pericial (nuevo, B ✅)
- Botón "Generar informe pericial" en Documentos → sintetiza 7 secciones (resumen
  ejecutivo, datos del perito, cadena de custodia con SHA-256, metodología+herramientas,
  hallazgos por severidad, correlación MITRE con veredicto, conclusiones) desde los datos
  reales del caso, lo crea como borrador con integridad SHA-256 y renderiza PDF pericial.
  Verificado E2E (PDF %PDF 7.7 KB). Honesto: si no hay hallazgos/MITRE, lo dice (RULE 2).

## Custodia (nuevo, C ✅)
- La vista "Casos y evidencias" muestra por evidencia: tamaño (1.1 GB), SHA-256 baseline,
  nivel solo-lectura, y **acta de adquisición** (modal + descarga JSON) con la cadena
  hash-encadenada verificada (entry_hash del audit). Verificado E2E sobre dvwa-disk.raw.

## Bugs / cosas raras
-

## Ideas de mejora
-

---
*(ir rellenando)*
