# Prompt para Claude Code — implementación de las Fases 0-2

> Segunda ronda. Depende de [`diagnostico.md`](diagnostico.md) y [`plan.md`](plan.md).
> Aprueba las Fases 0-2, deja 3 y 4 fuera con encargo de medición, y abre una fase
> nueva de diagnóstico sobre el número de turnos.
>
> **Nota histórica.** Este documento registra el encargo tal y como se dio el
> 2026-07-29. Las decisiones «NO implementes» de las Fases 3 y 4 fueron
> revisadas después: ambas están implementadas en la rama `Rama-Enrique`
> (2026-07-30) — el estado vigente lo lleva [`plan.md`](plan.md).

---

He revisado `diagnostico.md` y `plan.md`. Diagnóstico aprobado: la medición está bien
hecha, y reconciliar la conversión chars→tokens contra el coste facturado (0,13 % de
desviación) es lo que la sostiene. Refutar H3 y H4 en vez de darme la razón también
cuenta. Van mis decisiones sobre tus tres preguntas, más el encargo.

## Decisiones

1. **Fases 0-2: aprobadas como bloque.** Implementa.
2. **Fase 3 (retirar windowing): NO la implementes.** Decisión aparte cuando tenga
   datos de la Fase 1. Sí quiero de ti la medición que permita decidirla.
3. **Fase 4 (`--system-prompt`): NO la implementes.** Mídela aislada, y la medición
   tiene que incluir calidad de análisis, no solo coste.
4. **Fase nueva (número de turnos): diagnostícala.** Sin implementar nada.

---

## Lo que implementas ahora

### Fase 0 — instrumentación, con dos exigencias añadidas

Lo que propones en el plan, más:

- **Guardia de regresión permanente.** Esto no es telemetría de usar y tirar. Todo el
  ahorro depende de dónde coloca Claude Code sus breakpoints de caché, que es un
  detalle interno del CLI: una subida de versión puede revertirlo en silencio. Quiero
  que, con sesión activa, si `cache_read` no crece durante ≥3 turnos consecutivos,
  quede un aviso accionable en el log y en el audit. Que el sistema note su propia
  regresión en vez de que la descubramos en la factura.
- **`estimate.py` es un bug de corrección, no un efecto secundario de esta fase.** La
  estimación que se le enseña al perito antes de lanzar un análisis está mal por un
  factor ~15× porque se ancla en `input_tokens`, que es solo el resto no cacheado.
  Arréglalo con su propio test de regresión, recalibra `HEUR_TOKENS_PER_ITER` (5.000
  frente a los ~34.500 medidos) y deja constancia fechada de la calibración. Si la UI
  muestra ese número, comprueba que lo que se enseña sea coherente.

### Fase 1 — sesión y delta, con el guardia que le falta al plan

Tu diseño cubre bien «resume falla → contexto completo + `resume_failed` auditado».
Falta el caso contrario, que es el peligroso: **resume que funciona sobre una sesión
que ha divergido.**

Tus propios datos lo insinúan: en las variantes B y D el modelo hizo entre 1 y 6
iteraciones internas por llamada (`num_turns`). Esas iteraciones acumulan turnos en la
sesión del CLI que Agentopsy no ha escrito. Un delta contra una sesión cuyo historial
≠ la lista canónica de Agentopsy es exactamente el fallo que la restricción prohíbe:
el modelo concluye sobre evidencia que cree haber visto y no vio.

Antes de escribir código, resuelve empíricamente:

- ¿`claude -p --resume <id>` devuelve el mismo `session_id` o uno nuevo?
- ¿Reenvía su propio system prompt en cada resume, o solo la primera vez?
- ¿Qué le pasa a la sesión cuando `num_turns > 1`? ¿Quedan esos turnos internos en el
  historial de la sesión?
- ¿Hay compactación interna en sesiones largas? ¿Es observable desde fuera?

Con esas respuestas, diseña un guardia con esta propiedad: **es imposible que un delta
llegue a una sesión de la que Agentopsy no pueda dar cuenta.** No me valen buenas
intenciones — quiero un mecanismo de detección y que la política quede en el audit. Si
la detección no es posible con lo que expone el CLI, dímelo y reconsideramos el diseño;
no lo tapes con un «asumimos que va bien».

`session_id`, `resume: true|false`, `num_turns` y el motivo de cualquier reapertura van
al audit. Este cambio debe **añadir** trazabilidad, nunca restarla (INVARIANT 4).

### Fase 2 — reordenar el prompt

Como está en el plan. Un matiz: mediste +4 % en aislamiento y lo leíste como «no ahorra
pero es precondición». De acuerdo. Verifica además que el contrato de respuesta siga
siendo lo último que lee el modelo — es lo que sostiene el parseo estricto de
`_parse_action`, y si se degrada aumentan los reintentos, que cuestan un turno entero
de suelo cada uno.

---

## Lo que NO implementas, y qué entregas en su lugar

### Fase 3 — windowing

No la toques. En la validación de la Fase 1, mide qué aporta realmente retirarlo con
sesión activa. Y añade al informe qué pasa con el techo de `_bounded_json` (8.000 × 4
resultados) cuando el historial deja de acotarse: tú mismo lo llamaste «bomba armada»
sobre un `bulk_extractor` o un `tsk_fls` de disco real, y sin windowing esa bomba queda
activa.

### Fase 4 — `--system-prompt`

Mídela aislada, con `num_turns` normalizado para que la lectura no salga contaminada
como en la variante D. La medición tiene que responder a una pregunta que no es de
coste: **¿analiza igual de bien?** Sustituir el system prompt de Claude Code cambia cómo
razona el modelo. Compara sobre el mismo caso y el mismo prompt: hallazgos registrados,
procedencia correcta, técnicas propuestas. Si el resultado es ambiguo, la recomendación
es descartar — un 15 % no compensa degradar el producto.

### Fase nueva — el número de turnos

22 turnos × 34.491 tokens de suelo = **758.802 tokens solo por existir**, más de dos
tercios de la entrada de la corrida. Es una palanca comparable a la reutilización de
sesión, recorta entrada **y** salida, y se acumula con las Fases 0-2. Nadie la ha
mirado todavía.

Diagnostica sobre la corrida `fe00dad1`:

- ¿Se está usando `tool_batch`? Si el contrato de respuesta lo promueve y el modelo no
  lo usa, ¿por qué?
- ¿Cuántos turnos fueron reintentos, correcciones de formato o el structural nudge?
- ¿Cuántos turnos no produjeron ni una llamada a herramienta ni un hallazgo?
- **El turno 1 hizo timeout a 120 s** y tu análisis no lo comenta. Pagó 34.988 tokens de
  prefijo y no devolvió nada. ¿Qué ocurrió, y qué hace el bucle ante un timeout —
  reintenta reenviando todo?

Entrégalo como sección nueva del diagnóstico o fichero aparte, con propuesta y sin
implementar.

---

## Validación — cierra la extrapolación

Tus números de caché son de réplica con `haiku`; el −72 % a 22 turnos con `opus` es
extrapolación, y tú mismo lo marcaste como límites 1 y 2 del diagnóstico.

Ya tienes una línea base medida con `opus`: la corrida `fe00dad1`, 22 turnos, 12,97 USD.
**No hace falta volver a pagarla.** Reejecuta el mismo caso con el mismo prompt y las
Fases 0-2 dentro, y compara contra ella.

Criterios de aceptación:

1. `cache_read` **crece** turno a turno, en vez de quedarse clavado en 9.051.
2. `cache_creation` queda acotado al tamaño del delta.
3. Coste total de la corrida por debajo de 4,5 USD (el plan extrapola ~3,6).
4. Los hallazgos registrados y su procedencia son equivalentes a los de la corrida base.

**El criterio 4 manda sobre los otros tres.** Si el ahorro llega acompañado de un
análisis peor, no hemos ahorrado: hemos roto el producto.

---

## Las líneas rojas

Las mismas de la primera ronda. Las reafirmo porque la Fase 1 pasa cerca de dos:

- **RULE 2 — sin fallbacks ni truncados silenciosos.** El único fallback admitido es el
  de contenido: mandar de más (contexto completo), nunca de menos, y anotado en el audit.
- **INVARIANT 4 — la auditoría no se toca**, y esta fase debe añadir campos, no quitarlos.
- **La procedencia sobrevive.** Un `Finding` sigue citando su `run_id` y el SHA-256 de su
  artefacto. Descartaste comprimir con resúmenes generados por el modelo por esta razón;
  mantenlo descartado.
- **RULE 3** — la lógica en `forensia/*`; routers y frontend siguen siendo adaptadores finos.
- **RULE 7** — sin claves de API. `--resume` usa la misma sesión OAuth del volumen
  `forensia-cli-auth`.
- **Sin ejecutor por defecto.** La selección sigue siendo explícita del operador.
- **Los cuatro ejecutores.** Lo común (Fases 0 y 2) los beneficia por construcción. Para
  Codex, Gemini y Ollama: si no soportan continuidad de sesión, es una capacidad no
  disponible reportada con motivo accionable en `capabilities`, nunca un silencioso «con
  este ejecutor sale más caro».

---

## Método

- Implementa 0-2, valida, y **para**. No sigas con la 3, la 4 ni la fase de turnos sin
  mi aprobación.
- RULE 5 al empezar (`git pull`). RULE 4 antes de commitear: `CLAUDE.md` §Status,
  `tools/graph/CONTEXT.md`, y `docs/agentes/contrato-paquetes.md` si cambia el contrato
  del ejecutor.
- RULE 6 antes de cualquier push: desde `backend/`, `pip install -e ".[dev,mcp]"`,
  `ruff check .`, `pytest -q`; desde `web/`, `npm ci && npm run typecheck && npm run build`
  si tocas el frontend.
- Tests nuevos, como mínimo: parseo de los campos de caché por ejecutor (y `None` cuando
  el ejecutor no los reporte), el guardia de divergencia de sesión, la recalibración de
  `estimate.py`, y que el audit conserve el argv literal y gane `session_id` / `resume`.
- Al terminar, tres líneas: qué implementaste, qué midió la validación A/B, y qué
  decisión me pides.
