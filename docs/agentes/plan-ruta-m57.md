# FORENSIA-WIN — Hoja de ruta: escenario M57-Patents (2009)

**Rol:** entrenamiento del sub-agente `windows` · rama `tools`
**Objetivo:** incorporar un segundo escenario Windows con **memoria funcional en
Vol3** y **exfiltración/keylogger** documentados, para cubrir los huecos que
LoneWolf deja (insider puro, y RAM Win10 degradada en este build).

> Auditor: Miguel ejecuta (codex/ollama/Volatility/TSK); el auditor da el
> contenido exacto y revisa cada salida contra el ground-truth **antes** de
> commitear. Fuente de verdad: el repo + la solución oficial, no la memoria.

---

## Principio metodológico (léelo antes que el resto)

El objetivo del producto es: dada una imagen **sin solución**, los agentes + MCPs
del orquestador encuentran evidencias, montan timeline y redactan el informe por sí
solos. De ahí, tres reglas que ordenan TODO el entrenamiento:

1. **La solución nunca la ve el agente.** Ni en entrenamiento ni en producción. El
   agente se comporta igual en ambos: solo ve el handle read-only de la evidencia +
   su allowlist. El ground-truth/solución es un **instrumento de medida** que usan
   el harness y el auditor para puntuar la salida — jamás un input del prompt. Un
   agente que "se compara con la solución" haría trampa (circular).

2. **Las mejoras son metodológicas, no factuales del caso.** Se entrena a *razonar*,
   no a saber la respuesta. Válido: «si `pslist` sale vacío, diagnostica símbolos y
   no cites T1055» (generaliza). Prohibido: «el documento exfiltrado es `m57biz.xls`»
   (es la respuesta → sobreajuste). **Gate de auditoría por cada cambio:** ¿enseña a
   razonar o enseña la respuesta de este caso? Si es lo segundo, se rechaza.

3. **Disciplina de hold-out (da rigor publicable).** Fable 5 se ancló a LoneWolf ⇒
   LoneWolf es "train". Por tanto:
   - **Congela el paquete** antes de correr M57.
   - Corre **M57-memoria sin tocar nada** → esas métricas son la **generalización
     zero-shot** (el resultado del TFM: el método entrenado en A funciona en B sin
     re-tunear). Se registra tal cual, antes de cualquier iteración.
   - *Después* se iteran los huecos **metodológicos** y se re-valida.
   - **LoneWolf queda como regresión:** una mejora por M57 que rompa LoneWolf se
     rechaza.

**Niveles de fidelidad (no sobre-afirmar):** `codex_auto` (codex ejecuta las tools)
valida el *playbook/razonamiento*, no el camino del producto (`{tool_id, params}` →
backend). Cadena: autónomo CLI → single-shot `--mode forensia` (dispatcher mock,
valida el contrato) → motor real (Bloque B). Lo validado en autónomo se re-confirma
en contrato y motor; el método solo transfiere si las mejoras se quedan en el nivel
declarativo.

**Por-SO, no universal.** Un paquete por `os_profile` (windows/unix), sin fallback
(RULE 2). Lo que generaliza entre SO es la **metodología transversal** (custodia,
fallbacks, coste, anti-alucinación, MITRE), no un mega-agente. Foco Fase 2: windows.

**Cumplimiento/IP:** la solución de M57 es de acceso restringido (faculty). El
`ground-truth/m57-patents.md` es un **resumen derivado** (lista de hallazgos), no una
copia del packet; no se pega el packet verbatim en el repo y la evidencia sigue fuera
de git.

---

## Por qué M57-Patents y no NGDC

| Criterio | M57-Patents (2009) | NGDC (2012) |
|---|---|---|
| Memoria RAM | **Sí, imágenes diarias por máquina** | **No hay** |
| Disco Windows | Sí, E01 diarios (XP) | Solo 1 equipo (resto móvil/macOS) |
| Vol3 sobre su RAM | XP = símbolos sólidos (**no degrada** como Win10 LoneWolf) | N/A |
| USB / cadena 4 | Sí (imágenes USB) | Parcial |
| Exfiltración / keylogger | Sí, documentado (hoja `m57biz.xls`) | Keylogger sí, pero en macOS |
| Solución/ground-truth | Instructor packet + detective reports + emails + hash-sets | Answer keys por dispositivo |
| Foco del escenario | Corporativo: exfil + eavesdropping + red herring | Móvil + esteganografía + red |

NGDC descartado para este agente: sin memoria y mayoritariamente iOS/Android/macOS.
Contrapartida de M57: es Windows **XP** → sin Amcache/SRUM/EVTX moderno (las guías
A3 de artefactos modernos no aplican); el núcleo (Run/Services/SAM/USBSTOR/Prefetch/
`$MFT`/pslist/malfind/netscan/cmdline) sí. Para memoria es ideal.

---

## Qué descargar (NO el corpus entero — son TB de imágenes diarias)

Bucket público, sin credenciales. Enumerar primero:

```
aws s3 ls --no-sign-request s3://digitalcorpora/corpora/scenarios/2009-m57-patents/ram/
aws s3 ls --no-sign-request s3://digitalcorpora/corpora/scenarios/2009-m57-patents/drives-redacted/
```
(si no tienes aws-cli: `pip install awscli`; o abre el índice en el navegador:
`https://downloads.digitalcorpora.org/corpora/scenarios/2009-m57-patents/ram/`)

Selección mínima para arrancar (foco: **exfiltración**, protagonista **Jo**):

1. **1 imagen de RAM de la máquina de Jo** del día del incidente de exfiltración
   (≈ 2009-11-24; **confirmar la fecha exacta contra el instructor packet**). Es
   pequeña (XP, ~0.5–1 GB) y con enumeración fiable en Vol3.
2. **El E01 redactado final de la misma máquina (Jo)** (`drives-redacted/`), para
   la sección A de disco (persistencia, USB, `$MFT`, correo/adjuntos).
3. Opcional: la RAM de **Pat** (presidente suplantado) el mismo día, para
   correlación entre máquinas.

Descarga a `evidence-corpus/m57-patents/` (gitignored, igual que LoneWolf). Ejemplo:

```
aws s3 cp --no-sign-request "s3://digitalcorpora/corpora/scenarios/2009-m57-patents/ram/<FICHERO_RAM_JO>" "evidence-corpus\m57-patents\"
```

**Checkpoint auditor M0:** cada fichero descargado se registra en
`docs/agentes/corpus-windows.md` con URL + SHA-256 (usa `scripts/hash-evidence.py`)
+ ground-truth resumido. Sin hash baseline no entra en el flujo.

---

## Fase M1 — Ground-truth desde la solución (antes de correr nada)

El auditor construye `docs/agentes/ground-truth/m57-patents.md` (misma forma que
`lonewolf-2018.md`): tabla de hallazgos esperados → artefacto → herramienta →
técnica MITRE, por cada pieza de evidencia seleccionada.

- **Necesito de ti:** el **instructor packet descifrado** (o al menos la sección de
  *Exfiltration* y la timeline) para anclar el ground-truth con precisión. Dijiste
  que tienes las soluciones — pásame esa parte y la convierto en traza dorada.
- **Auditoría MITRE:** cada `technique_id` esperado tiene que existir en la semilla
  cerrada. Exfil por correo probablemente exija añadir a la semilla
  `T1114` (Email Collection) y/o `T1048`/`T1567`; suplantación por email,
  `T1566` (Phishing). Se añaden como ampliación fechada, sin duplicar ids, igual que
  T1567 en la pasada Fable 5. Lo verifico con el script de la semilla.

**Checkpoint auditor M1:** ground-truth no vacío; todos los ids en la semilla;
manifiesto en sync (RULE 4).

---

## Fase M2 — Corrida de memoria (el test que LoneWolf no pudo dar limpio)

Prerrequisito: Volatility3 ya instalado (verificado). La RAM de XP enumera bien,
así que aquí **sí** se mide razonamiento (no laguna de entorno).

```
python agentes\forensia-windows\evals\harness\run_investigation.py --motor codex_auto --type memory --mode autonomous --evidence "C:\Users\super\Desktop\TFM - Forensia\Forensia-AI\evidence-corpus\m57-patents\<FICHERO_RAM_JO>" --yes
```

Task genérica del harness (`--type memory`) sirve. Si quieres dirigir el foco a
exfiltración sin tocar el paquete, usa un prompt ensamblado con tarea propia
(`build_agent_prompt.py` → `--prompt-file`), tarea sugerida:
> «Investiga exfiltración de documentos: procesos ofimáticos y de correo abiertos,
> el documento en juego, conexiones de red y destinatarios, USB. Registra cada
> hallazgo con su herramienta y artefacto. No inventes.»

**Checkpoint auditor M2 (lo que reviso yo):**
- `findings_recall` / `precision` frente al ground-truth M1 (¡ahora medible!).
- Los 8 clusters Fable 5 sobre imagen **sana**: en especial la **cadena 5** —
  ¿ahora que `pslist`/`cmdline` funcionan, construye la correlación
  Excel+correo+documento+red que en LoneWolf quedó en hipótesis por `filescan=0`?
- ¿Mapea el MITRE de exfil de la semilla? ¿Cero invención?

---

## Fase M3 — Corrida de disco (tras instalar el maletín)

Prerrequisito (mayor fricción): TSK + libewf + RegRipper + EvtxECmd, o el
**toolkit Docker del repo** (`docker/docker/forensic-toolkit/`) o WSL con
`sleuthkit`. Soundness: trabaja sobre **copia**, nunca montes el NTFS en escritura,
pre-extrae artefactos con `tsk_icat` antes de RegRipper/EvtxECmd.

```
python agentes\forensia-windows\evals\harness\run_investigation.py --motor codex_auto --type disk --mode autonomous --evidence "C:\Users\super\Desktop\TFM - Forensia\Forensia-AI\evidence-corpus\m57-patents\<E01_JO>" --yes
```

**Checkpoint auditor M3:** persistencia (Run/Services), USB (cadena 4 USBSTOR),
ejecución (Prefetch/registro), y el correo/adjunto de la exfil en `$MFT`. Verifico
que respeta la regla de oro de custodia (contenedor nunca recibe la imagen cruda).

---

## Fase M4 — Evals derivadas + iteración anclada

- Convertir el ground-truth M1 en 2-3 `case-win-*.yaml` (formato §9.4 del diseño):
  `expected_findings` + `expected_mitre` + `budget`. Trazables a M57.
- Método de siempre: corrida real → clusters de fallos recurrentes → **una mejora
  declarativa** (prompt/eval/KB) por cluster → validar con corrida nueva. Nada de
  iterar a ciegas.

**Checkpoint auditor M4:** cada eval trazable al ground-truth; ids en la semilla;
allowlist intacta; tests del paquete verdes; RULE 0 en el diff.

---

## Orden inmediato

1. `aws s3 ls` de `ram/` y `drives-redacted/` → me pasas la lista (o eliges tú por
   los criterios de arriba).
2. Pásame la sección **Exfiltration** del instructor packet descifrado → monto M1.
3. Descarga RAM de Jo → hash → corrida M2 → te audito antes de commitear.

Disco (M3) queda para cuando tengas el maletín TSK; la memoria (M2) es el camino de
menor fricción y el que valida de verdad las mejoras Fable 5 sobre imagen sana.
