# Fase 1 — lo que pido (usuario)

Documento **del usuario**: aquí van mis peticiones y mis comentarios sobre los resultados.
Las **decisiones técnicas y el cómo** están en el documento del asistente
[`REGISTRO-DECISIONES.md`](REGISTRO-DECISIONES.md); desde cada petición enlazo con `↳` a la
entrada del registro que la resuelve.

> Contexto: esta carpeta es un banco de pruebas para diseñar **desde cero** un flujo de
> agentes, **sin el contexto de Forensia** y sin heredar nada de otros proyectos. Objetivo:
> que salga un **flujo reproducible**, no un apaño para un caso concreto.
>
> Método de trabajo pedido: **una cosa a la vez**, enseñando el resultado para validarlo
> antes de seguir, y documentándolo todo (esta telaraña de MDs).

---

<!-- Las entradas nuevas van justo debajo, la más reciente primero. -->

### 2026-07-28 — 🔁 Reintentar convertir el disco a raw

- **Lo que decido:** ya con Docker estable, **reintentar la conversión vmdk→raw** para poder
  analizar el disco (E1 password, E2 nombre del fichero, hora fina de P1, subida a Drive).
- **Diferencia con el intento fallido:** ahora hay **51,8 GB reales libres** (antes ~22 reales
  disfrazados de 82 por el purgable). El raw ocupa ≤20 GB → margen de sobra, sin riesgo de
  llenar el disco.
- ↳ [REGISTRO-DECISIONES.md#a8-acceso-disco](REGISTRO-DECISIONES.md#a8-acceso-disco)

### 2026-07-28 — 💽 Llega el disco · tokens · decisión sobre el hash

- **Lo que pido:** copiar `IE11-Win7-VMWare-disk1.vmdk` al input. Y aviso: "creo que conté
  60–70k tokens, ¿de dónde sale tu cuenta?".
- **Sobre los tokens:** acepto la corrección del asistente — sus cifras eran estimaciones
  infladas, no medidas. La fuente real es el panel de uso.
- **Decisión sobre el hash (⛔ no coincidía):** el SHA-256 del `.vmdk` difiere del enunciado
  en un carácter. **Decido: seguir asumiendo que es una errata del PDF**, y analizar el disco
  igualmente **dejándolo escrito en el informe**. (Reafirmado tras avisarme el asistente del
  riesgo.)
- **Mis comentarios:** _(pendiente)_
- ↳ [REGISTRO-DECISIONES.md#a7-hash-vmdk](REGISTRO-DECISIONES.md#a7-hash-vmdk) ·
  [#a8-acceso-disco](REGISTRO-DECISIONES.md#a8-acceso-disco)

### 2026-07-28 — 🕒 La documentación debe ser simultánea y en vivo

- **Lo que pido:** "la documentación de todo debe ser simultánea y en vivo". No documentar en
  bloque al final: según pasa cada cosa, se escribe.
- **Cómo se aplica:** regla 7 nueva del [`../CLAUDE.md`](../CLAUDE.md). Cada tool que termina
  → su `_run.md` + `_vista` + hallazgos en la ficha, **antes** de lanzar la siguiente; en un
  lote, se documenta cada salida según cae.
- ↳ [REGISTRO-DECISIONES.md#a4-arranque-ram](REGISTRO-DECISIONES.md#a4-arranque-ram)

### 2026-07-28 — ▶️ Empezar ya con la evidencia que hay (RAM)

- **Lo que decido:** "empecemos por la evidencia que ya hay". Cambio la decisión anterior:
  **arrancamos el análisis con `ram.raw`**, sin esperar al disco. El `.vmdk` se incorporará
  cuando esté.
- **Mis comentarios:** _(pendiente)_
- ↳ Cómo se ejecuta y qué se puede/no responder solo con RAM:
  [REGISTRO-DECISIONES.md#a4-arranque-ram](REGISTRO-DECISIONES.md#a4-arranque-ram)

### 2026-07-28 — ⏸️ Esperar al disco antes de ejecutar

- **Lo que decido:** falta el `.vmdk`. **No arrancamos el análisis con RAM sola**: prefiero
  hacerlo **completo de una tanda** (RAM + disco) cuando tenga las dos evidencias, no en dos
  pasadas.
- **Lo que hago yo:** descargar `IE11-Win7-VMWare-disk1.vmdk` de "Recursos para la tarea" y
  dejarlo en `input/murcielago/`.
- ↳ [REGISTRO-DECISIONES.md#a3-objetivo-fase1](REGISTRO-DECISIONES.md#a3-objetivo-fase1)

### 2026-07-28 — 🎯 El objetivo de la Fase 1

- **Lo que pido:** el objetivo es **responder las preguntas** de la tarea de la UCM
  ([`refs/enunciado-tarea-UCM.pdf`](refs/enunciado-tarea-UCM.pdf)) **mientras se documentan
  las decisiones**, y al final **crear un flujo reproducible para cualquier tipo de análisis
  forense**, apoyado en las herramientas ya disponibles (el maletín de Forensia en Docker:
  `toolkit-unix` + `toolkit-windows`, 33 tools de catálogo).
- **Mis comentarios:** _(pendiente)_
- ↳ Cómo se ha entendido y estructurado, y qué falta:
  [REGISTRO-DECISIONES.md#a3-objetivo-fase1](REGISTRO-DECISIONES.md#a3-objetivo-fase1)

### 2026-07-28 — 📥 Primera evidencia al `input/`

- **Lo que pido:** copiar `Forensia-AI/evidence/windows7-x64-ram-dump/ram.raw` dentro del
  `input/`.
- **Mis comentarios:** _(pendiente)_
- ↳ Cómo se hizo y qué se decidió no traer:
  [REGISTRO-DECISIONES.md#a2-evidencia-ram](REGISTRO-DECISIONES.md#a2-evidencia-ram)

### 2026-07-28 — 🧰 Las tools son las de Forensia (Docker) · 📤 qué espero de `output/`

- **Tools:** usaremos el **maletín de tools de Forensia, que ya está montado en Docker**.
  **Es lo único que tomamos de Forensia y nada más** — para que no se confunda ni se
  mezclen contextos.
- **`output/`:** ahí quiero **organización pura y dura**. Que estén las **salidas de cada
  tool que se use**, que yo pueda verlas, y **la versión tal cual la da la tool**.
- **Mis comentarios:** _(pendiente)_
- ↳ Cómo queda: [REGISTRO-DECISIONES.md#a1-tools-y-outputs](REGISTRO-DECISIONES.md#a1-tools-y-outputs)

### 2026-07-28 — Crear la carpeta y la estructura de trabajo

- **Lo que pido:** una carpeta nueva donde recrear la **estructura de documentación** de
  `prueba-dwg` (toma de decisiones + flujo + `CLAUDE.md`). Lo que voy a hacer aquí es
  **completamente distinto**: no me sirve nada de la arquitectura ni del contenido, **solo
  la organización y las instrucciones**.
- **Para qué:** montar aquí un **flujo nuevo para los agentes de Forensia**, pero **sin el
  contexto de Forensia**, empezando desde 0 — igual que hago con `prueba-dwg` y con VerIA.
- **Mis comentarios:** _(pendiente)_
- ↳ Cómo se montó: [REGISTRO-DECISIONES.md#a0-estructura](REGISTRO-DECISIONES.md#a0-estructura)

### <AAAA-MM-DD> — <plantilla de petición, borrar cuando haya entradas reales>

- **Lo que pido:** …
- **Por qué / qué me importa:** …
- **Mis comentarios sobre lo entregado:** …
- ↳ [REGISTRO-DECISIONES.md#a…](REGISTRO-DECISIONES.md)
