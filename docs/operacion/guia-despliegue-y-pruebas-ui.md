# Guía de despliegue y pruebas desde la interfaz (usuario)

> Cómo levantar FORENSIA con `docker compose`, prepararlo, y **probar el proyecto de
> principio a fin desde el navegador** como lo haría un investigador. Incluye qué comprobar
> en disco para verificar la cadena de custodia, y — con honestidad — **qué está cableado al
> backend real y qué todavía es maqueta**.
>
> Fuente de verdad: el repo. Si algo aquí diverge del código, gana el código.

---

## 0. TL;DR (camino rápido, 100 % local con Ollama)

```bash
cd "TFM - Forensia/Forensia-AI"
docker compose up --build            # levanta los 5 servicios (tarda la 1ª vez)
docker compose exec ollama ollama pull qwen2.5:14b   # un modelo capaz (el 3B no basta)
# abre http://127.0.0.1:5173
```

En la UI: **Configuración → Ejecutores/IA** (elige `ollama` como *Ejecutor por defecto*) →
**Casos y evidencias** (crea caso → registra una evidencia de `./evidence`) →
**Investigación** (pregúntale al agente). El resto de esta guía lo detalla.

---

## 1. Requisitos

- **Docker con el plugin Compose** (Docker Desktop en Windows/macOS; `docker-ce` +
  `docker-compose-plugin` en Linux). Es el **único** prerrequisito de la app.
- **Un ejecutor de IA** (elige uno):
  - **Ollama** — 100 % local, no requiere cuenta; solo *descargar un modelo* (paso 3).
  - **Claude Code / Codex CLI / Gemini CLI** — tu propia suscripción; hay que *iniciar
    sesión una vez* (paso 3).
- **Espacio en disco**: los builds de los maletines + un modelo de Ollama (qwen2.5:14b ≈ 9 GB)
  ocupan. Ten varios GB libres. (Ver Troubleshooting: el host puede llegar a 0 bytes.)
- **(Opcional) Windows sin WSL**: si tu shell no define `HOME`, copia `.env.example` a `.env`
  y ajusta `HOME` (solo afecta al *seeding* de credenciales de los CLIs cloud; con Ollama no
  hace falta).

> **Dónde vive la evidencia y los casos.** Por defecto el compose usa `./evidence` (bandeja
> de entrada, montada **solo lectura**) y `./projects` (casos, artefactos, audit log,
> informes). Puedes apuntarlos a otra carpeta con `FORENSIA_EVIDENCE_DIR` /
> `FORENSIA_CASES_DIR` (export o `.env`).

---

## 2. Desplegar

Desde la raíz del repo:

```bash
docker compose up --build
```

Levanta **5 servicios** (todos contenedores Linux, puertos **solo en `127.0.0.1`**):

| Servicio | Qué es | Puerto (host) |
|---|---|---|
| `web` | SPA React servida por nginx (proxy `/api`+`/ws` al api) | `127.0.0.1:5173` |
| `api` | FastAPI — el núcleo `backend/forensia` + los CLIs de ejecución | `127.0.0.1:8000` |
| `ollama` | ejecutor 100 % local | interno (sin puerto publicado) |
| `toolkit-windows` | maletín forense Windows (exec-agent) | interno |
| `toolkit-unix` | maletín forense Unix (exec-agent) | interno |

El `api` **espera** a que los dos maletines estén *healthy* antes de arrancar, así que el
primer arranque tarda. Comprobaciones rápidas:

```bash
docker compose ps                         # los 5 arriba; api "healthy"
curl http://127.0.0.1:8000/api/health     # {"status":"ok","version":"..."}
curl http://127.0.0.1:8000/api/capabilities   # ejecutores, tools, agentes, os, python
docker compose exec toolkit-unix    forensia-info   # lista las herramientas del maletín
docker compose exec toolkit-windows forensia-info
```

Abre **<http://127.0.0.1:5173>**. Si la cabecera muestra error de conexión, el `api` aún no
está *healthy* — espera y recarga.

---

## 3. Preparar un ejecutor (obligatorio: sin ejecutor no hay análisis)

FORENSIA **nunca elige ejecutor por ti** (RULE 2). Tienes que dejar uno disponible y
seleccionarlo.

### Opción A — Ollama (100 % local, recomendado para probar)

El servicio `ollama` arranca vacío: **descarga un modelo capaz** (uno pequeño como `*:3b`
no razona lo suficiente para conducir herramientas):

```bash
docker compose exec ollama ollama pull qwen2.5:14b     # o qwen2.5:7b-instruct si vas justo de RAM
docker compose exec ollama ollama list                 # confírmalo
```

Luego en la UI, **Configuración → Ejecutores/IA**: pon *Ejecutor por defecto* = **Ollama** y,
si quieres, fija *Modelo de Ollama* (`OLLAMA_MODEL`, p. ej. `qwen2.5:14b`). También puedes
elegir proveedor y modelo desde el propio chat (menús *Proveedor* / *Modelo* del composer);
la elección se **recuerda** por proveedor (`DEFAULT_EXECUTOR` + `OLLAMA_MODEL` /
`CLAUDE_CODE_MODEL` / `CODEX_MODEL` / `GEMINI_MODEL`).

Para los **CLIs cloud** (Claude Code / Codex / Gemini) el modelo se pasa como `--model`. El
menú *Modelo* ofrece atajos (p. ej. `opus`, `sonnet` para Claude) y admite escribir cualquier
id que acepte el CLI; *Por defecto del CLI* lo deja sin fijar y manda el modelo por defecto del
CLI. FORENSIA **no puede enumerar** el catálogo de un CLI cloud sin API key (SECURITY 7): la
lista son sugerencias, no el catálogo completo. Ollama sí lista los modelos realmente instalados.

### Opción B — Claude Code / Codex CLI / Gemini CLI (tu suscripción, sin API keys)

Inicia sesión **una vez dentro del contenedor** (la sesión persiste en el volumen
`forensia-cli-auth`):

```bash
docker compose exec -it api claude auth login          # Claude Code
docker compose exec -it api codex login --device-auth  # Codex CLI (device-code)
docker compose exec -it -e NO_BROWSER=true api gemini  # Gemini CLI (URL + código)
```

### Verificar

**Configuración → Ejecutores/IA** muestra los 4 con estado *Disponible / No disponible* y, si
no lo están, **la razón accionable** (p. ej. "inicia sesión con…", "Ollama sin modelo"). Pulsa
**Actualizar estado** tras loguearte o descargar el modelo. (Equivale a `GET /api/capabilities`.)

> **Privacidad (RGPD).** Elegir un ejecutor **cloud** envía contenido derivado de la evidencia
> a ese proveedor bajo tu cuenta; la UI lo advierte y, con un caso abierto, **bloquea el envío
> hasta que aceptas** — y registra el consentimiento en el audit del caso. Ollama no sale de tu
> máquina.

---

## 4. La interfaz, página por página (qué está vivo y qué es maqueta)

Navegación (barra lateral):

| Página | Estado | Qué hace |
|---|---|---|
| **Guía de uso** | viva | Flujo recomendado + cómo loguear el ejecutor. |
| **Casos y evidencias** | **viva (backend real)** | Crear/editar/cerrar casos; registrar y **verificar** evidencia (hash gate). |
| **Investigación** | **viva (backend real)** | Chat con el sub-agente; panel de hallazgos y de herramientas en vivo. |
| **Estado del sistema** | **viva (backend real)** | `capabilities`: ejecutores, herramientas, agentes, versión, Python, OS. |
| **Configuración** | **viva (parcial)** | Ejecutores + `OLLAMA_MODEL/HOST`, timeout, tema. *Operador y reportes* es **vista previa** (deshabilitada). |
| **Timeline** | **maqueta (datos demo)** | Aún no lee eventos del caso real. |
| **MITRE ATT&CK** | **maqueta (datos demo)** | Aún no lee la correlación del caso real. |
| **Visor de documentos** | **maqueta (datos demo)** | La generación de informes real aún no existe. |

Esto es importante para tus pruebas: **Timeline, MITRE y Visor muestran datos de ejemplo**,
no los de tu caso. Lo real hoy es el ciclo **Casos → Evidencia → Investigación → hallazgos +
audit**.

---

## 5. Prueba de principio a fin (el ciclo que SÍ está cableado)

### 5.1 Crear un caso

**Casos y evidencias → “+ Abrir caso nuevo”** → *Nombre* y *Examinador* (obligatorios) +
*notas* (opcional) → **Guardar**. **No eliges el sistema operativo**: lo deriva el orquestador
(triage) del contenido de la evidencia. Al crear, la UI te baja directo a *Registrar evidencia*.

### 5.2 Registrar evidencia (aquí se ve la cadena de custodia)

1. Lleva el fichero de evidencia a la bandeja de una de estas dos formas (formatos: `.E01`,
   `.raw`/`.dd`, `.vmdk`, volcados de RAM/`.mem`):
   - **Arrástralo** a la zona *Registrar evidencia* (o pulsa **Examinar…**): se SUBE a la
     bandeja (`POST /api/evidence/upload`) y queda auto-seleccionado. Subir no registra; solo
     deposita el fichero para que lo registres en el paso 2.
   - O **cópialo** a la carpeta `./evidence` del repo (o a tu `FORENSIA_EVIDENCE_DIR`) y pulsa
     **Buscar en la bandeja**.
   *El api monta la bandeja en lectura-escritura solo para esta subida del perito; el
   agente/maletines la ven en solo lectura (cadena de custodia).*
2. En **Registrar evidencia**, con el fichero **seleccionado** pulsa
   **Registrar**. FORENSIA ejecuta el **hash gate**: calcula el **SHA-256 baseline**, copia la
   evidencia a una copia inmutable (solo lectura), corre el **triage** (deriva `os_profile` y
   tipo) y registra el evento en el audit. La fila aparece en *Evidencias del caso*.
3. Pulsa **Verificar** en la fila: re-hashea y compara con el baseline, dejando un registro
   *verificado el día X con resultado Y* (cadena de custodia).

> **De dónde sacar evidencia de prueba.** El repo referencia imágenes públicas de CTF por
> URL+SHA-256 en `docs/agentes/corpus-windows.md` y en `docs/pruebas/**` (DVWA rootfs,
> Metasploitable2, EVTX/MFT/hives de Windows, volcado RAM). No viajan en git (son grandes). Para
> un humo rápido de la UI vale cualquier `.raw` pequeño; para un análisis real, usa una imagen
> real del corpus.

### 5.3 Investigar (el agente conduciendo herramientas)

**Investigación**: la cabecera muestra el caso activo, la evidencia y el **agente activo**
(según el `os_profile` detectado). En el composer elige **Proveedor** (ejecutor) y **Modelo**;
si es cloud y hay caso, acepta el aviso de consentimiento. Escribe una consulta, p. ej.:

- “¿Qué herramientas tengo disponibles para esta evidencia?”
- “Lista las particiones y el árbol de ficheros de la imagen.”
- “Busca indicios de exfiltración y regístralos como hallazgos.”

Verás el **árbol de actividad en vivo** (estilo Claude Code): `▸ razonamiento`, llamadas a
herramienta (`▸ tool_id params`), resultados (`✓/✗`), y hallazgos (`★`). Al terminar cada
turno se refrescan los paneles laterales:

- **Hallazgos del caso** — lo que el agente persistió (`record_finding`), con severidad, `tool_id`
  y `run_id`.
- **Tools** — cada herramienta ejecutada con su recuento ok/fallos.

> Si la cabecera dice “el SO de este caso aún no está determinado”, es que la evidencia aún no
> permite enrutar: registra una evidencia enrutable. Si dice “sin agente para perfil X”, falta
> el paquete `agentes/forensia-X/` — compruébalo en **Estado del sistema**.

### 5.4 Estado del sistema / Configuración

- **Estado del sistema**: ejecutores disponibles, **herramientas detectadas** (por maletín),
  agentes cargados, versión, Python, OS. Es tu panel de diagnóstico.
- **Configuración → Sistema**: resumen compacto de lo mismo.

---

## 6. Verificar la cadena de custodia en disco (lo que hace fuerte al TFM)

Todo queda en `./projects/` (o `FORENSIA_CASES_DIR`). Tras registrar evidencia y correr alguna
herramienta:

```bash
# Estructura del caso
ls -R projects/                     # cases/<case-id>/: case.json, evidence/, artifacts/, audit.jsonl, chats/, findings.jsonl

# Baseline de la evidencia (hash gate)
cat projects/cases/*/evidence/*/baseline.json          # sha256, size, triage (os/kind), source

# Audit log append-only y encadenado por hash
tail -n 20 projects/cases/*/audit.jsonl
#  -> evidence_register (sha256), tool_run_start / tool_run_finish con:
#     argv literal, evidence_id + baseline sha256, tool_version, exit code,
#     sha256 de stdout/stderr y de cada artefacto de salida, derived_inputs

# Artefactos por corrida (manifiesto + salidas hasheadas)
cat projects/cases/*/artifacts/*/manifest.json
```

Qué demostrar con esto: el **argv literal ejecutado** (no la intención del LLM), que cada
acción está **anclada a la evidencia exacta** (id + hash) y a la **versión exacta de la
herramienta**, y que la cadena de auditoría es **verificable/tamper-evident**. La UI (panel de
hallazgos/tools) es la vista amable de este mismo registro.

---

## 7. Troubleshooting

- **La UI carga pero da error de conexión**: el `api` aún no está *healthy* (espera a los
  maletines). `docker compose ps` → espera a `healthy`; recarga.
- **“Ejecutor no disponible”**: en Ollama, descarga un modelo (paso 3A) y **Actualizar estado**;
  en un CLI cloud, inicia sesión en el contenedor y **Actualizar estado**. La razón concreta
  sale en Configuración → Ejecutores/IA.
- **El agente no arranca herramientas / respuestas pobres**: modelo local demasiado pequeño.
  Usa `qwen2.5:14b` (o un modelo cloud). Sube `FORENSIA_EXECUTOR_TIMEOUT` si tu modelo local
  responde lento.
- **“Sin agente para perfil windows/unix”**: falta `agentes/forensia-<perfil>/`. Verifica que
  la carpeta existe y reinicia el stack (`docker compose restart api`).
- **`.E01` no se procesa**: los maletines necesitan `cap_add: SYS_ADMIN` + `devices: /dev/fuse`
  (ya están en el compose) para `ewfmount`. No los comentes.
- **Apple Silicon / arm64**: los maletines corren emulados (amd64); funcionan igual pero el
  build y los análisis pesados van más lentos (ver README).
- **Docker Desktop frágil / disco lleno** (visto en desarrollo): si `docker version` falla o hay
  corrupción de capas, cierra Docker Desktop, `wsl --shutdown`, relánzalo; si persiste,
  `docker builder prune -af` y reconstruye. Purga cachés (`docker builder prune`, `pip cache
  purge`, `npm cache clean --force`) si te quedas sin espacio.
- **Revocar sesiones de CLIs / empezar limpio**: `docker compose down -v` (borra el volumen de
  credenciales **y** los modelos de Ollama descargados).

---

## 8. Qué NO está terminado (para no confundir en la demo)

- **Timeline, MITRE ATT&CK y Visor de documentos**: muestran **datos de ejemplo**, no los del
  caso real, todavía.
- **Generación de informes** (court-style / export PDF-DOCX-JSON) y la pestaña *Operador y
  reportes*: **vista previa**, aún no persiste ni genera.
- **Adjuntar evidencia desde el chat**: icono maqueta; la vía real de evidencia es *Registrar
  evidencia* — arrastra/sube el fichero a la bandeja o cópialo a `./evidence`.

El ciclo **sólido y demostrable hoy** es: crear caso → registrar/verificar evidencia (hash
gate, triage, custodia) → investigar con el sub-agente (herramientas reales del maletín por el
canal exec-agent, con timeout acotado y artefactos byte-exactos) → hallazgos + **audit log
encadenado por hash** con evidencia, versión de tool y SHA-256 de cada salida.
```
