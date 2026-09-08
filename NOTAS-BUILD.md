# Notas — rendimiento del build y del arranque

Análisis estático del stack (`docker-compose.yml` + los tres Dockerfiles), hecho el
2026-09-07 sobre `main` @ `e41b626`. **No se ha modificado nada**: esto es solo el
inventario de lo que cuesta tiempo y de lo que está mal montado.

## Veredicto

Los 5-10 minutos son el **primer build**, no el arranque. El coste es red
(~4-5 GB de descarga), no CPU. Un segundo `docker compose up --build` sin editar
nada debería tardar 15-30 s, solo revalidando caché.

> Si el rebuild sin cambios tarda minutos **cada vez**, eso es un problema de
> invalidación de caché distinto y hay que medirlo antes de tocar nada:
> `docker compose build --progress=plain` y mirar qué capa dice `CACHED` y cuál no.

## Reparto del tiempo

El camino crítico es el stage `base` de `docker/docker/forensic-toolkit/Dockerfile`:
los dos maletines cuelgan de él, así que hasta que no termina no arranca ninguno
de los dos. Encima, `windows` añade casi tanto como `base`.

**Stage `base`** (compartido windows + unix):

- `libguestfs-tools` (`Dockerfile:55`) — arrastra el appliance completo más qemu.
  Con diferencia el paquete individual más caro de todo el stack.
- `plaso-tools` (`Dockerfile:61`) desde el PPA GIFT, con sus decenas de
  dependencias Python.
- `sleuthkit`, `bulk-extractor`, `libewf-tools`, `qemu-utils`, `foremost`.
- `add-apt-repository ppa:gift/stable` (`Dockerfile:39`) obliga a un segundo
  `apt-get update` completo.
- pip moderno + `volatility3` (`Dockerfile:74-75`).
- Descargas sueltas verificadas por SHA: `ftkimager` (CDN de AccessData),
  `aff4imager` (releases de GitHub).

**Stage `windows`** (encima de `base`):

- Runtime .NET 9 vía el script oficial (`Dockerfile:294-296`), ~200 MB.
- `hayabusa` con su árbol de reglas, `chainsaw` + `git clone` de `chainsaw-src`.
- RegRipper 3.0 (`git clone`).
- 11 zips de EZ Tools, secuenciales (`Dockerfile:330`).
- `requirements-windows.txt`, que incluye `ccl_chromium_reader` desde git
  (`Dockerfile:373`).

**Stage `unix`**: e2fsprogs / xfsprogs / systemd / lnav. Barato.

**En paralelo con los maletines**:

- `api`: `npm install -g` de los tres CLIs (claude-code + codex + gemini).
- `web`: `npm ci` + `tsc --noEmit` + `vite build`.
- `ollama`: `docker pull` de la imagen oficial.

## Problemas concretos

### 1. Sin cache mounts, en ningún sitio

Los tres Dockerfiles declaran `# syntax=docker/dockerfile:1.7`, que soporta
`RUN --mount=type=cache`, y no se usa ni una vez. Consecuencia: cualquier bump de
un `ARG` de versión, o cualquier cambio en una capa anterior, rehace la descarga
íntegra de apt / pip / npm de esa capa.

Aplicaría a: el apt de `base`, los dos `pip3 install`, el
`pip install -r requirements-windows.txt`, el `npm install -g` del `api` y el
`npm ci` del `web`.

### 2. `api`: el `pip install` va después del `COPY` del código

`docker/api/Dockerfile:51-54`:

```
COPY backend/pyproject.toml backend/pyproject.toml
COPY backend/agentopsy backend/agentopsy
RUN pip install --no-cache-dir -e "./backend[mcp]"
```

Tocar una sola línea del backend invalida la capa de instalación y reinstala
**todas** las dependencias Python. Falta el split habitual:
copiar solo el `pyproject.toml` → instalar dependencias → copiar el código.

En `docker/web/Dockerfile:17-20` esto **sí** está bien resuelto
(`package.json` + `npm ci` antes de `COPY web/`). Es el patrón a replicar.

### 3. EZ Tools: 11 descargas secuenciales de un CDN que sirve *latest*

`docker/docker/forensic-toolkit/Dockerfile:330` y siguientes. Un bucle `for` con
un `wget` por herramienta, cada uno seguido de `sha256sum -c` contra un ARG
pinneado.

Dos problemas, y el segundo es peor que el primero:

- Es serie pura. Nada impide bajarlos en paralelo.
- La URL (`download.ericzimmermanstools.com/net9/<Tool>.zip`) sirve siempre el
  último build. El día que Eric Zimmerman publique una versión nueva, **el build
  entero falla** sin que nadie haya tocado el repo. El propio comentario del
  Dockerfile lo reconoce ("cada SHA hay que re-pinnearlo").

### 4. `requirements-windows.txt` sin pins

El fichero lo admite en su propia cabecera. Con la capa cacheada no se nota en
tiempo, pero un rebuild limpio puede dar un entorno distinto en silencio —
justo lo que el resto del proyecto evita con tanto cuidado (SHA pinneados por
todas partes, manifiesto inmutable de versiones vía `gen_versions.py`).

Es una incoherencia con FORENSIC INVARIANT 4, no solo una cuestión de velocidad.

### 5. `git clone` de chainsaw con `|| true`

`docker/docker/forensic-toolkit/Dockerfile:283`. Si el clone falla, el build
continúa y `CHAINSAW_RULES` / `CHAINSAW_MAPPING` apuntan a rutas inexistentes.
Fallo silencioso: la imagen se construye "bien" y chainsaw no tiene reglas.

Contrasta con el resto del Dockerfile, donde cualquier verificación que falla
aborta el build (RULE 2).

### 6. Healthchecks lentos — esto se paga en *cada* `up`, no solo el primero

`docker-compose.yml:85-88` (maletines) y `183-186` (api):

```
interval: 15s
start_period: 10s
```

El servicio `api` espera `service_healthy` de los dos maletines. Aunque el
exec-agent esté escuchando en 1 s, el primer check no ocurre hasta los 10 s y,
si falla por poco, el siguiente es a los 25 s. Son 10-25 s muertos en todo
arranque en frío.

Docker Compose soporta `start_interval` (checks rápidos durante el
`start_period`), que es exactamente el arreglo.

### 7. El README manda `up --build` como comando único

`README.md:41` y `docker-compose.yml:4`. Para el primer arranque es correcto y
está bien pensado como promesa de producto ("un solo comando"). Para el día a
día, `docker compose up` a secas se salta la revalidación de las capas.

Merecería una línea en el README distinguiendo primer arranque de arranques
posteriores.

## Lo que ya está bien

No todo es mejorable — conviene no romperlo al optimizar:

- **Contextos de build minúsculos**: 84 K el del maletín, y el `.dockerignore`
  de la raíz solo deja entrar `backend/` + `web/` + los dos ficheros de `docker/`.
  El contexto no es el cuello de botella.
- **`base` compartida** entre los dos maletines: se construye una vez.
- **`exec_agent.py` copiado al final** de ambos stages, para no invalidar las
  capas caras. Deliberado y correcto.
- **Todo pinneado por SHA-256** (ftkimager, aff4imager, hayabusa, chainsaw,
  las 11 EZ Tools) salvo el `requirements-windows.txt` del punto 4.
- **`web`** tiene el orden de capas correcto.
- En un host x86_64, `platform: linux/amd64` no cuesta nada. El aviso de Apple
  Silicon del README solo aplica en ARM.

## Orden de ataque sugerido

Si en algún momento se toca, por relación mejora/riesgo:

1. Reordenar el `pip install` del `api` (punto 2) — trivial, y es el que más se
   nota en el bucle de desarrollo del backend.
2. `start_interval` en los healthchecks (punto 6) — trivial, se nota en cada `up`.
3. Cache mounts para apt/pip/npm (punto 1) — donde está el grueso de la mejora
   en rebuilds.
4. Pinnear `requirements-windows.txt` (punto 4) — coherencia forense.
5. Quitar el `|| true` de chainsaw (punto 5).
6. Paralelizar las EZ Tools o vendorizarlas (punto 3) — lo más invasivo, y hay
   que decidir antes qué hacer con el CDN "latest".

Nota aparte: revisar si `libguestfs-tools` (punto del stage `base`) es realmente
necesario. El comentario del propio compose dice que el camino producto para EWF
es `ewfmount`, y guestmount aparece como "si se usa". Si es opcional, sacarlo de
`base` es la mayor reducción de tamaño y tiempo disponible de una sola tacada.

---

## Apéndice — el servicio `ollama` se levanta vacío

Pregunta de partida: el compose construye/descarga un contenedor de Ollama;
¿lo usa la app, y lo usa por defecto?

### Sí está cableado, y bien

- `docker-compose.yml` (servicio `api`) exporta `OLLAMA_HOST=http://ollama:11434`.
- `backend/agentopsy/executors/ollama.py:47` lee esa clave vía `config.get`.
- No hay ninguna otra URL de Ollama en el repo ni un segundo host posible.

El contenedor no publica puerto: solo es alcanzable por la red interna del
compose, coherente con SECURITY INVARIANT 1.

### No es el ejecutor por defecto — y no debe serlo

`backend/agentopsy/executors/__init__.py:31` declara los cuatro ejecutores
(`claude-code`, `codex`, `gemini`, `ollama`) sin preferencia, y
`backend/agentopsy/config.py` no tiene ningún fallback: `require()` falla en
alto cuando falta un valor.

Sí existe una clave `DEFAULT_EXECUTOR`, pero **no trae valor de fábrica**: se
fija solo por acto explícito del operador — el botón *USE AS DEFAULT* de
Ajustes, o `web/src/pages/ChatPage.tsx:504`, que recuerda el proveedor elegido
en un chat. Los routers la leen siempre como `req.executor or
config.get("DEFAULT_EXECUTOR")` (`routers/agent.py:105`, `documents.py:146`,
`graphs.py:240`) y, si ninguna de las dos existe, fallan con un mensaje
accionable en vez de elegir.

Es deliberado (RULE 2, y el README lo vende como garantía de privacidad: "sin
ejecutor elegido no hay análisis: nunca se escoge uno por ti"). **No tocar.**

### El problema: no se descarga ningún modelo, en ningún sitio

No hay un `ollama pull` ni una llamada a `/api/pull` en el compose, ni en
`docker/api/entrypoint.sh`, ni en el README. Tampoco hay un valor por defecto
para `OLLAMA_MODEL`.

Secuencia real tras un `docker compose up --build` limpio:

1. El contenedor `ollama` arranca con el volumen `ollama:/root/.ollama` vacío.
2. `OllamaExecutor.is_available()` (`ollama.py:53`) sondea `/api/version`, que
   responde → la UI marca Ollama como **disponible**.
3. `executor_models("ollama")` consulta `/api/tags` y devuelve **lista vacía**,
   sin `note` (no es un error: el host contesta, simplemente no hay modelos).
4. Cualquier corrida muere en `ollama.py:107`:
   *"falta 'model' en el contexto del ejecutor ollama"*.

Es decir: el servicio ocupa imagen, volumen y RAM, se anuncia como disponible,
y no puede ejecutar nada hasta que alguien haga a mano:

```
docker compose exec ollama ollama pull <modelo>
```

Y ese `pull` son varios GB **en caliente**, no durante el build — justo cuando
el perito espera empezar a trabajar.

### Qué hacer con esto (a decidir, no implementado)

Tres opciones, de menos a más invasiva:

1. **Documentarlo.** Una línea en el README: Ollama requiere un `pull` previo, con
   el comando exacto. Coste cero, y hoy no está dicho en ninguna parte.
2. **Que la UI lo distinga.** Ollama alcanzable pero con cero modelos no es lo
   mismo que Ollama disponible. `is_available()` podría devolver
   `available=False` con el `reason` accionable (el comando `pull`), igual que
   ya se hace con los CLIs sin sesión. Encaja con RULE 2 mejor que el estado
   actual, que es un "disponible" que no lo está.
3. **Precargar un modelo en el arranque.** Contradice la promesa de "un solo
   comando" si añade GB al primer `up`, y contradice RULE 2 si Agentopsy elige
   el modelo por el operador. Probablemente no merece la pena.

Ortogonal a todo lo anterior: si no se va a usar Ollama (porque se trabaja con
Claude Code / Codex / Gemini), el servicio se puede dejar sin arrancar y ahorrar
el `pull` de la imagen y la RAM. Hoy no hay perfil de compose que lo permita.

---

## Apéndice 2 — no hay forma de instalar modelos de Ollama desde la web

Continuación del apéndice anterior. Si el contenedor de Ollama arranca vacío,
¿hay alguna vista para llenarlo, o la única salida es `docker compose exec`?

### Estado actual: no existe

- `backend/agentopsy/routers/executors.py` expone **solo** endpoints de login
  (`/login`, `/login/status`, `/login/code`, `/login/cancel`,
  `/login-capabilities`). Ningún `pull`.
- No hay ninguna llamada a `/api/pull` de Ollama en todo el repo (backend ni
  frontend).
- En *Ajustes → Ejecutores*, Ollama solo permite editar `OLLAMA_HOST`
  (`web/src/pages/SettingsPage.tsx:389-407`) y **escribir a mano** el nombre del
  modelo en `OLLAMA_MODEL`. El selector lista los instalados, que de fábrica son
  cero.
- Si el servicio no responde, la UI enseña una frase estática:
  *"Levanta el servicio ollama del compose para usarlo"*
  (`web/src/i18n/es.ts:606`, `SettingsPage.tsx:450`). No hay botón, ni comando,
  ni enlace.
- Y como el servicio **no publica puerto** (correcto por SECURITY INVARIANT 1),
  tampoco cabe hacerle `curl` desde el host ni apuntarle una UI externa tipo
  Open WebUI. La red interna del compose es el único camino.

Único procedimiento hoy:

```
docker compose exec ollama ollama pull llama3.1:8b
docker compose exec ollama ollama list
```

### La asimetría: los ejecutores de nube SÍ tienen vista

Esto es lo que hace que la ausencia chirríe. Para los tres CLIs de nube existe
un flujo web completo, construido a propósito (`backend/agentopsy/executors/login.py`,
cabecera del módulo, 2026-07-15):

- Relaya el login del propio CLI dentro del contenedor: lanza el proceso sin
  shell (argv de enum cerrada, SECURITY INVARIANT 4), lee su salida hasta
  encontrar `{url, code}` y mantiene vivo el proceso hasta que el flujo termina.
- Distingue por CLI: **Codex** imprime URL estática + código de un solo uso y
  sale solo; **Claude Code** además bloquea esperando que le pegues el código de
  vuelta (`needs_code_input=True`, relayado a stdin por `submit_code`).
- `login_status` devuelve `waiting | logged_in | error | expired` cruzando el
  proceso vivo con el mismo sondeo real que usa `/api/capabilities`.
- Hay "Renovar sesión" con `force=true`, porque el sondeo puede mentir
  (`claude auth status` devuelve `loggedIn: true` con el token ya caducado).
- **Y hay degradación explícita**: Gemini no se puede relayar (Google rechaza el
  flujo con `IneligibleTierError` antes de imprimir URL), así que
  `routers/executors.py:64` responde **409 con la cabecera
  `X-Agentopsy-Manual-Command`** llevando el comando literal, y la UI pinta ese
  comando más un botón de recomprobar — en vez de un spinner infinito (RULE 2).

Resumen de la asimetría:

- **Elegir modelo**: simétrico. Los cuatro ejecutores son `editable` en Ajustes.
- **Aprovisionar el ejecutor**: asimétrico. Nube = crear sesión → tiene flujo web
  completo, con caso degradado incluido. Ollama = descargar modelo → no tiene
  nada.

Lo llamativo es que Ollama es el ejecutor que el README vende como la opción
100 % local y la garantía de privacidad, y es el único cuyo aprovisionamiento
obliga a bajar a la terminal.

### Propuesta (no implementada)

El trabajo es pequeño porque la infraestructura ya está montada:

1. **Mínimo, cero backend.** Reutilizar el precedente de Gemini: cuando Ollama
   responda pero `/api/tags` venga vacío, enseñar el comando exacto
   (`docker compose exec ollama ollama pull <modelo>`) en lugar de la frase
   estática. Es literalmente el patrón `X-Agentopsy-Manual-Command` que ya
   existe.
2. **Completo.** Un endpoint proxy a `POST /api/pull` de Ollama, que emite
   progreso por stream, y un botón "Descargar modelo" junto al selector que ya
   está en Ajustes. El diálogo con progreso ya existe para el login de los CLIs
   y es reutilizable casi tal cual.

Detalle relacionado, del apéndice 1: `is_available()` devuelve `True` con cero
modelos instalados, porque solo sondea `/api/version`. Si se toca esto,
arreglar ambas cosas a la vez — la UI debería decir "disponible, sin modelos"
y no "disponible" a secas.

---

## Apéndice 3 — ¿y si instalo Ollama en el host en vez de en el contenedor?

Pregunta de partida: si descargo un modelo en el portátil (Ollama nativo), ¿lo
usa el contenedor?

### No: son almacenes distintos

El contenedor guarda los modelos en el volumen con nombre `ollama:/root/.ollama`
(`docker-compose.yml`, servicio `ollama`). Un `ollama pull` en el host los deja
en `~/.ollama`. No hay ninguna relación entre ambos: descargar en el host no
llena el contenedor.

### Lo que sí se puede hacer: apuntar la app al Ollama del host

`OLLAMA_HOST` es editable desde *Ajustes → Ejecutores*
(`web/src/pages/SettingsPage.tsx:389-407`), así que redirigir el `api` a un
Ollama externo no requiere tocar código. Dos obstáculos en Linux:

1. El daemon del host escucha en `127.0.0.1:11434` por defecto — el contenedor
   no llega. Habría que arrancarlo con `OLLAMA_HOST=0.0.0.0`, lo que lo expone a
   la LAN salvo firewall. En una herramienta forense es exactamente lo que el
   compose evita a propósito (SECURITY INVARIANT 1: todo en `127.0.0.1`, y el
   servicio `ollama` ni siquiera publica puerto).
2. El compose no define `host.docker.internal`: no hay
   `extra_hosts: ["host.docker.internal:host-gateway"]`. Habría que meter a mano
   la IP del gateway del bridge, que no es estable entre entornos.

### La variante limpia, si aun así se quiere gestionar desde el host

Montar `~/.ollama` del host en el contenedor en lugar del volumen con nombre.
Un cambio de una línea, no expone ningún puerto, y permite `ollama pull` con el
CLI nativo viéndolo el contenedor. Requiere Ollama instalado en el host (hoy no
lo está en esta máquina).

### Por qué probablemente no compensa (en este portátil)

El motivo habitual para sacar Ollama del contenedor es el acceso a la GPU —y el
compose, en efecto, **no le pasa ninguna**: el servicio `ollama` no tiene `gpus`,
ni `deploy.resources.devices`, ni `runtime: nvidia`. (El bloque `devices:` de la
línea 73 es el `/dev/fuse` de los maletines, nada que ver.)

Pero en esta máquina el argumento no aplica:

- GPU: Intel Iris Xe integrada (Alder Lake-P). Ollama solo acelera con CUDA o
  ROCm; la iGPU de Intel se queda fuera. Va por CPU dentro y fuera del
  contenedor — no se gana rendimiento moviéndolo.
- RAM: 15 GB totales, con el stack forense completo encima. Poco margen para un
  modelo que merezca la pena.

**Conclusión**: dejar el contenedor como está y usar
`docker compose exec ollama ollama pull`. Si el análisis local resulta
demasiado lento —que lo será—, la salida no es mover Ollama al host, es usar un
ejecutor de nube, que es para lo que existe todo el flujo de login del
apéndice 2.

---

## Apéndice 4 — qué modelo aguanta esta máquina (llmfit)

Medido con [llmfit](https://github.com/AlexsJones/llmfit) v1.1.14, instalado en
`~/.local/bin/llmfit` (script oficial, modo `--local`, sin sudo).

### Hardware detectado

```
CPU   12th Gen Intel Core i7-1260P — 16 hilos
RAM   15,23 GB totales · 7,46 GB disponibles (con el stack levantado)
GPU   Intel Alder Lake-P GT2 [Iris Xe Graphics] (integrada)
       backend SYCL · unified_memory: true · vram_gb: 15,23
```

### Dos correcciones a lo que reporta llmfit

Sus números salen optimistas por dos motivos, y conviene tenerlos presentes
antes de fiarse del ranking:

1. **Cuenta los 15,23 GB enteros como VRAM** y estima en modo GPU con backend
   SYCL, porque la Iris Xe usa memoria unificada. Pero **Ollama no soporta
   SYCL ni la iGPU de Intel** — solo acelera con CUDA o ROCm. Los ~10-28 tok/s
   que estima son para un backend que Ollama no va a usar; en CPU pura, menos.
2. **`available_ram_gb` es 7,46**, no 15,23. Con `api`, `web`, `ollama` y los
   dos maletines corriendo, todo lo que pida 9-10 GB no entra de verdad: haría
   swap.

Resultado: los modelos de 8B que encabezan el ranking (DeepSeek-R1-0528-Qwen3-8B
y compañía, ~10 GB) quedan descartados en la práctica. La franja realista es
3-4B, que es justo la que llmfit marca como `fit_label: Perfect`.

### Candidatos reales (todos con capacidad `tool_use`, que el agente necesita)

| score | modelo | params | RAM | tps~ | GGUF |
|---|---|---|---|---|---|
| 85.2 | `khazarai/Qwen3-4B-Qwen3.6-plus-Reasoning-Distilled-GGUF` | 3,13B | 4,1 GB | 28 | sí (Q4_1/Q6_K/Q8_0) |
| 84.2 | `khazarai/Qwen3-4B-Kimi2.5-Reasoning-Distilled-GGUF` | 3,13B | 4,9 GB | 28 | sí (Q4_K_M/Q6_K/Q8_0/BF16) |
| 83.4 | `sajan-sarker/Qwen3.5-4B-LoRA-GRPO-CyberSec-Reasoner` | 4,21B | 5,2 GB | 21 | **NO** |

### Trampa: el de CyberSec no es instalable en Ollama tal cual

Es el más apetecible por temática (razonador de ciberseguridad, encaja con el
dominio de Agentopsy), pero comprobado contra la API de HuggingFace
(`/api/models/<repo>`) solo publica `model.safetensors` — **ningún fichero
`.gguf`** — y además es un LoRA, no un modelo fusionado.

Ollama consume GGUF. Para usarlo habría que fusionar el LoRA con su base y
convertir a GGUF a mano. No es un `pull`.

### Cómo instalar los que sí valen

`backend/agentopsy/executors/base.py:72` acepta explícitamente etiquetas con
espacio de nombres (`hf.co/user/model:tag`), así que se puede tirar directo de
HuggingFace sin pasar por la biblioteca de Ollama:

```
docker compose exec ollama ollama pull hf.co/khazarai/Qwen3-4B-Qwen3.6-plus-Reasoning-Distilled-GGUF:Q8_0
docker compose exec ollama ollama pull hf.co/khazarai/Qwen3-4B-Kimi2.5-Reasoning-Distilled-GGUF:Q8_0
docker compose exec ollama ollama pull qwen3:4b
```

~3,3 GB cada uno de los dos primeros. El tercero es de la biblioteca oficial y
sirve de **línea base**: si un resultado sale raro, permite distinguir si el
problema es el modelo o el cableado.

Se cambian desde *Settings → Analysis engine → Ollama*, pegando el nombre
completo incluido el prefijo `hf.co/` y el sufijo de cuantización.

### Expectativa realista

Un 4B en CPU cabe y funciona, pero el agente de Agentopsy hace un bucle de
tool-use con turnos largos y mucho contexto de caso. Para verificar que el
cableado funciona, sobra. Para trabajar un caso de verdad, la salida es un
ejecutor de nube — que es para lo que existe todo el flujo de login del
apéndice 2.

---

# Pruebas Ollama

Registro de la puesta en marcha del ejecutor local y de por qué, en esta
máquina, no llega a completar una iteración del agente. 2026-09-07.

## Modelos instalados

Con el contenedor `agentopsy-ollama` levantado, vía `docker compose exec`:

```
qwen3:4b                                                             2,5 GB
hf.co/khazarai/Qwen3-4B-Qwen3.6-plus-Reasoning-Distilled-GGUF:Q4_1   2,6 GB
hf.co/khazarai/Qwen3-4B-Kimi2.5-Reasoning-Distilled-GGUF:Q4_K_M      2,5 GB
```

Los tres son Qwen3-4B (`qwen3:4b` de la biblioteca oficial; los otros dos,
destilados de Qwen3-4B-Thinking-2507 por khazarai). Se eligió Q4 sobre Q8
porque en CPU la inferencia va limitada por ancho de banda de memoria: la mitad
de bytes es aproximadamente el doble de tok/s.

Confirmado que el formato `hf.co/usuario/repo:CUANT` funciona de extremo a
extremo: `executors/base.py:72` ya admite etiquetas con espacio de nombres.

## Configuración resultante (`/cases/config.json`)

```json
{
  "CLAUDE_CODE_MODEL": "opus",
  "DEFAULT_EXECUTOR": "ollama",
  "OLLAMA_MODEL": "hf.co/khazarai/Qwen3-4B-Kimi2.5-Reasoning-Distilled-GGUF:Q4_K_M"
}
```

## El fallo observado

Al escribir en el chat del caso, la UI devuelve:

```
The model Ollama failed during iteration 1: ExecutorError: no se pudo
contactar con Ollama en http://ollama:11434/api/generate: timed out.
```

## Qué pasó en realidad

**El mensaje engaña: Ollama contestó perfectamente.** Los logs del contenedor:

```
slot operator(): new prompt, n_ctx_slot = 4096, n_keep = 4, task.n_tokens = 2050
slot print_timing: n_decoded = 939, tg = 4.68 t/s
srv          stop: cancel task, id_task = 0
slot      release: stop processing: n_tokens = 2989, truncated = 0
```

Secuencia real:

1. Prompt de entrada: **2050 tokens** (agent.md + contexto del caso).
2. El modelo generó **939 tokens a 4,7 tok/s** ≈ 200 s solo de decodificación,
   más el prefill de esos 2050 tokens en CPU.
3. Superado el presupuesto, **Agentopsy canceló la petición** (`cancel task`
   viene del cliente, no del servidor). Nunca terminó de responder.

El presupuesto es `DEFAULT_TIMEOUT_S = 300` (`executors/base.py:52`), porque no
hay `AGENTOPSY_EXECUTOR_TIMEOUT` fijado.

## Las cuatro causas, por orden de peso

### 1. Velocidad real: 4,7 tok/s, no los ~28 que estimaba llmfit

El apéndice 4 ya avisaba de que la estimación de llmfit asumía GPU con backend
SYCL. Medido de verdad: **4,7 tok/s**. Un factor 6 por debajo. Los logs
confirman que va todo por CPU (`load_tensors: CPU model buffer size`, ningún
`offload`).

### 2. Es un modelo *Thinking*

Qwen3-4B-Thinking-2507 gasta cientos de tokens razonando en `<think>` antes de
contestar. Para responder a un «hola» llevaba 939 tokens y aún no había
terminado. A 4,7 tok/s, el razonamiento interno se come el presupuesto entero
antes de producir una sola línea útil.

Los logs muestran `srv init: chat template, thinking = 0`: el bloque de
razonamiento no se separa, se emite como tokens normales.

### 3. `stream: false`

`executors/ollama.py:113` envía `"stream": False`. Agentopsy espera la respuesta
COMPLETA en una sola lectura HTTP. No hay tokens parciales, ni progreso en la
UI, ni forma de aprovechar lo generado cuando salta el timeout: los 939 tokens
que sí produjo se tiran a la basura.

### 4. Ventana de contexto justa

`n_ctx = 4096` y el prompt ya ocupa 2050. La mitad de la ventana se va en el
system prompt y el contexto del caso antes de que el perito escriba nada. El log
avisa además: `n_ctx_seq (4096) < n_ctx_train (262144)`.

## Hallazgo aparte: el mensaje de error es incorrecto

`executors/ollama.py:155-157`:

```python
except (urllib.error.URLError, OSError) as exc:
    self._audit_finish(audit, case_id, started, error=str(exc))
    raise ExecutorError(f"no se pudo contactar con Ollama en {url}: {exc}") from exc
```

Un **timeout de lectura** de `urlopen` levanta `OSError`, así que cae en la
misma rama que «servicio caído». El resultado es que un Ollama sano pero lento
se reporta como inalcanzable, y el operador se pone a depurar la red cuando el
problema es el presupuesto de tiempo.

Choca con RULE 2 (fallos accionables): el mensaje debería distinguir
«no contesta» de «no terminó en N segundos» y, en el segundo caso, decir qué
subir (`AGENTOPSY_EXECUTOR_TIMEOUT`).

Agravante: los botones de la UI ofrecen 60 / 120 / 300 s, y **300 ya es el
valor por defecto**. Desde la interfaz no se puede subir el límite; hay que
tocar `config.json` o la variable de entorno.

## Intento de convertir el modelo de CyberSec (fallido)

Del apéndice 4 quedaba pendiente `sajan-sarker/Qwen3.5-4B-LoRA-GRPO-CyberSec-Reasoner`,
sin GGUF publicado. Se intentó generarlo. **Corrección al apéndice 4**: no es un
adaptador LoRA, es el LoRA ya fusionado (`model.safetensors`, 8,41 GB); el
nombre solo dice cómo lo entrenaron. No hacía falta fusionar nada.

Cadena ejecutada con `ghcr.io/ggml-org/llama.cpp:full` (trae
`convert_hf_to_gguf.py` y `llama-quantize`, no hay que instalar nada en el host):

1. Descarga del repo: 8,43 GB. **Ojo**: `/tmp` en esta máquina es tmpfs de
   7,6 GB — hay que trabajar en disco (`~/.cache`), no en `/tmp`.
2. Conversión: falla con
   `ValueError: Tokenizer class TokenizersBackend does not exist`.
   El `tokenizer_config.json` usa convención de transformers 5 y la imagen trae
   la 4.57.6. **Solución**: poner `"tokenizer_class": "Qwen2Tokenizer"` (Qwen3.5
   usa el BPE de Qwen2). Con eso convierte: 426 tensores, 8,42 GB f16.
3. Cuantización a Q4_K_M: 2,71 GB (5,13 bits por peso).
4. `ollama create`: registra bien, pero **no carga**:
   `error loading model: missing tensor 'blk.32.attn_norm.weight'`.

### Por qué no hay arreglo

Qwen3.5 es una arquitectura **híbrida**: 32 capas, la mayoría `linear_attention`
(estilo Mamba — el `config.json` trae `mamba_ssm_dtype`, `linear_conv_kernel_dim`)
y una `full_attention` cada 4 (`full_attention_interval: 4`), más una capa MTP
de predicción multi-token.

El GGUF salía con `general.architecture = qwen35`, `block_count = 33` y
`nextn_predict_layers = 1`, pero **cero tensores para `blk.32`**: el conversor
cuenta la capa MTP y no la escribe. Corregir el metadato a `block_count = 32`
con `gguf_set_metadata.py` solo mueve el error a
`missing tensor 'blk.31.nextn.eh_proj.weight'`.

Causa raíz, leyendo la cabecera del `model.safetensors` original:

```
tensores totales: 426
tensores MTP/nextn: NINGUNO
índices de capa presentes: 0 .. 31 (32 capas)
```

**Quien subió el modelo descartó la cabeza MTP al guardar el fine-tune**, y el
motor `qwen35` de Ollama 0.31.1 la exige. Los pesos no existen: no es
convertible. Descartado y borrados los 18,4 GB de restos.

### Los otros dos sí serían viables

Comprobado antes de gastar el ancho de banda, contra
`model.safetensors.index.json` de cada uno:

| repo | tensores | capas | MTP |
|---|---|---|---|
| `TeichAI/Qwen3.5-4B-Claude-Opus-Reasoning-Distill` | 738 | 0..31 | **sí** (`mtp.layers.0.*`) |
| `Jackrong/Qwen3.5-4B-Claude-4.6-Opus-Reasoning-Distilled` | 738 | 0..31 | **sí** |

Ambos traen la capa que le faltaba al de CyberSec, así que la conversión
debería completarse. Pendiente de hacer — y con la reserva de que, a 4,7 tok/s,
el problema de fondo seguiría siendo el mismo.

## Conclusión

El cableado Ollama ↔ Agentopsy **funciona**: el modelo carga, recibe el prompt
del agente y genera. Lo que no funciona es el presupuesto: 4,7 tok/s contra un
agente que hace bucle de tool-use con prompts de 2000+ tokens por turno.

Órdenes de actuación, de más a menos útil:

1. **Usar un ejecutor de nube** para trabajar casos de verdad. Es la conclusión
   a la que apuntan todos los apéndices.
2. Si se quiere seguir en local, **un modelo sin *thinking*** (`qwen3:4b` con el
   razonamiento desactivado, o un instruct puro): elimina el gasto que ahora se
   lleva el presupuesto entero.
3. **Subir `AGENTOPSY_EXECUTOR_TIMEOUT`** por encima de 300 en `config.json`
   (desde la UI no se puede). Con 900-1200 s una iteración terminaría, aunque
   la experiencia sea inviable para un caso completo.
4. **Arreglar el mensaje de error** y, ya puestos, considerar `stream: true`:
   hoy un timeout tira 939 tokens ya calculados.

## Segunda prueba: con `AGENTOPSY_EXECUTOR_TIMEOUT = 1200`

### Cómo se aplicó

La clave se puede fijar por API, pero `/api/config` exige el token de sesión
(`security.py:39`). Editar `projects/config.json` desde el host **no basta** por
dos motivos:

- El fichero lo escribe el contenedor como root: `PermissionError` desde el host.
- `Config.__init__` (`config.py:19`) lee `config.json` UNA vez al importar. Solo
  la ruta de la API refresca el singleton en vivo
  (`routers/config.py:183`, `config._data[key] = value`).

Camino que sí funciona: escribir el fichero desde dentro del contenedor y
reiniciar el servicio.

```
docker exec agentopsy-api python -c "..."   # edita /cases/config.json
docker compose restart api
```

Verificado en caliente: `resolve_timeout({})` devuelve `1200`.

### Resultado: el timeout era el problema, y se resolvió

```
[GIN] 2026/09/07 - 22:00:31 | 200 | 4m8s | 172.20.0.5 | POST "/api/generate"
```

**4 min 8 s y HTTP 200.** La misma petición que antes moría a los 300 s ahora
completa. En la UI el turno aparece con `EXECUTION CHAIN · 0 STEPS · RECORDED`,
es decir: Agentopsy recibió y parseó correctamente el envoltorio del modelo.

### Pero la respuesta seguía hablando de un error

En pantalla:

> Lamento informarte que hubo un error al contactar el modelo Ollama. Por favor,
> intenta nuevamente.

Eso **no lo escribió Agentopsy: lo escribió el modelo**. El historial
(`/cases/cases/<id>/chats/main.jsonl`) lo deja claro:

```
user:      'opla'
assistant: 'The model `Ollama` failed during iteration 1: `ExecutorError: no se
            pudo contactar con Ollama en http://ollama:11434/api/generate: timed out`.'
user:      'ola'
assistant: 'Lamento informarte que hubo un error al contactar el modelo Ollama.
            Por favor, intenta nuevamente.'
```

### Hallazgo: los fallos de infraestructura se persisten como turnos del asistente

Agentopsy guarda sus propios errores de ejecución en `chats/main.jsonl` con
`role: assistant`, indistinguibles de lo que el modelo dijo de verdad. En el
turno siguiente ese texto vuelve al modelo dentro de su propio historial.

Un modelo de 4B lee «hubo un error contactando con Ollama» atribuido a sí mismo
y lo repite. Es envenenamiento de contexto: el fallo de una corrida contamina
todas las siguientes de esa conversación, y de forma especialmente cruel porque
el síntoma (un mensaje de error) es idéntico a la causa original, lo que lleva a
diagnosticar de nuevo el ejecutor cuando ya está arreglado.

Merecería un `role` distinto (o un flag) para los errores de infraestructura,
de modo que la UI los siga pintando pero queden FUERA del historial que se le
manda al modelo.

**Mitigación inmediata**: abrir un chat nuevo tras cualquier fallo del ejecutor.

### Estado

- Cableado Ollama ↔ Agentopsy: **funciona de extremo a extremo**.
- Coste real: ~4 min por turno con un prompt de ~2000 tokens, a 4,7 tok/s.
- Sigue en pie la conclusión del apartado anterior: viable para verificar la
  integración, inviable para instruir un caso completo.

## Tercera prueba: caso nuevo, historial limpio

Caso «segunda prueba», sin turnos de error previos. Prompt del perito:
«revisa la evidencia».

**Respuesta del agente** (coherente, sin rastro del envenenamiento anterior):

> Please specify which evidence you would like to review (e.g., time zone,
> accounts, artifacts).

Confirma el diagnóstico del apartado anterior: con el historial limpio el
modelo responde con normalidad. `EXECUTION CHAIN · 0 STEPS`: no llamó a ninguna
herramienta.

### Los números

```
[GIN] 2026/09/07 - 22:32:07 | 200 | 10m38s | POST "/api/generate"
slot print_timing: n_decoded = 2292, tg = 4.25 t/s
slot      release: stop processing: n_tokens = 2305, truncated = 1
```

- **10 min 38 s** para producir una sola línea de salida.
- 2292 tokens generados a 4,25 t/s — casi todos de razonamiento interno.
- 638 s consumidos de los 1200 disponibles: entró, pero sin holgura.

### `truncated = 1`: el modelo pierde sus propias instrucciones

El dato decisivo. `n_ctx = 4096`, el prompt del agente ocupa ~2000 y el modelo
generó 2292 de razonamiento: la suma se sale de la ventana y llama.cpp descarta
el principio del contexto durante la propia generación.

Es decir: mientras «piensa», el modelo va perdiendo el system prompt, el
playbook y el contexto del caso que Agentopsy le acababa de dar. Que responda
pidiendo aclaración en vez de usar una herramienta es la consecuencia esperable
— para cuando decide qué hacer, ya no tiene delante la allowlist de tools.

### Agentopsy no puede subir la ventana

`executors/ollama.py:112-116` construye el payload así:

```python
payload = {"model": model, "prompt": prompt, "stream": False}
temperature = ctx.get("temperature")
if temperature is not None:
    payload["options"] = {"temperature": float(temperature)}
```

Nunca se envía `options.num_ctx`, así que Ollama aplica su default de 4096. No
hay clave en Settings ni variable de entorno que lo cambie: para un agente cuyo
prompt base ya ronda los 2000 tokens, y más aún con un modelo *thinking*, esa
ventana es insuficiente y el backend no ofrece forma de ampliarla.

Es el tercer hallazgo accionable de esta serie, junto al mensaje de error
engañoso y a los fallos persistidos como turnos `assistant`.

### Balance de la serie

| prueba | timeout | resultado | duración |
|---|---|---|---|
| 1ª — Kimi2.5, historial vacío | 300 s | cancelada a los 300 s | — |
| 2ª — Kimi2.5, historial con error | 1200 s | OK, pero repite el error del historial | 4 m 08 s |
| 3ª — `qwen3:4b`, caso nuevo | 1200 s | OK, respuesta coherente, 0 tools, contexto truncado | 10 m 38 s |

> **Corrección**: esta tercera prueba se hizo ya con `qwen3:4b`, no con el
> destilado de Kimi. Y con ella cae la idea de «usar un modelo sin *thinking*»:
> **Qwen3 razona por defecto**, hay que desactivarlo explícitamente. Los 2292
> tokens de razonamiento de arriba son de `qwen3:4b`. La palanca que parecía
> quedar libre no existía.

La integración es correcta. El modelo es el que no da: 4-4,7 tok/s y una
ventana de 4096 no sostienen un bucle de tool-use.

## Cuarta prueba: `qwen3:4b` llega a llamar una herramienta

Mismo caso, segundo turno. Prompt: «recisa la evidecia» (con las erratas del
original).

### Lo que hizo

Del `chats/main.jsonl`:

```
iteración 1 · tool_result · consultar_conocimiento {doc_id: ''} → status: error
   "doc_id '' does not exist. Package reference: []. Nodes of this case: []
    (create it with anotar_conocimiento)."
iteración 2 · final
   "No evidence has been recorded yet. Please use `anotar_conocimiento` to add
    evidence first."
```

Tiempos (dos llamadas a `/api/generate` para un solo turno del perito):

```
[GIN] 22:45:01 | 200 | 9m7s  | POST /api/generate   ← iteración 1
[GIN] 22:50:01 | 200 | 4m59s | POST /api/generate   ← iteración 2
                              n_tokens 3878 y 2708, truncated = 0 en ambas
```

**14 minutos** para el turno completo. Sin truncado esta vez.

### Avance real

Es la primera vez que el modelo **emite una llamada a herramienta** en vez de
limitarse a pedir aclaración. El bucle de tool-use de Agentopsy funciona
extremo a extremo con un modelo local: el envoltorio se parsea, la tool se
resuelve, el error vuelve al modelo y hay una segunda iteración.

### Los dos fallos del modelo

1. **Llamada malformada**: `consultar_conocimiento` con `doc_id: ''`. Un 4B no
   sostiene el contrato de argumentos.
2. **Vuelve a hacer de loro**. El mensaje de error termina con
   `(create it with anotar_conocimiento)` y el modelo se lo traslada AL PERITO
   como instrucción: «Please use `anotar_conocimiento` to add evidence first».
   Pero `anotar_conocimiento` es una tool suya, no algo que el operador pueda
   ejecutar desde la UI. Mismo patrón que en la segunda prueba: el modelo repite
   el texto que tiene delante en lugar de actuar sobre él.

   Nota de diseño: los mensajes de error de las tools están redactados para un
   agente competente («créalo con X»). Un modelo pequeño los reenvía al humano.

### Observación sobre el audit log

El `audit.jsonl` del caso contiene:

```
executor_run_start: 3 · executor_run_finish: 3 · evidence_register: 1 · os_profile_routed: 1
```

**Ninguna entrada `tool_run_*`** para la llamada fallida a
`consultar_conocimiento`. El intento queda registrado en el historial del chat
(`activity` / `tool_calls`) pero no en la cadena de custodia.

Puede ser deliberado —es una tool in-process que ni siquiera llegó al maletín, y
falló en validación de argumentos— pero conviene decidirlo a propósito: una
llamada que el agente emitió durante un caso es un hecho del expediente, y hoy
solo sobrevive en el chat.

### Conclusión de la serie

Con `qwen3:4b`, ventana de 4096 y ~4,3 tok/s:

- El bucle de agente **funciona**: llamada, error, reintento, respuesta final.
- Cuesta **14 minutos por turno** y las llamadas salen malformadas.
- Una instrucción real de caso son decenas de turnos. No es viable.

Sigue en pie la recomendación de toda la serie: **ejecutor de nube** para
trabajar, Ollama para verificar que la integración no está rota.

---

# Prueba con ejecutor de nube (Claude Code · sonnet)

Mismo caso y misma evidencia que las pruebas locales, cambiando solo el
ejecutor: `DEFAULT_EXECUTOR: claude-code`, `CLAUDE_CODE_MODEL: sonnet`.
La comparación es directa.

## Métricas del turno

```
usuario 22:59:05  →  agente 23:16:57      ≈ 18 minutos
22 executor_run · 19 iteraciones
10 tool_run en el maletín · 55 tool_result en total
20 findings (8 critical) · 1 pivot · 1 informe final
```

Herramientas del maletín usadas: `file_info` (1), `volatility3` (2),
`strings_head` (1), `xxd_head` (3), `aff4imager` (1), `bulk_extractor` (2).

## Lo que hizo

Evidencia: `original.mem`, volcado de RAM de ~958 MB.

**Volatility3 falló las dos veces** (exit 1: no logra establecer una capa de
traducción, no hay ISF que case con ese kernel). En lugar de detenerse, el
agente cambió de estrategia: confirmó que no era AFF4, inspeccionó cabeceras con
`xxd_head` en offsets concretos, y reconstruyó el incidente entero a partir de
`strings_head` y `bulk_extractor`.

Cronología que reconstruyó, con offset de memoria para cada afirmación:

1. **2015-08-23** — reconocimiento con `Wget/1.16` desde varios hosts 10.20.0.x
   contra el dashboard de XAMPP.
2. **2015-09-02** — `sqlmap/1.0-dev-20150902` desde 192.168.56.102 contra el
   módulo SQLi de DVWA. Enumera el esquema de phpMyAdmin y extrae el registro
   del usuario `gordonb` (hash MD5 `e99a18c4…` = "abc123"), **verificado contra
   el `INSERT` original en otro offset**.
3. **2015-09-03 07:10** — subida de `phpshell.php` (31 bytes) por el File Upload
   de DVWA, fecha recuperada de la salida de un `dir` de Windows en memoria.
4. **2015-09-03 07:17:58** — RCE confirmado: `phpshell.php?cmd=mkdir%20abc`
   devuelve 200.
5. **2015-09-03 07:31:54** — stager Meterpreter (`phpshell2.php`) ejecutándose;
   la cadena «Evaling main meterpreter stage» aparece en memoria.
6. APIs `stdapi_registry_create_key` / `set_value` presentes: capacidad de
   persistencia, aunque no se recuperan las claves concretas escritas.

También identifica el utillaje (`c99shell` de ccteam.ru, `hiderefer.com`,
`pentestmonkey.net`) y sitúa al atacante en una VM Linux consistente con Kali
2015 (Iceweasel 38.2.0).

## Criterio pericial, no solo ejecución

Dos cosas que separan esto de «un modelo llamando herramientas»:

- **No sobreconcluye.** Señala que el entorno parece un laboratorio DVWA de
  entrenamiento, pero marca dos elementos que no encajan (el `c99shell` ruso,
  que no se distribuye en cursos, y la subred 10.20.0.x con 11+ hosts) y afirma
  explícitamente que *la evidencia disponible no resuelve* si aquello derivó en
  actividad no autorizada.
- **Apartado de preguntas abiertas** con seis puntos, cada uno diciendo qué
  haría falta para cerrarlo: un ISF que case para Volatility3, un hive SYSTEM
  para verificar el huso, una imagen de disco para el registro, etc.

## Contraste con el ejecutor local

| | Ollama `qwen3:4b` | Claude Code `sonnet` |
|---|---|---|
| duración del turno | 14 min | 18 min |
| iteraciones | 2 | 19 |
| tools del maletín | 0 | 10 |
| llamadas malformadas | sí (`doc_id: ''`) | no |
| hallazgos | 0 | 20 (8 críticos) |
| resultado | pide aclaración | informe pericial completo |

El coste en tiempo es comparable. Lo que cambia es todo lo demás. Confirma la
conclusión de la serie: la integración local sirve para verificar que el
cableado funciona, el trabajo real necesita un ejecutor de nube.

## Dos observaciones

### `mitre_hints` vacío en los 20 hallazgos

Es el comportamiento diseñado: `agentes/agent.md` (§8) indica que la correlación
ATT&CK se hace cuando el perito la pide («dame la correlación MITRE»), llamando
a `annotate_mitre` por hallazgo. Hasta entonces el tablero de ATT&CK queda
vacío. No es un fallo, pero conviene saberlo: tras un informe así, el paso
siguiente hay que pedirlo.

### Solo 10 de 55 invocaciones de tool llegan al audit log

`audit.jsonl` registra 10 `tool_run_start` / `tool_run_finish` — exactamente las
que se ejecutaron en el maletín, cada una con `stdout_sha256`, `stderr_sha256`,
`tool_version`, `exit_code` y el encadenado `prev_hash` / `entry_hash`. La
cadena de custodia sobre la evidencia está impecable.

Las otras 45 son tools in-process (`leer_artefacto`, `record_finding`,
`anotar_conocimiento`) que no tocan la evidencia y no aparecen ahí. Se persisten
en `findings.jsonl` y `graphs/`, así que no se pierden, pero quedan fuera de la
cadena encadenada por hash.

Es defendible —el audit log protege lo que se ejecuta SOBRE la evidencia— pero
conviene que sea una decisión consciente y documentada: hoy, reconstruir qué
pidió el agente durante un caso exige leer el chat, no el audit. Mismo detalle
que ya se observó en la cuarta prueba con la llamada fallida a
`consultar_conocimiento`.

## Correlación MITRE: propuesta hecha, dictamen pendiente

> **Esta sección se reescribió.** La primera versión concluía que el agente
> había mentido al decir que persistió las anotaciones. **Era un error de
> diagnóstico mío**, por dos comprobaciones mal planteadas: busqué `mitre_hints`
> en `findings.jsonl` (no es donde se guardan) y el chat no renderiza
> `annotate_mitre` como `tool_result` (así que parecían cero llamadas). El
> agente hizo lo que dijo.

Pedida la correlación ATT&CK, el agente devuelve una tabla y afirma:

> All annotations have been persisted to the board.

**Es cierto.** `mitre_proposals.jsonl` contiene 16 registros —8 hallazgos por
cada uno de los dos turnos en que se pidió (23:22-23:23 y 23:30)— cada uno con
`finding_id`, `technique_ids` y una `note` justificativa.

### Por qué la matriz aparece vacía: son propuestas, no anotaciones

`backend/agentopsy/mitre/coverage.py` documenta dos capas separadas:

1. **Propuesta del agente** (`proposed_by`) → `mitre_proposals.jsonl`.
2. **Dictamen del operador** (`adjudication`) → `mitre_adjudications.jsonl`,
   append-only, el último gana.

El agente **propone**; el perito **adjudica**. Por eso el panel lateral dice
exactamente «4 techniques · **not adjudicated**»: las técnicas están ahí,
esperando el dictamen humano.

Es una decisión de diseño correcta para una herramienta pericial —el modelo no
decide solo qué técnica queda anclada al expediente— pero **la UI no la
explica**. «not adjudicated» es preciso y a la vez opaco: quien no conoce el
modelo de datos ve un tablero vacío y concluye que la correlación falló. Un
enlace o un botón «adjudicar» junto al contador cerraría la distancia.

Nota de método, ya que este apartado nació de un diagnóstico equivocado: el
estado real de la correlación se lee en `mitre_proposals.jsonl` y
`mitre_adjudications.jsonl`. Ni `findings.jsonl` ni el `activity` del chat lo
reflejan.

### Lo que sí es un límite: la semilla se queda corta

`annotate_mitre` valida contra una **enum cerrada**, la semilla
`agentes/_orchestrator/knowledge/mitre_attack_seed.md`, con **49 técnicas**. Un
id fuera de ella «rechaza el hallazgo entero».

El agente propuso 4 técnicas distintas, todas dentro de la semilla:

```
T1505.003 (Web Shell) ×8 · T1059 (Command and Scripting) ×8
T1083 (File and Directory Discovery) ×2 · T1003 (OS Credential Dumping) ×2
```

Pero en la tabla en prosa del turno anterior había citado otras cuatro que
**no** están en la semilla: `T1071.001`, `T1105`, `T1552` y, sobre todo,
**`T1190` · Exploit Public-Facing Application** — la técnica canónica de este
incidente: inyección SQL contra una aplicación web expuesta. Al anclar, esas
desaparecen.

O sea: la correlación que queda en el expediente es correcta pero **incompleta**,
y lo es por la semilla, no por el modelo. Una lista de 49 técnicas centrada en
artefactos de host se queda corta en cuanto el caso tiene componente web o de
red.

Dos cosas a decidir:

- **Ampliar la semilla** para escenarios web/red (T1190 como mínimo).
- **Rechazar por hint, no por hallazgo**: hoy un id no reconocido tumba la
  anotación completa, incluidos los ids que sí eran válidos. Un rechazo parcial
  con aviso conservaría lo bueno.

### Por qué la matriz marca 4 celdas y no 8

Duda recurrente al mirar el tablero: se anotaron 8 hallazgos, pero la matriz
solo enciende 4 casillas. **No es un fallo.** La matriz de ATT&CK indexa por
**técnica**, no por hallazgo, y los 8 hallazgos colapsan sobre 4 técnicas.

Fusionando `mitre_proposals.jsonl` por hallazgo (`coverage.py:78`, «se fusionan
por hallazgo»), el mapa inverso queda así:

| técnica | hallazgos | cuáles |
|---|---|---|
| `T1059` · Command and Scripting Interpreter | 4 | `f8398966` sqlmap · `d09a032a` cmd=dir · `2d918f65` stager Meterpreter · `5b59acc2` main stage |
| `T1505.003` · Web Shell | 4 | `9b432fff` phpshell.php · `e49be3e9` c99shell en memoria · `57a61476` c99shell/ccteam.ru · `2d918f65` phpshell2.php |
| `T1003` · OS Credential Dumping | 1 | `60e049af` credenciales DVWA |
| `T1083` · File and Directory Discovery | 1 | `d09a032a` cmd=dir |

Dos hallazgos aportan **dos técnicas cada uno**:

- `d09a032a` (salida de `cmd=dir` vía phpshell) → `T1059` + `T1083`. Ejecutar el
  comando es una cosa; enumerar el directorio, otra.
- `2d918f65` (stager PHP de Meterpreter) → `T1505.003` + `T1059`. Es webshell y
  es intérprete de comandos a la vez.

Total: **10 pares hallazgo-técnica repartidos en 4 celdas**. La cuenta cuadra.

### Lo que sí encoge la matriz de verdad

El agente había identificado **8 técnicas** en su tabla en prosa. Al anclar solo
pudo usar 4, porque las otras cuatro no existen en la semilla:

| técnica identificada | en la semilla | acabó en la matriz |
|---|---|---|
| T1059 · Command and Scripting Interpreter | sí | sí |
| T1505.003 · Web Shell | sí | sí |
| T1083 · File and Directory Discovery | sí | sí |
| T1003 · OS Credential Dumping | sí | sí |
| **T1190 · Exploit Public-Facing Application** | **no** | **no** |
| T1071.001 · Web Protocols | no | no |
| T1105 · Ingress Tool Transfer | no | no |
| T1552 · Unsecured Credentials | no | no |

Ni siquiera se intentaron: el agente conoce el enum cerrado y se autocensura al
anclar. No hay rechazo visible en ninguna parte —ni en el chat, ni en el audit,
ni en la UI—, así que la pérdida es **silenciosa**. El perito ve 4 técnicas y no
tiene forma de saber que el agente había reconocido 8.

Es el mismo tipo de problema que el «not adjudicated» opaco: el sistema hace lo
correcto internamente y no lo comunica. Aquí, además, se pierde información
pericial real — que el vector inicial fue la explotación de una aplicación web
expuesta (T1190) es la conclusión más importante del caso, y es justo la que no
llega al tablero.

Mínimo accionable, sin tocar la semilla: cuando el agente proponga un id fuera
del enum, **registrarlo como propuesta rechazada visible** en lugar de
descartarla en silencio. El perito decide entonces si la ancla a mano.

---

# ¿Qué modelo local podría completar un análisis?

Serie de pruebas para responder si algún modelo de Ollama, en esta máquina,
llega a hacer un análisis de verdad. **Respuesta corta: ninguno de los
probados**, y el motivo no es el que parecía.

## Hallazgo previo: `num_ctx` sí se puede fijar, vía Modelfile

El apartado «Agentopsy no puede subir la ventana» señalaba que
`executors/ollama.py` nunca envía `options.num_ctx`, así que Ollama aplica su
default de 4096 y el contexto se trunca.

**Hay una vuelta que no exige tocar el código**: un Modelfile puede fijarlo, y
Ollama lo aplica como default de ese modelo derivado.

```
FROM qwen2.5:7b-instruct
PARAMETER num_ctx 16384
```

```
docker exec agentopsy-ollama ollama create agentopsy-q25-7b -f /tmp/Mf
```

Es la mitigación práctica del problema del contexto mientras el backend no
exponga la clave.

Lo que **no** se puede hacer por Modelfile es desactivar el razonamiento:
`PARAMETER think false` → `Error: unknown parameter 'think'`. Y `/no_think` en
el `SYSTEM` tampoco funciona: medido, `agentopsy-qwen3:4b` con ese system sigue
generando 2357 tokens y tarda 351 s en responder una frase. Ollama esconde el
bloque de razonamiento en otro campo, pero los tokens se generan y se pagan.

## Comparativa de velocidad (mismo prompt, una frase de respuesta)

| modelo | tiempo | tokens generados | t/s |
|---|---|---|---|
| `agentopsy-qwen3:4b` (razona) | **351 s** | 2357 | 6,7 |
| `agentopsy-q25-7b` (instruct) | **18,7 s** | 41 | 5,6 |
| `agentopsy-q25-3b` (instruct) | **6,3 s** | 39 | 15,5 |

El dato que importa: la ganancia **no está en tokens por segundo** —el 7B es más
lento por token que el 4B— sino en no generar 2300 tokens de razonamiento para
decir una frase. 19× el 7B, 55× el 3B.

Nota de calidad: el 7B expandió «MFT» como *File Allocation Table* en lugar de
*Master File Table*. El 3B acertó. Una sola muestra, pero apuntada.

## La prueba de verdad: `agentopsy-q25-7b` sobre el volcado de RAM

Caso nuevo, misma evidencia que usó sonnet, `num_ctx 16384`, timeout 1200 s.

```
23:57:17 → 00:42:25     ≈ 45 minutos
4 executor_run: 690 s · 802 s · 1146 s · 67 s   (sin errores)
2 iteraciones · 4 tool_run · 0 findings · SIN respuesta final
```

Secuencia de herramientas:

```
tsk_mmls  exit=1
tsk_fls   exit=1
tsk_mmls  exit=1     ← repite las mismas
tsk_fls   exit=1
```

El campo `text` del turno es `None`: el bucle terminó sin producir nada. La
cuarta llamada al modelo duró 67 s y devolvió algo que no era ni llamada ni
respuesta final, y ahí acabó (`max_iterations` por defecto es 8, así que no se
agotó: simplemente se quedó sin decir nada).

La tercera llamada tardó **1146 s**, a 54 segundos del límite de 1200.

## El diagnóstico, que es lo aprovechable

**El formato de las llamadas dejó de ser el problema.** El 4B mandaba
`doc_id: ''`; el 7B construye llamadas impecables, con tool ids reales y argv
bien formado. Subir de 4B a 7B resolvió eso.

**Lo que falta es criterio, en dos niveles:**

1. **Elección inicial equivocada.** `mmls` y `fls` son de The Sleuth Kit, para
   imágenes de disco particionadas. La evidencia era un volcado de RAM. Sonnet
   empezó por `file_info` justamente para averiguar qué tenía delante antes de
   decidir.
2. **No aprende del fallo.** Vio `exit 1` cuatro veces y repitió las dos mismas
   llamadas. Sonnet, ante dos fallos de `volatility3`, abandonó esa vía y
   reconstruyó el caso entero con `strings_head` y `bulk_extractor`.

Adaptar la estrategia cuando una herramienta falla es lo que separa a los dos, y
no se arregla con más ventana de contexto, ni con más timeout, ni con una
cuantización mejor. Es capacidad del modelo.

## Conclusión de toda la serie

| | `qwen3:4b` | `agentopsy-q25-7b` | Claude Code `sonnet` |
|---|---|---|---|
| duración | 14 min | 45 min | 18 min |
| iteraciones | 2 | 2 | 19 |
| tool_run maletín | 0 | 4 (todas exit 1) | 10 |
| llamadas bien formadas | no | **sí** | sí |
| cambia de estrategia al fallar | — | **no** | **sí** |
| hallazgos | 0 | 0 | 20 (8 críticos) |
| respuesta final | pide aclaración | **ninguna** | informe pericial |

Ollama en esta máquina sirve para **verificar que la integración no está rota**:
el modelo carga, recibe el prompt del agente, emite llamadas válidas y el bucle
de tool-use funciona de extremo a extremo. Para instruir un caso hace falta un
ejecutor de nube.

Queda sin probar si un modelo local mayor (14B-32B) cerraría la brecha de
criterio. En esta máquina no cabe: 15 GB de RAM compartidos con el resto del
stack y sin GPU aprovechable.

---

# Prueba B — no era capacidad del modelo, era la posición en el prompt

**Esta sección corrige la anterior.** La conclusión de «¿Qué modelo local podría
completar un análisis?» era que al 7B le faltaba criterio: elegía herramientas
de disco sobre un volcado de RAM y no aprendía del fallo. **Era un diagnóstico
equivocado.** El modelo nunca vio la instrucción.

## El descubrimiento

`executors/ollama.py:132` audita el prompt íntegro en cada `executor_run_start`.
El que se le mandó al 7B mide **70.543 caracteres ≈ 17.846 tokens**.

Los logs de Ollama de aquella corrida:

```
new prompt, n_ctx_slot = 16384, n_keep = 4, task.n_tokens = 8194
stop processing: n_tokens = 8236, truncated = 0
```

`task.n_tokens = 8194` — exactamente la mitad de los 16384 de la ventana, cuatro
veces idéntico. Y `truncated = 0`: **llama.cpp no cortó nada**. El recorte pasa
antes, en Ollama, que limita el prompt de entrada a la mitad del contexto para
dejar sitio a la generación, **conservando la cola**.

De los 17.846 tokens enviados, al modelo le llegaron 8.194: el último 46 %.

### Qué se perdía y qué sobrevivía

Posición de los hitos dentro del prompt:

```
allowlist ................  1 %
file_info (playbook) ..... 16 %   ← se pierde
tsk_mmls ................. 21 %   ← se pierde
JSON (formato) ........... 49 %
```

La instrucción del playbook —«**Empieza por `file_info`, siempre**»
(`agentes/agent.md:172`)— está al 16 %. Desaparece.

Y esto es lo que **sí** sobrevive, porque son las últimas líneas del prompt:

> «...decide the next one (a batch of plugins, **mmls plus fls**, extracting
> several artifacts). Every turn re-sends the whole conversation, so 5 tools in
> one turn cost much less than 5 turns of one.»

El último texto que el modelo lee usa **«mmls plus fls»** como ejemplo de
agrupar herramientas, y le pide que agrupe varias por turno. El 7B emitió `mmls`
y `fls` juntos, dos veces.

**No ignoró la instrucción: obedeció la única que le llegó.**

## La prueba

A/B sobre el **mismo prompt real** de 70.543 chars sacado del audit, fuera de la
aplicación (sin caso, sin UI, sin custodia). Tres condiciones, midiendo qué
herramienta pide primero.

| condición | primera herramienta | coste |
|---|---|---|
| 1 · ventana 16k, prompt tal cual | **`tsk_fls`** ❌ | 1052 s |
| 2 · ventana 16k + recordatorio **al final** | **`file_info`** ✅ | **1039 s** |
| 3 · ventana 32k, prompt entero | **`file_info`** ✅ | 3082 s |

El recordatorio de la condición 2 son cinco líneas pegadas al final:

```
REMINDER (procedure, overrides any example above): this evidence has NOT been
identified yet. Your FIRST tool call must be `file_info` on the evidence. Do not
call any tsk_* tool until file_info tells you the evidence is a partitioned disk
image.
```

### Lectura

- **Las dos hipótesis se confirman**, pero por caminos de coste muy distinto.
- **La posición gana**: arregla la elección a **coste cero** (1039 s frente a
  1052 s). Es la misma llamada, con el texto en otro sitio.
- **El tamaño también funciona, pero no es viable**: 3082 s contra 1052 s. El
  prefill de 17.846 tokens va a **9,7 tokens/s** en CPU — media hora solo para
  leer el prompt, antes del primer token de respuesta. Con 19 iteraciones serían
  9 horas de puro prefill.
- **El formato también se degradaba**: la condición 1 devolvió el JSON
  malformado (`{{"action"...}}`, llaves dobladas). Las 2 y 3 salieron limpias, y
  la 3 hasta añadió un parámetro sensato (`also_mime: true`). El prompt truncado
  no solo desviaba la decisión: rompía la sintaxis.

## Qué implica para Agentopsy

El problema no es de modelos locales: es de **ensamblado del prompt**. Hoy
`agent.py` monta el prompt con el playbook al principio y notas operativas al
final. Cualquier recorte por la cola —el de Ollama, o el de cualquier motor con
ventana menor que el prompt— se lleva el procedimiento y deja los ejemplos.

Que un modelo de nube no lo sufra no significa que el orden sea correcto:
significa que su ventana lo tapa.

Tres cosas a considerar, en orden de coste:

1. **Mover lo crítico al final del prompt.** El procedimiento obligatorio —«qué
   herramienta primero», «no inventes tool_ids»— debería ir donde sobrevive a
   cualquier recorte. Coste cero, beneficia a todos los ejecutores.
2. **Revisar el ejemplo «mmls plus fls».** Ilustrar el batching con dos
   herramientas de disco, en la última línea del prompt, es un pie forzado hacia
   la elección equivocada cuando la evidencia no es un disco. Un ejemplo
   neutro (o derivado del `detected_kind`) lo evita.
3. **Avisar cuando el prompt no cabe.** Agentopsy sabe cuántos caracteres manda
   (`prompt_chars` ya está en el audit) y podría saber la ventana del modelo. Un
   aviso al operador —«el prompt supera la ventana del modelo, se recortará»—
   convierte un fallo silencioso en un problema visible. Hoy no hay ninguna
   señal: ni en el chat, ni en el audit, ni en la UI.

## Límite de esta prueba

Mide **una sola decisión** —la primera elección de herramienta— con **una
muestra por condición**. No demuestra que el 7B complete un análisis de 19
iteraciones. Lo que sí hace es descartar las tres explicaciones que se barajaban
(capacidad del modelo, ventana de contexto, cuantización) y señalar un arreglo
de coste cero.

**Siguiente prueba pendiente**: análisis completo con el recordatorio al final,
para ver si el 7B mantiene el rumbo más allá de la primera llamada.
