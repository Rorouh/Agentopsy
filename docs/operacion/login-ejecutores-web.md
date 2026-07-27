# Login web de los ejecutores CLI cloud (2026-07-15)

Cómo el operador **conecta un ejecutor CLI cloud (Codex/Claude/Gemini) desde la
web**, sin abrir una terminal. Agentopsy relaya el flujo *device*/OAuth del propio
CLI dentro del contenedor `api`: lanza el login shell-free, lee su salida hasta
la URL (+ código), y mantiene el proceso vivo hasta que el flujo termina. La
sesión sigue viviendo en el volumen `forensia-cli-auth` (SECURITY INVARIANT 7 —
sin API keys); esto **no** cambia el mecanismo de auth, solo la forma de crearla.

Contexto de auth (seeding, revocado, refresh): [`../../README.md`](../../README.md)
§ *Sesión de los CLIs*.

## El problema

Los tres ejecutores CLI cloud se autentican con la sesión del volumen
`forensia-cli-auth`. Crearla exigía una terminal:
`docker compose exec -it api <cli> login`. La única superficie del producto es la
web (CLAUDE.md: *one surface*), así que un usuario que no abre una terminal no
podía conectar un ejecutor cloud — la fila quedaba «No disponible» sin salida.

## Diagnóstico real de cada CLI (capturado dentro del contenedor `api`)

El parser de cada CLI se diseñó a partir de su **E/S real**, no de suposiciones
(versiones fijadas en la imagen: codex-cli 0.142.5, Claude Code 2.1.187,
gemini-cli 0.49.0):

| Ejecutor | argv de login | qué imprime (stdout) | ¿pega código? | fin |
|----------|---------------|----------------------|---------------|-----|
| **Codex** | `codex login --device-auth` | URL **estática** `https://auth.openai.com/codex/device` + **código** `XXXX-XXXXX` («expires in 15 minutes») | **No** — el código se introduce en el navegador; el CLI sondea en segundo plano | **exit 0** del proceso |
| **Claude** | `claude auth login` | URL de autorización `https://claude.com/cai/oauth/authorize?…` (PKCE + state) y luego bloquea en `Paste code here if prompted >` | **Sí** — se autoriza en el navegador y se **pega de vuelta** el código del callback al stdin | **exit 0** tras validar el código |
| **Gemini** | `gemini` (`NO_BROWSER=true`) | **nada relayable**: el login individual lo rechaza Google en el servidor (`IneligibleTierError: UNSUPPORTED_CLIENT` — «migrate to the Antigravity suite») **antes** de emitir URL | — | — |

Por eso **Gemini no puede relayarse** (`relay_supported=false`) y degrada al
comando manual + «Comprobar» (RULE 2: nunca un spinner que no acaba). Una cuenta
elegible (Workspace/Vertex) puede completar el login manual y pulsar «Comprobar».

## Arquitectura

```
web (modal ExecutorLoginModal)  ──HTTP (token de sesión)──▶  api (routers/executors.py)
                                                              │
                                                              ▼
                                        forensia.executors.login  ──subprocess(shell=False)──▶  codex/claude login
                                        (registro en memoria, 1 login activo por ejecutor)
```

- **Lógica**: `backend/forensia/executors/login.py` (RULE 3). Registro en memoria
  de un login activo por ejecutor; lanza el CLI con **argv fijo por id de enum
  cerrada** (nunca construido con input del usuario — SECURITY INVARIANT 4/5); un
  hilo lector extrae `{url, code}` de la salida (ANSI stripped) y deja el proceso
  vivo. El código de un solo uso y cualquier token **nunca** se escriben en un log
  ni en el audit (RULE 3: el módulo tampoco hace `print()`).
- **Router fino**: `backend/forensia/routers/executors.py`. Todos los endpoints
  con efectos son POST y exigen token de sesión (SECURITY INVARIANT 3 — el
  allowlist CORS + el Host-header middleware cubren el anti-rebinding, igual que
  los demás POST). El id se confina al enum cloud (RULE 2).
- **UI**: `web/src/components/ExecutorLoginModal.tsx`, reutilizado en
  `SettingsPage` (Ajustes → Ejecutores / IA) y `ChatPage` (selector de proveedor).

## Endpoints

| Método | Ruta | Efecto | Respuesta |
|--------|------|--------|-----------|
| `GET` | `/api/executors/login-capabilities` | — | `{executors: {id: {relay_supported, needs_code_input, manual_command, reason}}}` |
| `POST` | `/api/executors/{id}/login` | lanza (o resume) el login | `{executor, state:"waiting", url, code, needs_code_input}` |
| `GET` | `/api/executors/{id}/login/status` | — | `{executor, state, available, reason?, needs_code_input?, code_submitted?}` |
| `POST` | `/api/executors/{id}/login/code` | relaya el código al stdin (Claude) | `{ok, executor}` |
| `POST` | `/api/executors/{id}/login/cancel` | mata el proceso de login | `{ok, executor}` |

`state ∈ {waiting, logged_in, error, expired}`. `id ∈ {claude-code, codex,
gemini}` (Ollama es 100 % local: no tiene login → 422 accionable).

## Estados y detección de fin (RULE 2 — fallo alto, sin fallback silencioso)

- **`start_login`** falla alto y accionable si: id desconocido / no-cloud
  (`ValueError` → 422); el ejecutor **ya tiene sesión** (nada que conectar);
  la salida **no es parseable** (no emite URL en 30 s → el tail capturado); el
  login **no puede relayarse** (`LoginRelayUnsupported` → 409, con el comando
  manual en el detalle y en la cabecera `X-Forensia-Manual-Command`).
- **`login_status`** refleja el proceso vivo + la **comprobación real de
  disponibilidad** (la misma que usa `/api/capabilities`): `waiting` mientras el
  proceso vive; `logged_in` cuando **exit 0** *y* la sesión es usable; `error` si
  exit≠0 (con el tail, con el código redactado) o si terminó 0 pero la sesión no
  es usable (se muestra la razón real, nunca se afirma disponibilidad no
  confirmada); `expired` si supera ~16 min (el código caduca a los ~15).
- **`submit_code`** solo aplica a los CLIs con `needs_code_input=true` (Claude);
  en Codex devuelve error accionable («no requiere pegar código»). El código va
  al **stdin** del proceso, nunca a argv.

## Flujo en la UI

1. `ExecutorLoginModal` consulta `login-capabilities` al abrir.
2. Si `relay_supported=false` (Gemini): muestra el comando manual + «Comprobar»
   (re-sondea `status`).
3. Si `relay_supported=true`: `POST …/login` → muestra URL (+ código) y sondea
   `status` cada 2,5 s. Para Codex el código se introduce **en el navegador**;
   para Claude se **pega de vuelta** en un input → `POST …/login/code`.
4. En `logged_in`: refresca `capabilities` (la fila pasa a *Disponible*) y, desde
   el chat, preselecciona el ejecutor. Al cerrar en `waiting`: `POST …/login/cancel`.

## Seguridad y custodia

- **Shell-free**: `subprocess.Popen([...], shell=False)`, argv fijo por id
  (SECURITY INVARIANT 4/5). El operador nunca inyecta el comando.
- **Sin secretos en logs/audit**: el código de un solo uso y los tokens no se
  registran; el módulo de lógica no hace `print()` (RULE 3). Los tails de error
  redactan el código capturado.
- **Sin API keys** (SECURITY INVARIANT 7): el login crea/renueva la sesión del
  usuario en el volumen; Agentopsy no maneja claves.
- **Token de sesión** en cada POST (SECURITY INVARIANT 3); bind `127.0.0.1` por el
  compose (SECURITY INVARIANT 1).

## Tests

`backend/tests/test_executor_login.py` — con un **CLI de login falso** (stand-in
que imprime URL+código y, ante el código correcto por stdin, «loguea» escribiendo
un fichero-marca): parseo de url+código (Codex), paso a `logged_in` por exit 0,
relayo del código a stdin (Claude), ya-logueado / id desconocido / no-cloud /
Gemini-no-relayable → error accionable, y el gating token/enum de los endpoints.
Nunca un OAuth real ni red: solo se falsea el proceso externo.
