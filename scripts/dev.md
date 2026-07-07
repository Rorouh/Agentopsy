# Desarrollo local

La vía del usuario final es una sola: `docker compose up --build` y trabajar en
`http://127.0.0.1:5173`. Para desarrollar sin reconstruir imágenes, cada pieza
también corre suelta:

## 1. Backend (una vez)

```bash
cd backend
uv venv --python 3.12 .venv        # o: python3.12 -m venv .venv
. .venv/bin/activate               # Windows: .venv\Scripts\activate
uv pip install -e ".[dev]"         # o: pip install -e ".[dev]"
pytest                             # smoke + security gates
```

El api también corre suelto: `python -m forensia.server` (imprime url + token en
stdout; puerto efímero en 127.0.0.1).

## 2. SPA web (contra un api local)

```bash
cd web
npm install
npm run dev                        # Vite en http://127.0.0.1:5173
```

El proxy de dev de Vite (`web/vite.config.ts`) reenvía `/api` y `/ws` hacia
`http://127.0.0.1:8000`, reproduciendo la topología del nginx del compose
(la SPA siempre es mismo-origen con su backend). Levanta el api en ese puerto:

```bash
cd backend && . .venv/bin/activate
python -c "import uvicorn; from forensia.server import create_app; \
uvicorn.run(create_app(8000), host='127.0.0.1', port=8000)"
```

La SPA obtiene el token de sesión con `GET /api/session` — no hay que copiarlo
a mano.

## 3. El stack completo (lo que ve el usuario)

```bash
docker compose up --build          # web + api + ollama + toolkit-windows + toolkit-unix
docker compose ps                  # estado de los servicios
docker compose logs -f api         # seguir el backend
```
