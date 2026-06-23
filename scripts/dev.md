# Desarrollo local

Dos runtimes: backend Python (sidecar) y Electron. En dev, Electron lanza el sidecar desde
el venv del backend (`backend/.venv`), así que solo necesitas prepararlo una vez.

## 1. Backend (una vez)

```bash
cd backend
uv venv --python 3.12 .venv        # o: python3.12 -m venv .venv
. .venv/bin/activate               # Windows: .venv\Scripts\activate
uv pip install -e ".[dev]"         # o: pip install -e ".[dev]"
pytest                             # smoke + security gates
```

El sidecar también corre suelto: `python -m forensia.server` (imprime url + token en stdout).

## 2. Desktop

```bash
cd desktop
npm install
npm run dev                        # arranca Vite (5173) + Electron; Electron lanza el sidecar
```

La ventana debe mostrar la plataforma, los modelos disponibles y el maletín (todo en gris/⚪
hasta que se vendoricen las herramientas — eso es lo esperado en el esqueleto).

## 3. Empaquetar (por OS/arch, en la máquina de ese OS)

```bash
cd backend && pyinstaller build/forensia.spec --noconfirm
cp -r dist/forensia-sidecar ../desktop/resources/forensia-sidecar
cd ../desktop && npm run dist
```
