# FORENSIA — Maletín forense contenedorizado

Maletín de herramientas forenses CLI empaquetado en Docker, en dos imágenes:
**`toolkit-windows`** (artefactos de Windows) y **`toolkit-unix`** (artefactos
Unix-like). Es la base sobre la que los agentes de IA harán *tool-calling*
(sección «Cómo lo consulta la IA»).

> **Aclaración importante.** Son contenedores **Linux** que contienen las
> herramientas para analizar evidencias de Windows y de Unix. No es un contenedor
> con sistema operativo Windows: RegRipper, hayabusa, chainsaw, TSK, Volatility y
> plaso son ejecutables sobre Linux y es el enfoque que el documento de alcance
> asume (`docker compose up` en localhost, multiplataforma). Si en algún momento
> necesitas un binario que SOLO exista para Windows, ese caso se trataría aparte
> con un contenedor Windows real (requiere host Windows en modo *Windows
> containers*).

## Requisitos

- Docker Engine 24+ y Docker Compose v2 (`docker compose`, no `docker-compose`).
- Conexión a Internet en el primer build (descarga paquetes, hayabusa y chainsaw).
- Linux o Windows/macOS con Docker Desktop. En Windows usa WSL2 como backend.

## Estructura

```
forensia/
├── docker-compose.yml              # define los dos maletines
├── docker/forensic-toolkit/
│   ├── Dockerfile                  # multi-stage: base + windows + unix
│   ├── requirements-windows.txt    # parsers Python de artefactos Windows
│   └── .dockerignore
├── docs/CATALOGO_MALETIN.md        # catálogo de herramientas y comandos
├── evidence/                       # <- coloca aquí las evidencias (.raw/.vmdk/.E01)
└── projects/                       # <- salidas, casos e informes
```

## Construir y levantar (un solo comando)

```bash
cd forensia
docker compose up --build -d
```

Comprobar que el maletín está listo:

```bash
docker compose exec toolkit-windows forensia-info
docker compose exec toolkit-unix    forensia-info
```

Debería listar cada herramienta con su ruta. El primer build tarda (compila e
instala plaso y descarga ~50 MB de binarios); los siguientes usan caché.

## Uso básico

1. Copia la evidencia a `./evidence/` (se monta en `/evidence` en **solo
   lectura**).
2. Verifica integridad (cadena de custodia):

   ```bash
   docker compose exec toolkit-windows forensia-hash /evidence/disco.raw
   ```
3. Lanza herramientas; las salidas van a `./projects` (`/cases` dentro):

   ```bash
   docker compose exec toolkit-windows fls -r -p /evidence/disco.raw
   docker compose exec toolkit-unix    log2timeline.py /cases/out.plaso /evidence/linux.raw
   ```

Catálogo completo de herramientas y ejemplos: [`docs/CATALOGO_MALETIN.md`](docs/CATALOGO_MALETIN.md).

## Cómo lo consulta la IA (tool-calling)

El maletín queda **habilitado para que el agente lo consulte** así:

- Cada contenedor se mantiene vivo (`sleep infinity`) con todas las herramientas
  en el `PATH`, las evidencias en `/evidence:ro` y las salidas en `/cases`.
- El orquestador de IA expone cada herramienta CLI como una función invocable y,
  cuando el modelo decide usarla, ejecuta el comando dentro del contenedor:

  ```bash
  docker exec forensia-toolkit-windows <herramienta> <args...>
  ```

  La salida (stdout/stderr/JSON) se devuelve al modelo como resultado de la
  llamada. El agente Windows apunta a `toolkit-windows` y el Unix-like a
  `toolkit-unix`.
- Este es el «contrato CLI→JSON» del documento. La capa de *wrappers* que
  formaliza ese contrato y los *system prompts* de cada agente se implementan en
  la siguiente fase (no incluidos en esta entrega, que cubre Dockerfile + compose).

## Privacidad y cadena de custodia

- Evidencias montadas en **solo lectura**; se trabaja sobre copias y se verifica
  hash SHA-256 antes y después.
- Modelo de IA **local por defecto** (Ollama) por la sensibilidad de las
  evidencias; al usar un modelo cloud, la herramienta debe advertir de que los
  datos salen a una API externa.

## Notas de seguridad del contenedor

`docker-compose.yml` añade `SYS_ADMIN` + `/dev/fuse` para permitir montar
imágenes con `guestmount`/`qemu-nbd` **dentro** del contenedor. Es un privilegio
elevado: si prefieres montar las imágenes en el host y pasar solo la carpeta
montada, comenta `cap_add`, `devices` y `security_opt` en el compose.

## Versiones

Ver tabla de versiones fijadas en [`docs/CATALOGO_MALETIN.md`](docs/CATALOGO_MALETIN.md).
Los binarios descargados (hayabusa, chainsaw) se verifican por SHA-256 durante
el build.
