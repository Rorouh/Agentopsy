#!/usr/bin/env python3
"""Agentopsy exec-agent — el canal api→maletín (§B, sin socket de Docker).

Corre DENTRO de cada maletín (`toolkit-unix` / `toolkit-windows`) y expone un HTTP
mínimo en la red interna del compose. El servicio `api` lo llama para consultar y
ejecutar herramientas sin necesidad del socket de Docker del host:

  - GET  /health                          -> ¿el maletín está vivo? (+ su stage)
  - GET  /versions                        -> manifiesto INMUTABLE de versiones horneado
                                             en el build de la imagen (versions.json):
                                             {"stage": ..., "versions": {binario: versión}}.
                                             Cerrado: no acepta parámetros, no ejecuta
                                             nada, solo sirve identidades allowlisted;
                                             si falta/corrupto -> 500 accionable (RULE 2).
  - POST /which  {"binaries": [...]}       -> subconjunto de binarios presentes en PATH
  - POST /exec   {"argv": [...],           -> ejecuta argv shell-free y devuelve
                  "timeout": N|null,          {exit, stdout, stderr, timed_out,
                  "stdout_path": P|null,      executed_argv} — con stdout_path: {exit,
                  "ewf_image": E|null,        stdout_file, stdout_sha256, stdout_size,
                  "qemu_image": Q|null,       stderr, timed_out, executed_argv} —
                  "qemu_format": F|null}      stdout va a fichero CRUDO

Toda respuesta 200 de /exec incluye `executed_argv`: el argv EXACTO que se pasó a
`subprocess.run` (P0.5-4). Sin desencapsulado es idéntico al solicitado; con EWF difiere
SOLO en el token `.E01` reescrito al bloque raw `ewf1`, y con contenedor qemu SOLO en el
token del contenedor reescrito al raw `raw.img`. El cliente (`forensia.toolkit.maletin`)
lo verifica token a token — un maletín que ejecutara un argv distinto del auditado
rompería FORENSIC INVARIANT 4 y se detecta ahí, no se confía a ciegas.

Canal binario-seguro (`stdout_path`): herramientas como TSK `icat` emiten BYTES CRUDOS
por stdout (hives, EVTX, $MFT, ejecutables). Decodificarlos como texto los corrompe
(cada byte no-UTF-8 → U+FFFD, irreversible). Cuando el api pasa `stdout_path`, el hijo
escribe su stdout DIRECTAMENTE a ese fichero (sin decodificar) en el volumen `/cases`
compartido; el agente devuelve ruta+SHA-256+tamaño en vez del texto. stderr sigue como
texto (es diagnóstico). El api re-hashea el artefacto (defensa en profundidad).

Routing EWF (`ewf_image`): TSK no lee `.E01` nativo. Cuando el api pasa `ewf_image` (el
token EXACTO del argv que porta la ruta `.E01`), el agente lo monta con `ewfmount` (FUSE,
SOLO LECTURA — expone la imagen como bloque raw `ewf1`, NO monta el sistema de ficheros de
la evidencia, FORENSIC INVARIANT 3), reescribe ese token del argv al raw `ewf1`, ejecuta la
tool y **desmonta SIEMPRE** (incl. en error). El `.E01` no se modifica (montaje RO). Si
`ewfmount`/FUSE no está disponible → respuesta no-200 nombrando la dependencia (RULE 2):
jamás se trata el `.E01` como raw. Compone con `stdout_path` (icat sobre `.E01`).

Routing contenedor qemu (`qemu_image`+`qemu_format`): TSK del maletín tampoco abre
vmdk/vdi/qcow2/vhd/vhdx (no trae libvmdk/libvhdi). Cuando el api pasa `qemu_image` (el
token EXACTO del argv con la ruta del contenedor) y `qemu_format` (enum cerrado:
vmdk|vdi|qcow2|vpc|vhdx, elegido por el api desde la triage, no por el LLM), el agente lo
expone con `qemu-storage-daemon` (FUSE export, SOLO LECTURA a nivel de bloque — NO monta el
FS de la evidencia, FORENSIC INVARIANT 3) como raw `raw.img`, reescribe ese token del argv
al raw, ejecuta la tool y **desencapsula SIEMPRE** (para el daemon + desmonta, incl. en
error). El contenedor no se modifica (RO). Mutuamente excluyente con `ewf_image`. Si
qemu-storage-daemon/FUSE no está → no-200 nombrando la dependencia (RULE 2). Compone con
`stdout_path`.

Por qué existe (docs/operacion/exec-agent.md, proximos-pasos.md §B):
La alternativa §A (montar `/var/run/docker.sock` en el `api` + docker-cli) le daría al
api control del Docker del HOST en cada despliegue — una escalada de privilegios que el
repo evita a propósito. Este agente mantiene al api hablando SOLO con los maletines por
la red interna, igual que hace con `ollama`.

SEGURIDAD:
  - Shell-free SIEMPRE: `subprocess.run(argv, shell=False)`; `argv` debe ser list[str]
    no vacía (SECURITY INVARIANT 4).
  - El allowlist de herramientas/flags lo impone el `api` ANTES de llamar (el LLM emite
    un id de tool + params tipados, el backend resuelve el argv real — SECURITY
    INVARIANT 5). Aquí solo se ejecuta el argv ya resuelto.
  - Sin puerto publicado: el maletín no declara `ports:` en el compose, así que este
    servidor (bind 0.0.0.0 DENTRO del contenedor) solo es alcanzable en la red interna
    del compose — nunca desde el host (SECURITY INVARIANT 1), idéntico modelo a `ollama`.
  - Endurecimiento opcional: si `FORENSIA_EXEC_AGENT_TOKEN` está definido, exige la
    cabecera `X-Forensia-Exec-Token` con ese valor; si no, sin auth (confianza de red
    interna).

Solo stdlib: el maletín trae python3 (`http.server` + `json` + `subprocess`).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_PORT = int(os.environ.get("FORENSIA_EXEC_AGENT_PORT", "8666"))
_STAGE = os.environ.get("FORENSIA_STAGE", "base")
_TOKEN = os.environ.get("FORENSIA_EXEC_AGENT_TOKEN") or None
# Tope duro de tiempo por ejecución: una tool que no termina no bloquea al agente para
# siempre. El api pide su propio timeout (acotado a este techo); si pide `null`, este techo
# ES el timeout efectivo — NUNCA se ejecuta con timeout None (sería `subprocess.run` sin
# límite y el api podría hashear un artefacto que aún muta si su cliente HTTP se rinde
# antes, INVARIANT 4). `subprocess.run` mata y recolecta el hijo al expirar, así que al
# retornar el proceso está MUERTO y su fichero de stdout ya no cambia.
_MAX_TIMEOUT_S = 1800
# Lectura por bloques para hashear el stdout crudo sin cargar el fichero entero en RAM
# (icat puede extraer artefactos grandes: $MFT, hives).
_HASH_CHUNK = 1024 * 1024  # 1 MiB
# Techo de tiempo para montar/desmontar el `.E01` con ewfmount (no debe colgar el run).
_EWF_MOUNT_TIMEOUT_S = 120
# Techo para arrancar/parar el FUSE export de qemu-storage-daemon (no debe colgar el run).
_QEMU_MOUNT_TIMEOUT_S = 120
# Formatos de contenedor que qemu desencapsula a raw vía FUSE export. Enum CERRADO: el api
# elige el formato desde la triage (contenido de la evidencia), nunca el LLM (RULE 2). Son
# los nombres de driver de bloque de qemu: `vpc` es VHD (conectix), `vhdx` es VHDX.
_QEMU_FORMATS = frozenset({"vmdk", "vdi", "qcow2", "vpc", "vhdx"})
# Basename del fichero raw que expone el FUSE export dentro del mkdtemp, análogo a `ewf1`.
# El api lo verifica token a token (`maletin._verify_executed_argv`): la reescritura del
# token del contenedor debe apuntar a un absoluto con ESTE basename.
_QEMU_RAW_BASENAME = "raw.img"
# Manifiesto INMUTABLE de versiones de tools, generado durante el build de la imagen
# (gen_versions.py — el build FALLA si una tool declarada no tiene versión determinista
# y no vacía). El exec-agent solo lo SIRVE (`GET /versions`); nunca ejecuta `--version`
# por corrida ni inventa un valor (RULE 2). Override solo para tests.
_VERSIONS_MANIFEST = os.environ.get(
    "FORENSIA_VERSIONS_MANIFEST", "/opt/forensia/versions.json"
)


class _EwfMountError(RuntimeError):
    """`ewfmount` no pudo exponer el `.E01` como raw (binario ausente, FUSE no disponible,
    o el mount falló). El handler la traduce en una respuesta no-200 accionable; nunca se
    trata el `.E01` como raw (RULE 2)."""


def ewf_mount(ewf_image: str, mountpoint: str) -> str:
    """Monta `ewf_image` (`.E01`) con `ewfmount` en `mountpoint` (FUSE, SOLO LECTURA) y
    devuelve la ruta del bloque raw `ewf1`. `ewfmount` expone la imagen como dispositivo
    de bloques raw — NO monta el sistema de ficheros de la evidencia (FORENSIC INVARIANT 3)
    — y abre el `.E01` en solo lectura, así que no lo modifica. Lanza `_EwfMountError`
    (accionable) si el binario no está, FUSE no está disponible o el mount falla."""
    try:
        proc = subprocess.run(  # noqa: S603 — argv list, shell=False
            ["ewfmount", ewf_image, mountpoint],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=_EWF_MOUNT_TIMEOUT_S,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise _EwfMountError(
            "ewfmount no está instalado en el maletín (paquete ewf-tools/libewf); sin él "
            "TSK no puede leer el .E01 (no lo abre nativo). Instálalo en la imagen del "
            "maletín (RULE 1) — no se trata el .E01 como raw (RULE 2)."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise _EwfMountError(
            f"ewfmount agotó {_EWF_MOUNT_TIMEOUT_S}s montando {ewf_image}"
        ) from exc
    if proc.returncode != 0:
        raise _EwfMountError(
            f"ewfmount falló (exit {proc.returncode}) montando {ewf_image}: "
            f"{proc.stderr.strip()} — ¿/dev/fuse presente y CAP SYS_ADMIN? "
            "(docker-compose: devices:[/dev/fuse], cap_add:[SYS_ADMIN])"
        )
    raw = os.path.join(mountpoint, "ewf1")
    if not os.path.exists(raw):
        raise _EwfMountError(
            f"ewfmount no expuso el bloque raw esperado ({raw}) tras montar {ewf_image}"
        )
    return raw


def ewf_unmount(mountpoint: str) -> None:
    """Desmonta un mount FUSE de ewfmount. Best-effort pero SIEMPRE se intenta (soundness:
    no dejar un mount colgado). Prueba `fusermount -u` y, si no, `umount`."""
    for cmd in (["fusermount", "-u", mountpoint], ["umount", mountpoint]):
        try:
            proc = subprocess.run(  # noqa: S603 — argv list, shell=False
                cmd, capture_output=True, text=True, timeout=_EWF_MOUNT_TIMEOUT_S, shell=False
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
        if proc.returncode == 0:
            return


class _QemuMountError(RuntimeError):
    """`qemu-storage-daemon` no pudo exponer el contenedor (vmdk/vdi/qcow2/vhd/vhdx) como
    bloque raw (binario ausente, FUSE no disponible, formato no reconocido, o el export no
    llegó a servir). El handler la traduce en una respuesta no-200 accionable; nunca se
    trata el contenedor como raw (RULE 2)."""


def qemu_mount(qemu_image: str, qemu_format: str, mountpoint_dir: str) -> tuple[str, subprocess.Popen]:
    """Expone `qemu_image` (contenedor `qemu_format`) como fichero raw vía el FUSE export de
    `qemu-storage-daemon`, SOLO LECTURA a nivel de bloque — NO monta el sistema de ficheros
    de la evidencia (FORENSIC INVARIANT 3) — y devuelve `(raw_path, daemon)`. El daemon queda
    corriendo; el llamador DEBE pararlo con `qemu_unmount`. Lanza `_QemuMountError`
    (accionable) si el binario no está, el formato es inválido, o el export no sirve a tiempo.
    """
    if qemu_format not in _QEMU_FORMATS:
        raise _QemuMountError(
            f"formato de contenedor no soportado: {qemu_format!r} "
            f"(esperado uno de {sorted(_QEMU_FORMATS)})"
        )
    raw = os.path.join(mountpoint_dir, _QEMU_RAW_BASENAME)
    # El FUSE export de qemu monta SOBRE un fichero regular ya existente.
    open(raw, "wb").close()
    log_path = os.path.join(mountpoint_dir, "qsd.log")
    argv = [
        "qemu-storage-daemon",
        "--blockdev", f"driver=file,filename={qemu_image},node-name=src,read-only=on",
        "--blockdev", f"driver={qemu_format},file=src,node-name=fmt,read-only=on",
        "--export", f"type=fuse,id=exp,node-name=fmt,mountpoint={raw},writable=off",
    ]
    # stdout+stderr del daemon a un fichero (no a un PIPE): evita cualquier bloqueo por
    # buffer lleno mientras el daemon vive, y deja el diagnóstico legible si muere.
    log = open(log_path, "wb")
    try:
        daemon = subprocess.Popen(  # noqa: S603 — argv list, shell=False
            argv, stdout=log, stderr=subprocess.STDOUT, shell=False
        )
    except FileNotFoundError as exc:
        log.close()
        raise _QemuMountError(
            "qemu-storage-daemon no está instalado en el maletín (paquete qemu-utils); sin "
            "él no se puede desencapsular el contenedor a raw. Instálalo en la imagen del "
            "maletín (RULE 1) — no se trata el contenedor como raw (RULE 2)."
        ) from exc
    # Espera activa a que el export sirva: el fichero pasa de 0 al tamaño del disco.
    deadline = time.monotonic() + _QEMU_MOUNT_TIMEOUT_S
    while time.monotonic() < deadline:
        if daemon.poll() is not None:
            detail = _read_tail(log_path)
            raise _QemuMountError(
                f"qemu-storage-daemon murió exponiendo {qemu_image} (formato {qemu_format}, "
                f"exit {daemon.returncode}): {detail} — ¿/dev/fuse presente y CAP SYS_ADMIN? "
                "(docker-compose: devices:[/dev/fuse], cap_add:[SYS_ADMIN])"
            )
        try:
            if os.path.getsize(raw) > 0:
                return raw, daemon
        except OSError:
            pass
        time.sleep(0.1)
    _terminate(daemon)
    raise _QemuMountError(
        f"qemu-storage-daemon no expuso {raw} en {_QEMU_MOUNT_TIMEOUT_S}s "
        f"(formato {qemu_format}): {_read_tail(log_path)}"
    )


def qemu_unmount(mountpoint_dir: str, daemon: subprocess.Popen | None) -> None:
    """Para el daemon del FUSE export y desmonta. Best-effort pero SIEMPRE se intenta
    (soundness: no dejar un export/mount colgado). SIGTERM a qemu-storage-daemon desmonta y
    sale limpio; `fusermount -u` queda de respaldo por si el mount quedó zombie."""
    _terminate(daemon)
    raw = os.path.join(mountpoint_dir, _QEMU_RAW_BASENAME)
    for cmd in (["fusermount", "-u", raw], ["umount", raw]):
        try:
            proc = subprocess.run(  # noqa: S603 — argv list, shell=False
                cmd, capture_output=True, text=True, timeout=_QEMU_MOUNT_TIMEOUT_S, shell=False
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
        if proc.returncode == 0:
            return


def _terminate(daemon: subprocess.Popen | None) -> None:
    """Termina un daemon best-effort: SIGTERM y, si no muere a tiempo, SIGKILL."""
    if daemon is None or daemon.poll() is not None:
        return
    try:
        daemon.terminate()
        daemon.wait(timeout=_QEMU_MOUNT_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        daemon.kill()
    except OSError:
        pass


def _read_tail(path: str, limit: int = 800) -> str:
    """Últimos `limit` chars de un log de texto (diagnóstico), tolerante a fallos."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()[-limit:].strip()
    except OSError:
        return ""


def _sha256_size(path: str) -> tuple[str, int]:
    """SHA-256 + tamaño en bytes de un fichero, leído por bloques (nunca entero en RAM)."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(_HASH_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


class Handler(BaseHTTPRequestHandler):
    # Silenciamos el log por-petición a stderr para no ensuciar los logs del contenedor.
    def log_message(self, *_args) -> None:  # noqa: D401
        return

    # -- helpers ----------------------------------------------------------------
    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self) -> bool:
        if _TOKEN is None:
            return True
        return self.headers.get("X-Forensia-Exec-Token") == _TOKEN

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    # -- routes -----------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 (http.server contract)
        path = self.path.rstrip("/")
        if path == "/health":
            return self._send(200, {"ok": True, "stage": _STAGE})
        if path == "/versions":
            if not self._authed():
                return self._send(401, {"error": "invalid or missing exec-agent token"})
            return self._versions()
        return self._send(404, {"error": "not found"})

    def _versions(self) -> None:
        """Sirve el manifiesto de versiones horneado en el build. Endpoint CERRADO:
        sin parámetros, sin paths del caller, sin ejecutar comandos — solo lee el
        fichero inmutable de la imagen. Falta/corrupto → 500 accionable, jamás un
        placeholder (RULE 2)."""
        try:
            with open(_VERSIONS_MANIFEST, encoding="utf-8") as handle:
                manifest = json.load(handle)
        except FileNotFoundError:
            return self._send(500, {
                "error": (
                    f"manifiesto de versiones ausente ({_VERSIONS_MANIFEST}) — la imagen "
                    "del maletín es anterior al manifiesto de build; reconstruye con "
                    "docker compose build (gen_versions.py lo hornea y el build falla "
                    "si una tool declarada no tiene versión)."
                )
            })
        except (OSError, ValueError) as exc:
            return self._send(500, {
                "error": f"manifiesto de versiones ilegible ({_VERSIONS_MANIFEST}): {exc}"
            })
        versions = manifest.get("versions") if isinstance(manifest, dict) else None
        if not isinstance(versions, dict) or not all(
            isinstance(k, str) and isinstance(v, str) and v.strip()
            for k, v in versions.items()
        ):
            return self._send(500, {
                "error": (
                    f"manifiesto de versiones corrupto ({_VERSIONS_MANIFEST}): se "
                    "esperaba {'versions': {binario: versión no vacía}} — reconstruye "
                    "el maletín."
                )
            })
        return self._send(200, {
            "stage": manifest.get("stage", _STAGE),
            "versions": versions,
        })

    def do_POST(self) -> None:  # noqa: N802
        if not self._authed():
            return self._send(401, {"error": "invalid or missing exec-agent token"})
        try:
            payload = self._read_json()
        except (ValueError, OSError) as exc:
            return self._send(400, {"error": f"bad json: {exc}"})
        path = self.path.rstrip("/")
        if path == "/which":
            return self._which(payload)
        if path == "/exec":
            return self._exec(payload)
        return self._send(404, {"error": "not found"})

    def _which(self, payload: dict) -> None:
        binaries = payload.get("binaries")
        if not isinstance(binaries, list) or not all(isinstance(b, str) for b in binaries):
            return self._send(400, {"error": "'binaries' must be a list[str]"})
        present = [b for b in binaries if shutil.which(b) is not None]
        return self._send(200, {"present": present})

    def _exec(self, payload: dict) -> None:
        argv = payload.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            return self._send(400, {"error": "'argv' must be a non-empty list[str]"})
        timeout = payload.get("timeout")
        if timeout is None:
            # `null` del api → aplica el techo duro como timeout EFECTIVO. Nunca se corre con
            # timeout None (sin límite): el techo garantiza que `subprocess.run` mata y
            # recolecta el hijo, así que al hashear el stdout el proceso ya está muerto y el
            # fichero no cambia (INVARIANT 4). Siempre acotado y positivo.
            timeout = _MAX_TIMEOUT_S
        else:
            try:
                timeout = float(timeout)
            except (TypeError, ValueError):
                return self._send(400, {"error": "'timeout' must be a number or null"})
            if timeout <= 0:
                return self._send(400, {"error": "'timeout' must be a positive number or null"})
            timeout = min(timeout, _MAX_TIMEOUT_S)
        stdout_path = payload.get("stdout_path")
        if stdout_path is not None:
            if not isinstance(stdout_path, str) or not stdout_path:
                return self._send(400, {"error": "'stdout_path' must be a non-empty string or null"})
            # El api resuelve esta ruta desde el ArtifactRun (confinada al caso, jamás la
            # elige el LLM). Guarda defensiva mínima: absoluta y sin traversal.
            if not os.path.isabs(stdout_path) or ".." in stdout_path.split("/"):
                return self._send(400, {"error": "'stdout_path' must be an absolute path without '..'"})
        ewf_image = payload.get("ewf_image")
        qemu_image = payload.get("qemu_image")
        # EWF (ewfmount) y contenedor qemu (qemu-storage-daemon) son dos rutas de
        # desencapsulado distintas: una evidencia es de UNA clase, no de ambas.
        if ewf_image is not None and qemu_image is not None:
            return self._send(400, {"error": "'ewf_image' and 'qemu_image' are mutually exclusive"})
        if ewf_image is not None:
            if not isinstance(ewf_image, str) or not ewf_image:
                return self._send(400, {"error": "'ewf_image' must be a non-empty string or null"})
            if not os.path.isabs(ewf_image) or ".." in ewf_image.split("/"):
                return self._send(400, {"error": "'ewf_image' must be an absolute path without '..'"})
            # El api nombra el token EXACTO del argv (tiene el allowlist); montar algo que no
            # está en el comando sería adivinar. Exigimos que sea uno de los tokens.
            if ewf_image not in argv:
                return self._send(400, {"error": "'ewf_image' must be one of the argv tokens"})
            try:
                result = self._exec_with_ewf(argv, timeout, stdout_path, ewf_image)
            except _EwfMountError as exc:
                # 424 Failed Dependency: el mount previo a la ejecución falló. El api lo
                # eleva a un error accionable; no hay exit code de tool que inventar.
                return self._send(424, {"error": str(exc)})
            return self._send(200, result)
        if qemu_image is not None:
            if not isinstance(qemu_image, str) or not qemu_image:
                return self._send(400, {"error": "'qemu_image' must be a non-empty string or null"})
            if not os.path.isabs(qemu_image) or ".." in qemu_image.split("/"):
                return self._send(400, {"error": "'qemu_image' must be an absolute path without '..'"})
            if qemu_image not in argv:
                return self._send(400, {"error": "'qemu_image' must be one of the argv tokens"})
            qemu_format = payload.get("qemu_format")
            if qemu_format not in _QEMU_FORMATS:
                return self._send(400, {
                    "error": f"'qemu_format' must be one of {sorted(_QEMU_FORMATS)}"
                })
            try:
                result = self._exec_with_qemu(argv, timeout, stdout_path, qemu_image, qemu_format)
            except _QemuMountError as exc:
                # 424 Failed Dependency: el desencapsulado previo a la ejecución falló.
                return self._send(424, {"error": str(exc)})
            return self._send(200, result)
        return self._send(200, self._run_argv(argv, timeout, stdout_path))

    def _exec_with_ewf(self, argv: list[str], timeout, stdout_path, ewf_image: str) -> dict:
        """Monta el `.E01` (RO, FUSE), reescribe el token del argv al raw `ewf1`, ejecuta y
        DESMONTA SIEMPRE (finally). El resto del contrato (stdout_path binario, shell-free)
        no cambia: solo se sustituye el token de la imagen por su bloque raw."""
        mountpoint = tempfile.mkdtemp(prefix="forensia-ewf-")
        try:
            raw = ewf_mount(ewf_image, mountpoint)
            rewritten = [raw if token == ewf_image else token for token in argv]
            return self._run_argv(rewritten, timeout, stdout_path)
        finally:
            ewf_unmount(mountpoint)
            shutil.rmtree(mountpoint, ignore_errors=True)

    def _exec_with_qemu(
        self, argv: list[str], timeout, stdout_path, qemu_image: str, qemu_format: str
    ) -> dict:
        """Expone el contenedor qemu como raw (RO, FUSE, block-level), reescribe el token del
        argv al raw expuesto, ejecuta y DESENCAPSULA SIEMPRE (finally): para el daemon y
        desmonta. Mismo contrato (stdout_path binario, shell-free); solo cambia el token de
        la imagen por su vista raw."""
        mountpoint_dir = tempfile.mkdtemp(prefix="forensia-qemu-")
        daemon: subprocess.Popen | None = None
        try:
            raw, daemon = qemu_mount(qemu_image, qemu_format, mountpoint_dir)
            rewritten = [raw if token == qemu_image else token for token in argv]
            return self._run_argv(rewritten, timeout, stdout_path)
        finally:
            qemu_unmount(mountpoint_dir, daemon)
            shutil.rmtree(mountpoint_dir, ignore_errors=True)

    def _run_argv(self, argv: list[str], timeout, stdout_path) -> dict:
        """Ejecuta el argv ya resuelto y devuelve el dict de respuesta (sin enviarlo).
        Sin `stdout_path`: stdout como texto. Con él: canal binario-seguro a fichero."""
        if stdout_path is None:
            return self._run_text(argv, timeout)
        return self._run_to_file(argv, timeout, stdout_path)

    def _run_text(self, argv: list[str], timeout) -> dict:
        # `executed_argv` en TODA respuesta: el argv literal que este proceso lanzó (o
        # intentó lanzar — exit 127). El api lo compara contra el argv que auditó
        # (P0.5-4, INVARIANT 4): nunca se confía en que el maletín "hizo lo correcto".
        executed = list(argv)
        try:
            # errors="replace": la salida forense (nombres de fichero, bytes crudos) a
            # menudo NO es UTF-8 válido; sin esto, text=True lanzaría UnicodeDecodeError y
            # el hilo moriría dejando al api con "RemoteDisconnected" (Bug 004).
            proc = subprocess.run(  # noqa: S603 — argv list, shell=False, resolved by the api allowlist
                argv, capture_output=True, text=True, errors="replace", timeout=timeout, shell=False
            )
        except FileNotFoundError:
            return {
                "exit": 127,
                "stdout": "",
                "stderr": f"{argv[0]}: not found",
                "timed_out": False,
                "executed_argv": executed,
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "exit": 124,
                "stdout": exc.stdout or "",
                "stderr": (exc.stderr or "") + "\n[exec-agent] timeout",
                "timed_out": True,
                "executed_argv": executed,
            }
        return {
            "exit": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "timed_out": False,
            "executed_argv": executed,
        }

    def _run_to_file(self, argv: list[str], timeout, stdout_path: str) -> dict:
        """Canal binario-seguro: el stdout del hijo se escribe CRUDO a `stdout_path`
        (sin decodificar), y se devuelve su SHA-256 + tamaño en vez del texto. stderr
        sigue como texto (diagnóstico). Idéntico contrato shell-free (argv, shell=False)."""
        timed_out = False
        exit_code = 0
        stderr = ""
        try:
            with open(stdout_path, "wb") as stdout_file:
                proc = subprocess.run(  # noqa: S603 — argv list, shell=False, resolved by the api allowlist
                    argv,
                    stdout=stdout_file,
                    stderr=subprocess.PIPE,
                    text=True,
                    errors="replace",
                    timeout=timeout,
                    shell=False,
                )
            exit_code, stderr = proc.returncode, proc.stderr
        except FileNotFoundError:
            exit_code, stderr = 127, f"{argv[0]}: not found"
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            exit_code = 124
            stderr = (exc.stderr or "") + "\n[exec-agent] timeout"
        sha256, size = _sha256_size(stdout_path)
        return {
            "exit": exit_code,
            "stdout_file": stdout_path,
            "stdout_sha256": sha256,
            "stdout_size": size,
            "stderr": stderr,
            "timed_out": timed_out,
            # El argv literal lanzado (P0.5-4) — mismo contrato que el canal de texto.
            "executed_argv": list(argv),
        }


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", _PORT), Handler)
    print(
        f"[forensia exec-agent] stage={_STAGE} escuchando en 0.0.0.0:{_PORT} "
        f"(auth={'on' if _TOKEN else 'off'})",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
