"""qemu_nbd wrapper — attach a disk image as a READ-ONLY NBD block device (mount helper).

Side-effecting. Exposes a raw/qcow2/vmdk/vdi image at `/dev/nbdX` so tools that need a real
block device can read it — activar LVM, montar un FS, o dar a TSK un device en vez de un
fichero. **Read-only a nivel de BLOQUE** (`-r`): es la forma *sound* de exponer una imagen
(un `mount -o ro` puede disparar journal replay y escribir; el block-RO no).

⚠️ **Runtime:** requiere el módulo de kernel `nbd` + nodos `/dev/nbdX` + privilegios. El
maletín del compose NO es privilegiado ni tiene `nbd`, así que esta tool **no se puede
ejecutar por el dispatcher hoy** — el wrapper queda listo para un entorno privilegiado. Ver
docs/pruebas/grupo-b/.../qemu_nbd.md.
"""

from __future__ import annotations

import re
from typing import Any

ALLOWED_FLAGS = frozenset({"-r", "-f", "-c"})

_FORMATS = frozenset({"raw", "qcow2", "vmdk", "vdi", "vhdx", "vpc"})
_NBD_DEVICE_RE = re.compile(r"^/dev/nbd\d+$")


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for qemu-nbd (read-only connect).

    params:
        image_path (str, required): image to expose. Injected by FORENSIA.
        nbd_device (str, optional): target NBD device, `/dev/nbd0` default.
        image_format (str, optional): raw (default) / qcow2 / vmdk / vdi / vhdx / vpc.
        read_only (bool, optional): block-level read-only (`-r`). Default True (soundness).
    """
    image_path = params.get("image_path")
    if not image_path or not isinstance(image_path, str):
        raise ValueError("qemu_nbd requires params.image_path: str")

    nbd_device = params.get("nbd_device", "/dev/nbd0")
    if not isinstance(nbd_device, str) or not _NBD_DEVICE_RE.match(nbd_device):
        raise ValueError("qemu_nbd nbd_device must be like /dev/nbd0")

    image_format = params.get("image_format", "raw")
    if image_format not in _FORMATS:
        raise ValueError(f"qemu_nbd image_format must be one of {sorted(_FORMATS)}")

    argv: list[str] = []
    if params.get("read_only", True):
        argv.append("-r")
    argv += ["-f", image_format, "-c", nbd_device, image_path]
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """qemu-nbd `-c` no imprime nada en éxito; el efecto es el device conectado."""
    return {
        "note": (
            "si exit=0, la imagen quedó conectada al dispositivo NBD (read-only, block-level). "
            "Requiere módulo nbd + /dev/nbdX + privilegios (no disponible en el maletín del compose)."
        ),
        "raw": stdout[:200],
    }
