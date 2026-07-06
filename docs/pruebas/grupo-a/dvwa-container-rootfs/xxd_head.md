# `xxd_head` — sobre `dvwa-container-rootfs/dvwa-disk.raw`

- **Grupo:** A · **Imagen:** DVWA docker rootfs · **Estado:** ✅ (antes bloqueada: binario `xxd` no instalado)
- **Binario:** `xxd` · **Maletín:** `toolkit-unix` (Cross)
- **run_id:** `cc56b3e9-f0ee-4ccd-a85f-f5f20e158205`

## Desbloqueo

`xxd` no estaba instalado en el maletín (capabilities: ❌). Se **añadió `xxd` al Dockerfile**
(stage base) y se reconstruyeron los maletines → ahora disponible.

## Objetivo (máxima expresión)

Volcado **hexadecimal** de una región concreta para inspeccionar **magic bytes**, cabeceras y
estructuras a bajo nivel — el complemento de `file_info` cuando quieres ver los bytes crudos.

## Cómo la usé (params + argv)

`image_path` + `bytes` (`-l`), `skip` (`-s`, offset), `cols` (`-c`). Volqué el **superbloque
ext4** (offset 1024):
```
execute("xxd_head", {"image_path": <img>, "skip": 1024, "bytes": 256}, …)
argv = xxd -s 1024 -l 256 <img>   →   exit 0, run cc56b3e9
```

## Resultado obtenido — exit 0

En offset `0x430` aparece **`53 ef`** = el *magic* ext2/3/4 (`0xEF53` little-endian), más el
volumen/features del superbloque. Confirma a bajo nivel lo que `file_info` dijo (ext4).

## Veredicto / lecciones

- **Eficaz** para ver cabeceras/magic exactos. Úsalo con `skip` para saltar a un offset de
  interés (p. ej. el superbloque en 1024, o un offset que dio `strings -t x`).
- **Es un visor**: no genera hallazgo por sí solo; sirve para **confirmar/depurar** (¿es esto
  un JPEG? ¿un PE? ¿un superbloque?) — mira los primeros bytes.
- Acota `bytes` (no vuelques MB en hex al contexto).

## Registro

- **Sin finding** (visor de bajo nivel; confirma el ext4 ya reportado por file_info/fsstat).
- **Evidencia recopilada:** [`xxd_head/superblock-hex.txt`](xxd_head/superblock-hex.txt).
