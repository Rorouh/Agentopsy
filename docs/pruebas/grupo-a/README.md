# Grupo A — tools sobre disco (evidencia local, sin descargas)

Pruebas de las herramientas que corren ya sobre las imágenes de disco que tenemos, **una
tool a la vez**, exprimiéndolas al máximo y documentando cada paso para **entrenar los
agentes** luego. Plan general: [`../matriz-tools-evidencia.md`](../matriz-tools-evidencia.md).

## Organización

```
grupo-a/
└── <imagen>/                 # una carpeta por imagen probada
    ├── README.md             # identidad de la imagen + índice/checklist de tools
    └── <tool>.md             # bitácora detallada de esa tool sobre esa imagen
```

Cada `<tool>.md` documenta: objetivo (qué se espera de la tool), cómo se usó (params + argv
real + por qué), resultado obtenido, veredicto de eficacia y **lecciones para el agente**.

## Imágenes en este grupo

| Imagen | Qué es | Estado |
|--------|--------|--------|
| [`dvwa-container-rootfs/`](dvwa-container-rootfs/README.md) | rootfs del contenedor DVWA (ext4 plano, sin particiones) | ✅ completado (9/9 tools) |

## Tools del grupo A (checklist, sobre `dvwa-container-rootfs`)

| Tool | Estado | Bitácora |
|------|--------|----------|
| `file_info` | ✅ probada | [file_info.md](dvwa-container-rootfs/file_info.md) |
| `strings_head` | ✅ probada | [strings_head.md](dvwa-container-rootfs/strings_head.md) |
| `tsk_fls` | ✅ probada | [tsk_fls.md](dvwa-container-rootfs/tsk_fls.md) |
| `tsk_icat` | ✅ integrada + probada (fix Bug 003) | [tsk_icat.md](dvwa-container-rootfs/tsk_icat.md) |
| `tsk_mactime` | ✅ probada | [tsk_mactime.md](dvwa-container-rootfs/tsk_mactime.md) |
| `hashdeep` | ✅ integrada + probada (fix Bug 003) | [hashdeep.md](dvwa-container-rootfs/hashdeep.md) |
| `foremost` | ✅ integrada + probada (fix Bug 003) | [foremost.md](dvwa-container-rootfs/foremost.md) |
| `bulk_extractor` | ✅ probada | [bulk_extractor.md](dvwa-container-rootfs/bulk_extractor.md) |
| `jq` | ✅ probada | [jq.md](dvwa-container-rootfs/jq.md) |
