# `ewf_info` — sobre `metasploitable2-linux/Metasploitable_e01.E01`

- **Grupo:** B · **Imagen:** Metasploitable 2 (E01 convertido) · **Estado:** ✅ eficaz
- **Binario:** `ewfinfo` (libewf) · **Maletín:** `toolkit-unix`
- **run_id:** `328bf83d-4d4e-4ab4-8c1b-2e23ee67b189`

## Objetivo (máxima expresión)

`ewf_info` lee los **metadatos del contenedor EWF/E01**: datos de adquisición (caso,
examiner, fecha), formato/compresión, y los **hashes que el propio E01 transporta** —
la cadena de custodia embebida en el formato pericial estándar.

## Preparación — raw → E01

El disco es raw; para probar EWF lo **adquirí a E01** con `ewfacquire` (libewf, en el
maletín):
```
ewfacquire -u -t Metasploitable_e01 -f encase6 -c deflate:fast -S 1900MiB \
  -C Metasploitable2 -e campana-tools -E 1 -m fixed -M physical  Metasploitable.raw
→ SUCCESS: Metasploitable_e01.E01 (924 MB comprimido de 8 GiB), MD5 1cd5cd2f…
```

## Cómo la usé (params + argv)

```
execute("ewf_info", {"image_path": <E01>}, case_id=…, os_profile="unix")
argv = ewfinfo <E01>   →   exit 0, run 328bf83d
```

## Resultado obtenido — exit 0

`parse` devolvió los campos estructurados:
- **Adquisición:** caso `Metasploitable2`, examiner `campana-tools`, evidencia `1`, fecha
  `2026-07-04`, OS `Linux`, software libewf `20140816`.
- **EWF:** formato `EnCase 6`, compresión `deflate` (good/fast), 64 sectores/chunk.
- **Media:** disco fijo, físico, 512 B/sector.
- **Hash embebido:** `MD5: 1cd5cd2fc5adcb08ea53f21326c1602c` — el hash de los datos que el E01
  guarda dentro (cadena de custodia del formato).

## Veredicto de eficacia

- **Eficaz**: extrajo toda la ficha de adquisición + el MD5 embebido sin tocar los datos.
- Complementa a `hashdeep`: aquí el hash **viaja dentro** de la evidencia (E01), no se calcula
  aparte — se coteja para probar integridad.

## Lecciones para entrenar al agente

1. **Con evidencia `.E01`/`.Ex01`, empieza por `ewf_info`**: te da la ficha de adquisición y
   el **hash embebido** — cótejalo con el baseline de Agentopsy para validar integridad antes
   de analizar.
2. **El resto de TSK sobre E01**: usa `-i ewf` (o convierte a raw). El hash del E01 es de los
   *datos*, no del fichero .E01 (que comprime).
3. **La ficha de adquisición es metadato pericial**: caso, examiner, fecha — cítalos en el
   informe; son parte de la cadena de custodia.

## Registro en el caso

- **Finding:** `48695cd2` — "E01 con metadatos de adquisición y hash integrado" (low), run `328bf83d`.
- **Evidencia recopilada:** [`ewf_info/ewfinfo.txt`](ewf_info/ewfinfo.txt) (ficha EWF completa).
