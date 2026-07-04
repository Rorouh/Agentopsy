# `foremost` — sobre `metasploitable2-linux/Metasploitable.raw`

- **Grupo:** B · **Imagen:** Metasploitable 2 (disco particionado real) · **Estado:** ✅ eficaz (aquí sí brilla)
- **Binario:** `foremost` · **Maletín:** `toolkit-unix` (integrada — fix Bug 003)
- **run_id:** `800452a7-8a40-4e36-9505-db2780586fd5`

## Objetivo (máxima expresión)

Comprobar el carving en su terreno natural: un **disco usado** con espacio no asignado real.
En el Grupo A (rootfs limpio) foremost solo recuperó assets embebidos (277); aquí esperaba
**mucho más** — contenido borrado real de un sistema con historia.

## Cómo la usé (params + argv)

```
execute("foremost", {"image_path": <raw 8GB>, "types": ["jpg","png","gif","pdf","doc","zip","htm"], "quick": True}, …)
argv = foremost -t jpg,png,gif,pdf,doc,zip,htm -q -o <output_dir>/foremost -i <raw>
→ exit 0, run 800452a7
```
Nota: foremost carva el **disco entero** (no toma offset de partición); recorre todas las
particiones y su no-asignado.

## Resultado obtenido — exit 0

**3.967 ficheros recuperados** (del `audit.txt`):

| Tipo | Nº | Tipo | Nº |
|------|----|------|----|
| png | 1738 | zip | 100 |
| gif | 1609 | pdf | 31 |
| htm | 388 | jpg | 101 |

+ carpeta `jar`. **~14× más que el DVWA** (277). Los **388 htm** y los zip/jar proceden de las
**apps web vulnerables** (TWiki, DVWA, etc.) y de contenido no asignado.

## Veredicto de eficacia

- **Aquí sí brilla**: 3.967 ficheros de un disco usado, con variedad (imágenes, HTML, archivos,
  PDF). El contraste con el Grupo A confirma la lección: foremost rinde en **discos usados**.
- Corriendo por el dispatcher, integrada, con cadena de custodia.

## Lecciones para entrenar al agente

1. **El valor de foremost depende del tipo de evidencia**: en un rootfs fabricado, poco; en un
   **disco usado**, mucho (contenido borrado real). Ajusta expectativas.
2. **Correlaciona con `fls -d`**: `fls -d` dio 7.100 borrados por metadatos; foremost recupera
   por firma (incluso sin metadatos). Los **388 htm** apuntan a las apps web — cruza con el
   árbol (`/var/www`, TWiki) para dar contexto.
3. **El resumen está en `audit.txt`** (no en `parsed`, Bug de foremost ya documentado en el
   Grupo A): léelo del artefacto.
4. **quick + types** para acotar en discos grandes (8 GB emulados tardan).

## Registro en el caso

- **Finding:** `5e072e70` — "foremost recuperó 3.967 ficheros de un disco usado (incl. 388 htm web)" (low), run `800452a7`.
- **Evidencia recopilada:** [`foremost/audit.txt`](foremost/audit.txt) (resumen + offsets). Los
  3.967 ficheros carveados viven en el `ArtifactRun` `800452a7/out/foremost/`.
