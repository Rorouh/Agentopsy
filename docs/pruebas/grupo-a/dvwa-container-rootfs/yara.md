# `yara` — sobre `dvwa-container-rootfs/dvwa-disk.raw`

- **Grupo:** A · **Imagen:** DVWA docker rootfs · **Estado:** ✅ (antes bloqueada: binario `yara` no instalado)
- **Binario:** `yara` 4.1.3 · **Maletín:** `toolkit-unix` (Cross)
- **run_id:** `177b21da-3063-4a5a-b414-4113c804bf4a`

## Desbloqueo

`yara` no estaba instalado (capabilities: ❌). Se **añadió `yara` al Dockerfile** (stage base)
y se reconstruyeron los maletines → disponible.

## Objetivo (máxima expresión)

Match de **reglas YARA** (firmas de webshells, malware, persistencia, IOCs) sobre ficheros o
imágenes. El caller aporta las reglas (`rules_path`) y el objetivo (`target_path`).

## Cómo la usé (params + argv)

Escribí una regla propia de prueba y escaneé la imagen DVWA:
```yara
rule DVWA_credentials {
  strings: $a="p@ssw0rd"  $b="config.inc.php"  $c="db_password"
  condition: any of them
}
rule ELF_binary { strings: $m={7f 45 4c 46} condition: $m at 0 }
```
```
execute("yara", {"rules_path": "/…/dvwa.yar", "target_path": <img>}, …)
argv = yara /…/dvwa.yar <img>   →   exit 0, run 177b21da
```

## Resultado obtenido — exit 0

**`DVWA_credentials` matcheó** la imagen. `parse` devuelve estructurado:
`{"matches": [{"rule": "DVWA_credentials", "target": "…/original.raw"}], "count": 1}`.

## Veredicto / lecciones para el agente

- **Eficaz**: matching por regla con salida parseada (rule + target). Escalable a rulesets
  reales (signature-base / Yara-Rules) para cazar webshells/malware/persistencia.
- **El caller aporta las reglas**: Agentopsy no inyecta `rules_path` (no es la evidencia) — hay
  que darle el path del `.yar` (como `jq` con su `input_path`).
- **Dirígelo a ficheros extraídos** (webshells en `/var/www`, binarios sospechosos) más que a
  la imagen entera cuando puedas — más rápido y con menos ruido; usa `recursive` sobre un dir.
- **`print_strings`** para ver qué cadena disparó cada match.

## Registro

- **Finding:** `09b7d6c8` — "Regla YARA detecta credenciales/config DVWA en el disco" (low), run `177b21da`.
- **Evidencia recopilada:** [`yara/dvwa.yar`](yara/dvwa.yar) (la regla) · [`yara/matches.txt`](yara/matches.txt).
