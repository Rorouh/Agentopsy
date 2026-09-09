# Reauditoría 2026-09-08: procedencia y aprobación verificable

Los siete hallazgos RA01 a RA07 de la reauditoría, la reproducción que los
comprueba y el resultado observado sobre el código corregido.

El escenario adverso de cada uno se ejecuta contra los almacenes reales, sobre un
caso sintético aislado en un directorio temporal. No se usa ni una evidencia real
ni una llamada a ningún proveedor.

## Qué hay aquí

| Fichero | Qué es |
|---|---|
| `reproduccion_ra01_ra07.py` | La reproducción de los siete escenarios, más el recorrido válido. Cada uno declara el resultado ESPERADO junto al observado. |
| `resultados-ra01-ra07.json` | La salida de esa reproducción sobre el código corregido. |

## Cómo se ejecuta

```bash
cd backend
python ../docs/reauditoria/reproduccion_ra01_ra07.py
```

Necesita el entorno de desarrollo del backend (`pip install -e ".[dev,mcp]"`), y
nada más: ni Docker, ni un ejecutor, ni red.

## Dónde vive cada garantía

Los escenarios de este script son una reproducción para leerla de un vistazo. Los
GATES que impiden la regresión están en la batería de pruebas, uno por hallazgo:

| Hallazgo | Gate |
|---|---|
| RA01, retirar el respaldo sin invalidar el hash | `backend/tests/test_ra01_procedencia_anclada.py` |
| RA02, aprobar sin verificar los bytes de la evidencia | `backend/tests/test_ra02_evidencia_real.py` |
| RA03, confiar en el hash declarado de un hallazgo | `backend/tests/test_ra03_hallazgos.py` |
| RA04, estado final sin acta de aprobación | `backend/tests/test_ra04_acta_aprobacion.py` |
| RA05, ancla tomada de una cadena inválida | `backend/tests/test_ra05_cadena_y_ancla.py` |
| RA06, localizadores con un extremo inexistente | `backend/tests/test_ra06_localizadores.py` |
| RA07, conclusiones sin respaldo que abrir | `backend/tests/test_ra07_respaldo_conclusiones.py` |
| El recorrido entero, por la superficie HTTP | `backend/tests/test_recorrido_ra01_ra07.py` |

## El límite que se documenta en vez de disimularse

Todo esto detecta manipulaciones PARCIALES: un artefacto reescrito, un manifiesto
sustituido, un hallazgo alterado, un estado final fabricado, una entrada del log
tocada. La cadena de hashes vive junto a los datos que protege, así que no
detiene a quien pueda reescribir el almacenamiento completo del caso y recalcular
la cadena entera. Eso exigiría un sellado externo, que esta fase no implementa y
por tanto no promete.

Lo mismo con el cerrojo por documento: serializa a los escritores de la
aplicación, no a quien edite los ficheros por fuera de ella.
