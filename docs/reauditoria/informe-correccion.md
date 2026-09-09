# Corrección de la reauditoría RA01 a RA07: detalle

Detalle completo del bloque «Procedencia y aprobación verificable». El resumen
para auditar de un vistazo está en el mensaje de entrega; aquí está lo que no
cabe en él.

## Base

Rama `limpieza`, commit inicial `e41b626`, sincronizada con `origin/limpieza` (0
por delante, 0 por detrás) al empezar. El árbol de trabajo traía ya la entrega
anterior sin confirmar (lectura verificada de artefactos, referencias
estructuradas, comprobaciones de aprobación). Esas modificaciones se han
CONSERVADO: nada se ha revertido, ni se ha confirmado, ni se ha subido.

`origin/main` avanzó a `b3bd2dc` durante la sesión. No se ha mezclado.

## RA01 · Vincular el informe a sus fuentes

**Antes:** el hash del documento se calculaba excluyendo `fuentes`, así que
sustituir el manifiesto por `{"case_id": "..."}` conservaba texto y hash, y el
informe volvía a ser aprobable.

**Ahora:** el manifiesto tiene un digest canónico versionado, ese digest entra en
el contenido canónico del documento (esquema 3, que además incorpora `id` y
`case_id`) y viaja anclado al `document_created`. Los tres tienen que casar.

- `backend/agentopsy/reports/fuentes.py` (nuevo, 357 líneas): `normalizar`,
  `digest_de_fuentes:262`, `validar_manifiesto:280`, `refs_de_bloque:73`,
  `ESQUEMA_DOCUMENTO_ANCLADO:53`.
- `backend/agentopsy/reports/store.py:66` `SCHEMA_VERSION = 3`, `:106`
  `fuentes_sha256`, `:129` `_canonical_content` versionado, `_audit` ancla el
  digest.
- `backend/agentopsy/reports/aprobacion.py:240` `comprobar`, bloques de
  procedencia y manifiesto.

**Compatibilidad:** un documento de esquema anterior se lee y se exporta como
borrador y NO se aprueba (`procedencia_sin_ancla`, `sin_manifiesto`). No se le
recalcula el hash para que parezca comprobado.

## RA02 · Verificar la evidencia real

**Antes:** se comparaba el `sha256` del handle con el del manifiesto. Alterar los
bytes no cambiaba ninguno de los dos.

**Ahora:** `EvidenceManager.comprobar_integridad` (`backend/agentopsy/evidence.py:906`)
re-hashea cada segmento contra su baseline, sin efectos secundarios, y la
aprobación la llama siempre. `verify:978` es la mitad AUDITADA y usa la misma
lectura. Sin caché y sin reutilizar verificaciones anteriores: se documenta por
qué (una verificación de ayer dice lo que era verdad ayer).

También se comprueba que el baseline con el que corrió la ejecución sea el de la
evidencia registrada (`aprobacion.py:689` `_comprobar_evidencia`, `:790`
`_comprobar_artefacto`), y una verificación negativa registrada bloquea hasta que
se vuelva a verificar.

## RA03 · Verificar hallazgos y su procedencia

**Antes:** se comparaban dos `content_sha256` almacenados, y
`provenance_state` era informativo.

**Ahora:** `aprobacion.py:887` `_comprobar_hallazgo` recomputa el hash del
contenido canónico de la revisión citada, lo contrasta con su evento de
auditoría, reabre sus fuentes por el servicio común y `:1053`
`_procedencia_insuficiente` convierte el estado en una DECISIÓN.

Un `descarte` o una `limitacion` sin fuente siguen siendo legítimos si declaran
su alcance. Un histórico sin referencias se lee, se muestra como no verificado y
no sostiene un informe nuevo.

## RA04 · Exigir una aprobación auditada para el estado final

**Antes:** escribir `status: "final"` y datos de aprobador en el JSON producía un
PDF sin marca de borrador.

**Ahora:** `aprobacion.py:473` `_comprobar_acta` exige un `document_approved` en
una cadena VÁLIDA que case con documento, caso, versión, contenido recomputado,
digest de fuentes RECOMPUTADO, revisor y fecha. El PDF de un documento en ese
estado sale marcado y sin ninguna señal de aprobación
(`backend/agentopsy/reports/pdf.py:173` `_fecha_de`, `:511` `_signature`).

**Concurrencia:** `store.py:448` `_lock` enuncia el protocolo (un solo ámbito por
documento, relectura del estado dentro del cerrojo, ningún cerrojo anidado) y es
reentrante, de modo que componer dos operaciones del dominio no revienta contra
la detección de abrazo mortal de `filelock`. `delete:420` entra por el mismo
cerrojo. Se documenta que NO protege frente a ediciones externas del sistema de
ficheros.

## RA05 · Validar la cadena antes de confiar en sus anclas

**Antes:** `_ancla_auditada` leía el digest sin mirar la cadena.

**Ahora:** `backend/agentopsy/audit/log.py:37` `EstadoCadena` y `:108` `estado()`
verifican y dicen DÓNDE se rompió; `verify()` es un envoltorio que ya no revienta
con un log corrupto. `backend/agentopsy/artifacts/lectura.py:494`
`_ancla_auditada` valida la cadena antes de leer nada de ella y levanta
`CadenaRotaError:150`.

Se distingue el histórico del roto: `es_moderno:449` mira si el manifiesto declara
su propio `manifest_sha256`; un run moderno sin ancla levanta
`AnclaAusenteError:166` en vez de degradarse a `sin_ancla`.

`ArtefactoIntegridadError:135` pasa a heredar de las DOS familias, así que un
consumidor que captura `ArtefactoError` se entera también de los fallos de
integridad. Propagado a REST, MCP (`mcp/toolkit.py`, `mcp/resources.py`), agente y
procedencia.

**Sin caché**, y se explica por qué: el estado de la cadena se recalcula en cada
lectura, por la misma razón por la que el hash se recalcula sobre el descriptor.

## RA06 · Validar los dos extremos del localizador

Semántica fijada y documentada (`backend/agentopsy/findings/procedencia.py:114`):
`lineas` desde 1 con los dos extremos inclusivos; `bytes` desde 0 con `hasta`
exclusivo; rango vacío rechazado. `_validar_localizador:183` rechaza inversión y
vacío según el tipo; `_extraer:229` recorre el artefacto entero y rechaza el
rango cuyo final se pase, en vez de recortarlo.

Una cita cuyo localizador no existe se sirve con estado `localizador_invalido`,
que no es lo mismo que `alterada`. Documentado en `agentes/agent.md`,
`agentes/agent.en.md` y en el esquema que lee el agente.

## RA07 · Abrir la fuente de cada conclusión

Modelo de bloques ampliado con `refs` (revisiones de hallazgo) y `limitacion`
(código). `backend/agentopsy/reports/indice.py:96` declara qué apartados afirman
sobre la evidencia y `:105` `exige_respaldo` decide bloque a bloque, dejando
fuera títulos, comandos auditados y fichas de campos.

- Quinta puerta del redactor: `backend/agentopsy/reports/writer.py:719`
  `_validar_respaldo`. El encargo lo pide (regla 9.bis) y el material lleva los
  códigos exigidos, así que no se pide nada que no se haya dicho.
- La aprobación lo vuelve a comprobar: `aprobacion.py:544` `_comprobar_citas`.
- `backend/agentopsy/reports/citas.py` (nuevo) resuelve el recorrido entero en el
  servidor; `backend/agentopsy/routers/documents.py:325` lo expone en
  `GET …/documents/{id}/citas/{finding_id}`.
- Interfaz: `web/src/components/SourceCard.tsx` (extraído para que Hallazgos e
  Informe usen la MISMA ficha) y `web/src/pages/DocumentsPage.tsx` (`CitationPanel`,
  `BlockRefs`).
- Exportación: `pdf.py:366` `_citas` imprime el respaldo de cada bloque con
  identificador y revisión.

**Integridad técnica no es suficiencia interpretativa**: se dice en la ficha, en
el panel y en la documentación.

## Limitaciones relacionadas

- Las limitaciones exigidas se declaran por CÓDIGO y se cruzan con lo que el
  material exige. «El apartado 9 tiene texto» ya no vale.
- Rutas de datos corregidas en `agentes/README.md`: con el compose por defecto,
  `./projects/cases/<id>` en el host y `/cases/cases/<id>` en el contenedor;
  `~/.agentopsy/cases/<id>` solo en ejecución nativa. Comprobado contra
  `docker-compose.yml` (`AGENTOPSY_HOME: /cases`, bind `./projects:/cases`).
- Los bloqueos se resuelven en el IDIOMA de quien los lee. Lo destapó la revisión
  visual del PDF: un informe en inglés imprimía el motivo en castellano.

## Corrección incidental

`backend/tests/test_documents.py::_texto_por_pagina` usaba `zlib.decompress` sobre
un flujo que la expresión regular corta a veces por un `endstream` incrustado en
los datos comprimidos. El resultado era una hoja leída con cero caracteres y un
fallo intermitente (1 de cada 25 a 30 pasadas) de
`test_no_page_of_a_long_report_is_left_almost_empty`. Se cambia a
`decompressobj`, que infla el prefijo válido. 60 pasadas seguidas del fichero sin
un fallo. Es una fragilidad del AYUDANTE de prueba, no del producto.

## Validación

| Puerta | Comando | Resultado |
|---|---|---|
| Backend, lint | `cd backend && ruff check .` | All checks passed |
| Backend, pruebas | `cd backend && python -m pytest -q` | 1848 correctas, 1 fallida, 24 omitidas |
| Interfaz, tipado | `cd web && npm run typecheck` | limpio |
| Interfaz, pruebas | `cd web && npm run test` | 13 correctas (2 ficheros) |
| Interfaz, build | `cd web && npm run build` | correcto |
| Compose, config | `docker compose config --quiet` | correcto |
| Compose, imágenes | `docker compose build api web` | `agentopsy/api:0.1` y `agentopsy/web:0.1` construidas |
| Reproducción | `cd backend && python ../docs/reauditoria/reproduccion_ra01_ra07.py` | los 7 escenarios bloqueados, recorrido válido intacto |

Entorno: Windows 11, Python 3.12 en `backend/.venv`, Node con el `package-lock`
del repositorio, Docker 29.6.2 con Compose v5.3.1.

**La prueba fallida es previa y del entorno, no del producto.**
`test_executors.py::test_codex_rejects_an_effort_the_model_cannot_take` espera el
mensaje «el CLI codex no está en el PATH» y en esta máquina `codex` SÍ está
instalado (`/c/Users/super/AppData/Local/Programs/OpenAI/Codex/bin/codex`), así
que el ejecutor responde «no hay sesión». Nada de este bloque toca
`agentopsy/executors`. Fallaba igual antes de la primera línea de esta sesión.

### Pruebas nuevas

92 regresiones adversas, una batería por hallazgo:

| Fichero | Pruebas |
|---|---|
| `test_ra01_procedencia_anclada.py` | 12 |
| `test_ra02_evidencia_real.py` | 8 |
| `test_ra03_hallazgos.py` | 12 |
| `test_ra04_acta_aprobacion.py` | 9 |
| `test_ra05_cadena_y_ancla.py` | 10 |
| `test_ra06_localizadores.py` | 18 |
| `test_ra07_respaldo_conclusiones.py` | 16 |
| `test_recorrido_ra01_ra07.py` | 7 |

Más `backend/tests/_informe.py`, la fábrica de casos sintéticos completos
(evidencia registrada por la puerta de hash, ejecución cerrada y anclada,
hallazgo con su cita, informe con su manifiesto). No hay dobles de las
verificaciones que se están probando: los hashes y los baselines son coherentes
de verdad.

## Casos adversos

| Alteración | Esperado | Observado |
|---|---|---|
| Bytes de la evidencia cambiados | Bloqueo | `evidencia_alterada`; `verify` falso |
| Resumen del hallazgo alterado, hash declarado intacto | Bloqueo | `hallazgo_alterado` |
| Resumen alterado y hash recalculado en local | Bloqueo | `hallazgo_revisado` |
| Fuentes sustituidas por `{"case_id": …}` | Bloqueo | `procedencia_alterada`, `manifiesto_invalido`, `cita_fuera_del_manifiesto` |
| Fuentes sustituidas, digest y hash recalculados | Bloqueo | `ancla_no_casa`, `procedencia_no_casa` |
| Estado final forjado sin acta | PDF borrador | `X-Agentopsy-Pdf-Draft: 1`, `aprobacion_sin_acta`, 0 eventos de aprobación |
| Artefacto, manifiesto y un evento alterados | Lectura rechazada | `CadenaRotaError` |
| Ancla de una ejecución moderna eliminada | Lectura rechazada | `CadenaRotaError` / `AnclaAusenteError` |
| Localizador 1 a 999999 sobre 3 líneas | Rechazo | `ProcedenciaError` |
| Rango de bytes vacío o invertido | Rechazo | `ProcedenciaError` |
| Histórico sin referencias en un informe nuevo | Legible, no aprobable | legible; `hallazgo_sin_procedencia` |
| **Recorrido válido** | Aprobable y final | aprobable, `final`, 2 citas, PDF `Draft: 0`, cadena válida |

## Revisión visual del PDF

Hecha, no declarada pendiente. Los PDF se rasterizaron con `pypdfium2` en un
entorno virtual aislado (el del proyecto no se tocó) y se miraron página a
página.

- Informe aprobado: sin marca de borrador, con la línea de respaldo
  («Support: `<finding_id>` rev. 1») bajo cada conclusión, el comando auditado
  literal y el pie de aprobación humana auditada.
- Informe con el estado final forjado: marca DRAFT en la cabecera de todas las
  páginas, banner con el motivo del bloqueo en lenguaje llano, y NINGUNA señal de
  aprobación. El nombre del aprobador inventado no aparece en el fichero.

## Pendientes y observaciones

1. `test_executors.py::test_codex_rejects_an_effort_the_model_cannot_take` sigue
   roja en esta máquina por tener `codex` instalado. Previa y ajena al bloque.
2. El recorrido NO se ha ejercido sobre el stack en marcha (`docker compose up`)
   con un caso sintético. Las imágenes se construyen, pero levantar la pila
   habría tocado el entorno del investigador. Las pruebas de superficie HTTP
   (`test_recorrido_ra01_ra07.py`) usan la aplicación real de FastAPI.
3. Un documento sintético muy corto deja la firma en una segunda página casi
   vacía. Es cosmético y no es una regresión: el gate de paginación cubre los
   informes largos.
4. Los documentos de esquema 1 y 2 existentes en casos ya creados dejarán de ser
   aprobables y pedirán volver a finalizar la investigación. Es el
   comportamiento buscado, y conviene saberlo antes de abrir un caso antiguo.
5. Nada de esto detiene a quien reescriba el almacenamiento completo del caso y
   recalcule la cadena. Haría falta un sellado externo, que esta fase no
   implementa.

## Evidencias

| Qué | Dónde |
|---|---|
| Reproducción de los 7 escenarios | `docs/reauditoria/reproduccion_ra01_ra07.py` |
| Resultado observado | `docs/reauditoria/resultados-ra01-ra07.json` |
| Cómo se ejecuta y qué gate cubre cada hallazgo | `docs/reauditoria/README.md` |
| Regresiones | `backend/tests/test_ra0*.py`, `backend/tests/test_recorrido_ra01_ra07.py` |
| Fábrica de casos sintéticos | `backend/tests/_informe.py`, `backend/tests/_procedencia.py` |
| Interfaz | `web/src/pages/DocumentsPage.test.tsx` |
