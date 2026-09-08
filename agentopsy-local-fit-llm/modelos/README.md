# Modelos

Los Modelfiles de este directorio son la definición reproducible del modelo que
usa el motor (RM-3). Todos parten de un modelo de la biblioteca de Ollama y fijan
solo la ventana (`num_ctx`): la identidad del agente vive en `agentes/*.md`, no en
el Modelfile, para que cambiar de modelo no cambie al agente.

Crear uno (dentro del servicio ollama del compose):

```
docker compose cp agentopsy-local-fit-llm/modelos/local-q25-3b.Modelfile ollama:/tmp/Modelfile
docker compose exec ollama ollama create agentopsy-local-q25-3b -f /tmp/Modelfile
```

Elegirlo sin tocar código (RM-4): `LOCALFIT_MODEL=agentopsy-local-q25-3b` en el
entorno del servicio `local-fit-llm` o la clave `LOCALFIT_MODEL` en
`projects/config.json`. Se lee en cada petición.

| Modelfile | base | RAM aprox. | razona | para qué |
|---|---|---|---|---|
| `local-q25-3b.Modelfile` | `qwen2.5:3b-instruct` | 2,5 GB | no | el candidato por defecto: 15 tok/s en CPU |
| `local-q25-7b.Modelfile` | `qwen2.5:7b-instruct` | 5,5 GB | no | más criterio, la mitad de velocidad |
| `local-qwen3-4b.Modelfile` | `qwen3:4b` | 3 GB | sí, acotado con `LOCALFIT_THINK=false` | probar razonamiento (RM-2). Exige Ollama >= 0.9 para que `think` tenga efecto |

`num_ctx` se fija a 4096 en los tres: el prompt de un paso mide ~1.200-1.800
tokens y la respuesta está acotada por `LOCALFIT_NUM_PREDICT`. Lo que sobre en
ventana es KV cache que en 8 GB no sobra. El motor comprueba antes de cada
llamada que el prompt cabe (RA-4) y `LOCALFIT_NUM_CTX` no puede superar la
ventana real del modelo según `/api/show`.
