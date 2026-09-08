# agentopsy-local-fit-llm: el motor para 8 GB sin GPU. Imagen pequeña: Python y
# cuatro dependencias. Sin CLIs de nube, sin node. Los maletines y Ollama son
# servicios aparte del mismo compose.
FROM python:3.12-slim-bookworm

WORKDIR /app/agentopsy-local-fit-llm

COPY agentopsy-local-fit-llm/requirements.txt requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip pip install --no-cache-dir -r requirements.txt

COPY agentopsy-local-fit-llm/ .

# LOCALFIT_BIND=0.0.0.0 solo DENTRO del contenedor: el compose no publica el puerto
# (SECURITY INVARIANT 1); el nginx del servicio web es quien lo alcanza.
ENV LOCALFIT_BIND=0.0.0.0 LOCALFIT_PORT=8001 PYTHONUNBUFFERED=1
EXPOSE 8001
CMD ["python", "api.py"]
