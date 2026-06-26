# forensia/evtxecmd:latest
#
# EvtxECmd (Eric Zimmerman) — ejecuta .NET sobre archivos .evtx pre-extraidos.
# Entrada esperada: /in/evtx (montaje read-only con .evtx adentro)
# Salida esperada:  /out/   (CSV resultante)
#
# Build:   docker build -t forensia/evtxecmd:latest images/evtxecmd/
# Verify:  docker run --rm forensia/evtxecmd:latest --help

FROM mcr.microsoft.com/dotnet/runtime:8.0-alpine AS runtime

ARG EVTXECMD_ZIP=https://download.ericzimmermanstools.com/net6/EvtxECmd.zip

RUN apk add --no-cache --virtual .build-deps curl unzip ca-certificates \
    && mkdir -p /opt/evtxecmd \
    && curl -fsSL "${EVTXECMD_ZIP}" -o /tmp/EvtxECmd.zip \
    && unzip /tmp/EvtxECmd.zip -d /opt/evtxecmd \
    && rm /tmp/EvtxECmd.zip \
    && apk del .build-deps

RUN adduser -S -D -H -u 65532 forensia \
    && chmod -R a-w /opt/evtxecmd

USER forensia
WORKDIR /work

ENTRYPOINT ["dotnet", "/opt/evtxecmd/EvtxECmd/EvtxECmd.dll"]
CMD ["--help"]
