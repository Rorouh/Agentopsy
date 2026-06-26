# forensia/mftecmd:latest
#
# MFTECmd (Eric Zimmerman) — parsea $MFT (y $J, $Boot, $SDS) pre-extraidos.
# Entrada esperada: /in/mft  (montaje read-only)
# Salida esperada:  /out/    (CSV resultante)
#
# Build:   docker build -t forensia/mftecmd:latest images/mftecmd/
# Verify:  docker run --rm forensia/mftecmd:latest --help

FROM mcr.microsoft.com/dotnet/runtime:8.0-alpine AS runtime

ARG MFTECMD_ZIP=https://download.ericzimmermanstools.com/net6/MFTECmd.zip

RUN apk add --no-cache --virtual .build-deps curl unzip ca-certificates \
    && mkdir -p /opt/mftecmd \
    && curl -fsSL "${MFTECMD_ZIP}" -o /tmp/MFTECmd.zip \
    && unzip /tmp/MFTECmd.zip -d /opt/mftecmd \
    && rm /tmp/MFTECmd.zip \
    && apk del .build-deps

RUN adduser -S -D -H -u 65532 forensia \
    && chmod -R a-w /opt/mftecmd

USER forensia
WORKDIR /work

ENTRYPOINT ["dotnet", "/opt/mftecmd/MFTECmd.dll"]
CMD ["--help"]
