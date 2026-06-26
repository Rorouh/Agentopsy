# forensia/regripper:latest
#
# RegRipper 3.0 (Perl) ejecutado contra hives de registro pre-extraidas en el host.
# Entrada esperada: /in/hive (montaje read-only)
# Salida: stdout (parseado por el wrapper Python en forensia.toolkit.wrappers.regripper)
#
# Build:   docker build -t forensia/regripper:latest images/regripper/
# Verify:  docker run --rm forensia/regripper:latest -l

FROM perl:5.38-slim AS build

ARG REGRIPPER_REF=master

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "${REGRIPPER_REF}" \
        https://github.com/keydet89/RegRipper3.0.git /opt/regripper

RUN cpanm --notest \
        Parse::Win32Registry \
        Time::ParseDate \
        DateTime \
    && rm -rf /root/.cpanm

FROM perl:5.38-slim

COPY --from=build /opt/regripper /opt/regripper
COPY --from=build /usr/local/lib/perl5 /usr/local/lib/perl5

# Read-only filesystem hardening: nothing inside the image should mutate at runtime.
# The container is also started by the executor with --network none.
RUN useradd --system --no-create-home --uid 65532 forensia \
    && chmod -R a-w /opt/regripper

USER forensia
WORKDIR /opt/regripper

ENTRYPOINT ["perl", "/opt/regripper/rip.pl"]
CMD ["-l"]
