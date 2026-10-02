FROM debian:trixie

LABEL org.opencontainers.image.authors="Stefan Meinecke <meinecke@greensec.de>"

ENV DEBIAN_FRONTEND=noninteractive

RUN set -e \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates git gpg reprepro \
       python3 python3-git python3-gnupg python3-debian \
    && rm -rf /var/lib/apt/lists/*

COPY scripts /

ENTRYPOINT ["python3", "/entrypoint.py"]
