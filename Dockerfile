FROM debian:bookworm

LABEL maintainer="Stefan Meinecke <meinecke@greensec.de>"

ENV DEBIAN_FRONTEND=noninteractive

RUN set -e \
    && apt update \
    && apt install -y reprepro gpg python3 python3-git python3-gnupg expect python3-debian

COPY scripts /

ENTRYPOINT ["python3", "/entrypoint.py"]
