# syntax=docker/dockerfile:1
FROM debian:13-slim

ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iproute2 iptables openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0700 /var/lib/sakhtar-wg /etc/sakhtar-wg /run/sakhtar-wg

COPY dist/sakhtar-wg-linux-${TARGETARCH} /usr/local/bin/sakhtar-wg

ENTRYPOINT ["/usr/local/bin/sakhtar-wg"]
CMD ["up", "-c", "/etc/sakhtar-wg/config.yaml"]
