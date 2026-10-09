# The scanner image provides nmap and the custom SNMP NSE scripts.
ARG SCANNER_IMAGE=ghcr.io/mwallraf/nmap-network-discovery:1.2.0
FROM ${SCANNER_IMAGE}
ARG SCANNER_IMAGE

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*

COPY . /src
RUN python3 -m venv /opt/ndp \
 && /opt/ndp/bin/pip install --no-cache-dir /src \
 && rm -rf /src

ENV PATH=/opt/ndp/bin:$PATH \
    NDP_CONFIG=/etc/ndp/ndp.yaml \
    NDP_SCANNER_IMAGE=${SCANNER_IMAGE}

ENTRYPOINT ["ndp"]
CMD ["--help"]
