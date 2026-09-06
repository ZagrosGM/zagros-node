# Zagros Node — standalone, multi-core remote node for the Zagros panel.
#
# Shape inherited from gozargah/marzban-node (one container per server,
# Docker-first, certificate pairing with the panel), capability rebuilt:
# every Zagros core (xray, sing-box, OpenVPN, WireGuard, SSH, SoftEther,
# PPTP) is managed here through the panel's own vendored driver runtime.
#
# NO core binary is baked in: each driver downloads and verifies its own
# official release at install time, exactly like the panel. The only
# compiled artefact is accel-ppp (PPTP engine), which is built from an
# immutable, sha256-verified upstream commit.
ARG PYTHON_VERSION=3.12

# --------------------------------------------------------------------------
# Stage 1: pinned ACCEL-PPP engine for the PPTP core (ppp is not packaged
# as a server by any distribution we ship on). Only the allowlisted modules
# reach the final image — no compiler, no toolchain.
# --------------------------------------------------------------------------
FROM python:$PYTHON_VERSION-slim AS accel-ppp-build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl cmake make gcc libc6-dev linux-libc-dev \
       libpcre2-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY vendor/accel-ppp-manifest.json /tmp/accel-ppp-manifest.json
RUN set -eux; \
    version="$(python3 -c 'import json;print(json.load(open("/tmp/accel-ppp-manifest.json"))["version"])')"; \
    url="$(python3 -c 'import json;print(json.load(open("/tmp/accel-ppp-manifest.json"))["source"])')"; \
    expected="$(python3 -c 'import json;print(json.load(open("/tmp/accel-ppp-manifest.json"))["sha256"])')"; \
    curl -fL --retry 3 --proto '=https' --tlsv1.2 -o /tmp/accel-ppp-source.tar.gz "$url"; \
    echo "$expected  /tmp/accel-ppp-source.tar.gz" | sha256sum -c -; \
    mkdir -p /src /src/build /stage /bundle/sbin /bundle/lib/accel-ppp /bundle/source; \
    tar -xzf /tmp/accel-ppp-source.tar.gz -C /src --strip-components=1; \
    cmake -S /src -B /src/build \
      -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/zagros/accel-ppp/1.14.0 \
      -DLIB_SUFFIX= -DRADIUS=FALSE -DSHAPER=FALSE -DNETSNMP=FALSE -DLUA=FALSE \
      -DBUILD_PPTP_DRIVER=FALSE -DBUILD_IPOE_DRIVER=FALSE \
      -DBUILD_VLAN_MON_DRIVER=FALSE; \
    cmake --build /src/build --parallel "$(nproc)"; \
    DESTDIR=/stage cmake --install /src/build; \
    cp /stage/opt/zagros/accel-ppp/1.14.0/sbin/accel-pppd /bundle/sbin/accel-pppd; \
    for module in libtriton.so libpptp.so libauth_mschap_v2.so libchap-secrets.so libippool.so libsigchld.so libpppd_compat.so liblog_file.so; do \
      found="$(find /stage/opt -type f -name "$module" -print -quit)"; \
      test -n "$found"; cp "$found" "/bundle/lib/accel-ppp/$module"; \
    done; \
    cp /tmp/accel-ppp-source.tar.gz "/bundle/source/accel-ppp-${version}-source.tar.gz"; \
    cp /src/COPYING /bundle/source/COPYING; \
    cp /tmp/accel-ppp-manifest.json /bundle/source/manifest.json; \
    LD_LIBRARY_PATH=/bundle/lib/accel-ppp /bundle/sbin/accel-pppd --version | grep -Fx "accel-ppp ${version}"; \
    test "$(find /bundle/lib/accel-ppp -maxdepth 1 -type f | wc -l)" -eq 8

# --------------------------------------------------------------------------
# Stage 2: python dependencies (isolated venv, no build leftovers)
# --------------------------------------------------------------------------
FROM python:$PYTHON_VERSION-slim AS build

ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential gcc python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY ./requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade -r /tmp/requirements.txt

# --------------------------------------------------------------------------
# Final image
# --------------------------------------------------------------------------
FROM python:$PYTHON_VERSION-slim
ARG ZAGROS_NODE_VERSION=0.3.3
LABEL org.opencontainers.image.title="Zagros Node" \
      org.opencontainers.image.description="Zagros Node — multi-core remote node agent (xray, sing-box, OpenVPN, WireGuard, SSH, SoftEther, PPTP)" \
      org.opencontainers.image.source="https://github.com/ZagrosGM/zagros-node" \
      org.opencontainers.image.version="${ZAGROS_NODE_VERSION}" \
      org.opencontainers.image.licenses="AGPL-3.0"

# Runtime tooling for the host-managing cores:
#  * iptables/nftables/iproute2 — per-user accounting and classifiers
#  * openvpn / wireguard-tools  — TUN cores (client + server tooling)
#  * procps                     — sysctl required by wg-quick, process probes
#  * openssh-client/server      — managed SSH egress and the SSH core
#  * ppp                        — PPP character-device tunnels
#  * busybox-static, iproute2   — network namespace helpers
# All are inert until the matching core is installed. NET_ADMIN/NET_RAW and
# /dev/net/tun come from the compose spec (the installer grants them).
RUN set -eux; \
    test "$(dpkg --print-architecture)" = "amd64"; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
       ca-certificates curl iptables nftables iproute2 conntrack procps busybox-static \
       openvpn wireguard-tools openssh-client openssh-server ppp \
       libpcre2-8-0 libssl3 kmod; \
    mkdir -p /usr/share/doc/zagros-node; \
    rm -rf /var/lib/apt/lists/*

COPY --from=accel-ppp-build /bundle/sbin/accel-pppd /opt/zagros/accel-ppp/1.14.0/sbin/accel-pppd
COPY --from=accel-ppp-build /bundle/lib/accel-ppp /opt/zagros/accel-ppp/1.14.0/lib/accel-ppp
COPY --from=accel-ppp-build /bundle/source /usr/share/doc/zagros-node/accel-ppp-1.14.0

COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /code
COPY vendor/zagros /code/vendor/zagros
COPY node_agent /code/node_agent
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
    && mkdir -p /var/lib/zagros/node /var/lib/zagros/cores

# The vendored core runtime is imported as the `app` package; the node's own
# code lives in `node_agent`. Nothing else is on the path — a node cannot
# accidentally import panel machinery.
ENV PYTHONPATH=/code/vendor/zagros \
    PYTHONUNBUFFERED=1 \
    ZAGROS_NODE_DATA=/var/lib/zagros/node \
    ZAGROS_NODE_HOST=0.0.0.0 \
    ZAGROS_NODE_PORT=62050 \
    ZAGROS_NODE_API_PORT=62051 \
    ZAGROS_NODE_IMAGE=ghcr.io/zagrosgm/zagros-node:latest

# Read-only info port is the only unauthenticated surface; see
# node_agent/info_api.py for what it publishes (and what it never does).
EXPOSE 62050 62051

VOLUME ["/var/lib/zagros"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('ZAGROS_NODE_API_PORT','62051')+'/healthz',timeout=3).read()"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["python", "-m", "node_agent"]
