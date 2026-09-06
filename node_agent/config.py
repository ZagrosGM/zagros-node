"""Runtime configuration for the Zagros node agent.

Everything is environment-driven: the container receives its whole
configuration from ``/opt/zagros-node/.env`` (written by ``install.sh``),
so the image itself hardcodes nothing.

Layout inside the container (single mounted volume at ``/var/lib/zagros``)::

    /var/lib/zagros/node/      — ZAGROS_NODE_DATA: identity, sealed state, TLS
    /var/lib/zagros/cores/     — per-core runtime (driver default paths)

The cores' own default paths are ``/var/lib/zagros/cores/...``; mounting the
node volume there keeps every driver working unmodified instead of
re-writing paths per core.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

AGENT_NAME = "zagros-node"
AGENT_VERSION = "0.3.3"
API_VERSION = 1

DEFAULT_PORT = 62050          # HTTPS control plane (panel → node, signed)
DEFAULT_API_PORT = 62051      # bootstrap/info (read-only, see info_api.py)

# Cores a node is allowed to host. The list is explicit (rather than "anything
# the vendored registry ships") so that adding a driver to the panel never
# silently widens the remote attack surface of every deployed node.
NODE_CORE_ALLOWLIST = frozenset({
    "xray", "sing-box", "openvpn", "wireguard", "ssh", "softether", "pptp",
})


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    try:
        return int(raw) if raw else default
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "")
    if not raw:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class NodeConfig:
    """Immutable, validated view of the agent's environment."""

    data_dir: str
    host: str
    port: int
    api_port: int
    info_bind: str
    tls_cert: str
    tls_key: str
    registration_hash: str
    name: str
    address: str
    image: str
    allow_insecure_test: bool

    # ---- derived paths -------------------------------------------------
    @property
    def root(self) -> Path:
        return Path(self.data_dir)

    @property
    def tls_dir(self) -> Path:
        return self.root / "tls"

    @property
    def cores_dir(self) -> Path:
        """Per-core runtime root (drivers default below ``/var/lib/zagros``)."""
        return Path("/var/lib/zagros/cores")

    @staticmethod
    def from_env() -> "NodeConfig":
        data_dir = os.environ.get("ZAGROS_NODE_DATA", "/var/lib/zagros/node")
        cfg = NodeConfig(
            data_dir=data_dir,
            host=os.environ.get("ZAGROS_NODE_HOST", "0.0.0.0"),
            port=_int("ZAGROS_NODE_PORT", DEFAULT_PORT),
            api_port=_int("ZAGROS_NODE_API_PORT", DEFAULT_API_PORT),
            info_bind=os.environ.get("ZAGROS_NODE_INFO_BIND", "0.0.0.0"),
            tls_cert=os.environ.get(
                "ZAGROS_NODE_TLS_CERT", str(Path(data_dir) / "tls" / "node.crt")),
            tls_key=os.environ.get(
                "ZAGROS_NODE_TLS_KEY", str(Path(data_dir) / "tls" / "node.key")),
            registration_hash=os.environ.get(
                "ZAGROS_NODE_REGISTRATION_HASH", "").strip().lower(),
            name=os.environ.get("ZAGROS_NODE_NAME", "").strip(),
            # Comma-separated DNS names / IPs the panel will reach this node
            # on. They become certificate SANs — without them hostname
            # verification fails, because a panel addresses nodes by IP.
            address=os.environ.get("ZAGROS_NODE_ADDRESS", "").strip(),
            image=os.environ.get("ZAGROS_NODE_IMAGE", "ghcr.io/zagrosgm/zagros-node:latest"),
            allow_insecure_test=_bool("ZAGROS_NODE_ALLOW_INSECURE_TEST", False),
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if not 1 <= self.port <= 65535:
            raise ValueError(f"ZAGROS_NODE_PORT out of range: {self.port}")
        if not 1 <= self.api_port <= 65535:
            raise ValueError(f"ZAGROS_NODE_API_PORT out of range: {self.api_port}")
        if self.port == self.api_port:
            raise ValueError(
                "ZAGROS_NODE_PORT and ZAGROS_NODE_API_PORT must differ "
                f"(both are {self.port})")
        if self.registration_hash and len(self.registration_hash) != 64:
            raise ValueError(
                "ZAGROS_NODE_REGISTRATION_HASH must be a 64-char hex sha256")


def load_config() -> NodeConfig:
    return NodeConfig.from_env()
