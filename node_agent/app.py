"""HTTPS control plane for the Zagros multi-core node agent.

Everything on this port is mutually authenticated:

* the agent proves itself with a certificate the panel has pinned, and
* the panel proves itself with an HMAC-SHA256 signature over every request
  (see :mod:`node_agent.security`).

There is deliberately **no shell endpoint, no Docker socket and no file
endpoint**. The API surface is a fixed set of core lifecycle and
configuration verbs, each constrained by an allowlist and by the driver's
own settings schema.
"""
from __future__ import annotations

# The compatibility shims MUST be installed before any vendored driver is
# imported: several of them touch panel modules at import/render time.
from node_agent import compat
compat.install()

import asyncio
import base64
import copy
import inspect
import json
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

import psutil
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from app.cores.manager import CoreManager
from app.cores.types import Capability, CoreState, UserAccount
from app.cores.registry import available_drivers, discover_builtin, get_driver_class
from node_agent.accounts_store import AccountsStore
from node_agent.limits import NodeBandwidthLimiter
from node_agent import tls
from node_agent.config import (
    AGENT_NAME,
    AGENT_VERSION,
    API_VERSION,
    NODE_CORE_ALLOWLIST,
    load_config,
)
from node_agent.info_api import start_info_server
from node_agent.jobs import JobConflictError, JobManager
from node_agent.security import (
    NodeIdentityStore,
    NodeSecurityError,
    ReplayGuard,
    verify_signature,
)
from node_agent.state import NodeCoreStateStore

CFG = load_config()
STARTED_AT = time.time()

identity = NodeIdentityStore(CFG.data_dir, CFG.registration_hash or None)
replays = ReplayGuard(CFG.data_dir)
jobs = JobManager()
discover_builtin()

CERTIFICATE = tls.ensure(CFG)

# Per-action job deadlines: installs download and verify release archives,
# restarts are bounded by the driver's own readiness probe.
_JOB_TIMEOUT = {"install": 1200.0, "uninstall": 600.0, "update": 1200.0}
# A full account reconcile touches every user of the core; SoftEther does it
# in one authenticated PTY session, WireGuard rewrites its peer table.
_ACCOUNTS_TIMEOUT = 300.0


# Core binaries, configs and runtime state live under one root. Production
# images mount the node volume at /var/lib/zagros — the same path the drivers
# use inside the panel — so every driver default works untouched. The override
# exists for tests and bare-metal/development runs, where /var/lib/zagros may
# be unwritable; it is applied generically by rewriting driver *defaults*, so
# new drivers need no per-core knowledge here.
CORE_ROOT_DEFAULT = "/var/lib/zagros"
CORE_ROOT = os.environ.get("ZAGROS_CORE_ROOT", "").strip().rstrip("/") or CORE_ROOT_DEFAULT


def _node_driver_settings(core_id: str, settings: dict[str, Any]) -> dict[str, Any]:
    """Compose the settings a node-owned driver instance is built with."""
    merged: dict[str, Any] = {
        **settings,
        # Explicit composition context; unlike a process-global environment
        # flag, this cannot make panel-owned drivers select node backends.
        "_runtime_mode": "node",
    }
    if CORE_ROOT == CORE_ROOT_DEFAULT:
        return merged
    try:
        defaults = get_driver_class(core_id).metadata.default_settings or {}
    except Exception:  # noqa: BLE001 — unknown core: nothing to relocate
        return merged
    for key, default in defaults.items():
        if key in merged or not isinstance(default, str):
            continue
        if default.startswith(CORE_ROOT_DEFAULT + "/"):
            merged[key] = CORE_ROOT + default[len(CORE_ROOT_DEFAULT):]
    return merged


core_manager = CoreManager(
    NodeCoreStateStore(CFG.data_dir), builtin_core_ids=frozenset(),
    settings_transform=_node_driver_settings)

# Host-level traffic shaping. The panel owns the rates, this host owns the
# wire — see node_agent/limits.py.
limiter = NodeBandwidthLimiter(core_manager, CFG.data_dir)
accounts_store = AccountsStore(CFG.data_dir)

_SECRET_MARKERS = ("secret", "password", "passwd", "token", "key", "psk", "pass")


def _mask_settings(settings: dict[str, Any]) -> dict[str, Any]:
    masked: dict[str, Any] = {}
    for key, value in (settings or {}).items():
        lowered = str(key).lower()
        if any(marker in lowered for marker in _SECRET_MARKERS) and value:
            masked[key] = f"set ({len(str(value))} chars)"
        else:
            masked[key] = value
    return masked


def _authorize_core(core_id: str, settings: dict[str, Any] | None = None) -> None:
    """Constrain signed authority to known adapters and schema-owned settings."""
    if core_id not in NODE_CORE_ALLOWLIST:
        raise HTTPException(403, f"core '{core_id}' is not in the node allowlist")
    if core_id not in available_drivers():
        raise HTTPException(404, f"core '{core_id}' has no driver in this image")
    if not settings:
        return
    metadata = get_driver_class(core_id).metadata
    allowed = set((metadata.config_schema.get("properties") or {}).keys())
    allowed.update(metadata.default_settings)
    allowed.add("release_version")
    unknown = sorted(set(settings) - allowed)
    if unknown:
        raise HTTPException(422, f"settings are not allowlisted for {core_id}: {unknown}")
    # A signed command must never be able to point a core at (or write to) an
    # arbitrary host path — every path-ish setting stays under the core root.
    root = Path(CORE_ROOT).resolve()
    for key, value in settings.items():
        lowered = key.lower()
        if not isinstance(value, str) or not any(
                marker in lowered for marker in ("path", "root", "dir")):
            continue
        path = Path(value)
        if path.is_absolute() and root != path.resolve() and root not in path.resolve().parents:
            raise HTTPException(
                422, f"setting '{key}' must remain under {CORE_ROOT}")


# --------------------------------------------------------------------------- #
# application
# --------------------------------------------------------------------------- #
@asynccontextmanager
async def lifespan(_app: FastAPI):
    await core_manager.boot()
    # The public bootstrap endpoint must not be held hostage by core recovery.
    # A persisted SoftEther/OpenVPN/etc. start can legitimately take minutes;
    # the installer and panel discovery only need identity + certificate data,
    # so bind the info port first and keep it serving while enabled cores and
    # account/limit state are restored.  The signed control plane still does
    # not report application startup complete until reconciliation finishes.
    stop_info = await start_info_server(CFG, identity, core_manager, CERTIFICATE,
                                        started_at=STARTED_AT)
    try:
        await core_manager.start_enabled()
        restore_usage_baselines()
        await restore_accounts()
        limiter.load()
        limiter.apply()   # limits pushed earlier must survive a restart
        yield
    finally:
        await stop_info()
        await core_manager.stop_all()


logger = logging.getLogger("node_agent.app")

app = FastAPI(title="Zagros Node Agent", version=AGENT_VERSION, lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


class RegisterBody(BaseModel):
    panel_id: str = Field(min_length=8, max_length=128,
                          pattern=r"^[A-Za-z0-9._-]+$")
    registration_token: str = Field(min_length=16, max_length=512)


class CoreActionBody(BaseModel):
    action: Literal["install", "uninstall", "start", "stop", "restart", "update"]
    settings: dict[str, Any] = Field(default_factory=dict)
    purge: bool = False
    force: bool = False


class InboundDocument(BaseModel):
    document: dict[str, Any]
    # Node-local file material referenced by ``zagros-material://<name>`` in
    # the document.  Currently restricted to validated Xray TLS PEM pairs;
    # this is deliberately not a generic remote file-write API.
    material: dict[str, str] = Field(default_factory=dict)


class SettingsPatch(BaseModel):
    settings: dict[str, Any]


class AccountsPayload(BaseModel):
    """The panel's desired account set for one core.

    ``replace=True`` makes the node converge to exactly this list (removing
    accounts the panel no longer knows about); with ``replace=False`` the
    node only creates/updates what is sent, which is what an incremental
    user save does.
    """

    accounts: list[dict[str, Any]] = Field(default_factory=list)
    replace: bool = True


# --------------------------------------------------------------------------- #
# registration + authenticated request dependency
# --------------------------------------------------------------------------- #
@app.post("/v1/register")
async def register(body: RegisterBody, request: Request):
    # Production always serves TLS. An explicit test-only switch is required
    # to exercise this route over TestClient's in-memory HTTP.
    if request.url.scheme != "https" and not CFG.allow_insecure_test:
        raise HTTPException(400, "node registration requires HTTPS")
    try:
        key = identity.register(body.registration_token, body.panel_id)
    except NodeSecurityError as exc:
        raise HTTPException(401, str(exc)) from exc
    return {
        "node_id": identity.node_id,
        # Returned once, over the certificate-pinned TLS registration channel.
        # It is a signing key, not the bootstrap token (which is burned).
        "signing_key": base64.b64encode(key).decode("ascii"),
        "agent": AGENT_NAME,
        "agent_version": AGENT_VERSION,
        "api_version": API_VERSION,
    }


async def signed_request(
    request: Request,
    x_zagros_node: str | None = Header(default=None, alias="X-Zagros-Node"),
    x_zagros_timestamp: str | None = Header(default=None, alias="X-Zagros-Timestamp"),
    x_zagros_nonce: str | None = Header(default=None, alias="X-Zagros-Nonce"),
    x_zagros_signature: str | None = Header(default=None, alias="X-Zagros-Signature"),
) -> str:
    # Missing credentials must be indistinguishable from wrong ones: both are
    # 401. A 422 would tell an unauthenticated caller which headers exist.
    if not all((x_zagros_node, x_zagros_timestamp, x_zagros_nonce, x_zagros_signature)):
        raise HTTPException(401, "missing signature headers")
    key = identity.signing_key()
    if key is None or x_zagros_node != identity.node_id:
        raise HTTPException(401, "node is not registered for this signer")
    try:
        timestamp = int(x_zagros_timestamp)
        body = await request.body()
        verify_signature(
            key, x_zagros_signature, request.method, request.url.path,
            x_zagros_timestamp, x_zagros_nonce, body)
        replays.accept(x_zagros_nonce, timestamp)
    except (ValueError, NodeSecurityError) as exc:
        raise HTTPException(401, str(exc)) from exc
    return x_zagros_node


# --------------------------------------------------------------------------- #
# node-level endpoints
# --------------------------------------------------------------------------- #
@app.get("/v1/heartbeat")
async def heartbeat(_node=Depends(signed_request)):
    return {"node_id": identity.node_id, "ts": int(time.time()),
            "agent": AGENT_NAME, "agent_version": AGENT_VERSION,
            "api_version": API_VERSION}


@app.post("/v1/revoke")
async def revoke(_node=Depends(signed_request)):
    identity.revoke()
    return {"revoked": True}


@app.get("/v1/info")
async def info(_node=Depends(signed_request)):
    return await _node_info(detailed=True)


@app.get("/v1/health")
async def health(_node=Depends(signed_request)):
    resources, cores = await asyncio.gather(
        asyncio.to_thread(_resources), asyncio.to_thread(_cores_summary))
    return {"node_id": identity.node_id, "healthy": True,
            "uptime_seconds": round(time.time() - STARTED_AT, 1),
            "resources": resources, "cores": cores}


@app.get("/v1/audit")
async def audit(limit: int = 100, _node=Depends(signed_request)):
    return {"entries": identity.audit_tail(max(1, min(limit, 500)))}


@app.get("/v1/jobs")
async def list_jobs(limit: int = 50, _node=Depends(signed_request)):
    return {"jobs": jobs.recent(limit)}


@app.get("/v1/jobs/{job_id}")
async def job_status(job_id: str, _node=Depends(signed_request)):
    job = jobs.get(job_id)
    if job is None:
        raise HTTPException(404, f"job '{job_id}' not found")
    return job.to_dict()


# --------------------------------------------------------------------------- #
# cores: inventory, lifecycle, logs, configuration
# --------------------------------------------------------------------------- #
@app.get("/v1/cores")
async def cores(_node=Depends(signed_request)):
    statuses = await core_manager.status_all()
    by_id = {status.core_id: status.model_dump(mode="json") for status in statuses}
    installed = set(core_manager.list_cores())
    return {
        "installed": by_id,
        # Explicit protocol capabilities let a patched panel roll out before
        # patched nodes without sending reserved material references to an old
        # agent that would persist them as ordinary (and unusable) paths.
        "features": {"xray_tls_material": 1},
        # catalog = every allowlisted core this image can install, minus the
        # ones already installed (exactly the panel's Master semantics).
        "available": sorted(NODE_CORE_ALLOWLIST.intersection(
            available_drivers()) - installed),
        "preview": {core_id: _catalog_entry(core_id)
                    for core_id in sorted(NODE_CORE_ALLOWLIST.intersection(
                        available_drivers()) - installed)},
    }


@app.get("/v1/cores/{core_id}")
async def core_status(core_id: str, _node=Depends(signed_request)):
    _authorize_core(core_id)
    if core_id not in core_manager.list_cores():
        raise HTTPException(404, f"core '{core_id}' is not installed")
    status = await core_manager.status(core_id)
    return status.model_dump(mode="json")


@app.get("/v1/cores/{core_id}/version")
async def core_version(core_id: str, _node=Depends(signed_request)):
    _authorize_core(core_id)
    if core_id not in core_manager.list_cores():
        raise HTTPException(404, f"core '{core_id}' is not installed")
    return (await core_manager.get(core_id).version()).model_dump(mode="json")


@app.get("/v1/cores/{core_id}/logs")
async def core_logs(core_id: str, tail: int = 200, _node=Depends(signed_request)):
    _authorize_core(core_id)
    if core_id not in core_manager.list_cores():
        raise HTTPException(404, f"core '{core_id}' is not installed")
    lines = await asyncio.wait_for(
        core_manager.get_logs(core_id, tail=max(1, min(tail, 2000))), timeout=30)
    return {"core_id": core_id, "lines": lines}


@app.get("/v1/cores/{core_id}/settings")
async def core_settings(core_id: str, _node=Depends(signed_request)):
    _authorize_core(core_id)
    if core_id not in core_manager.list_cores():
        raise HTTPException(404, f"core '{core_id}' is not installed")
    driver = core_manager.get(core_id)
    return {"core_id": core_id, "settings": _mask_settings(dict(driver.settings or {}))}


@app.put("/v1/cores/{core_id}/settings")
async def core_settings_update(core_id: str, body: SettingsPatch,
                               _node=Depends(signed_request)):
    _authorize_core(core_id, body.settings)
    if core_id not in core_manager.list_cores():
        raise HTTPException(404, f"core '{core_id}' is not installed")
    driver = core_manager.get(core_id)
    merged = {**dict(driver.settings or {}), **body.settings}
    driver.settings = merged
    await core_manager._store.save_state(  # noqa: SLF001 — persist through the manager's store
        core_id, state=core_manager._states[core_id],  # noqa: SLF001
        enabled=core_manager.is_enabled(core_id), settings=merged)
    identity.audit("core.settings", {"core_id": core_id,
                                     "keys": sorted(body.settings)})
    return {"ok": True, "core_id": core_id,
            "settings": _mask_settings(merged),
            "restart_required": True}


class IdentityPayload(BaseModel):
    """The master's SERVER identity material for one core.

    A node that generated its own keys would answer with a different CA /
    server public key / IPsec PSK than the one the portal has already handed
    to users — every profile pointing at this node would fail to
    authenticate the server. Nodes therefore adopt the master's identity.
    The map is opaque here: each driver names its own material (relative
    file paths, or reserved keys such as ``ipsec_psk``).
    """

    material: dict[str, str] = Field(default_factory=dict)


@app.put("/v1/cores/{core_id}/identity")
async def core_identity(core_id: str, body: IdentityPayload,
                        _node=Depends(signed_request)):
    """Adopt the master's server identity (CA / server key / IPsec PSK).

    Material is written BEFORE the listener document is applied and the core
    is restarted, so the next handshake answers with the federated identity
    instead of a locally generated one.
    """
    _authorize_core(core_id)
    if core_id not in core_manager.list_cores():
        raise HTTPException(404, f"core '{core_id}' is not installed")
    driver = core_manager.get(core_id)
    importer = getattr(driver, "import_identity", None)
    if not callable(importer):
        raise HTTPException(
            409, f"core '{core_id}' has no server identity to adopt")
    try:
        applied = importer(body.material)
        if inspect.isawaitable(applied):
            applied = await applied
    except NotImplementedError as exc:
        raise HTTPException(
            409, f"core '{core_id}' cannot adopt an identity ({exc})") from exc
    except Exception as exc:  # noqa: BLE001 — driver errors are node-visible
        identity.audit("identity.failed", {"core_id": core_id,
                                           "error_type": type(exc).__name__})
        raise HTTPException(409, str(exc)) from exc
    if not applied:
        return {"ok": True, "core_id": core_id, "applied": [],
                "restarted": False}
    # Settings-backed material (SoftEther's PSK) only survives a restart if
    # it is persisted through the manager, under the core lifecycle lock.
    persist = getattr(core_manager, "persist_settings", None)
    if callable(persist):
        try:
            await persist(core_id)
        except Exception:  # noqa: BLE001 — never fail an applied identity
            logger.warning("identity: could not persist settings for %s", core_id)
    restarted = False
    was_running = core_manager._states.get(core_id) == CoreState.RUNNING  # noqa: SLF001
    try:
        if was_running:
            await asyncio.wait_for(core_manager.stop_core(core_id), timeout=120)
            await asyncio.wait_for(core_manager.start_core(core_id), timeout=180)
            restarted = True
    except asyncio.TimeoutError as exc:
        raise HTTPException(504, "identity apply timed out on restart") from exc
    except Exception as exc:  # noqa: BLE001
        identity.audit("identity.restart_failed", {
            "core_id": core_id, "error_type": type(exc).__name__})
        raise HTTPException(409, f"identity applied but restart failed: {exc}") from exc
    identity.audit("identity.apply", {"core_id": core_id,
                                      "applied": sorted(applied),
                                      "restarted": restarted})
    return {"ok": True, "core_id": core_id, "applied": sorted(applied),
            "restarted": restarted}


@app.put("/v1/cores/{core_id}/accounts")
async def core_accounts(core_id: str, body: AccountsPayload,
                        _node=Depends(signed_request)):
    """Converge a core's user accounts to the panel's desired state.

    This is the other half of "a config pointing at the node works": pushing
    the inbound *configuration* alone is useless unless the accounts that
    authenticate against it exist on this server too. Accounts arrive over
    the same signed channel as every other command, and their settings are
    validated as plain JSON data (no paths, no nested objects we would have
    to interpret) before the driver sees them.
    """
    _authorize_core(core_id)
    if core_id not in core_manager.list_cores():
        raise HTTPException(404, f"core '{core_id}' is not installed")
    driver = core_manager.get(core_id)
    accounts = [_to_user_account(raw) for raw in body.accounts]
    try:
        await asyncio.wait_for(
            driver.sync_accounts(accounts), timeout=_ACCOUNTS_TIMEOUT)
    except asyncio.TimeoutError as exc:
        raise HTTPException(504, "account sync timed out") from exc
    except NotImplementedError as exc:
        raise HTTPException(
            409, f"core '{core_id}' cannot manage accounts ({exc})") from exc
    except Exception as exc:  # noqa: BLE001 — driver errors are node-visible
        identity.audit("accounts.failed", {"core_id": core_id,
                                           "error_type": type(exc).__name__})
        raise HTTPException(409, str(exc)) from exc
    accounts_store.store(core_id, [raw for raw in body.accounts
                                   if isinstance(raw, dict)],
                         replace=bool(body.replace))
    identity.audit("accounts.sync", {"core_id": core_id,
                                     "count": len(accounts),
                                     "replace": body.replace})
    return {"ok": True, "core_id": core_id, "count": len(accounts),
            "replace": body.replace}


class IPBansBody(BaseModel):
    """Panel-owned active bans, projected onto this node's VPN listeners."""
    bans: list[dict[str, Any]] = Field(default_factory=list)


@app.put("/v1/ip-bans")
async def apply_ip_bans(body: IPBansBody, _node=Depends(signed_request)):
    from node_agent import ip_limits

    tcp, udp = await ip_limits.managed_ports(core_manager)
    result = await asyncio.to_thread(ip_limits.apply, body.bans, tcp, udp)
    if not result.get("ok"):
        raise HTTPException(409, result.get("error") or "IP ban apply failed")
    ips = {str(row.get("ip")) for row in body.bans if row.get("ip")}
    closed = await ip_limits.terminate(core_manager, ips)
    closed += await asyncio.to_thread(ip_limits.drop_conntrack, ips, tcp, udp)
    identity.audit("ip_bans.apply", {"active": result.get("active", 0),
                                     "connections_closed": closed})
    return {**result, "connections_closed": closed}


class BandwidthLimitsBody(BaseModel):
    """The panel's per-user speed limits for this host."""

    limits: dict[str, Any] = Field(default_factory=dict)


@app.put("/v1/bandwidth/limits")
async def bandwidth_limits(body: BandwidthLimitsBody,
                           _node=Depends(signed_request)):
    """Enforce the panel's per-user speed limits on THIS host.

    Shaping cannot be done from the panel: tc filters and nft marks only
    affect the machine carrying the packets. The panel computes the rates (it
    owns the users), the node installs them (it owns the wire).
    """
    result = await asyncio.to_thread(limiter.apply, body.limits)
    identity.audit("bandwidth.apply", {
        "limited_users": result.get("limited_users"),
        "ok": result.get("ok"),
    })
    if not result.get("ok"):
        raise HTTPException(409, result.get("error") or "bandwidth apply failed")
    return {"ok": True, **result}


@app.get("/v1/bandwidth/status")
async def bandwidth_status(_node=Depends(signed_request)):
    return await asyncio.to_thread(limiter.status)


# --------------------------------------------------------------------------- #
# runtime telemetry — what the panel cannot see from here
# --------------------------------------------------------------------------- #
# The panel drives quota, presence and limits from its OWN cores only, so a
# user connected through this node looked offline, consumed nothing and was
# never shaped. These endpoints hand the panel the same three readings its
# local drivers give it; the panel folds them into the very same pipelines
# (UsageRecord/DeviceSession already carry a node_id for exactly this).

_TELEMETRY_TIMEOUT = 30.0


def _capable_drivers(capability) -> list[tuple[str, Any]]:
    """(core_id, driver) for every installed, enabled core with `capability`."""
    out: list[tuple[str, Any]] = []
    for core_id in core_manager.list_cores():
        try:
            if not core_manager.is_enabled(core_id):
                continue
            driver = core_manager.get(core_id)
        except Exception:  # noqa: BLE001 — a half-loaded core contributes none
            continue
        if capability in driver.metadata.capabilities:
            out.append((core_id, driver))
    return out


@app.get("/v1/runtime/devices")
async def runtime_devices(_node=Depends(signed_request)):
    """Every online session this node is serving, across all cores.

    Presence is derived from the drivers themselves (wg handshakes, openvpn
    status, accel-ppp sessions, ...), exactly as the panel does locally.
    """
    sessions: list[dict] = []
    failed: list[str] = []
    for core_id, driver in _capable_drivers(Capability.ONLINE_TRACKING):
        try:
            found = await asyncio.wait_for(
                driver.get_online_devices(account_ids=None),
                timeout=_TELEMETRY_TIMEOUT)
        except asyncio.TimeoutError:
            failed.append(core_id)
            continue
        except Exception as exc:  # noqa: BLE001 — one bad core never blocks
            logger.warning("online devices read failed for %s: %s", core_id, exc)
            failed.append(core_id)
            continue
        for session in found or []:
            payload = session.model_dump(mode="json")
            payload.setdefault("core_id", core_id)
            sessions.append(payload)
    return {"devices": sessions, "failed_cores": failed}


@app.get("/v1/runtime/usage")
async def runtime_usage(_node=Depends(signed_request)):
    """Per-account usage DELTAS since the previous call.

    Counters are cumulative on the providers; the drivers' trackers turn them
    into deltas, and the baselines are persisted here so an agent restart
    cannot re-emit a whole counter as fresh traffic (the classic multi-node
    double-count).
    """
    records: list[dict] = []
    baselines: dict[str, Any] = {}
    for core_id, driver in _capable_drivers(Capability.USAGE_ACCOUNTING):
        try:
            found = await asyncio.wait_for(
                driver.get_usage(account_ids=None), timeout=_TELEMETRY_TIMEOUT)
        except asyncio.TimeoutError:
            continue
        except Exception as exc:  # noqa: BLE001 — isolate a broken tick
            logger.warning("usage read failed for %s: %s", core_id, exc)
            continue
        for record in found or []:
            if not (record.uplink_bytes or record.downlink_bytes):
                continue
            payload = record.model_dump(mode="json")
            payload.setdefault("core_id", core_id)
            records.append(payload)
        # Persist the cursor ONLY after the deltas were handed over: losing a
        # delta is honest, moving the cursor before delivery loses bytes.
        try:
            snapshot = driver.usage_tracker_snapshot(None) or {}
        except Exception:  # noqa: BLE001
            snapshot = {}
        for account_id, totals in snapshot.items():
            baselines[f"{core_id}:{account_id}"] = [int(totals[0]), int(totals[1])]
    if baselines:
        _save_usage_baselines(baselines)
    return {"usage": records}


def _usage_baseline_path() -> Path:
    return Path(CFG.data_dir) / "usage-baselines.json"


def _save_usage_baselines(baselines: dict[str, Any]) -> None:
    try:
        path = _usage_baseline_path()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        merged: dict[str, Any] = {}
        if path.exists():
            try:
                merged = json.loads(path.read_text(encoding="utf-8")) or {}
            except (OSError, ValueError):
                merged = {}
        merged.update(baselines)
        path.write_text(json.dumps(merged, sort_keys=True), encoding="utf-8")
    except OSError as exc:  # never fail a telemetry read over bookkeeping
        logger.warning("usage baseline persist failed: %s", exc)


def restore_usage_baselines() -> None:
    """Boot-time restore: a restarted agent must not re-report old bytes."""
    path = _usage_baseline_path()
    if not path.exists():
        return
    try:
        stored = json.loads(path.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return
    by_core: dict[str, dict[str, tuple[int, int]]] = {}
    for key, totals in stored.items():
        core_id, _, account_id = str(key).partition(":")
        if not core_id or not isinstance(totals, (list, tuple)) or len(totals) != 2:
            continue
        by_core.setdefault(core_id, {})[account_id] = (int(totals[0]), int(totals[1]))
    for core_id, mapping in by_core.items():
        if core_id not in core_manager.list_cores():
            continue
        try:
            core_manager.get(core_id).restore_usage_baselines(mapping)
        except Exception:  # noqa: BLE001
            logger.warning("usage baseline restore failed for %s", core_id)


async def restore_accounts() -> None:
    """Boot-time replay of the accounts the panel last pushed.

    The drivers hold accounts in memory only, so a restart used to leave a
    node serving traffic normally while silently losing everything that reads
    the account list — bandwidth identities above all, which is how a pushed
    speed limit turned into a no-op until the next full sync. Replaying the
    snapshot restores the same state without waiting for the panel.
    """
    for core_id, raws in accounts_store.all().items():
        if not raws or core_id not in core_manager.list_cores():
            continue
        accounts = []
        for raw in raws:
            try:
                accounts.append(_to_user_account(raw))
            except HTTPException as exc:
                logger.warning("stored account for %s is stale: %s",
                               core_id, exc.detail)
        if not accounts:
            continue
        try:
            await asyncio.wait_for(core_manager.get(core_id).sync_accounts(
                accounts), timeout=_ACCOUNTS_TIMEOUT)
        except Exception as exc:  # noqa: BLE001 — never block the boot
            logger.warning("account restore failed for %s: %s", core_id, exc)
        else:
            logger.info("restored %d account(s) for %s", len(accounts), core_id)


@app.post("/v1/cores/{core_id}/lifecycle")
async def core_lifecycle(core_id: str, body: CoreActionBody, wait: float = 0,
                         _node=Depends(signed_request)):
    """Submit a lifecycle action.

    ``?wait=<seconds>`` blocks until the job reaches a terminal state (or the
    deadline), which keeps fast actions a single round-trip while long ones
    stay pollable through ``GET /v1/jobs/{job_id}``.
    """
    _authorize_core(core_id, body.settings)
    action = body.action
    timeout = _JOB_TIMEOUT.get(action, 120.0)

    async def execute() -> dict[str, Any]:
        if action == "install":
            await core_manager.install_core(core_id, settings=body.settings)
        elif action == "uninstall":
            await core_manager.uninstall_core(
                core_id, purge=body.purge, force=body.force)
            if body.purge:
                accounts_store.forget(core_id)
            return {"core_id": core_id, "state": "uninstalled"}
        elif action == "start":
            await core_manager.start_core(core_id)
        elif action == "stop":
            await core_manager.stop_core(core_id)
        elif action == "restart":
            await core_manager.restart_core(core_id)
        elif action == "update":
            version = await core_manager.update_core(
                core_id, body.settings.get("release_version"))
            return {"core_id": core_id, "version": version}
        return (await core_manager.status(core_id)).model_dump(mode="json")

    try:
        job = await jobs.submit(core_id, action, execute, timeout=timeout)
    except JobConflictError as exc:
        raise HTTPException(409, str(exc)) from exc
    identity.audit("core.lifecycle.submit", {"core_id": core_id, "action": action})

    deadline = time.time() + max(0.0, min(wait, timeout + 5))
    while wait > 0 and job.state not in ("succeeded", "failed", "cancelled"):
        if time.time() >= deadline:
            break
        await asyncio.sleep(0.25)

    payload = job.to_dict()
    if job.state == "failed":
        identity.audit("core.failed", {"core_id": core_id, "action": action,
                                       "error_type": job.error_type})
        raise HTTPException(409, job.error or f"{action} failed")
    if job.state == "succeeded":
        identity.audit("core.lifecycle", {"core_id": core_id, "action": action})
    return payload


_NODE_MATERIAL_PREFIX = "zagros-material://"
_NODE_MATERIAL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
_NODE_TLS_FILE_LIMIT = 32
_NODE_TLS_ITEM_BYTES = 128 * 1024
_NODE_TLS_TOTAL_BYTES = 2 * 1024 * 1024


def _materialize_xray_tls(document: dict[str, Any],
                          material: dict[str, str]) -> dict[str, Any]:
    """Resolve transported Xray PEM pairs into this node's confined data root.

    The panel may supply file *contents*, never a destination.  References are
    recognised only inside native Xray TLS certificate entries; names are
    basename-only, every pair is cryptographically validated, and unused
    uploads are rejected.  This keeps node sync from becoming a generic
    signed arbitrary-file-write primitive.
    """
    if len(material) > _NODE_TLS_FILE_LIMIT:
        raise ValueError("too many Xray TLS material files")
    total = 0
    for name, value in material.items():
        if not _NODE_MATERIAL_NAME.fullmatch(name):
            raise ValueError(f"invalid Xray TLS material name: {name!r}")
        if not isinstance(value, str):
            raise ValueError(f"Xray TLS material '{name}' must be PEM text")
        size = len(value.encode("utf-8"))
        if size > _NODE_TLS_ITEM_BYTES:
            raise ValueError(f"Xray TLS material '{name}' is too large")
        total += size
    if total > _NODE_TLS_TOTAL_BYTES:
        raise ValueError("Xray TLS material exceeds 2 MiB")

    driver = core_manager.get("xray")
    cert_dir = Path(str(driver.settings.get("cert_dir")
                        or f"{CORE_ROOT}/cores/xray/certs")).resolve()
    root = Path(CORE_ROOT).resolve()
    if cert_dir != root and root not in cert_dir.parents:
        raise ValueError("the Xray certificate directory escapes the node core root")
    cert_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    prepared = copy.deepcopy(document)
    consumed: set[str] = set()
    for inbound in prepared.get("inbounds") or []:
        if not isinstance(inbound, dict):
            continue
        tls = ((inbound.get("streamSettings") or {}).get("tlsSettings") or {})
        certificates = tls.get("certificates") or []
        if not isinstance(certificates, list):
            continue
        for pair in certificates:
            if not isinstance(pair, dict):
                continue
            cert_ref = str(pair.get("certificateFile") or "")
            key_ref = str(pair.get("keyFile") or "")
            cert_remote = cert_ref.startswith(_NODE_MATERIAL_PREFIX)
            key_remote = key_ref.startswith(_NODE_MATERIAL_PREFIX)
            if not cert_remote and not key_remote:
                continue
            if not cert_remote or not key_remote:
                raise ValueError("Xray TLS material references must be a complete pair")
            cert_name = cert_ref[len(_NODE_MATERIAL_PREFIX):]
            key_name = key_ref[len(_NODE_MATERIAL_PREFIX):]
            if (not _NODE_MATERIAL_NAME.fullmatch(cert_name)
                    or not _NODE_MATERIAL_NAME.fullmatch(key_name)
                    or not cert_name.endswith(".crt")
                    or not key_name.endswith(".key")
                    or cert_name[:-4] != key_name[:-4]):
                raise ValueError("invalid paired Xray TLS material references")
            try:
                cert_pem, key_pem = material[cert_name], material[key_name]
            except KeyError as exc:
                raise ValueError(f"missing Xray TLS material '{exc.args[0]}'") from exc
            from app.studio.certs import CertificateError, validate_pem_pair

            try:
                validate_pem_pair(
                    cert_pem, key_pem,
                    context=f"Xray TLS inbound '{inbound.get('tag') or '?'}'")
            except CertificateError as exc:
                raise ValueError(str(exc)) from exc
            cert_path, key_path = cert_dir / cert_name, cert_dir / key_name
            for path, text, mode in (
                (cert_path, cert_pem, 0o644),
                (key_path, key_pem, 0o600),
            ):
                part = path.with_name(path.name + ".part")
                part.write_text(text, encoding="utf-8")
                os.chmod(part, mode)
                os.replace(part, path)
            pair["certificateFile"] = str(cert_path)
            pair["keyFile"] = str(key_path)
            consumed.update((cert_name, key_name))
    unused = sorted(set(material) - consumed)
    if unused:
        raise ValueError(f"unused Xray TLS material: {unused}")
    return prepared


@app.put("/v1/cores/{core_id}/inbounds")
async def core_inbounds(core_id: str, body: InboundDocument,
                        _node=Depends(signed_request)):
    """Apply a Config Studio document (the panel's desired inbound state)."""
    _authorize_core(core_id)
    if core_id not in core_manager.list_cores():
        raise HTTPException(404, f"core '{core_id}' is not installed")
    if body.material and core_id != "xray":
        raise HTTPException(422, "file material is supported only for Xray TLS sync")
    try:
        document = (_materialize_xray_tls(body.document, body.material)
                    if core_id == "xray" else body.document)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    try:
        await asyncio.wait_for(
            core_manager.apply_studio_document(core_id, document), timeout=120)
    except asyncio.TimeoutError as exc:
        raise HTTPException(504, "inbound apply timed out") from exc
    except Exception as exc:
        identity.audit("inbounds.failed", {"core_id": core_id,
                                           "error_type": type(exc).__name__})
        raise HTTPException(409, str(exc)) from exc
    identity.audit("inbounds.apply", {
        "core_id": core_id,
        "inbound_count": len(body.document.get("inbounds") or []),
    })
    return {"ok": True, "core_id": core_id,
            "inbound_count": len(body.document.get("inbounds") or [])}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _to_user_account(raw: dict[str, Any]) -> UserAccount:
    """Validate one account dict into a :class:`UserAccount`.

    Account settings carry secret material (keys, passwords), so they are
    accepted as JSON data only: everything must survive a round-trip through
    ``json``, which rules out anything the driver would have to interpret
    (objects, byte strings, callables). No path-valued account setting is
    honoured — the core root confinement is for *core* settings.
    """
    if not isinstance(raw, dict):
        raise HTTPException(422, "each account must be an object")
    try:
        user_id = int(raw["user_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(422, "account is missing a numeric 'user_id'") from exc
    username = str(raw.get("username") or "")
    account_id = str(raw.get("account_id") or "")
    protocol = str(raw.get("protocol") or "")
    if not (1 <= len(username) <= 128):
        raise HTTPException(422, "account 'username' must be 1–128 characters")
    if not (1 <= len(account_id) <= 256):
        raise HTTPException(422, "account 'account_id' must be 1–256 characters")
    if not (1 <= len(protocol) <= 64):
        raise HTTPException(422, "account 'protocol' must be 1–64 characters")
    settings = raw.get("settings") or {}
    if not isinstance(settings, dict):
        raise HTTPException(422, "account 'settings' must be an object")
    try:
        settings = json.loads(json.dumps(settings))
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, "account settings must be plain JSON data") from exc
    expire_at = raw.get("expire_at")
    return UserAccount(
        user_id=user_id,
        username=username,
        account_id=account_id,
        protocol=protocol,
        enabled=bool(raw.get("enabled", True)),
        expire_at=expire_at,
        data_limit_bytes=raw.get("data_limit_bytes"),
        settings=settings,
    )


def _catalog_entry(core_id: str) -> dict[str, Any]:
    """Registry metadata for a not-yet-installed core (the node catalog row)."""
    meta = get_driver_class(core_id).metadata
    return {
        "id": meta.id,
        "name": meta.name,
        "description": meta.description,
        "protocols": list(meta.protocols or []),
        "capabilities": [cap.value if hasattr(cap, "value") else str(cap)
                         for cap in (meta.capabilities or [])],
        "config_schema": meta.config_schema,
        "default_settings": dict(meta.default_settings or {}),
        "security_class": meta.security_class,
        "homepage": meta.homepage,
        "installed": False,
    }


def _cores_summary() -> dict[str, Any]:
    installed = core_manager.list_cores()
    return {
        "installed": installed,
        "running": sorted(cid for cid in installed
                          if str(core_manager._states.get(cid))  # noqa: SLF001
                          in ("CoreState.RUNNING", "running")),
    }


def _resources() -> dict[str, Any]:
    disk = psutil.disk_usage(CFG.data_dir)
    memory = psutil.virtual_memory()
    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "cpu_count": os.cpu_count(),
        "memory_total": memory.total,
        "memory_used": memory.used,
        "disk_total": disk.total,
        "disk_used": disk.used,
        "load_average": list(os.getloadavg()) if hasattr(os, "getloadavg") else None,
    }


async def _node_info(*, detailed: bool) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "node_id": identity.node_id,
        "name": CFG.name or None,
        "agent": AGENT_NAME,
        "agent_version": AGENT_VERSION,
        "api_version": API_VERSION,
        "control_plane_port": CFG.port,
        "info_port": CFG.api_port,
        "registered": identity.signing_key() is not None,
        "registered_panel": identity.registered_panel,
        "uptime_seconds": round(time.time() - STARTED_AT, 1),
        "certificate_sha256": CERTIFICATE.fingerprint,
        "certificate_pem": CERTIFICATE.pem,
        "certificate_not_after": CERTIFICATE.not_after,
    }
    if detailed:
        payload["image"] = CFG.image
        payload["allowlist"] = sorted(NODE_CORE_ALLOWLIST)
        payload["cores"] = await asyncio.to_thread(_cores_summary)
        payload["resources"] = await asyncio.to_thread(_resources)
    return payload
