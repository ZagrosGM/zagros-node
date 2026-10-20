"""Node-side policy routing plane (f-noderouting-2, phase A).

The master's ``PolicyRoutingManager`` materialises named outbound domains
(sing-box/Xray TUN, WireGuard/OpenVPN client interfaces, PPP, SoftEther
bridges) and applies the service-traffic classifiers as ONE nftables table.
The agent now exposes the same primitive behind a signed endpoint:

``PUT /v1/policy`` carries the FULL desired state for this node —
``{"outbounds": [...], "rules": [...]}`` — so every apply is also a
reconcile: rules the master dropped disappear here, and re-sending the same
state is idempotent. An EMPTY payload tears the plane down symmetrically
(table + domains + counters), which is what unpairing must leave behind.

Design constraints, inherited from the master's engine:
* credentials arrive over the same signed channel identity material uses
  (the FR explicitly asks for this) and are never logged;
* the master's own default stays ``direct`` when the node cannot be
  reached — a dead node never black-holes traffic, it just stops receiving
  updates (the panel keeps its own copy of the desired state);
* per-rule applied/unsupported results go back to the panel verbatim, so
  the Nodes UI can say WHY a rule did not land (missing binary, missing
  capability), never silently drop it.

The last applied payload is persisted under the data dir and re-applied on
agent boot, exactly like accounts reconcile.
"""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger("zagros.node.policy")

_STATE_FILE = "policy_state.json"


class PolicyPlane:
    """One process-wide manager behind a lock; full-state apply/teardown."""

    def __init__(self, core_manager, data_dir: str | Path) -> None:
        self._core_manager = core_manager
        self._root = Path(data_dir)
        self._state_path = self._root / _STATE_FILE
        self._lock = threading.RLock()
        self._manager = None  # lazy: import + construct on first use

    # ------------------------------------------------------------------ #
    def _get(self):
        if self._manager is None:
            from app.cores.routing.policy import PolicyRoutingManager

            self._manager = PolicyRoutingManager(
                self._core_manager,
                runtime_root=str(self._root / "routing"))
        return self._manager

    # ------------------------------------------------------------------ #
    def _parse(self, payload: dict[str, Any]) -> tuple[list, list]:
        from app.cores.outbounds.model import Outbound
        from app.cores.routing.model import RoutingRule

        outbounds = [Outbound(**o) for o in (payload.get("outbounds") or [])]
        rules = [RoutingRule(**r) for r in (payload.get("rules") or [])]
        return outbounds, rules

    # ------------------------------------------------------------------ #
    #: cores that route INSIDE their own process (the host policy plane's
    #: nft classifiers never see their traffic — same split as the master).
    _NATIVE_ROUTING_CORES = ("xray", "sing-box")

    def _apply_native(self, outbounds: list, rules: list) -> dict[str, Any]:
        """Deploy routing into the node's in-process cores (f-routingfix-2).

        Phase A only fed the host policy plane, so an xray/sing-box inbound
        on this node ignored every rule — traffic kept following the default
        outbound. The drivers own the native translation (xray
        ``routing.rules`` / sing-box ``route.rules``) and the standalone
        backends persist the managed artifacts, so re-syncs cannot wipe
        them. Runs in a worker thread: drivers are sync, asyncio.run wraps
        their async surface.
        """
        import asyncio

        from app.cores.outbounds.manager import OutboundManager
        from app.cores.routing.model import RouteContext
        from app.cores.types import Capability

        async def _run() -> dict[str, Any]:
            applied: dict[str, list[str]] = {}
            unsupported: dict[str, list[dict]] = {}
            notes: dict[str, list[str]] = {}
            targets = [core_id for core_id in self._core_manager.list_cores()
                       if core_id in self._NATIVE_ROUTING_CORES]
            if not targets:
                return {"applied": {}, "unsupported": {}, "notes": {}}
            manager = OutboundManager(self._core_manager)
            ctx = RouteContext(
                available_outbounds=[o.name for o in outbounds])
            for core_id in targets:
                try:
                    driver = self._core_manager.get(core_id)
                except Exception:  # noqa: BLE001 — per-core isolation
                    continue
                resolved: list = []
                core_notes: list[str] = []
                for ob in outbounds:
                    if (ob.kind.value == "core"
                            and ob.settings.get("core_id") == core_id):
                        core_notes.append(
                            f"outbound '{ob.name}' chains INTO this core; "
                            "not materialized locally.")
                        continue
                    try:
                        resolved.append(await manager.materialize(
                            ob, requester_core_id=core_id))
                    except Exception as exc:  # noqa: BLE001
                        core_notes.append(
                            f"outbound '{ob.name}': {exc}")
                if driver.supports(Capability.OUTBOUND_MANAGEMENT) and resolved:
                    await driver.deploy_outbounds(resolved)
                native = await driver.deploy_routing_rules(rules, ctx)
                applied[core_id] = list(native.applied)
                unsupported[core_id] = [u.model_dump(mode="json")
                                        for u in native.unsupported]
                notes[core_id] = core_notes + list(native.notes)
            return {"applied": applied, "unsupported": unsupported,
                    "notes": notes}

        return asyncio.run(_run())

    # ------------------------------------------------------------------ #
    def apply(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Apply the FULL desired state; empty state = symmetric teardown."""
        from app.cores.routing.policy import PolicyRuleReport

        outbounds, rules = self._parse(payload)
        with self._lock:
            if not rules and not outbounds:
                summary = self.teardown()
                return {"ok": True, "teardown": True, **summary}
            manager = self._get()
            # The master's own order: prove every outbound interface/table
            # first, then atomically replace classifiers. prepare() starts
            # the domain processes; failures name the outbound, never a
            # bare 500.
            manager.prepare(outbounds)
            report: PolicyRuleReport = manager.apply_rules(rules)
            summary = {
                "applied": {k: list(v) for k, v in report.applied.items()},
                "unsupported": {k: [u.model_dump(mode="json")
                                    for u in v]
                                for k, v in report.unsupported.items()},
                "notes": {k: list(v) for k, v in report.notes.items()},
            }
            # f-routingfix-2: xray/sing-box route in their own processes —
            # feed them natively or their inbounds ignore every rule.
            try:
                native = self._apply_native(outbounds, rules)
            except Exception as exc:  # noqa: BLE001 — honest per-plane report
                summary["notes"].setdefault("_native", []).append(
                    f"native routing deployment failed: {exc}")
            else:
                for section in ("applied", "unsupported", "notes"):
                    for core_id, value in (native.get(section) or {}).items():
                        target = summary[section].setdefault(core_id, [])
                        if section == "unsupported":
                            target.extend(value)
                        elif section == "applied":
                            summary[section][core_id] = list(
                                dict.fromkeys(list(target) + list(value)))
                        else:
                            target.extend(value)
            self._persist(payload)
            return {"ok": True, "teardown": False, **summary}

    # ------------------------------------------------------------------ #
    def teardown(self) -> dict[str, Any]:
        """Remove EVERYTHING this plane owns — idempotent by construction."""
        with self._lock:
            if self._manager is not None:
                try:
                    self._manager.stop()
                except Exception as exc:  # noqa: BLE001 — best-effort teardown
                    logger.warning("policy teardown error: %s", exc)
                self._manager = None
            try:
                self._state_path.unlink(missing_ok=True)
            except OSError:
                pass
            return {"cleared": True}

    # ------------------------------------------------------------------ #
    def _persist(self, payload: dict[str, Any]) -> None:
        try:
            self._root.mkdir(parents=True, exist_ok=True)
            tmp = self._state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload))
            tmp.replace(self._state_path)
        except OSError as exc:  # noqa: BLE001 — reconcile is an optimisation
            logger.warning("policy state persist failed: %s", exc)

    def _load_state(self) -> dict[str, Any] | None:
        try:
            return json.loads(self._state_path.read_text())
        except (OSError, ValueError):
            return None

    # ------------------------------------------------------------------ #
    def reconcile_on_boot(self) -> dict[str, Any]:
        """Re-apply the last desired state after an agent restart."""
        payload = self._load_state()
        if not payload:
            return {"reconciled": False, "reason": "no stored policy state"}
        try:
            summary = self.apply(payload)
            summary["reconciled"] = True
            return summary
        except Exception as exc:  # noqa: BLE001 — boot must never die on policy
            logger.error("policy reconcile on boot failed: %s", exc)
            return {"reconciled": False, "error": str(exc)[:300]}


plane = None  # set by app.main on startup (needs the real core_manager)
