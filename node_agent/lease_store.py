"""Encrypted durable cache for panel-owned short-lived connection leases."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.persistence.cipher import SecretsCipher


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class LeaseStore:
    """Keep temporary credentials separate from the permanent account cache."""

    def __init__(self, data_dir: str | Path) -> None:
        root = Path(data_dir)
        self.path = root / "connection-leases.json"
        key_path = root / "state.key"
        key = key_path.read_bytes()
        if len(key) != 32:
            raise ValueError("node state.key must contain exactly 32 bytes")
        self._cipher = SecretsCipher(key)

    def _read(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or not raw.get("leases_enc"):
            return {}
        value = self._cipher.decrypt_json(
            str(raw["leases_enc"]), aad="node-connection-leases:v1")
        leases = value.get("leases") if isinstance(value, dict) else None
        return {str(key): dict(item) for key, item in (leases or {}).items()
                if isinstance(item, dict)}

    def _write(self, leases: dict[str, dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = {"v": 1, "leases_enc": self._cipher.encrypt_json(
            {"leases": leases}, aad="node-connection-leases:v1")}
        part = self.path.with_suffix(".part")
        part.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(part, 0o600)
        os.replace(part, self.path)

    def put(self, core_id: str, lease_id: str, record: dict[str, Any]) -> None:
        leases = self._read()
        leases[f"{core_id}:{lease_id}"] = dict(record)
        self._write(leases)

    def get(self, core_id: str, lease_id: str) -> dict[str, Any] | None:
        value = self._read().get(f"{core_id}:{lease_id}")
        return dict(value) if value is not None else None

    def remove(self, core_id: str, lease_id: str) -> dict[str, Any] | None:
        leases = self._read()
        value = leases.pop(f"{core_id}:{lease_id}", None)
        self._write(leases)
        return dict(value) if value is not None else None

    def active(self, core_id: str | None = None,
               now: datetime | None = None) -> list[dict[str, Any]]:
        now = _aware(now or datetime.now(timezone.utc))
        out: list[dict[str, Any]] = []
        for record in self._read().values():
            if core_id is not None and record.get("core_id") != core_id:
                continue
            try:
                expires = _aware(datetime.fromisoformat(str(record["not_after"])))
            except (KeyError, TypeError, ValueError):
                continue
            if expires > now:
                out.append(dict(record))
        return out

    def expired(self, now: datetime | None = None) -> list[dict[str, Any]]:
        now = _aware(now or datetime.now(timezone.utc))
        out: list[dict[str, Any]] = []
        for record in self._read().values():
            try:
                expires = _aware(datetime.fromisoformat(str(record["not_after"])))
            except (KeyError, TypeError, ValueError):
                expires = now
            if expires <= now:
                out.append(dict(record))
        return out
