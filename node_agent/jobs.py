"""Asynchronous lifecycle jobs.

Installing or uninstalling a core downloads and verifies release archives
and can legitimately take minutes. Running that inside the panel's HTTP
request would make the whole operation hostage to every proxy, NAT and
reverse proxy idle timeout between the two servers — a disconnected request
used to leave the operator with no idea whether the core was half-installed.

Lifecycle actions are therefore submitted as jobs: the caller gets a
``job_id`` immediately and polls. Jobs are serialized per core (two
concurrent installs of the same core would corrupt its runtime directory)
and a bounded history is kept so a panel reconnecting after an outage can
still observe the outcome.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

TERMINAL = ("succeeded", "failed", "cancelled")
_HISTORY_LIMIT = 200


class JobConflictError(RuntimeError):
    """A job for this core is already queued or running."""


@dataclass
class Job:
    job_id: str
    core_id: str
    action: str
    state: str = "queued"           # queued|running|succeeded|failed|cancelled
    queued_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    error_type: str | None = None

    @property
    def elapsed(self) -> float:
        end = self.finished_at or time.time()
        return round(end - self.queued_at, 3)

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id, "core_id": self.core_id, "action": self.action,
            "state": self.state, "queued_at": self.queued_at,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "elapsed_seconds": self.elapsed, "result": self.result,
            "error": self.error, "error_type": self.error_type,
        }


class JobManager:
    """Per-core serialized job execution with bounded history."""

    def __init__(self, history_limit: int = _HISTORY_LIMIT) -> None:
        self._history_limit = history_limit
        self._jobs: dict[str, Job] = {}
        self._order: list[str] = []
        self._active: dict[str, str] = {}      # core_id -> job_id
        self._lock = asyncio.Lock()

    # ----------------------------- submit ------------------------------ #
    async def submit(self, core_id: str, action: str,
                     coro_factory: Callable[[], Awaitable[dict[str, Any]]],
                     *, timeout: float = 900.0) -> Job:
        async with self._lock:
            if core_id in self._active:
                active = self._jobs[self._active[core_id]]
                # Lifecycle requests are safe to retry across a lost/slow HTTP
                # response.  Joining the identical in-flight action prevents a
                # double-click or panel convergence retry from turning a valid
                # long SoftEther start into a misleading HTTP 409.  A different
                # action still conflicts — stop while install is running is not
                # something the agent may guess about.
                if active.action == action:
                    return active
                raise JobConflictError(
                    f"a '{active.action}' job for core '{core_id}' is already "
                    f"{active.state} (job {active.job_id})")
            job = Job(job_id=uuid.uuid4().hex, core_id=core_id, action=action)
            self._remember(job)
            self._active[core_id] = job.job_id
        asyncio.create_task(self._run(job, coro_factory, timeout))
        return job

    # ------------------------------ run --------------------------------- #
    async def _run(self, job: Job,
                   coro_factory: Callable[[], Awaitable[dict[str, Any]]],
                   timeout: float) -> None:
        job.state = "running"
        job.started_at = time.time()
        try:
            job.result = await asyncio.wait_for(coro_factory(), timeout=timeout)
            job.state = "succeeded"
        except asyncio.TimeoutError:
            job.state = "failed"
            job.error = f"{job.action} timed out after {timeout:.0f}s"
            job.error_type = "TimeoutError"
        except asyncio.CancelledError:
            job.state = "cancelled"
            job.error_type = "CancelledError"
        except Exception as exc:  # noqa: BLE001 — report, never crash the agent
            job.state = "failed"
            job.error = str(exc)
            job.error_type = type(exc).__name__
        finally:
            job.finished_at = time.time()
            self._active.pop(job.core_id, None)

    # ----------------------------- queries ------------------------------ #
    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def active_for(self, core_id: str) -> Job | None:
        job_id = self._active.get(core_id)
        return self._jobs.get(job_id) if job_id else None

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        ids = list(reversed(self._order))[:max(1, min(limit, self._history_limit))]
        return [self._jobs[job_id].to_dict() for job_id in ids
                if job_id in self._jobs]

    # ---------------------------- bookkeeping --------------------------- #
    def _remember(self, job: Job) -> None:
        self._jobs[job.job_id] = job
        self._order.append(job.job_id)
        overflow = len(self._order) - self._history_limit
        if overflow > 0:
            for stale in self._order[:overflow]:
                self._jobs.pop(stale, None)
            self._order = self._order[overflow:]
