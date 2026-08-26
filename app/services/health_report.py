"""Expanded health/readiness probe for issue #32."""

from __future__ import annotations

import time
from dataclasses import dataclass

from redis import Redis
from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.core.db_retry import run_with_db_retry


@dataclass
class ComponentStatus:
    component: str
    status: str  # ok, warn, down
    details: dict


def _execute_db_ping(engine: Engine) -> None:
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))


def _pool_status(engine: Engine) -> ComponentStatus:
    try:
        pool = engine.pool
        size = pool.size()
        checked_out = pool.checkedout()
        overflow = pool.overflow()
        checked_in = pool.checkedin()
        warn = checked_out > size * 0.9
        return ComponentStatus(
            component="postgres_pool",
            status="warn" if warn else "ok",
            details={
                "pool_size": size,
                "checked_out": checked_out,
                "overflow": overflow,
                "checkedin": checked_in,
            },
        )
    except Exception as exc:
        return ComponentStatus("postgres_pool", "down", {"error": str(exc)})


def _db_ping(engine: Engine) -> ComponentStatus:
    start = time.monotonic()
    try:
        run_with_db_retry(lambda: _execute_db_ping(engine))
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        return ComponentStatus("database", "ok", {"latency_ms": elapsed_ms})
    except Exception as exc:
        return ComponentStatus("database", "down", {"error": str(exc)})


def _redis_ping(redis_url: str) -> ComponentStatus:
    start = time.monotonic()
    try:
        r = Redis.from_url(redis_url)
        r.ping()
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        return ComponentStatus("redis", "ok", {"latency_ms": elapsed_ms})
    except Exception as exc:
        return ComponentStatus("redis", "down", {"error": str(exc)})


def _dlq_depth(engine: Engine, warn_threshold: int = 1000) -> ComponentStatus:
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT COUNT(*) FROM webhook_deliveries " "WHERE status = 'DEAD_LETTER'"))
            count = result.scalar() or 0
        warn = count > warn_threshold
        return ComponentStatus(
            "webhook_dlq",
            status="warn" if warn else "ok",
            details={"dead_letter_count": count, "warn_threshold": warn_threshold},
        )
    except Exception as exc:
        return ComponentStatus("webhook_dlq", "down", {"error": str(exc)})


def build_readiness_report(engine: Engine, redis_url: str, dlq_warn_threshold: int = 1000) -> dict:
    """Build a structured readiness report for /health/readiness."""
    components = [
        _db_ping(engine),
        _pool_status(engine),
        _redis_ping(redis_url),
        _dlq_depth(engine, dlq_warn_threshold),
    ]

    overall = "ok"
    for c in components:
        if c.status == "down":
            overall = "down"
            break
        if c.status == "warn":
            overall = "warn"

    return {
        "status": overall,
        "components": {c.component: {"status": c.status, **c.details} for c in components},
    }
