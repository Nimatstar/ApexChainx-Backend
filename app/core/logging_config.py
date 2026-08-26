"""Centralized logging configuration via dictConfig (#21).

Correlation ID injection
------------------------
Every log record that passes through the root logger (or any handler that
applies the ``CorrelationIdFilter``) will have a ``correlation_id`` attribute
attached.  This means:

* The JSON formatter can include it without any extra wiring.
* The plain-text formatter exposes it via ``%(correlation_id)s``.
* Third-party or standard-library loggers (``logging.getLogger()``) that do
  *not* use ``app.utils.logging.StructuredLogger`` still emit the field
  automatically — it is stamped at the *filter* layer, not at call-site.
"""

import logging
import logging.config
import os

from app.utils.correlation_ctx import get_correlation_id


class CorrelationIdFilter(logging.Filter):
    """Logging filter that injects the current correlation ID into every record.

    Attaches a ``correlation_id`` attribute so that both the JSON formatter and
    the plain-text ``%(correlation_id)s`` format token can resolve it without
    raising a ``KeyError``.  When no correlation ID is active (e.g. startup
    log lines emitted before the first request), the field is set to the empty
    string so the format string remains valid.
    """

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        record.correlation_id = get_correlation_id() or ""
        return True


def configure_logging() -> None:
    level = os.getenv("LOG_LEVEL", "INFO")
    log_format = os.getenv("LOG_FORMAT", "plaintext")

    handlers: dict = {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json" if log_format == "json" else "plain",
            "stream": "ext://sys.stdout",
            "filters": ["correlation_id"],
        }
    }

    formatters: dict = {
        "plain": {
            # correlation_id is set by CorrelationIdFilter; it will be "" when
            # no request context is active, which is fine for startup logs.
            "format": "%(asctime)s [%(levelname)s] %(name)s %(correlation_id)s: %(message)s",
        },
        "json": {
            "()": "app.core.logging_config._JsonFormatter",
        },
    }

    filters: dict = {
        "correlation_id": {
            "()": "app.core.logging_config.CorrelationIdFilter",
        }
    }

    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "filters": filters,
            "formatters": formatters,
            "handlers": handlers,
            "root": {"level": level, "handlers": ["console"]},
        }
    )


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        import json as _json
        import traceback

        # ``correlation_id`` is stamped by CorrelationIdFilter before format()
        # is called.  Fall back to the empty string when the filter is absent.
        correlation_id = getattr(record, "correlation_id", "") or ""

        payload = {
                "timestamp": self.formatTime(record),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "correlation_id": correlation_id,
        }
        if record.exc_info:
            payload["exception"] = "".join(traceback.format_exception(*record.exc_info))
        return _json.dumps(payload)
