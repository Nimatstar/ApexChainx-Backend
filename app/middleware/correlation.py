import hashlib
import time

from fastapi import Request

from app.core.exceptions import ApexException
from app.utils.correlation_ctx import get_or_generate_correlation_id, set_correlation_id
from app.utils.logging import get_structured_logger

logger = get_structured_logger("access")


def _hash_value(value: str | None) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


# Add per-user API rate limits using Redis sliding-window counter
class CorrelationMiddleware:
    """ASGI-native middleware to add correlation IDs to requests and enable request tracing.

    Emits structured access logs with:
    - trace_id (correlation ID)
    - method (HTTP method)
    - route_template (URL path template)
    - status (HTTP response status)
    - duration_ms (request duration)
    - query_hash (SHA-256 prefix of query string)
    - user_id_hash (SHA-256 prefix of user identifier, if authenticated)
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)

        correlation_id = request.headers.get("X-Correlation-ID") or get_or_generate_correlation_id()
        set_correlation_id(correlation_id)
        request.state.correlation_id = correlation_id

        start_time = time.time()
        query_hash = _hash_value(str(request.query_params)) if request.query_params else None
        route_template: str | None = None
        user_id_hash: str | None = None

        async def send_wrapper(message):
            nonlocal route_template, user_id_hash
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                headers[b"x-correlation-id"] = correlation_id.encode()
                message["headers"] = list(headers.items())

                status_code = message.get("status", 0)

                if request.scope.get("route"):
                    route = request.scope.get("route")
                    if route is not None:
                        route_template = getattr(route, "path", None)

                try:
                    actor = getattr(request.state, "actor", None)
                    if actor:
                        uid = str(
                            actor.get("actor_id", "")
                            if isinstance(actor, dict)
                            else getattr(actor, "id", "")
                        )
                        if uid:
                            user_id_hash = _hash_value(uid)
                except (AttributeError, TypeError, ValueError):
                    pass  # user object may not have expected shape; non-critical for logging

                duration_ms = (time.time() - start_time) * 1000

                logger.info(
                    "Request completed",
                    trace_id=correlation_id,
                    method=request.method,
                    route_template=route_template,
                    status=status_code,
                    duration_ms=round(duration_ms, 2),
                    query_hash=query_hash,
                    user_id_hash=user_id_hash,
                )

            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except ApexException:
            raise  # already typed; let FastAPI exception handlers process it
        except Exception as exc:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(
                "Request failed",
                trace_id=correlation_id,
                method=request.method,
                route_template=route_template,
                error=str(exc),
                duration_ms=round(duration_ms, 2),
                query_hash=query_hash,
                user_id_hash=user_id_hash,
            )
            raise
