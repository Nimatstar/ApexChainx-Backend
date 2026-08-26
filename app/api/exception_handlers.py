"""RFC 7807 (Problem Details) exception handlers for all 4xx/5xx responses.

Every error response is normalised to ``application/problem+json`` so that
SDKs and partners can rely on stable machine-readable fields instead of
branching on cosmetic strings.

The shape is intentionally minimal — the spec allows extension members
(``correlation_id``, ``errors``) while keeping ``type``, ``title``,
``status``, and ``detail`` stable.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.utils.correlation_ctx import get_or_generate_correlation_id

logger = logging.getLogger(__name__)


class ProblemDetail(BaseModel):
    """RFC 7807 problem detail envelope.

    Extension members:
      - ``correlation_id`` – ties the error back to the request log.
      - ``errors`` – optional list of field-level errors (validation).
    """

    type: str = Field(
        default="about:blank",
        description="A URI reference identifying the problem type.",
    )
    title: str = Field(description="A short, human-readable summary.")
    status: int = Field(description="The HTTP status code.")
    detail: str = Field(default="", description="A human-readable explanation.")
    correlation_id: str | None = Field(default=None)
    errors: list[dict[str, Any]] | None = Field(default=None)


def _problem_response(
    status: int,
    title: str,
    detail: str = "",
    errors: list[dict[str, Any]] | None = None,
) -> JSONResponse:
    correlation_id = get_or_generate_correlation_id()
    problem = ProblemDetail(
        type="about:blank",
        title=title,
        status=status,
        detail=detail,
        correlation_id=correlation_id,
        errors=errors,
    )
    return JSONResponse(
        status_code=status,
        content=problem.model_dump(exclude_none=True),
        media_type="application/problem+json",
        headers={"X-Correlation-ID": correlation_id},
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Handle all HTTPException instances as RFC 7807 problem responses."""
    return _problem_response(
        status=exc.status_code,
        title=_default_title(exc.status_code),
        detail=exc.detail if isinstance(exc.detail, str) else str(exc.detail),
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handle Pydantic validation errors with field-level ``errors[].pointer``."""
    errors = []
    for e in exc.errors():
        pointer = "/" + "/".join(str(loc) for loc in e.get("loc", []))
        errors.append(
            {
                "pointer": pointer,
                "type": e.get("type", ""),
                "message": e.get("msg", str(e)),
            }
        )
    return _problem_response(
        status=422,
        title="Unprocessable Entity",
        detail="Request validation failed.",
        errors=errors,
    )


async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Last-resort catch-all for unhandled exceptions (500)."""
    correlation_id = get_or_generate_correlation_id()
    logger.exception(
        "Unhandled exception",
        extra={"correlation_id": correlation_id, "path": request.url.path},
    )
    return _problem_response(
        status=500,
        title="Internal Server Error",
        detail="An unexpected error occurred.",
    )


def _default_title(status_code: int) -> str:
    """Return a reasonable title for standard HTTP status codes."""
    titles = {
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        409: "Conflict",
        410: "Gone",
        413: "Payload Too Large",
        415: "Unsupported Media Type",
        422: "Unprocessable Entity",
        429: "Too Many Requests",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
    }
    return titles.get(status_code, "Unknown Error")
