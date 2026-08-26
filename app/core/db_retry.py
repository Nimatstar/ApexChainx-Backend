"""Transient DB error retry policy using tenacity for issue #34."""

from sqlalchemy.exc import DisconnectionError, OperationalError
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from typing import Callable, TypeVar

T = TypeVar("T")

db_retry_policy = retry(
    retry=retry_if_exception_type((OperationalError, DisconnectionError)),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    reraise=True,
)


def run_with_db_retry(operation: Callable[[], T]) -> T:
    return db_retry_policy(operation)()
