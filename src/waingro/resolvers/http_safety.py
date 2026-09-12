"""Shared bounded handling for HTTP Retry-After signals."""

from __future__ import annotations

from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

MAX_RETRY_AFTER_SECONDS = 3600


def retry_after_seconds(value: str | None) -> int | None:
    """Parse delta-seconds or an HTTP date without ever requesting a long sleep."""
    if not value:
        return None
    try:
        seconds = int(value)
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        seconds = int((parsed.astimezone(UTC) - datetime.now(UTC)).total_seconds())
    return min(MAX_RETRY_AFTER_SECONDS, max(0, seconds))
