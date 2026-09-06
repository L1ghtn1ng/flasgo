from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class HTTPException(Exception):
    """Structured exception used to build an HTTP response."""

    status_code: int
    detail: str = ""
    headers: dict[str, str] = field(default_factory=dict)


class _RequestRejection(HTTPException):
    """Framework rejection with a fixed diagnostic reason, independent of status."""

    def __init__(self, status_code: int, detail: str, reason: str) -> None:
        """Add a bounded internal reason while preserving the public HTTPException argument tuple."""
        super().__init__(status_code, detail)
        self.args = (status_code, detail)
        self.reason = reason


def abort(status_code: int, detail: str = "", headers: dict[str, str] | None = None) -> None:
    """Raise an :class:`HTTPException` for the current request."""

    raise HTTPException(status_code=status_code, detail=detail, headers=headers or {})
