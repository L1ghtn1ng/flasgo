from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Never


@dataclass(slots=True, eq=False)
class HTTPException(Exception):
    """Structured exception used to build an HTTP response.

    ``eq=False`` keeps exceptions hashable and compared by identity, like every other exception.
    """

    status_code: int
    detail: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # The dataclass __init__ bypasses Exception.__init__, which would leave args empty and str(exc) blank.
        Exception.__init__(self, self.status_code, self.detail)

    def __str__(self) -> str:
        return self.detail or str(self.status_code)

    def __reduce__(self) -> tuple[Any, ...]:
        return (type(self), (self.status_code, self.detail, dict(self.headers)))


class _RequestRejection(HTTPException):
    """Framework rejection with a fixed diagnostic reason, independent of status."""

    def __init__(self, status_code: int, detail: str, reason: str) -> None:
        """Add a bounded internal reason while preserving the public HTTPException argument tuple."""
        super().__init__(status_code, detail)
        self.reason = reason

    def __reduce__(self) -> tuple[Any, ...]:
        return (type(self), (self.status_code, self.detail, self.reason))


def abort(status_code: int, detail: str = "", headers: Mapping[str, str] | None = None) -> Never:
    """Raise an :class:`HTTPException` for the current request."""

    raise HTTPException(status_code=status_code, detail=detail, headers=dict(headers or {}))
