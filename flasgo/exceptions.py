from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class HTTPException(Exception):
    """Structured exception used to build an HTTP response."""

    status_code: int
    detail: str = ""
    headers: dict[str, str] = field(default_factory=dict)


def abort(status_code: int, detail: str = "", headers: dict[str, str] | None = None) -> None:
    """Raise an :class:`HTTPException` for the current request."""

    raise HTTPException(status_code=status_code, detail=detail, headers=headers or {})
