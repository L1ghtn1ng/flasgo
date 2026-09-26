"""Filesystem path helpers shared by static files, templates, and the reloader."""

from pathlib import Path, PurePosixPath


def safe_relative_path(value: str, *, allow_dotfiles: bool) -> PurePosixPath | None:
    """Parse a client-supplied relative path, or return ``None`` if it could escape its root.

    Backslashes are treated as separators, and absolute paths, ``..`` segments, Windows drive prefixes, and
    control characters are rejected. ``PurePosixPath`` already collapses empty and ``.`` segments.
    """
    if not value or any(char in value for char in ("\x00", "\r", "\n")):
        return None
    candidate = PurePosixPath(value.replace("\\", "/"))
    if candidate.is_absolute() or not candidate.parts or candidate.parts[0].endswith(":"):
        return None
    if allow_dotfiles:
        return None if ".." in candidate.parts else candidate
    return None if any(part.startswith(".") for part in candidate.parts) else candidate


def require_directory(path: str | Path, label: str) -> Path:
    """Resolve ``path`` and require it to be an existing directory."""
    resolved = Path(path).expanduser().resolve()
    if not resolved.exists():
        raise ValueError(f"{label} directory does not exist: {resolved}")
    if not resolved.is_dir():
        raise ValueError(f"{label} directory is not a directory: {resolved}")
    return resolved
