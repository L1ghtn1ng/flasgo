from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from jinja2 import BaseLoader, StrictUndefined, Template, TemplateNotFound, select_autoescape
from jinja2.sandbox import ImmutableSandboxedEnvironment

_DEFAULT_MAX_TEMPLATE_BYTES = 262_144


def _coerce_search_paths(template_dirs: str | Path | Sequence[str | Path]) -> tuple[Path, ...]:
    raw_paths: Sequence[str | Path]
    if isinstance(template_dirs, (str, Path)):
        raw_paths = (template_dirs,)
    else:
        raw_paths = template_dirs

    if not raw_paths:
        raise ValueError("At least one template directory must be configured.")

    resolved_paths: list[Path] = []
    for raw_path in raw_paths:
        resolved = Path(raw_path).expanduser().resolve()
        if not resolved.exists():
            msg = f"Template directory does not exist: {resolved}"
            raise ValueError(msg)
        if not resolved.is_dir():
            msg = f"Template directory is not a directory: {resolved}"
            raise ValueError(msg)
        resolved_paths.append(resolved)
    return tuple(resolved_paths)


def _normalize_template_name(template_name: str) -> PurePosixPath:
    if not template_name or any(char in template_name for char in ("\x00", "\r", "\n")):
        raise TemplateNotFound(template_name)

    normalized = template_name.replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if candidate.is_absolute():
        raise TemplateNotFound(template_name)
    if any(part in {"", ".", ".."} for part in candidate.parts):
        raise TemplateNotFound(template_name)
    if candidate.parts and candidate.parts[0].endswith(":"):
        raise TemplateNotFound(template_name)
    return candidate


class SecureTemplateLoader(BaseLoader):
    def __init__(
        self,
        template_dirs: str | Path | Sequence[str | Path],
        *,
        encoding: str = "utf-8",
        max_template_bytes: int = _DEFAULT_MAX_TEMPLATE_BYTES,
    ) -> None:
        if max_template_bytes <= 0:
            raise ValueError("max_template_bytes must be greater than 0.")

        self.search_paths = _coerce_search_paths(template_dirs)
        self.encoding = encoding
        self.max_template_bytes = max_template_bytes

    def get_source(self, environment: Any, template: str) -> tuple[str, str, Callable[[], bool]]:
        del environment
        normalized_template = _normalize_template_name(template)

        for root in self.search_paths:
            candidate = root.joinpath(*normalized_template.parts)
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(root)
            except FileNotFoundError, OSError, ValueError:
                continue
            if not resolved.is_file():
                continue

            try:
                payload = resolved.read_bytes()
            except OSError as exc:
                raise TemplateNotFound(template) from exc
            if len(payload) > self.max_template_bytes:
                raise TemplateNotFound(template)

            source = payload.decode(self.encoding)
            expected_mtime = resolved.stat().st_mtime

            def uptodate(path: Path = resolved, *, mtime: float = expected_mtime) -> bool:
                try:
                    return path.stat().st_mtime == mtime
                except OSError:
                    return False

            return source, str(resolved), uptodate

        raise TemplateNotFound(template)


def create_template_environment(
    template_dirs: str | Path | Sequence[str | Path],
    *,
    globals: Mapping[str, Any] | None = None,
    filters: Mapping[str, Callable[..., Any]] | None = None,
    tests: Mapping[str, Callable[..., Any]] | None = None,
    enable_async: bool = False,
    max_template_bytes: int = _DEFAULT_MAX_TEMPLATE_BYTES,
) -> ImmutableSandboxedEnvironment:
    environment = ImmutableSandboxedEnvironment(
        loader=SecureTemplateLoader(template_dirs, max_template_bytes=max_template_bytes),
        autoescape=select_autoescape(default_for_string=True, default=True),
        undefined=StrictUndefined,
        auto_reload=False,
        enable_async=enable_async,
    )
    if globals:
        environment.globals.update(globals)
    if filters:
        environment.filters.update(filters)
    if tests:
        environment.tests.update(tests)
    return environment


class JinjaTemplates:
    def __init__(
        self,
        template_dirs: str | Path | Sequence[str | Path],
        *,
        globals: Mapping[str, Any] | None = None,
        filters: Mapping[str, Callable[..., Any]] | None = None,
        tests: Mapping[str, Callable[..., Any]] | None = None,
        enable_async: bool = False,
        max_template_bytes: int = _DEFAULT_MAX_TEMPLATE_BYTES,
    ) -> None:
        self.environment = create_template_environment(
            template_dirs,
            globals=globals,
            filters=filters,
            tests=tests,
            enable_async=enable_async,
            max_template_bytes=max_template_bytes,
        )

    def get_template(self, template_name: str) -> Template:
        return self.environment.get_template(template_name)

    def render(self, template_name: str, context: Mapping[str, Any] | None = None) -> str:
        template = self.get_template(template_name)
        return template.render({} if context is None else dict(context))


def render_template(
    template_name: str,
    *,
    template_dirs: str | Path | Sequence[str | Path],
    context: Mapping[str, Any] | None = None,
    globals: Mapping[str, Any] | None = None,
    filters: Mapping[str, Callable[..., Any]] | None = None,
    tests: Mapping[str, Callable[..., Any]] | None = None,
    enable_async: bool = False,
    max_template_bytes: int = _DEFAULT_MAX_TEMPLATE_BYTES,
) -> str:
    templates = JinjaTemplates(
        template_dirs,
        globals=globals,
        filters=filters,
        tests=tests,
        enable_async=enable_async,
        max_template_bytes=max_template_bytes,
    )
    return templates.render(template_name, context)


__all__ = [
    "BaseLoader",
    "JinjaTemplates",
    "SecureTemplateLoader",
    "Template",
    "TemplateNotFound",
    "create_template_environment",
    "render_template",
]
