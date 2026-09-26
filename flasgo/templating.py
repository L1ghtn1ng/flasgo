import asyncio
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, cast, override

from jinja2 import BaseLoader, StrictUndefined, Template, TemplateNotFound, select_autoescape
from jinja2.sandbox import ImmutableSandboxedEnvironment

from ._paths import require_directory, safe_relative_path

_DEFAULT_MAX_TEMPLATE_BYTES = 262_144


def _coerce_search_paths(template_dirs: str | Path | Sequence[str | Path]) -> tuple[Path, ...]:
    raw_paths: Sequence[str | Path] = (template_dirs,) if isinstance(template_dirs, (str, Path)) else template_dirs

    if not raw_paths:
        raise ValueError("At least one template directory must be configured.")

    return tuple(require_directory(raw_path, "Template") for raw_path in raw_paths)


def _normalize_template_name(template_name: str) -> PurePosixPath:
    candidate = safe_relative_path(template_name, allow_dotfiles=True)
    if candidate is None:
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

    @override
    def get_source(self, environment: Any, template: str) -> tuple[str, str, Callable[[], bool]]:
        del environment
        normalized_template = _normalize_template_name(template)

        for root in self.search_paths:
            candidate = root.joinpath(*normalized_template.parts)
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(root)
            except OSError, ValueError:
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


def _event_loop_running() -> bool:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


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
        cast(dict[str, Callable[..., Any]], environment.tests).update(tests)
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
        if self.environment.is_async and _event_loop_running():
            # Jinja drives async templates with asyncio.run(), which cannot run inside an already running loop.
            # Outside a loop (scripts, the module-level render_template helper) that works fine.
            raise RuntimeError("Templates were configured with enable_async=True; use `await render_async(...)` instead.")
        template = self.get_template(template_name)
        return template.render({} if context is None else dict(context))

    async def render_async(self, template_name: str, context: Mapping[str, Any] | None = None) -> str:
        """Render a template configured with ``enable_async=True`` without blocking the event loop."""
        if not self.environment.is_async:
            raise RuntimeError("render_async requires templates configured with enable_async=True; use render(...) instead.")
        template = self.get_template(template_name)
        return await template.render_async({} if context is None else dict(context))


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
