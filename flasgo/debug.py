from __future__ import annotations

import os
import platform
import traceback
from pathlib import Path

from jinja2 import Environment, TemplateError

from .request import Request
from .response import Response


class Debug:
    """
    Provides debug error pages for template errors during development.

    When DEBUG is enabled, renders detailed error pages for Jinja2 template
    errors including the stack trace, request details, and environment info.
    """

    @staticmethod
    def render_template_debug_error(req: Request, exc: Exception, debug: bool) -> Response | None:
        if not debug:
            return None
        if not isinstance(exc, TemplateError):
            return None

        exc_info = (type(exc), exc, exc.__traceback__)
        stack_trace = "".join(traceback.format_exception(*exc_info))

        template_name: str = getattr(exc, "filename", None) or getattr(exc, "name", None) or "Unknown"
        lineno: int | None = getattr(exc, "lineno", None)

        debug_template_path = Path(__file__).parent / "debug_templates" / "debug_error.html"
        template_content = debug_template_path.read_text()

        safe_environ: dict[str, str] = {
            k: v
            for k, v in os.environ.items()
            if k.startswith(("PATH", "PYTHON", "LANG", "LC_", "HOME", "USER", "SHELL", "TERM"))
        }

        html = Environment(autoescape=True).from_string(template_content).render(
            error_type=type(exc).__name__,
            error_message=str(exc),
            template_name=template_name,
            lineno=lineno,
            stack_trace=stack_trace,
            request_method=req.method,
            request_path=req.path,
            environ=safe_environ,
            platform=platform.platform(),
            pid=os.getpid(),
        )
        return Response.html(html, status_code=500)

    @staticmethod
    def handle_debug_css(req: Request, debug: bool) -> Response | None:
        if not debug:
            return None
        if req.path != "/__flasgo_debug__/debug_error.css":
            return None
        if req.method != "GET":
            return Response.text("Method Not Allowed", status_code=405)

        css_path = Path(__file__).parent / "debug_templates" / "debug_error.css"
        css_content = css_path.read_text()
        return Response(
            body=css_content.encode("utf-8"),
            content_type="text/css; charset=utf-8",
        )
