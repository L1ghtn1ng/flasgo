from __future__ import annotations

from pathlib import Path

import pytest
from flasgo import (
    BaseLoader,
    Flasgo,
    JinjaTemplates,
    Response,
    Template,
    TemplateNotFound,
    create_template_environment,
    render_template,
)
from flasgo.templating import SecureTemplateLoader
from jinja2 import BaseLoader as JinjaBaseLoader
from jinja2 import Template as JinjaTemplate
from jinja2 import TemplateNotFound as JinjaTemplateNotFound
from jinja2.exceptions import SecurityError, UndefinedError


def test_template_exports_match_jinja2_types() -> None:
    assert BaseLoader is JinjaBaseLoader
    assert Template is JinjaTemplate
    assert TemplateNotFound is JinjaTemplateNotFound


def test_render_template_autoescapes_html(tmp_path: Path) -> None:
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "hello.html").write_text("Hello {{ name }}", encoding="utf-8")

    rendered = render_template("hello.html", template_dirs=template_dir, context={"name": "<script>alert(1)</script>"})

    assert rendered == "Hello &lt;script&gt;alert(1)&lt;/script&gt;"


def test_loader_blocks_path_traversal(tmp_path: Path) -> None:
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "safe.html").write_text("safe", encoding="utf-8")
    (tmp_path / "secret.html").write_text("secret", encoding="utf-8")

    templates = JinjaTemplates(template_dir)

    with pytest.raises(TemplateNotFound):
        templates.get_template("../secret.html")


def test_loader_blocks_symlink_escape(tmp_path: Path) -> None:
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    secret_dir = tmp_path / "outside"
    secret_dir.mkdir()
    (secret_dir / "secret.html").write_text("secret", encoding="utf-8")
    (template_dir / "alias.html").symlink_to(secret_dir / "secret.html")

    templates = JinjaTemplates(template_dir)

    with pytest.raises(TemplateNotFound):
        templates.get_template("alias.html")


def test_loader_rejects_oversized_templates(tmp_path: Path) -> None:
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "large.html").write_text("x" * 64, encoding="utf-8")

    loader = SecureTemplateLoader(template_dir, max_template_bytes=32)

    with pytest.raises(TemplateNotFound):
        loader.get_source(None, "large.html")


def test_environment_raises_on_undefined_variables(tmp_path: Path) -> None:
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "undefined.html").write_text("{{ missing_value }}", encoding="utf-8")

    templates = JinjaTemplates(template_dir)

    with pytest.raises(UndefinedError):
        templates.render("undefined.html")


def test_environment_sandbox_blocks_unsafe_attribute_access(tmp_path: Path) -> None:
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "unsafe.html").write_text("{{ ''.__class__ }}", encoding="utf-8")

    environment = create_template_environment(template_dir)
    template = environment.get_template("unsafe.html")

    with pytest.raises(SecurityError):
        template.render()


def test_loader_is_a_jinja_base_loader(tmp_path: Path) -> None:
    template_dir = tmp_path / "templates"
    template_dir.mkdir()

    loader = SecureTemplateLoader(template_dir)

    assert isinstance(loader, JinjaBaseLoader)


def test_response_template_renders_html_response(tmp_path: Path) -> None:
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "page.html").write_text("<h1>{{ title }}</h1>", encoding="utf-8")

    response = Response.template("page.html", template_dirs=template_dir, context={"title": "Dashboard"})

    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert response.body == b"<h1>Dashboard</h1>"


def test_flasgo_render_template_uses_configured_environment(tmp_path: Path) -> None:
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "layout.html").write_text("Hello {{ user }}", encoding="utf-8")

    app = Flasgo(settings={"CSRF_ENABLED": False})
    templates = app.configure_templates(template_dir)

    assert isinstance(templates, JinjaTemplates)
    assert app.render_template("layout.html", {"user": "alice"}) == "Hello alice"
