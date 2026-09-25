"""Swagger UI page for the optional API documentation endpoint."""

import html
import json
import secrets

from .response import Response

_SWAGGER_UI_VERSION = "5.32.12"
_SWAGGER_UI_CSS_INTEGRITY = "sha384-9Q2fpS+xeS4ffJy6CagnwoUl+4ldAYhOs9pgZuEKxypVModhmZFzeMlvVsAjf7uT"
_SWAGGER_UI_JS_INTEGRITY = "sha384-aPw2h1Un96ObRq1fD7AOgyf0r9jgkhMD51uBltHKtT0++4LsgMUkQD52RFNWcAil"


def swagger_ui_response(*, openapi_path: str, title: str) -> Response:
    """Render the docs page with a per-response nonce and a CSP that only allows the pinned, SRI-checked assets."""
    nonce = secrets.token_urlsafe(16)
    return Response.html(
        _swagger_ui_html(openapi_path=openapi_path, title=title, nonce=nonce),
        headers={
            "content-security-policy": (
                "default-src 'self'; "
                f"script-src 'self' https://unpkg.com 'nonce-{nonce}'; "
                f"style-src 'self' https://unpkg.com 'nonce-{nonce}'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "font-src https://unpkg.com; "
                "object-src 'none'; "
                "base-uri 'none'; "
                "frame-ancestors 'none'; "
                "form-action 'self'"
            )
        },
    )


def _swagger_ui_html(*, openapi_path: str, title: str, nonce: str) -> str:
    safe_title = html.escape(title, quote=True)
    safe_nonce = html.escape(nonce, quote=True)
    openapi_path_json = json.dumps(openapi_path)
    return f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{safe_title} Docs</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@{_SWAGGER_UI_VERSION}/swagger-ui.css"
      integrity="{_SWAGGER_UI_CSS_INTEGRITY}" crossorigin="anonymous" />
    <style nonce="{safe_nonce}">
      html, body {{
        margin: 0;
        padding: 0;
      }}
      #swagger-ui {{
        min-height: 100vh;
      }}
    </style>
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@{_SWAGGER_UI_VERSION}/swagger-ui-bundle.js"
      integrity="{_SWAGGER_UI_JS_INTEGRITY}" crossorigin="anonymous"></script>
    <script nonce="{safe_nonce}">
      window.ui = SwaggerUIBundle({{
        url: {openapi_path_json},
        dom_id: "#swagger-ui",
        deepLinking: true,
        queryConfigEnabled: false,
        validatorUrl: null,
      }});
    </script>
  </body>
</html>
"""
