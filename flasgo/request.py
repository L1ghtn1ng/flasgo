"""Import path kept for ``from flasgo.request import Request``; the implementation lives in ``flasgo._request``."""

from ._request import (
    DEFAULT_MAX_FORM_FIELDS,
    DEFAULT_MAX_MULTIPART_PARTS,
    FormData,
    Request,
    UploadedFile,
    parse_query_params,
    scope_header_values,
)

__all__ = [
    "DEFAULT_MAX_FORM_FIELDS",
    "DEFAULT_MAX_MULTIPART_PARTS",
    "FormData",
    "Request",
    "UploadedFile",
    "parse_query_params",
    "scope_header_values",
]
