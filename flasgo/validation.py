from __future__ import annotations

import inspect
import math
import types
from collections.abc import Mapping, Sequence
from dataclasses import MISSING, dataclass, fields, is_dataclass
from datetime import date, datetime
from enum import Enum
from typing import Any, Literal, Union, cast, get_args, get_origin, get_type_hints
from uuid import UUID

from .request import FormData, UploadedFile

type LocationPart = str | int

_LOCATION_PART_MAX_LENGTH = 64


def _safe_location_part(value: object) -> str:
    """Return a printable, bounded location component derived from request-controlled keys."""

    text = str(value)
    cleaned = "".join(char if 32 <= ord(char) < 127 else "?" for char in text)
    if len(cleaned) > _LOCATION_PART_MAX_LENGTH:
        cleaned = cleaned[:_LOCATION_PART_MAX_LENGTH] + "..."
    return cleaned


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    location: tuple[LocationPart, ...]
    code: str
    message: str

    def as_dict(self) -> dict[str, object]:
        return {"location": list(self.location), "code": self.code, "message": self.message}


class RequestValidationError(Exception):
    def __init__(self, issues: Sequence[ValidationIssue]) -> None:
        self.issues = tuple(issues)
        super().__init__("Request validation failed.")


class FormValidationError(RequestValidationError):
    def __init__(self, issues: Sequence[ValidationIssue], form_data: FormData) -> None:
        self.form_data = form_data
        super().__init__(issues)

    @property
    def errors(self) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = {}
        for issue in self.issues:
            field = str(issue.location[-1]) if len(issue.location) > 1 else "__all__"
            grouped.setdefault(field, []).append(issue.message)
        return grouped


class _InvalidValue(Exception):
    def __init__(self, issues: Sequence[ValidationIssue]) -> None:
        self.issues = tuple(issues)


@dataclass(slots=True)
class ValidationBudget:
    """Shared per-request limits for typed validation work and error output."""

    max_depth: int = 64
    max_work: int = 10_000
    max_issues: int = 100
    work: int = 0

    def consume(self, *, location: tuple[LocationPart, ...], depth: int) -> None:
        if depth > self.max_depth:
            raise _problem(
                location,
                "validation_limit",
                "Request validation exceeded the configured depth limit.",
            )
        self.work += 1
        if self.work > self.max_work:
            raise _problem(
                location,
                "validation_limit",
                "Request validation exceeded the configured work limit.",
            )


def validate_value(
    annotation: object,
    value: object,
    *,
    location: tuple[LocationPart, ...],
    budget: ValidationBudget | None = None,
) -> object:
    active_budget = budget or ValidationBudget()
    try:
        return _validate_value(
            annotation,
            value,
            location=location,
            from_text=False,
            budget=active_budget,
            depth=0,
        )
    except _InvalidValue as exc:
        raise RequestValidationError(exc.issues) from exc


def validate_text_values(
    annotation: object,
    values: Sequence[str],
    *,
    location: tuple[LocationPart, ...],
    budget: ValidationBudget | None = None,
) -> object:
    active_budget = budget or ValidationBudget()
    try:
        return _validate_text_values(annotation, values, location=location, budget=active_budget)
    except _InvalidValue as exc:
        raise RequestValidationError(exc.issues) from exc


def is_collection_annotation(annotation: object) -> bool:
    """Return whether an annotation contains a supported collection type."""

    annotation = _unwrap_annotated(annotation)
    if get_origin(annotation) in {list, set, tuple}:
        return True
    return any(is_collection_annotation(member) for member in get_args(annotation))


def validate_form_model(
    annotation: object,
    form: FormData,
    *,
    budget: ValidationBudget | None = None,
) -> object:
    active_budget = budget or ValidationBudget()
    if not is_dataclass(annotation) or not isinstance(annotation, type):
        raise RequestValidationError(
            (ValidationIssue(("form",), "model_required", "Form() requires a dataclass model."),)
        )
    values: dict[str, object] = {}
    issues: list[ValidationIssue] = []
    hints = _model_hints(annotation)
    input_fields = tuple(item for item in fields(annotation) if item.init)
    known = {item.name for item in input_fields}
    provided = {*form, *form.files}
    for name in provided:
        if name in known:
            continue
        if not extend_validation_issues(
            issues,
            (ValidationIssue(("form", _safe_location_part(name)), "unknown_field", "Unknown field."),),
            location=("form",),
            budget=active_budget,
        ):
            break
    for model_field in input_fields:
        if _issues_truncated(issues):
            break
        field_type = hints.get(model_field.name, model_field.type)
        file_annotation = _uploaded_file_annotation(field_type)
        file_origin = get_origin(file_annotation)
        raw_files = form.filelist(model_field.name)
        raw_values = form.getlist(model_field.name)
        if not raw_files and not raw_values:
            if model_field.default is not MISSING or model_field.default_factory is not MISSING:
                continue
            extend_validation_issues(
                issues,
                (ValidationIssue(("form", model_field.name), "missing", "Field is required."),),
                location=("form",),
                budget=active_budget,
            )
            continue
        try:
            if file_annotation is not None:
                if raw_values:
                    raise _problem(("form", model_field.name), "type_error", "Expected an uploaded file.")
                if file_origin in {list, set, tuple}:
                    values[model_field.name] = _collection_value(file_origin, raw_files)
                elif len(raw_files) == 1 and file_annotation is UploadedFile:
                    values[model_field.name] = raw_files[0]
                else:
                    raise _problem(("form", model_field.name), "type_error", "Expected one uploaded file.")
            else:
                values[model_field.name] = _validate_text_values(
                    field_type,
                    raw_values,
                    location=("form", model_field.name),
                    budget=active_budget,
                )
        except _InvalidValue as exc:
            if _has_validation_limit(exc.issues):
                raise FormValidationError(exc.issues, form) from exc
            extend_validation_issues(
                issues,
                exc.issues,
                location=("form",),
                budget=active_budget,
            )
    if issues:
        raise FormValidationError(issues, form)
    return annotation(**values)


def to_jsonable(value: object) -> object:
    """Convert supported values to JSON data without dataclass-private fields."""

    if is_dataclass(value) and not isinstance(value, type):
        # Underscore-prefixed fields are private by convention and are never serialized.
        return {
            model_field.name: to_jsonable(getattr(value, model_field.name))
            for model_field in fields(value)
            if not model_field.name.startswith("_")
        }
    if isinstance(value, Enum):
        return to_jsonable(value.value)
    if isinstance(value, (UUID, date, datetime)):
        return value.isoformat() if not isinstance(value, UUID) else str(value)
    if isinstance(value, Mapping):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_jsonable(item) for item in value]
    return value


def contains_uploaded_file(annotation: object, *, _seen: set[type[Any]] | None = None) -> bool:
    annotation = _unwrap_annotated(annotation)
    if annotation is UploadedFile:
        return True
    if is_dataclass(annotation) and isinstance(annotation, type):
        seen = _seen or set()
        if annotation in seen:
            return False
        seen.add(annotation)
        hints = _model_hints(annotation)
        return any(
            contains_uploaded_file(hints.get(item.name, item.type), _seen=seen)
            for item in fields(annotation)
            if item.init
        )
    return any(contains_uploaded_file(item, _seen=_seen) for item in get_args(annotation))


class SchemaRegistry:
    def __init__(self) -> None:
        self.schemas: dict[str, dict[str, Any]] = {}
        self._names: dict[tuple[type[Any], bool], str] = {}
        self._building: set[tuple[type[Any], bool]] = set()
        self.validation_error_name: str | None = None

    def schema_for(self, annotation: object, *, input_model: bool = False) -> dict[str, Any]:
        annotation = _unwrap_annotated(annotation)
        if annotation in {inspect.Signature.empty, Any, object}:
            return {}
        if annotation is str:
            return {"type": "string"}
        if annotation is int:
            return {"type": "integer"}
        if annotation is float:
            return {"type": "number"}
        if annotation is bool:
            return {"type": "boolean"}
        if annotation is bytes:
            return {"type": "string", "format": "binary"}
        if annotation is UUID:
            return {"type": "string", "format": "uuid"}
        if annotation is date:
            return {"type": "string", "format": "date"}
        if annotation is datetime:
            return {"type": "string", "format": "date-time"}
        if annotation in {None, type(None)}:
            return {"type": "null"}
        if annotation is UploadedFile:
            return {"type": "string", "format": "binary"}
        if isinstance(annotation, type) and issubclass(annotation, Enum):
            values = [member.value for member in annotation]
            base = _enum_type_schema(values, registry=self, input_model=input_model)
            return {**base, "enum": values}
        if is_dataclass(annotation) and isinstance(annotation, type):
            return self._dataclass_schema(annotation, input_model=input_model)

        origin = get_origin(annotation)
        args = get_args(annotation)
        if origin in {list, set}:
            return {
                "type": "array",
                "items": self.schema_for(args[0] if args else Any, input_model=input_model),
            }
        if origin is tuple:
            if len(args) == 2 and args[1] is Ellipsis:
                return {
                    "type": "array",
                    "items": self.schema_for(args[0], input_model=input_model),
                }
            if args:
                return {
                    "type": "array",
                    "prefixItems": [self.schema_for(item, input_model=input_model) for item in args],
                    "minItems": len(args),
                    "maxItems": len(args),
                }
            return {"type": "array", "items": {}}
        if origin in {dict, Mapping}:
            value_type = args[1] if len(args) == 2 else Any
            return {
                "type": "object",
                "additionalProperties": self.schema_for(value_type, input_model=input_model),
            }
        if origin is Literal:
            values = list(args)
            base = _enum_type_schema(values, registry=self, input_model=input_model)
            return {**base, "enum": values}
        if origin in {Union, types.UnionType}:
            return {"anyOf": [self.schema_for(arg, input_model=input_model) for arg in args]}
        return {}

    def _dataclass_schema(self, model: type[Any], *, input_model: bool) -> dict[str, Any]:
        key = (model, input_model)
        name = self._component_name(model, input_model=input_model)
        if key in self._building or name in self.schemas:
            return {"$ref": f"#/components/schemas/{name}"}
        self._building.add(key)
        properties: dict[str, Any] = {}
        required: list[str] = []
        hints = _model_hints(model)
        for model_field in fields(model):
            if input_model and not model_field.init:
                continue
            properties[model_field.name] = self.schema_for(
                hints.get(model_field.name, model_field.type),
                input_model=input_model,
            )
            if model_field.default is MISSING and model_field.default_factory is MISSING:
                required.append(model_field.name)
        schema: dict[str, Any] = {
            "type": "object",
            "properties": properties,
            "additionalProperties": False,
        }
        if required:
            schema["required"] = required
        self.schemas[name] = schema
        self._building.remove(key)
        return {"$ref": f"#/components/schemas/{name}"}

    def _component_name(self, model: type[Any], *, input_model: bool) -> str:
        key = (model, input_model)
        existing = self._names.get(key)
        if existing is not None:
            return existing
        base = model.__name__
        candidate = base
        index = 2
        while candidate in self.schemas or candidate in self._names.values():
            candidate = f"{base}{index}"
            index += 1
        self._names[key] = candidate
        return candidate


def _validate_value(
    annotation: object,
    value: object,
    *,
    location: tuple[LocationPart, ...],
    from_text: bool,
    budget: ValidationBudget,
    depth: int,
) -> object:
    budget.consume(location=location, depth=depth)
    annotation = _unwrap_annotated(annotation)
    if annotation in {Any, object, inspect.Signature.empty}:
        return value
    if annotation in {None, type(None)}:
        if value is None:
            return None
        raise _problem(location, "type_error", "Expected null.")
    if is_dataclass(annotation) and isinstance(annotation, type):
        if not isinstance(value, Mapping):
            raise _problem(location, "type_error", "Expected an object.")
        mapped_value = cast(Mapping[str, object], value)
        hints = _model_hints(annotation)
        input_fields = tuple(item for item in fields(annotation) if item.init)
        known = {item.name for item in input_fields}
        issues: list[ValidationIssue] = []
        for key in mapped_value:
            if key in known:
                continue
            if not extend_validation_issues(
                issues,
                (ValidationIssue((*location, _safe_location_part(key)), "unknown_field", "Unknown field."),),
                location=location,
                budget=budget,
            ):
                break
        kwargs: dict[str, object] = {}
        for model_field in input_fields:
            if _issues_truncated(issues):
                break
            if model_field.name not in mapped_value:
                if model_field.default is MISSING and model_field.default_factory is MISSING:
                    extend_validation_issues(
                        issues,
                        (ValidationIssue((*location, model_field.name), "missing", "Field is required."),),
                        location=location,
                        budget=budget,
                    )
                continue
            try:
                kwargs[model_field.name] = _validate_value(
                    hints.get(model_field.name, model_field.type),
                    mapped_value[model_field.name],
                    location=(*location, model_field.name),
                    from_text=False,
                    budget=budget,
                    depth=depth + 1,
                )
            except _InvalidValue as exc:
                if _has_validation_limit(exc.issues):
                    raise
                extend_validation_issues(issues, exc.issues, location=location, budget=budget)
        if issues:
            raise _InvalidValue(issues)
        return annotation(**kwargs)

    origin = get_origin(annotation)
    args = get_args(annotation)
    if origin in {Union, types.UnionType}:
        failures: list[_InvalidValue] = []
        for member in args:
            try:
                return _validate_value(
                    member,
                    value,
                    location=location,
                    from_text=from_text,
                    budget=budget,
                    depth=depth + 1,
                )
            except _InvalidValue as exc:
                if _has_validation_limit(exc.issues):
                    raise
                failures.append(exc)
        raise _problem(location, "type_error", "Value does not match any allowed type.") from failures[-1]
    if origin is Literal:
        if value in args and type(value) in {type(item) for item in args}:
            return value
        if from_text and isinstance(value, str):
            for allowed in args:
                try:
                    converted = _validate_value(
                        type(allowed),
                        value,
                        location=location,
                        from_text=True,
                        budget=budget,
                        depth=depth + 1,
                    )
                except _InvalidValue:
                    continue
                if converted == allowed and type(converted) is type(allowed):
                    return converted
        raise _problem(location, "literal_error", f"Expected one of: {', '.join(map(str, args))}.")
    if origin in {list, set, tuple}:
        if not isinstance(value, list | tuple | set) or (origin is tuple and isinstance(value, set)):
            raise _problem(location, "type_error", "Expected an array.")
        fixed_tuple = origin is tuple and bool(args) and not (len(args) == 2 and args[1] is Ellipsis)
        if fixed_tuple and len(value) != len(args):
            raise _problem(location, "tuple_length", f"Expected exactly {len(args)} items.")
        item_type = args[0] if args else Any
        items: list[object] = []
        issues: list[ValidationIssue] = []
        for index, item in enumerate(value):
            if _issues_truncated(issues):
                break
            try:
                items.append(
                    _validate_value(
                        args[index] if fixed_tuple else item_type,
                        item,
                        location=(*location, index),
                        from_text=from_text,
                        budget=budget,
                        depth=depth + 1,
                    )
                )
            except _InvalidValue as exc:
                if _has_validation_limit(exc.issues):
                    raise
                extend_validation_issues(issues, exc.issues, location=location, budget=budget)
        if issues:
            raise _InvalidValue(issues)
        return _collection_value(origin, items)
    if origin in {dict, Mapping}:
        if not isinstance(value, Mapping):
            raise _problem(location, "type_error", "Expected an object.")
        key_type, item_type = args if len(args) == 2 else (str, Any)
        if key_type is not str:
            raise _problem(location, "type_error", "Only string-keyed mappings are supported.")
        return {
            str(key): _validate_value(
                item_type,
                item,
                location=(*location, _safe_location_part(key)),
                from_text=from_text,
                budget=budget,
                depth=depth + 1,
            )
            for key, item in value.items()
        }

    if isinstance(annotation, type) and issubclass(annotation, Enum):
        if from_text and isinstance(value, str):
            for member in annotation:
                try:
                    converted = _validate_value(
                        type(member.value),
                        value,
                        location=location,
                        from_text=True,
                        budget=budget,
                        depth=depth + 1,
                    )
                except _InvalidValue:
                    continue
                if converted == member.value and type(converted) is type(member.value):
                    return member
        try:
            return annotation(value)
        except (TypeError, ValueError) as exc:
            raise _problem(location, "enum_error", "Value is not a valid enum member.") from exc
    if annotation is str:
        if isinstance(value, str):
            return value
        raise _problem(location, "type_error", "Expected a string.")
    if annotation is bool:
        if isinstance(value, bool):
            return value
        if from_text and isinstance(value, str):
            normalized = value.lower()
            if normalized in {"true", "1", "on"}:
                return True
            if normalized in {"false", "0", "off"}:
                return False
        raise _problem(location, "type_error", "Expected a boolean.")
    if annotation is int:
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        if from_text and isinstance(value, str):
            try:
                return int(value, 10)
            except ValueError:
                pass
        raise _problem(location, "type_error", "Expected an integer.")
    if annotation is float:
        if isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(float(value)):
            return float(value)
        if from_text and isinstance(value, str):
            try:
                parsed = float(value)
                if math.isfinite(parsed):
                    return parsed
            except ValueError:
                pass
        raise _problem(location, "type_error", "Expected a finite number.")
    if annotation is UUID:
        try:
            return value if isinstance(value, UUID) else UUID(str(value))
        except ValueError as exc:
            raise _problem(location, "uuid_error", "Expected a UUID.") from exc
    if annotation is date:
        if isinstance(value, date):
            return value
        if isinstance(value, str):
            try:
                return date.fromisoformat(value)
            except ValueError as exc:
                raise _problem(location, "date_error", "Expected an ISO date value.") from exc
    if annotation is datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except ValueError as exc:
                raise _problem(location, "date_error", "Expected an ISO datetime value.") from exc
    if annotation is UploadedFile and isinstance(value, UploadedFile):
        return value
    if isinstance(annotation, type) and isinstance(value, cast(type[Any], annotation)):
        return value
    raise _problem(location, "type_error", f"Unsupported or invalid value for {annotation!r}.")


def _validate_text_values(
    annotation: object,
    values: Sequence[str],
    *,
    location: tuple[LocationPart, ...],
    budget: ValidationBudget,
) -> object:
    annotation = _unwrap_annotated(annotation)
    args = get_args(annotation)
    if is_collection_annotation(annotation):
        return _validate_value(
            annotation,
            list(values),
            location=location,
            from_text=True,
            budget=budget,
            depth=0,
        )
    if len(values) != 1:
        raise _problem(location, "multiple_values", "Expected one value.")
    if values[0] == "" and _allows_none(annotation) and str not in args:
        return None
    return _validate_value(
        annotation,
        values[0],
        location=location,
        from_text=True,
        budget=budget,
        depth=0,
    )


def extend_validation_issues(
    issues: list[ValidationIssue],
    incoming: Sequence[ValidationIssue],
    *,
    location: tuple[LocationPart, ...],
    budget: ValidationBudget,
) -> bool:
    """Append issues without exceeding the configured response cardinality."""

    for issue in incoming:
        if len(issues) >= budget.max_issues - 1:
            if not _issues_truncated(issues):
                marker = (
                    issue
                    if issue.code == "too_many_errors"
                    else ValidationIssue(
                        location,
                        "too_many_errors",
                        "Additional validation errors were omitted.",
                    )
                )
                issues.append(marker)
            return False
        issues.append(issue)
    return True


def _has_validation_limit(issues: Sequence[ValidationIssue]) -> bool:
    return any(issue.code == "validation_limit" for issue in issues)


def _issues_truncated(issues: Sequence[ValidationIssue]) -> bool:
    return bool(issues and issues[-1].code == "too_many_errors")


def _allows_none(annotation: object) -> bool:
    return type(None) in get_args(annotation)


def _uploaded_file_annotation(annotation: object) -> object | None:
    annotation = _unwrap_annotated(annotation)
    if annotation is UploadedFile:
        return annotation
    origin = get_origin(annotation)
    args = get_args(annotation)
    if origin in {Union, types.UnionType}:
        non_null = tuple(item for item in args if item not in {None, type(None)})
        if len(non_null) == 1:
            return _uploaded_file_annotation(non_null[0])
        return None
    if origin in {list, set, tuple} and any(contains_uploaded_file(item) for item in args):
        return annotation
    return None


def _collection_value(origin: object, values: Sequence[object]) -> object:
    if origin is set:
        return set(values)
    if origin is tuple:
        return tuple(values)
    return list(values)


def _unwrap_annotated(annotation: object) -> object:
    from typing import Annotated

    return get_args(annotation)[0] if get_origin(annotation) is Annotated else annotation


def _model_hints(model: type[Any]) -> dict[str, object]:
    try:
        return get_type_hints(model, include_extras=True)
    except NameError, TypeError:
        return {}


def _enum_type_schema(
    values: list[object],
    *,
    registry: SchemaRegistry,
    input_model: bool,
) -> dict[str, Any]:
    if not values or len({type(value) for value in values}) != 1:
        return {}
    return registry.schema_for(type(values[0]), input_model=input_model)


def _problem(location: tuple[LocationPart, ...], code: str, message: str) -> _InvalidValue:
    return _InvalidValue((ValidationIssue(location, code, message),))
