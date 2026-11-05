"""JSON Schema loading and validation."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError as JsonSchemaError

from .errors import SchemaError

SCHEMA_FILES = {
    "advisory": "advisory.schema.json",
    "package": "package.schema.json",
    "lab": "lab.schema.json",
    "probe": "probe.schema.json",
    "validation": "validation.schema.json",
    "detection": "detection.schema.json",
    "detection-spec": "detection-spec.schema.json",
    "evidence": "evidence.schema.json",
    "exploitability": "exploitability.schema.json",
    "provenance": "provenance.schema.json",
}


@lru_cache(maxsize=None)
def load_schema(schemas_dir: Path, name: str) -> dict[str, Any]:
    try:
        filename = SCHEMA_FILES[name]
    except KeyError as exc:
        raise SchemaError(f"Unknown schema {name!r}") from exc

    path = schemas_dir / filename
    try:
        schema = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise SchemaError(f"Schema not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SchemaError(f"Invalid JSON in {path}: {exc}") from exc

    try:
        Draft202012Validator.check_schema(schema)
    except JsonSchemaError as exc:
        raise SchemaError(f"Invalid JSON Schema {path}: {exc.message}") from exc
    return schema


def validate_instance(
    instance: Any,
    schemas_dir: Path,
    schema_name: str,
    *,
    label: str = "instance",
) -> list[str]:
    """Return a list of human-readable schema violations (empty means valid)."""
    schema = load_schema(schemas_dir, schema_name)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.path))
    messages: list[str] = []
    for error in errors:
        location = "/".join(str(part) for part in error.path) or "<root>"
        messages.append(f"{label}: {location}: {error.message}")
    return messages
