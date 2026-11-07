from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any

import yaml

FRONTMATTER_RE = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n?", re.DOTALL)


def jsonable(value: Any) -> Any:
    """Convert YAML date/time values into JSON/YAML friendly strings."""
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [jsonable(item) for item in value]
    return value



class FrontmatterError(ValueError):
    pass


def split_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    match = FRONTMATTER_RE.match(text)
    if not match:
        return {}, text
    raw = match.group(1)
    try:
        meta = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        raise FrontmatterError(f"invalid YAML frontmatter: {exc}") from exc
    if not isinstance(meta, dict):
        raise FrontmatterError("frontmatter must be a YAML mapping")
    return jsonable(meta), text[match.end():]


def dump_frontmatter(meta: dict[str, Any], body: str) -> str:
    raw = yaml.safe_dump(
        jsonable(meta),
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        width=1000,
    ).rstrip()
    return f"---\n{raw}\n---\n\n{body.lstrip()}"


def as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return [str(value)]


def as_text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)
