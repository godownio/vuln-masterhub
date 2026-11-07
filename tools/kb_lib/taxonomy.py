from __future__ import annotations

from pathlib import Path
from typing import Any, Iterator

import yaml


class TaxonomyError(ValueError):
    pass


def load(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise TaxonomyError(f"taxonomy not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict) or not isinstance(data.get("domains"), dict):
        raise TaxonomyError("taxonomy must contain a 'domains' mapping")
    return data


def defaults(data: dict[str, Any]) -> dict[str, list[str]]:
    raw = data.get("defaults") or {}
    return {
        "allow": [str(x) for x in (raw.get("allow") or [])],
        "deny": [str(x) for x in (raw.get("deny") or [])],
    }


def walk(domains: dict[str, Any], prefix: tuple[str, ...] = ()) -> Iterator[tuple[str, dict[str, Any]]]:
    for slug, node in domains.items():
        if not isinstance(node, dict):
            raise TaxonomyError(f"node {slug} must be a mapping")
        path = "/".join(prefix + (str(slug),))
        yield path, node
        children = node.get("children") or {}
        if children:
            if not isinstance(children, dict):
                raise TaxonomyError(f"children of {path} must be a mapping")
            yield from walk(children, prefix + (str(slug),))


def flatten(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return dict(walk(data.get("domains") or {}))


def children_of(domains: dict[str, Any], path: str) -> list[tuple[str, dict[str, Any], str]]:
    """Return (child_path, child_node, child_slug) for a path."""
    parts = [p for p in path.split("/") if p]
    node: Any = {"children": domains}
    for part in parts:
        node = (node.get("children") or {}).get(part)
        if node is None:
            return []
    out: list[tuple[str, dict[str, Any], str]] = []
    for slug, child in (node.get("children") or {}).items():
        out.append(("/".join(parts + [str(slug)]), child, str(slug)))
    return out


def node_at(domains: dict[str, Any], path: str) -> dict[str, Any] | None:
    parts = [p for p in path.split("/") if p]
    node: Any = {"children": domains}
    for part in parts:
        node = (node.get("children") or {}).get(part)
        if node is None:
            return None
    return node


def top_domain(path: str) -> str:
    return path.split("/", 1)[0] if path else ""
