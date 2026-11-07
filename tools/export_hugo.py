"""Export the Markdown knowledge tree into the Hextra presentation site."""
from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from kb_lib.frontmatter import dump_frontmatter, split_frontmatter  # noqa: E402
from kb_lib.taxonomy import load, walk  # noqa: E402

SITE = ROOT / "hugo-site"
OUT = SITE / "content" / "docs"
INDEX = SITE / "static" / "kb-index.json"


def clean_generated() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)


def export() -> tuple[int, int]:
    taxonomy = load(ROOT / "taxonomy.yaml")
    nodes = {}
    for path, node in walk(taxonomy["domains"]):
        nodes[path] = {"path": path, "title": node.get("title", path.split("/")[-1]),
                       "description": node.get("description", ""), "count": 0, "children": []}
    clean_generated()
    for path, node in nodes.items():
        target = OUT / path
        target.mkdir(parents=True, exist_ok=True)
        source = ROOT / "knowledge" / path / "README.md"
        body = source.read_text(encoding="utf-8") if source.exists() else node["description"]
        # Source README navigation points to README.md; Hugo section URLs use directories.
        body = re.sub(r"\(([^)#]+/)README\.md\)", r"(\1)", body)
        body = re.sub(r"\(([^)#]+)\.md\)", r"(\1/)", body)
        (target / "_index.md").write_text(dump_frontmatter({"title": node["title"], "weight": 1}, body), encoding="utf-8")
        if "/" in path:
            nodes[path.rsplit("/", 1)[0]]["children"].append(node)

    cards = []
    for source in sorted((ROOT / "knowledge").rglob("*.md")):
        if source.name == "README.md":
            continue
        meta, body = split_frontmatter(source.read_text(encoding="utf-8"))
        path = str(meta.get("path") or source.parent.relative_to(ROOT / "knowledge").as_posix())
        if path not in nodes:
            raise ValueError(f"Card path not in taxonomy: {source}")
        slug = source.stem
        card_url = "/docs/" + path + "/" + slug + "/"
        title = str(meta.get("title") or slug)
        # Preserve the source frontmatter and content. Hugo uses url to keep stable paths.
        exported = {**meta, "title": title, "url": card_url, "draft": False}
        # Hugo reserves `aliases` for redirect URLs; KB aliases are search terms.
        exported["kb_aliases"] = exported.pop("aliases", [])
        (OUT / path / source.name).write_text(dump_frontmatter(exported, body), encoding="utf-8")
        parts = path.split("/")
        for i in range(1, len(parts) + 1):
            nodes["/".join(parts[:i])]["count"] += 1
        cards.append({"title": title, "path": path, "url": card_url,
                      "breadcrumb": " / ".join(nodes["/".join(parts[:i])]["title"] for i in range(1, len(parts)+1)),
                      "aliases": meta.get("aliases") or [], "tags": meta.get("tags") or [],
                      "cve": meta.get("cve") or [], "status": meta.get("status") or "draft",
                      "updated": str(meta.get("updated") or "")})
    tree = [node for path, node in nodes.items() if "/" not in path]
    INDEX.parent.mkdir(parents=True, exist_ok=True)
    INDEX.write_text(json.dumps({"tree": tree, "cards": cards,
                                "nodes": {p: {"title": n["title"]} for p, n in nodes.items()}}, ensure_ascii=False), encoding="utf-8")
    return len(nodes), len(cards)


if __name__ == "__main__":
    print("Exported %s tree nodes and %s cards" % export())
