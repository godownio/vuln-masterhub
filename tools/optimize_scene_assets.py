"""Encode existing artwork for the web without changing its composition."""
import json
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / 'hugo-site/static'


def main():
    manifest = STATIC / 'js/scene-assets.js'
    assets = json.loads(manifest.read_text(encoding='utf8').split('=', 1)[1].strip().rstrip(';'))
    before = after = 0
    for kind in ('cats', 'flora'):
        for item in assets[kind]:
            source = (STATIC / item['file']).with_suffix('.png')
            output = source.with_suffix('.webp')
            with Image.open(source) as image:
                image.thumbnail((512, 512) if kind == 'cats' else (768, 768), Image.Resampling.LANCZOS)
                image.save(output, 'WEBP', quality=84, method=6)
                item.update(file=output.relative_to(STATIC).as_posix(), width=image.width, height=image.height)
            before += source.stat().st_size
            after += output.stat().st_size
    source = STATIC / 'images/field-notes-background.png'
    with Image.open(source) as image:
        image.save(source.with_suffix('.webp'), 'WEBP', quality=82, method=6)
    before += source.stat().st_size
    after += source.with_suffix('.webp').stat().st_size
    manifest.write_text('window.KnowledgeSceneAssets = ' + json.dumps(assets, ensure_ascii=False, indent=2) + ';\n', encoding='utf8')
    print(json.dumps({'original_bytes': before, 'web_bytes': after, 'reduction_percent': round(100 * (1 - after / before), 1)}))


if __name__ == '__main__':
    main()
