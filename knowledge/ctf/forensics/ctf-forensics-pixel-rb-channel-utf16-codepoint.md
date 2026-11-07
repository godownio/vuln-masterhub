---
id: ctf-forensics-pixel-rb-channel-utf16-codepoint
title: 像素 R/B 通道拼 16 位码元：还原 UTF-16/Unicode 隐藏文本
type: scenario
domain: ctf
path: ctf/forensics
technique: pixel-rb-channel-utf16-codepoint
aliases:
- R/B 通道编码
- 像素 UTF-16
- 双通道 Unicode 隐写
- G 通道不变
- RGB 码点隐写
tags:
- ctf
- forensics
- pixel
- rgb
- utf16
- unicode
- stego
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:58:17+08:00'
  notes: 已对照原文我不是戏神与截图核对：G通道恒128、R/B组合(r<<8)+b→UTF-16码元、flag在文中一致；未验证点：未对附件复跑。
---

## 一句话结论

当图片的 G 通道几乎不变、R/B 通道看起来像噪声时，可把每个像素当作一个 16 位 Unicode 码元：`code=(R<<8)|B`，逐像素 `chr(code)` 即可还原整段隐藏文本，flag 常藏在文中。

## 原理

- **两个 8 位通道正好 16 位**：R 作高字节、B 作低字节，组成 `0..65535` 的码点，覆盖 Unicode 基本多文种平面（BMP）的 ASCII、汉字、标点等；G 通道保持原图颜色/噪声，避免整张图明显变色。
- **为什么用 R/B 而不是连续字节**：每个像素天然提供 3 个字节，选两个通道拼 16 位，容量为 `width*height*2` 字节；G 不动可以让图片看起来仍像正常纹理/照片。
- **文本可读性验证**：BMP 码点大多可打印（汉字、英文），直接 `chr()` 就能看到整段小说；若出现大量控制字符/替换符，说明字节序或通道选错。
- **本题**：图片是像素图，G 通道一直没变；hint 是 unicode，题干说小说；把 R、B 两通道两两组合成 `(r<<8)+b` 后 `chr()`，得到整段文本，flag 在文件中间。
- **非 BMP 字符**：需要 UTF-16 代理对（两个码元表示一个字符）；若文本含 emoji/生僻字，按 UTF-16 解码而不是逐 `chr` 拼接。

## 触发条件

- 图片看起来是彩色噪点/纹理，但 G 通道方差极小或恒定。
- R/B 通道的取值在可打印 Unicode 范围内有规律；直方图/通道分离可见文字轮廓。
- 题目提示“unicode/小说/文本/RGB/通道”。
- 文件为 BMP/PNG 等无损格式；JPEG 有损压缩会破坏精确码点。

## 利用步骤

1. 分离通道，统计每通道的方差/唯一值；确认 G 是否恒定、R/B 是否承载数据。
2. 按行优先遍历像素，计算 `code=(R<<8)|B`，`chr(code)` 拼接；先输出前几百字符观察是否可读。
3. 若乱码，尝试 `(B<<8)|R`、`(R<<8)|G`、`(G<<8)|B` 等通道组合，以及小端/大端。
4. 若文本含非 BMP 字符，改用 `bytes` 按 UTF-16LE/BE 解码：
   ```python
   raw = bytearray()
   for ...:
       raw += bytes([b, r])   # 或 [r, b]，对应 UTF-16LE/BE
   text = raw.decode("utf-16-le", "replace")
   ```
5. 在文本中搜索 `flag{`/`}`；若 flag 被拆在文中，按上下文拼接。
6. 若仍有少量乱码，检查是否有像素偏移/填充、通道值是否被加减偏移、以及图片是否被缩放。

## PoC

```python
from PIL import Image

im = Image.open("novel.bmp").convert("RGB")
w, h = im.size
chars = []
for y in range(h):
    for x in range(w):
        r, g, b = im.getpixel((x, y))
        code = (r << 8) | b
        if code == 0:
            continue
        chars.append(chr(code))
text = "".join(chars)
print(text[:500])
import re
print(re.findall(r"flag\{[^}]*\}", text))
```

说明：PoC 按原文 `(r<<8)+b` 思路重写；若文本含代理对，改用 UTF-16 字节流解码。未在本机对附件复跑。

## 变体与关联

- **通道组合**：R/G、G/B、R/B 都可能；先做通道方差分析确定哪两个通道在变化。
- **字节序**：`(R<<8)|B` 与 `(B<<8)|R` 分别对应大端/小端；也可把两通道写成字节流后整体按 UTF-16LE/BE 解码。
- **24 位码点**：R/G/B 三通道拼 24 位，可表示更大字符集或 RGB 颜色值。
- **偏移/异或**：码点可能先减去 0x4E00（汉字区）或与固定值异或；用可打印率/汉字比例判断。
- **调色板索引**：GIF/PNG 调色板图的索引值也可承载 16 位数据。
- **关联**：[[ctf-forensics-video-single-pixel-channel-extraction]]（逐像素/逐帧取通道值）、[[ctf-forensics-two-tone-gray-128-129-binary]]（同像素不同编码）、[[ctf-forensics-xor-known-key-large-pixel-block]]（像素块二值）。

## 检测与防御

- 检测：分通道计算熵/方差，正常照片三通道都有较高且相近的熵；若某通道恒定、另两通道呈现文本统计特征，即可疑。
- 防御：重新编码/压缩（JPEG 有损）会破坏精确码点；对上传图片做通道重采样/加噪可降低可恢复性。
- 取证：保留原图；不要用会做色彩管理/缩放的查看器另存。
