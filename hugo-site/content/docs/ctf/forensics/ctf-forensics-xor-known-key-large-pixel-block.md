---
id: ctf-forensics-xor-known-key-large-pixel-block
title: 已知密钥文件异或恢复 PNG：再按 10×10 大像素块转二进制
type: scenario
domain: ctf
path: ctf/forensics
technique: xor-known-key-large-pixel-block
tags:
- ctf
- forensics
- xor
- png
- pixel
- block
- stego
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:58:19+08:00'
  notes: 已对照原文Unsolved Mystery与截图核对：零宽解key camellia、XOR后PNG魔数、70x330、255/254双值、10x10块二值解flag一致；未验证点：未对附件复跑。
url: /docs/ctf/forensics/ctf-forensics-xor-known-key-large-pixel-block/
draft: false
kb_aliases:
- 文件异或恢复 PNG
- 零宽 key 异或
- 10x10 像素块
- 大像素二值
- 文件 XOR 隐写
---

## 一句话结论

当未知文件与一段已知内容等长、异或后出现 `89 50 4E 47` 的 PNG 文件头时，用已知 key 逐字节异或即可恢复 PNG；若恢复图只有 255/254 两种值、且实际以 10×10 像素为一块，则每块采样一位、按 8 位转 ASCII 得到 flag。

## 原理

- **XOR 是对合运算**：`C = P ⊕ K`，则 `P = C ⊕ K`；若 key 比文件短，按 `itertools.cycle(key)` 循环使用。已知明文头（PNG 的 8 字节魔数）可用于验证 key 或做已知明文攻击。
- **文件异或场景**：题目给两个文件，一个是密文，另一个是 key/掩码；把两者按字节异或，若结果以 PNG/JPEG/ZIP 魔数开头，就说明恢复成功。本题 key 来自零宽字符解码。
- **大像素块编码**：恢复的 PNG 尺寸为 70×330，出题脚本用 `pixelsize=10` 把每个逻辑像素放大成 10×10 的块；因此直接逐像素取 LSB 会得到大量重复位，正确做法是每 10×10 块采样一个点（如块中心/左上角），映射 `255→0、254→1`，再每 8 位转字符。
- **为什么容易误判**：直接按 7 bit/像素处理也能得到部分可读内容，但换行/对齐会错；观察到图像由大块组成、尺寸能被 10 整除，就应按块采样。
- **本题**：零宽隐写解出 key，与另一文件异或得到 PNG；像素只有 255/254，图片 70×330；按 10×10 块处理后解出 flag。

## 触发条件

- 两个文件大小相同/相近，未知文件高熵；题目提示“异或/XOR/key/掩码”。
- 异或结果出现已知文件魔数（PNG `89 50 4E 47`、JPEG `FF D8 FF`、ZIP `50 4B 03 04`）。
- 恢复图只有两种像素值，且宽/高能被 5、8、10 等块大小整除。
- 前置层可能是零宽字符/文本隐写，key 以 ASCII/hex 形式给出。

## 利用步骤

1. 读取两个文件为 bytes；若长度不同，用较短的循环 key 或对齐到较短长度。
2. 逐字节异或，检查结果前 8 字节是否为 PNG 魔数；保存为 `.png`。
3. 用 Pillow 统计唯一像素值；若只有两种（如 255/254），确定映射。
4. 观察图像结构：把图按 10×10 分块，统计每块内像素是否一致；若一致，说明每块是一个逻辑像素。
5. 每块采样一个点（左上/中心），按行优先生成 bit 流；每 8 位转 ASCII；尝试 7 位、LSB-first、映射互换。
6. 用 `flag{`/`}` 验证；若图像有偏移/边框，先裁掉再分块。

## PoC

```python
from itertools import cycle
from PIL import Image

# 1) 文件异或
c = open("mystery.bin", "rb").read()
k = open("key.bin", "rb").read()
plain = bytes(x ^ y for x, y in zip(c, cycle(k)))
assert plain[:8] == b"\x89PNG\r\n\x1a\n", plain[:8].hex()
open("recovered.png", "wb").write(plain)

# 2) 10x10 大像素块 -> bit 流
im = Image.open("recovered.png").convert("L")
w, h = im.size
BLOCK = 10
bits = []
for by in range(0, h, BLOCK):
    for bx in range(0, w, BLOCK):
        v = im.getpixel((bx, by))          # 取块左上角；也可取中心
        bits.append("0" if v >= 255 else "1")

bitstr = "".join(bits)
for width in (8, 7):
    out = []
    for i in range(0, len(bitstr) - width + 1, width):
        out.append(chr(int(bitstr[i:i+width], 2)))
    print(width, "".join(out)[:200])
```

说明：PoC 中 key 文件名/映射/块大小需按题目调整；原文先按 7 bit 尝试、后确认 10×10 块，故保留两种分组。未在本机对附件复跑。

## 变体与关联

- **循环 key**：key 比文件短时用 `cycle`；若 key 长度未知，可用 PNG 魔数/已知明文推断。
- **单字节 XOR**：key 只有一个字节，直接爆破 256 种并检查魔数。
- **块大小**：5×5、8×8、10×10 都可能；按图像尺寸与块内一致性推断。
- **双值映射**：255/254、0/1、128/129 都可能；按直方图确定。
- **关联**：[[ctf-misc-zero-width-unicode-binary-quinary-stego]]（key 的来源）、[[ctf-forensics-two-tone-gray-128-129-binary]]（双值像素位流）、[[ctf-misc-png-trailing-data-lcg-xor-base62]]（PNG 尾部 XOR 链）。

## 检测与防御

- 检测：未知文件与已知文件异或后出现魔数；图片直方图只有两个值且块状结构明显；`binwalk` 可识别恢复后的 PNG。
- 防御：XOR 只是混淆不是加密；对敏感数据应使用带认证的加密（AES-GCM 等），不要依赖自定义 XOR 掩码。
- 取证：保留原文件与 key，记录异或方向/长度；若 key 来自另一隐写层，先完整还原 key 再处理。
