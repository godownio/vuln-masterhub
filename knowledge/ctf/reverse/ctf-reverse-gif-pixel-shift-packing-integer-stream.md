---
id: ctf-reverse-gif-pixel-shift-packing-integer-stream
title: GIF 像素打包为十进制大整数流：逆向还原图像与二维码
type: scenario
domain: ctf
path: ctf/reverse
technique: gif-pixel-shift-packing-integer-stream
aliases:
- GIF-Zipper
- flag.gifzip
- 像素整数流
- RGB 大整数编码
- 拉链数字
tags:
- ctf
- reverse
- image
- gif
- pixel
- bit-shift
- qr
- encoding
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V192
  verified_at: '2026-11-06T23:05:29+08:00'
  notes: 已对照原文与图片核对：宽高124、24位RGB拆分与二维码flag一致；反编译表达式失真已在卡内说明；未本机复跑。
---

## 一句话结论

名为 `flag.gifzip` 的“加密 GIF”其实是文本：前两个数字是宽高，之后每个十进制整数按 `R<<16 | G<<8 | B` 打包一个像素；按 24 位拆回 RGB 重建图像，得到一个二维码，扫码即可得到 flag。

## 原理

- **数据布局**：程序用 `stb_image` 载入 `flag.gif`，先向输出文件写入 `width,height`，再逐像素把 RGB 合成为一个整数写出。文章展示的反编译表达式为 `r << (g + 16) << (b + 8)`，这是反编译器对 C++ `operator<<` 链的失真呈现，不能按字面理解为“用 g、b 当移位量”；从实际数据验证，每个值都落在 24 位内，且 `(v>>16)&0xFF`、`(v>>8)&0xFF`、`v&0xFF` 能还原出合理像素，说明实际布局是 `R` 在高 8 位、`G` 在中间 8 位、`B` 在低 8 位。
- **为什么能还原**：整数的低 24 位恰好容纳三个 8 位通道，通道之间没有重叠；只要按位掩码拆分并写回 `(r,g,b)`，就得到原图。前两个值 `124,124` 是宽高，后续值数量应等于 `width*height`，这是判断布局是否正确的直接依据。
- **二维码的出现**：还原出的 GIF 是一张二维码（QR），扫码得到 flag；题目名中的 “zipper” 是误导，真正的“压缩”只是把像素转成十进制整数序列。
- **与真 GIF 的区别**：真 GIF 以 `GIF87a`/`GIF89a` 开头并含逻辑屏幕描述符、全局色表、LZW 图像数据；这里的文件是纯文本逗号分隔整数，用图片查看器打不开，但用文本编辑器/`file` 一眼可辨。

## 触发条件

- 附件是文本文件，内容形如 `124,124,3719168,3719168,...`，逗号分隔的十进制整数。
- 前两个整数与随后的整数个数满足 `count ≈ width*height`（可能因末尾换行/分隔符略有差异）。
- 后续整数的最大值不超过 `0xFFFFFF`（16777215），高位字节分布与图像像素相符。
- 题目提示 GIF、图片、二维码，或给出的二进制中能看到 `stbi_load`、`ofstream` 与逐像素循环。

## 利用步骤

1. 用文本编辑器/`head` 查看文件，确认不是 `GIF8` 二进制；统计逗号分隔整数个数。
2. 取前两个数为宽 `w`、高 `h`；检查剩余个数是否等于 `w*h`，不相等时先排查分隔符、换行、是否多出元数据。
3. 按 `r=(v>>16)&0xFF`、`g=(v>>8)&0xFF`、`b=v&0xFF` 还原每个像素，按行优先写入新图像并保存为 PNG/GIF。
4. 用二维码解码器（如 zbar、QRazyBox、手机扫码）读取还原图；若扫不出，尝试反色、放大、灰度化、修正宽高互换。
5. 若还原图仍然错位，检查通道顺序是否为 BGR、是否使用 32 位 ARGB、是否每像素偏移了 alpha 字节、是否对像素做了行/列置换。

## PoC

按原文脚本整理（未在本机对附件执行）：

```python
import re
from PIL import Image

with open("flag.gifzip", "r", encoding="utf-8") as f:
    nums = [int(x) for x in re.findall(r"\d+", f.read())]

w, h = nums[0], nums[1]
pixels = nums[2:]
assert len(pixels) >= w * h, (len(pixels), w, h)

img = Image.new("RGB", (w, h))
pix = img.load()
for y in range(h):
    for x in range(w):
        v = pixels[y * w + x]
        r = (v >> 16) & 0xFF
        g = (v >> 8) & 0xFF
        b = v & 0xFF
        pix[x, y] = (r, g, b)
img.save("flag_rev.png")
```

随后用二维码工具扫描 `flag_rev.png`；原文还原出的二维码解码后得到 flag（形如 `sknb{...}`）。

## 变体与关联

- **通道顺序变体**：`BGR`、`ARGB`、`0xRRGGBBAA`；若颜色整体偏蓝/偏红，优先交换 R/B。
- **打包方式变体**：`(r<<16)+(g<<8)+b`、`r*65536+g*256+b`、每通道 10 位（30 位整数）、或每个像素写成十六进制字符串。
- **图像变体**：还原结果可能是二维码、条形码、文字图、迷宫；扫码失败时先确认尺寸与通道。
- **关联**：[[ctf-reverse-six-bit-block-printable-image-encoder]]（可打印字符位打包图像）、[[ctf-reverse-quadratic-swap-image-encryption-rounds]]（图像置换加密）、[[ctf-forensics-hex-png-stream-qr-chain-base64]]（十六进制流还原二维码）。
- **边界**：若整数是 32 位且最高字节不是 0，需先判断是 alpha 还是额外元数据；若数值大于 `0xFFFFFF`，按 24 位拆分会丢位，应重新分析位宽。

## 检测与防御

- **CTF 识别**：文本文件 + 大量 24 位整数 + 前两值像宽高，是“像素整数化”的强特征；不要被 `gifzip` 扩展名或“加密”描述带偏。
- **取证/分析**：先 `file` 与 `strings` 判断真实类型；统计数值范围与数量，验证 `w*h` 关系；还原后检查图像是否有二维码结构（定位图案）。
- **防御（真实系统）**：自定义序列化格式应带版本、magic、长度与校验和；不要把“把图像转成整数文本”当作加密或压缩，它既不保密也不减小体积。
- **出题思路**：利用扩展名与题目名误导，配合反编译表达式失真，迫使选手以数据布局而非源码字面为准。
