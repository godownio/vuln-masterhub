---
id: ctf-misc-sixel-dcs-image-decode
title: SIXEL DCS 图像流解码：终端图形隐写还原 flag
type: scenario
domain: ctf
path: ctf/misc
technique: sixel-dcs-image-decode
tags:
- ctf
- misc
- sixel
- dcs
- terminal-graphics
- image-decode
- steganography
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:51:14+08:00'
  notes: 已对照原文 §11 MISC1 核对：ESC P q…ESC 反斜杠 DCS、可见 BsHU 干扰项、?~减 63 六像素、双引号尺寸/井号调色板/!repeat/$ 回车/- 换行、输出 PNG 看底部 flag 均一致；原文有实测 flag，未本机复跑。
url: /docs/ctf/misc/ctf-misc-sixel-dcs-image-decode/
draft: false
kb_aliases:
- MISC1
- SIXEL
- DCS 图像
- ESC P q
- 终端图形
- 六像素 cell
---

## 一句话结论

`flag.txt` 不是普通文本，而是以 `ESC P q` 开头、`ESC \` 结尾的 SIXEL DCS 终端图像流；可见的 `BsHU...{@}` 是干扰项，真实 flag 在渲染出的图像底部。实现/使用 SIXEL 解码器处理调色板、repeat、换行和 6 像素垂直 cell，输出 PNG 后即可读出 flag。

## 原理

- **SIXEL 格式**：DCS 序列 `ESC P ... q ... ESC \` 内的数据用可打印字符 `?`..`~` 表示 6 个垂直像素（字符值减 63 得到 6 位掩码）；`"` 定义 raster 尺寸，`#` 定义/选择调色板，`!` 重复前一个 sixel，`$` 回到行首，`-` 换到下一行（y += 6）。
- **干扰项**：文件里可能包含看似 flag 的 ASCII 字符串，但只是题目诱导；真实内容需要渲染成图像后读取。
- **解码步骤**：第一遍扫描 `"` 取宽高、`#` 取 RGB 百分比调色板；第二遍按当前颜色/坐标绘制每个 sixel 的 6 个 bit，处理 repeat/CR/LF；最后按实际使用范围裁剪并保存 PNG。
- **为什么隐藏**：SIXEL 是终端图形协议，普通 `cat` 只会显示控制序列或乱码；文本编辑器/日志查看器不会渲染，容易忽略。

## 触发条件

- 附件是文本/二进制文件，以 `ESC P` 开头、`ESC \` 结尾，或包含 `q` 后的 SIXEL 数据。
- 常规字符串/十六进制/LSB 分析没有结果，但文件长度远大于可见文本。
- 需要终端图形渲染才能看到真实内容。

## 利用步骤

1. 检查文件头尾，确认 SIXEL DCS；剔除 DCS 前缀到 `q` 之前的内容。
2. 解析 raster 尺寸与调色板；初始化 RGB 画布。
3. 按字符绘制 sixel，处理 `!` repeat、`$` 回车、`-` 换行；记录最大 x/y。
4. 按实际使用范围裁剪并保存 PNG；放大/OCR/肉眼读取底部文字。

## PoC

```python
from pathlib import Path
from PIL import Image

def parse_int(data, i):
    start = i
    while i < len(data) and 48 <= data[i] <= 57:
        i += 1
    return int(data[start:i] or b"0"), i

def read_params(data, i):
    vals, value = [], b""
    while i < len(data):
        c = data[i]
        if 48 <= c <= 57:
            value += bytes([c]); i += 1; continue
        if c == ord(";"):
            vals.append(int(value or b"0")); value = b""; i += 1; continue
        break
    if value or vals:
        vals.append(int(value or b"0"))
    return vals, i

def rgb(r, g, b):
    return tuple(max(0, min(255, round(v * 255 / 100))) for v in (r, g, b))

raw = Path("flag.txt").read_bytes()
start, end = raw.find(b"\x1bP"), raw.rfind(b"\x1b\\")
data = raw[start + 2:end]
q = data.find(b"q")
if q >= 0:
    data = data[q + 1:]

width = height = 0
palette = {0: (0, 0, 0), 1: (255, 255, 255)}
current, x, y, max_x, max_y = 1, 0, 0, 0, 0

i = 0
while i < len(data):
    c = data[i]
    if c == ord('"'):
        vals, i = read_params(data, i + 1)
        if len(vals) >= 4:
            width, height = vals[2], vals[3]
    elif c == ord("#"):
        idx, i = parse_int(data, i + 1)
        if i < len(data) and data[i] == ord(";"):
            i += 1
        vals, i = read_params(data, i)
        if len(vals) >= 4 and vals[0] == 2:
            palette[idx] = rgb(vals[1], vals[2], vals[3])
    else:
        i += 1

img = Image.new("RGB", (width or 1920, height or 1080), (255, 255, 255))
pix = img.load()

def draw(ch, repeat=1):
    global x, y, max_x, max_y
    if not (63 <= ch <= 126):
        return
    bits, color = ch - 63, palette.get(current, (0, 0, 0))
    for _ in range(repeat):
        for bit in range(6):
            yy = y + bit
            if bits & (1 << bit) and 0 <= x < img.width and 0 <= yy < img.height:
                pix[x, yy] = color
                max_y = max(max_y, yy)
        max_x = max(max_x, x)
        x += 1

i = 0
while i < len(data):
    c = data[i]
    if c == ord('"'):
        _, i = read_params(data, i + 1)
    elif c == ord("#"):
        current, i = parse_int(data, i + 1)
        if i < len(data) and data[i] == ord(";"):
            i += 1
        _, i = read_params(data, i)
    elif c == ord("!"):
        repeat, i = parse_int(data, i + 1)
        if i < len(data):
            draw(data[i], repeat); i += 1
    elif c == ord("$"):
        x = 0; i += 1
    elif c == ord("-"):
        x = 0; y += 6; i += 1
    elif 63 <= c <= 126:
        draw(c); i += 1
    else:
        i += 1

img.crop((0, 0, max_x + 1, max_y + 1)).save("flag.png")
```

## 变体与关联

- 其他终端图形：ANSI art、Kitty graphics、iTerm2 inline image、Braille 点阵；先看控制序列头。
- 若 SIXEL 有多个调色板/透明色，按 `#` 定义与选择顺序处理；可用 `libsixel`/`img2sixel` 交叉验证。
- 若图像仍不可读，可放大、二值化、OCR；flag 可能在图像边缘/底部。
- 关联：终端控制序列隐写、图像渲染/OCR 卡。

## 检测与防御

- 这是 CTF 谜题；防御意义在于：不要把敏感信息编码在终端图形/图像中，文本通道的可见字符串可能是诱饵。
- 检测：文件中出现 `ESC P`/`ESC \`、大量 `#`/`!`/`$`/`-` 字符；渲染后图像包含文字。
