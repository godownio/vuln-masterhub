---
id: ctf-misc-bmp-header-size-repair
title: BMP 文件头尺寸字段篡改修复：按像素数据长度重算 biWidth/biHeight 显示被裁掉的隐藏图像
type: scenario
domain: ctf
path: ctf/misc
technique: bmp-header-size-repair
tags:
- ctf
- misc
- stego
- bmp
- file-header
- image-repair
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V216
  verified_at: '2026-11-07T04:44:14+08:00'
  notes: '已对照原文与图01/02/03/05核对并修正字段归属：图01是640×480的BMP字段说明，实际题目文件 offset 0x12 宽度为 0x780(1920)、offset 0x16 高度为 0x3C0(960)，改为 0x4FF(1279) 后显示 password: 21df#；后续零宽字符解码得 flag 与卡一致。PoC 的行填充边界卡已注明。未验证点：未本机修改BMP复跑；非组件漏洞无版本；frontmatter无sources/source_url。'
url: /docs/ctf/misc/ctf-misc-bmp-header-size-repair/
draft: false
kb_aliases:
- BMP 头修复
- biHeight 篡改
- 图片比例失衡
- 010 Editor 改 BMP
- 隐藏图像恢复
---

## 一句话结论

当 BMP 打开后比例失衡、只显示一部分或提示“图像损坏”时，检查 `BITMAPINFOHEADER` 的 `biWidth`（偏移 0x12）与 `biHeight`（偏移 0x16）是否被改小；按实际像素数据长度 `(fileSize − bfOffBits) ÷ (biBitCount/8) ÷ 已知宽度` 重算高度（或按已知高度重算宽度），改回头部即可显示被裁掉的隐藏区域或密码。

## 原理

- BMP 像素数据从 `bfOffBits` 开始，大小由 `biWidth × biHeight × (biBitCount/8)` 决定（行按 4 字节对齐时还要加 padding）。头部宽高被改小后，解码器只渲染头部声明的区域，剩余像素数据被忽略，图像看起来比例失衡或底部/右侧缺失。
- 文件本身仍保留完整像素数据，所以用文件大小反推真实尺寸即可恢复：`dataLen = fileSize − bfOffBits`，`height = dataLen ÷ bytesPerPixel ÷ width`；若已知高度，则 `width = dataLen ÷ bytesPerPixel ÷ height`。结果应为整数，否则考虑行填充或 `biCompression`。
- 文章图 01 用一张 BMP 解释字段（该示例 `biWidth = 0x280 (640)`、`biHeight = 0x1E0 (480)`）；实际题目文件在偏移 0x16 的高度字段为 `C0 03 00 00`（0x3C0 = 960，同图 0x12 的宽度为 `80 07 00 00`，即 0x780 = 1920），把高度改为 `FF 04 00 00`（0x4FF = 1279）后图像恢复正常并显示 `password: 21df#$de`，说明原头部把真实高度裁掉了。
- 为什么成立：BMP 头是纯明文结构，解码器信任头部字段；只要按数据长度修正字段，像素数据本身就能完整呈现。类似问题也出现在 PPM/PNG/JPEG 的宽高字段篡改。
- 边界：负的 `biHeight` 表示自上而下存储，修改时要保留符号；1/4/8/16/24/32 位色深与行填充规则不同；若 `biCompression` 非 0（RLE 等），不能简单按未压缩公式计算。

## 触发条件

- BMP 可被解析但显示比例异常、底部/右侧内容缺失，或文件大小与头部声明的宽高明显不匹配。
- 文件头 `42 4D`（BM）、`bfOffBits`、`biWidth`/`biHeight`/`biBitCount` 字段可读可改。
- 像素数据未被压缩（`biCompression = 0`），或已知压缩方式可按相应规则重算。

## 利用步骤

1. 用 010 Editor/xxd 查看 BMP 头：`42 4D`、`bfSize`（0x02）、`bfOffBits`（0x0A）、`biWidth`（0x12）、`biHeight`（0x16）、`biBitCount`（0x1C）、`biCompression`（0x1E），均为小端。
2. 计算 `bytesPerPixel = biBitCount / 8`，`dataLen = fileSize − bfOffBits`。
3. 用 `dataLen / bytesPerPixel / width` 求真实高度；若结果非整数，考虑行填充（每行补齐到 4 字节）或改用已知高度求宽度。
4. 把重算出的宽/高写回对应小端 4 字节字段，保存后重新打开图像。
5. 若图像恢复但仍有隐藏内容，继续检查调色板、附加数据、LSB/零宽字符等隐写；本题恢复后得到压缩包密码，后续用零宽字符解出 flag。

## PoC

```python
import struct, sys

data = open(sys.argv[1], "rb").read()
assert data[:2] == b"BM"
bf_off = struct.unpack_from("<I", data, 0x0A)[0]
width, height = struct.unpack_from("<ii", data, 0x12)
bpp = struct.unpack_from("<H", data, 0x1C)[0]
compression = struct.unpack_from("<I", data, 0x1E)[0]
bytes_per_px = bpp // 8
data_len = len(data) - bf_off
print("width=%d height=%d bpp=%d comp=%d dataLen=%d" % (width, height, bpp, compression, data_len))

if compression == 0 and width > 0:
    real_h = data_len // (bytes_per_px * width)
    print("real height ~", real_h)
    # 按需写回：struct.pack_into("<i", data, 0x16, real_h)
    # open("fixed.bmp", "wb").write(data)
```

```text
# 文章中的修复：高度字段 0x16 处
C0 03 00 00  ->  FF 04 00 00   # 0x3C0(960) -> 0x4FF(1279)
```

## 变体与关联

- 变体：PPM P6 头高度篡改（按数据长度重算高度）、PNG IHDR 宽高修改、JPEG SOF 宽高、GIF 逻辑屏幕尺寸；处理方式类似但字段位置不同。
- 变体：BMP 负高度（自上而下）、4 字节行填充、调色板偏移、`bfOffBits` 错误；需按格式规范逐项校验。
- 关联：[[ctf-misc-ppm-p6-header-height-tamper-hidden-rows]]（同类图像尺寸字段修复）、[[ctf-misc-zero-width-unicode-binary-quinary-stego]]（本题后续零宽字符解码）、[[ctf-misc-broken-docx-zip-mtime-thumbnail-stego]]（文件结构损坏修复）。
- 边界：若像素数据本身被加密/压缩/异或，修头只能恢复尺寸，不能还原内容；行填充计算错误会导致图像错位。

## 检测与防御

- **检测（CTF）**：BMP 打开比例异常但文件大小正常；`biWidth × biHeight × bytesPerPixel + bfOffBits` 远小于文件大小；头部字段与实际数据长度不匹配。
- **修复（真实解析器）**：图像库应校验 `bfOffBits + 行填充 × 高度` 不超过文件长度，拒绝越界；对宽高设上限，防止解码器按恶意尺寸分配内存（解压炸弹/DoS）。
- **加固**：文件上传/解析服务使用安全的图像处理库并限制像素数；对损坏文件做隔离与重编码；不要直接信任头部声明的尺寸。
