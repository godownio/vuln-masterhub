---
id: ctf-forensics-png-dct-qim-blue-channel-pyc-alpha-lsb
title: PNG 蓝通道 8×8 DCT QIM 提取隐藏 pyc，再按 alpha LSB 与循环 XOR 还原明文
type: scenario
domain: ctf
path: ctf/forensics
technique: png-dct-qim-blue-channel-pyc-alpha-lsb
aliases:
- DCT QIM 隐写
- 蓝通道 8x8 分块
- 系数 (3,4)
- QIM_STEP=36
- alpha LSB
- 隐藏 pyc
- 循环 XOR
tags:
- ctf
- forensics
- png
- dct
- qim
- stego
- pyc
- alpha-lsb
- xor
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:28:33+08:00'
  notes: 已对照原文 异常数据传输 2/3 核对：012.png 蓝通道 8x8 DCT 系数(3,4)、QIM_STEP=36、4 字节长度前缀、663 字节 pyc、009.png alpha LSB 550 字节、11 字节 key f92hj89h123 循环 XOR 得 NeverGiveUp 均一致；未实际运行。
---

## 一句话结论

异常 PNG 的文本块给出“蓝通道、8×8 分块、DCT、系数 (3,4)、`QIM_STEP=36`、4 字节长度前缀”的提取规则；按此提取出 663 字节 pyc，反汇编发现它从另一张 PNG 的 alpha 通道 LSB 读长度+数据并 base64 输出；用 `009.png` 的 Comment key 对 550 字节密文做 11 字节循环 XOR 得到明文。

## 原理

- **DCT QIM**：把蓝通道按 8×8 分块做二维 DCT，选固定中频系数 `(3,4)`，用 QIM（量化索引调制）把 1 bit 映射到量化格点的奇偶/索引；量化步长 `QIM_STEP=36.0` 决定鲁棒性与失真。读取时对系数做同样量化，按索引奇偶取 bit。
- **长度前缀**：前 32 bit 为 payload 长度（大端或小端需按实现确认），随后按该长度读取字节，得到完整 pyc。
- **pyc 是 Python 字节码**：`marshal` 加载 code object 后可 `dis` 反汇编；逻辑是从 `lsb.png` 的 alpha 通道最低位读 32 bit 长度，再读 n 字节并 base64 输出。
- **alpha LSB**：RGBA PNG 的 alpha 通道最低位常被用来藏数据；按行优先逐像素取 `a & 1`，每 8 bit 打包。
- **循环 XOR**：密文是固定 11 字节块重复 50 次；key 长度 11（来自 Comment），逐字节循环异或即可还原重复明文。

## 触发条件

- PNG 文本块含 `embed_logic_hint` 等提取参数提示。
- 图片有可用的蓝通道/alpha 通道，尺寸是 8 的倍数或可 padding。
- 存在配套的另一张 PNG/密文与 key 注释。
- 隐藏载荷是 pyc/脚本，可反汇编读逻辑。

## 利用步骤

1. 读取异常 PNG 的 `tEXt`/`iTXt` 文本块，提取通道、分块、DCT 系数坐标、QIM 步长、长度前缀格式。
2. 对蓝通道按 8×8 分块做 DCT，取 `(3,4)` 系数，按 QIM 步长量化，读取 bit；前 32 bit 为长度，随后读 payload。
3. 保存 payload 为 `.pyc`，用 `dis`/`uncompyle6`/`decompyle3` 反汇编，确认其读取 alpha LSB 的逻辑。
4. 对目标 PNG 的 alpha 通道按行优先取 LSB，读 32 bit 长度与密文。
5. 用 Comment 中的 key 做循环 XOR，得到重复明文；按题目要求取核心明文。

## PoC

```python
import numpy as np
from PIL import Image
from scipy.fftpack import dct, idct

def qim_bit(coef, step=36.0):
    idx = round(coef / step)
    return idx & 1

def extract_dct_bits(path, channel=2, block=8, pos=(3, 4), step=36.0):
    img = np.asarray(Image.open(path).convert("RGB"))[:, :, channel].astype(float)
    h, w = img.shape
    bits = []
    for y in range(0, h - block + 1, block):
        for x in range(0, w - block + 1, block):
            blk = img[y:y+block, x:x+block]
            coef = dct(dct(blk, axis=0, norm="ortho"), axis=1, norm="ortho")
            bits.append(qim_bit(coef[pos], step))
    return bits

def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits)//8*8, 8):
        v = 0
        for b in bits[i:i+8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)

payload = bits_to_bytes(extract_dct_bits("012.png"))
n = int.from_bytes(payload[:4], "big")
pyc = payload[4:4+n]

# alpha LSB
img = Image.open("009.png").convert("RGBA")
bits = [img.getpixel((x, y))[3] & 1 for y in range(img.height) for x in range(img.width)]
data = bits_to_bytes(bits)
n2 = int.from_bytes(data[:4], "big")
ct = data[4:4+n2]

key = b"f92hj89h123"
print(bytes(c ^ key[i % len(key)] for i, c in enumerate(ct)))
```

## 变体与关联

- **频域变体**：DWT/DCT/DST、不同中频坐标、QIM 步长/量化方式（奇偶、索引模 4）、分块大小 4/8/16。
- **载体变体**：RGB 单通道、YCbCr 的 Y 通道、alpha 通道、多图分片；长度前缀可能小端/变长。
- **载荷变体**：pyc、ELF、zip、加密 blob；pyc 可能被混淆或版本不匹配。
- **关联卡片**：[[ctf-forensics-png-lsb-column-major-scan-order]]（LSB 扫描顺序）、[[ctf-forensics-multilayer-png-wav-spectrogram-maze-stego]]（多层 PNG 隐写）、[[ctf-misc-png-trailing-data-lcg-xor-base62]]（PNG 尾部数据 + XOR）。
- **边界**：若图片经过有损压缩/缩放，DCT 系数会被破坏；QIM 步长/坐标错误会读出随机 bit。

## 检测与防御

- **CTF/审计验证**：先验证前 32 bit 长度与文件头（pyc magic `6f 0d 0d 0a` 或版本号）匹配，再反汇编确认逻辑；XOR 后检查明文是否可打印/重复。
- **防御**：对外图片统一重编码/压缩；检测频域隐写（DCT 系数直方图异常、QIM 周期）；不要用短 key 循环 XOR。
- **检测信号**：PNG 文本块含提取参数；蓝通道/alpha 通道 LSB 分布异常；图片尾部或隐藏文件含 pyc magic。
