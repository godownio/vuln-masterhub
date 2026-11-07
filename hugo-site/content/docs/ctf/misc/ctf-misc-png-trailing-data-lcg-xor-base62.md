---
id: ctf-misc-png-trailing-data-lcg-xor-base62
title: PNG 尾部附加数据：LCG 流 XOR 解出 base62 密文再还原 flag
type: scenario
domain: ctf
path: ctf/misc
technique: png-trailing-data-lcg-xor-base62
tags:
- ctf
- misc
- png
- steganography
- trailing-data
- lcg
- xor
- base62
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V111
  verified_at: '2026-11-06T01:53:02+08:00'
  notes: 已对照“像素中的秘密”原文与 59 张图片核对：IEND 尾部数据、seed 0x69CB3446、Numerical Recipes LCG 参数、逐字节 x&0xff XOR 得 16vPI4pqYkxFvJHGGgssbbrGLF7Zqg1YN；本机用卡片参数复跑 LCG 与该 base62 解码，输出 flag{final_flag_png_lcg}，与原文一致
url: /docs/ctf/misc/ctf-misc-png-trailing-data-lcg-xor-base62/
draft: false
kb_aliases:
- 像素中的秘密
- PNG 尾部数据
- LCG XOR
- seed 0x69CB3446
- base62 解码
- 纯白图片隐写
---

## 一句话结论

附件是一张纯白 PNG，像素/LSB 没有异常；用 010 查看文件末尾，IEND 之后还有附加数据。数据被分成三块，前四字节 `69 CB 34 46` 是 LCG seed；用 `x = 1664525*x + 1013904223 mod 2^32`、每字节密钥 `x & 0xff` 对后续密文 XOR，得到 base62 字符串 `16vPI4pqYkxFvJHGGgssbbrGLF7Zqg1YN`，base62 解码即 flag。

## 原理

- **PNG 结构**：PNG 以 `89 50 4E 47 0D 0A 1A 0A` 开头，以 `IEND` chunk（`00 00 00 00 49 45 4E 44 AE 42 60 82`）结束；解析器通常忽略 IEND 之后的字节，因此可在文件尾部追加任意载荷。
- **纯白图排除像素隐写**：如果所有像素都是纯白、LSB 平面无变化，像素/LSB/通道隐写基本不可能；信息更可能在文件尾/元数据/附加 chunk。
- **LCG**：`x_{n+1} = (a*x_n + c) mod 2^32`，本题 `a=1664525`、`c=1013904223`（Numerical Recipes LCG）；每次取 `x & 0xff` 作为流密钥与密文字节异或。
- **seed 识别**：附加数据分成三块，前 4 字节可能是 seed；尝试 `0x00000000` 与 `0x69CB3446`，后者解出可读 base62/明文，即可确认。
- **base62**：字符集 `0-9a-zA-Z`，解码后得到 `flag{...}`（或再经过一层编码）。

## 触发条件

- 图片没有可见/像素级异常，但文件大小明显大于图像数据，或 IEND 后有附加字节。
- 附加数据有固定块结构/前 4 字节疑似 seed。
- 使用常见 LCG 参数/自定义参数，且密钥流按字节取低位。
- 解密结果是可打印/base62/base64 字符串。

## 利用步骤

1. 用 010/`xxd` 查看 PNG 尾部，定位 IEND 与附加数据；记录分块。
2. 取前 4 字节作为候选 seed（大端/小端都试），实现 LCG XOR。
3. 解密后检查是否可打印；若是 base62，解码得到 flag。
4. 若 seed 不对，尝试其他 4 字节窗口/常见 LCG 参数（glibc、MSVC、Numerical Recipes）。
5. 校验解码结果格式（`flag{...}`）。

## PoC

```python
def lcg_xor_decrypt(seed=0x69CB3446):
    x = seed
    cipher = b''.join([
        b'\xDC\x5E\xD1\x8A\x38\x28\xBB\xDF\x6C\x7B\x57\x84\x4F\x0E\x9B\x51',
        b'\x3A\xDF\xC4\xD9\x63\x0E\xA9\x39\x89\x26\x08\xC8\xB8\xF3\xD2\xBF',
        b'\x43\x08\xC7\x7A\x91\xBC\xEB\x4E\x55\xB0\x4F\x62\x59\xE4\xF3\xB6',
        b'\x9D\x58\xD7\x4A\x21\x0C\xFB\x1E'])
    out = bytearray()
    for b in cipher:
        x = (1664525 * x + 1013904223) & 0xffffffff
        out.append(b ^ (x & 0xff))
    return bytes(out)

print(lcg_xor_decrypt())
# b'16vPI4pqYkxFvJHGGgssbbrGLF7Zqg1YN'
```

base62 解码（示例）：

```python
ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
def b62decode(s):
    n = 0
    for ch in s:
        n = n * 62 + ALPHABET.index(ch)
    return n.to_bytes((n.bit_length() + 7) // 8, "big")
print(b62decode("16vPI4pqYkxFvJHGGgssbbrGLF7Zqg1YN"))
```

## 变体与关联

- 尾部数据可换成 PNG `tEXt`/`zTXt`/`iTXt` chunk、EXIF、文件末尾 ZIP、隐写工具（steghide/outguess）。
- LCG 参数可换成 glibc `rand`、MSVC、`seed = time`；先尝试常见参数，再用已知明文/可打印性验证。
- 编码可换成 base64/base32/base85/自定义字母表；按解码结果格式判断。
- 关联：PNG 尾部隐写、LCG 流密码、base62 解码卡。

## 检测与防御

- 这是 CTF 谜题；防御意义在于：不要把敏感信息附加在图片 IEND 后或可预测 PRNG 流中。
- 检测：PNG 文件大小与图像数据不符、IEND 后仍有字节、尾部高熵块；对图片做重编码/裁剪可去除尾部载荷。
