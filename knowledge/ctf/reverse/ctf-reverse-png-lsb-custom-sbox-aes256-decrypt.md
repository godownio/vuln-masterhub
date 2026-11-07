---
id: ctf-reverse-png-lsb-custom-sbox-aes256-decrypt
title: PNG 蓝通道 LSB 提取自定义 S-box：复现 AES-256 变体解密 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: png-lsb-custom-sbox-aes256-decrypt
aliases:
- 消失的喵星密使
- hint.png
- MEOW 魔数
- 自定义 S-box AES
- 蓝通道 LSB
- libmobile03.so
tags:
- ctf
- reverse
- android
- png
- lsb
- steganography
- sbox
- aes
- crypto
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:24:36+08:00'
  notes: 已对照原文核对：hint.png 蓝通道 LSB 前 4 字节 MEOW + 256 字节 S-box、点击序列 VVFGDXGFAXXV 按步长 4 重排 VXXVDAFGXGFV、36 字符字母表与 row/col 映射、ctr+0x13 异或得 32 字节 key、base64+XOR 0x66 密文、自定义 S-box AES-256 逆轮解出 whi5ker_7r4ce_ayAP 均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

从 `hint.png` 蓝色通道 LSB 按行优先取位，得到 `MEOW` 魔数 + 256 字节自定义 S-box；用它替换 AES-256 的 SubBytes/InvSubBytes（密钥扩展的 SubWord 也同步替换），再按标准 AES-256 逆轮解密 base64 + XOR 0x66 的密文，即可还原 flag body。

## 原理

- **LSB 提取**：PNG 转 RGBA，按 `y` 行优先、`x` 列遍历，取 `pix[x,y][2] & 1`，高位先填（`1 << (7 - (bit % 8))`）；前 `0x830` 位即 `0x106` 字节。前 4 字节 `MEOW` 是魔数，用于确认不是随机噪声；后 256 字节为 S-box。
- **自定义 AES 变体**：分组 16 字节、AES-256 密钥扩展（Nk=8、Nr=14、60 words）、标准 InvShiftRows/InvMixColumns/AddRoundKey；唯一改动是 S-box 替换。加密端 SubBytes/SubWord 用自定义表，解密端 InvSubBytes 用其逆表。
- **密钥派生**：点击序列 `VVFGDXGFAXXV` 先按步长 4 交错重排：`tmp = ''.join(seq[i] for start in [1,0,2,3] for i in range(start, len(seq), 4))` → `VXXVDAFGXGFV`。然后每 2 字符一组，按 row/col 表映射到 36 字符字母表 `1t3k7lmhy2s6n58wfzoqpe9gcjuxbdairv04` 的下标，查 S-box 后与递增计数器 `ctr = (ctr + 0x13) & 0xff` 异或，得到 32 字节 key。
- **row/col 表**：`row = {'A':0,'D':6,'F':12,'G':18,'V':24,'X':30}`，`col = {'A':0,'D':1,'F':2,'G':3,'V':4,'X':5}`；`alph[row[a] + col[b]]` 的取值范围是 0..35。
- **密文**：base64 `z5hNvYOCx3SmRtyC9LmQdCI8NG6wcQ4l63I8Jkmg6cY=` 解码后每字节 XOR `0x66`，得到 `a9fe2bdbe5e4a112c020bae492dff612445a5208d61768438d145a402fc68fa0`。
- **为什么能解**：S-box 是双射，逆表可构造；AES 的线性层和密钥扩展结构不变，按标准逆流程即可。本题明文 `whi5ker_7r4ce_ayAP`，flag 为 `ISCC{whi5ker_7r4ce_ayAP}`。

## 触发条件

- APK 资源中有 PNG，native 读取图片像素；代码出现 256 字节表、AES 轮常量/密钥扩展。
- 密文为 base64/hex，且有 XOR/异或常量。
- 点击序列/种子可从 Java 层或资源恢复。
- 能提取图片原始像素（不能用有损压缩后的截图）。

## 利用步骤

1. 解包 APK，取 `assets/hint.png` 和 `libmobile03.so`；jadx 确认 `_v(flagBody, path, Bitmap)` 与点击路径来源。
2. 按行优先取蓝通道 LSB，断言前 4 字节为 `MEOW`，取 256 字节 S-box，构造 `invS`。
3. 从 DEX 恢复点击序列、坐标表和 36 字符字母表；按步长 4 重排并派生 32 字节 key。
4. base64 解码密文，逐字节 XOR `0x66`。
5. 用自定义 S-box 做 AES-256 密钥扩展（SubWord 用 S-box），按标准逆轮解密每个 16 字节块。
6. 去 NUL/填充，拼 `ISCC{...}`；用重新加密或 native 校验复核。

## PoC

```python
import base64
from PIL import Image

# 1) 蓝通道 LSB -> MEOW + 256 字节 S-box
img = Image.open("hint.png").convert("RGBA")
w, h = img.size
pix = img.load()
buf = bytearray(0x106)
bit = 0
for y in range(h):
    for x in range(w):
        if bit > 0x82f:
            break
        if pix[x, y][2] & 1:
            buf[bit // 8] |= 1 << (7 - (bit % 8))
        bit += 1
    if bit > 0x82f:
        break
assert buf[:4] == b"MEOW"
S = list(buf[4:4 + 256])
invS = [0] * 256
for i, v in enumerate(S):
    invS[v] = i

# 2) 从点击序列派生 32 字节 key
seq = "VVFGDXGFAXXV"
alph = "1t3k7lmhy2s6n58wfzoqpe9gcjuxbdairv04"
row = {"A": 0, "D": 6, "F": 12, "G": 18, "V": 24, "X": 30}
col = {"A": 0, "D": 1, "F": 2, "G": 3, "V": 4, "X": 5}
tmp = "".join(seq[i] for start in [1, 0, 2, 3] for i in range(start, len(seq), 4))
key = []
ctr = 0
for rcx in range(0, 64, 2):
    a = tmp[rcx % len(tmp)]
    b = tmp[(rcx + 1) % len(tmp)]
    key.append(S[ord(alph[row[a] + col[b]])] ^ ctr)
    ctr = (ctr + 0x13) & 0xff

# 3) AES-256 密钥扩展（SubWord 用自定义 S）
rcon = [1, 2, 4, 8, 16, 32, 64, 128, 0x1b, 0x36]
def subword(w): return [S[x] for x in w]
def rotword(w): return w[1:] + w[:1]
W = [key[i:i + 4] for i in range(0, 32, 4)]
for i in range(8, 60):
    temp = W[i - 1].copy()
    if i % 8 == 0:
        temp = subword(rotword(temp)); temp[0] ^= rcon[i // 8 - 1]
    elif i % 8 == 4:
        temp = subword(temp)
    W.append([W[i - 8][j] ^ temp[j] for j in range(4)])
round_keys = [[x for word in W[4 * r:4 * r + 4] for x in word] for r in range(15)]

# 4) 标准 AES 逆轮（InvSubBytes 用 invS）
def xtime(x):
    x2 = (x << 1) & 0xff
    return x2 ^ 0x1b if x & 0x80 else x2
def mul(a, b):
    res = 0
    while b:
        if b & 1: res ^= a
        a = xtime(a); b >>= 1
    return res
def add_rk(s, r): return [x ^ y for x, y in zip(s, round_keys[r])]
def inv_sub(s): return [invS[x] for x in s]
def inv_shift(s):
    o = s.copy()
    o[1], o[5], o[9], o[13] = s[13], s[1], s[5], s[9]
    o[2], o[6], o[10], o[14] = s[10], s[14], s[2], s[6]
    o[3], o[7], o[11], o[15] = s[7], s[11], s[15], s[3]
    return o
def inv_mix(s):
    o = s.copy()
    for c in range(4):
        i = 4 * c; a = s[i:i + 4]
        o[i]     = mul(a[0],14) ^ mul(a[1],11) ^ mul(a[2],13) ^ mul(a[3],9)
        o[i + 1] = mul(a[0],9)  ^ mul(a[1],14) ^ mul(a[2],11) ^ mul(a[3],13)
        o[i + 2] = mul(a[0],13) ^ mul(a[1],9)  ^ mul(a[2],14) ^ mul(a[3],11)
        o[i + 3] = mul(a[0],11) ^ mul(a[1],13) ^ mul(a[2],9)  ^ mul(a[3],14)
    return o
def dec_block(block):
    s = add_rk(list(block), 14)
    s = inv_sub(inv_shift(s))
    for r in range(13, 0, -1):
        s = inv_mix(add_rk(s, r))
        s = inv_sub(inv_shift(s))
    return bytes(add_rk(s, 0))

enc = base64.b64decode("z5hNvYOCx3SmRtyC9LmQdCI8NG6wcQ4l63I8Jkmg6cY=")
ct = bytes(x ^ 0x66 for x in enc)
pt = b"".join(dec_block(ct[i:i + 16]) for i in range(0, len(ct), 16))
print(pt.rstrip(b"\x00").decode())  # whi5ker_7r4ce_ayAP
```

## 变体与关联

- **S-box 来源变体**：图片 LSB、音频采样、资源文件、native 常量；提取前先找魔数/长度，确认 256 字节且为双射。
- **AES 变体**：可改 S-box、轮数、MixColumns 矩阵、密钥扩展；先识别哪些层被改，只对改动层求逆。
- **密钥派生变体**：点击序列可换坐标表/重排顺序/计数器步长；先正向验证派生出的 key 再解密。
- **关联卡片**：[[ctf-reverse-adfgvx-click-matrix-md5-constraint-brute-force]]（同题路径还原）、[[mobile-harmony-hap-arkts-native-sbox-affine-unicorn]]（S-box + 线性层）、[[ctf-reverse-sm4-constant-recognition-little-endian-decrypt]]（分组密码常量识别）。
- **边界**：若 S-box 不是双射或 AES 轮数/字序不同，需按实际实现调整；PoC 未在本库复跑。

## 检测与防御

- **防御视角**：不要用自定义 S-box 代替标准密码学；密钥不要从可预测的点击序列派生；图片资源不要放密钥材料。
- **检测信号**：native 中出现 256 字节表 + AES 轮常量；PNG 蓝通道 LSB 异常；base64 密文后跟 XOR 常量。
- **CTF 逆向**：先验证 `MEOW` 魔数，再构造逆 S-box；密钥派生注意重排顺序和计数器。
