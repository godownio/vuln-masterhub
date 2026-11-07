---
id: ctf-reverse-rc4-inverted-sbox-add-xor-oracle-keystream
title: RC4 变种 S[i]=~i + (P⊕X)+A：用全 0/全 255 加密 oracle 反推 keystream 解密 PNG
type: scenario
domain: ctf
path: ctf/reverse
technique: rc4-inverted-sbox-add-xor-oracle
tags:
- ctf
- reverse
- rc4
- variant
- keystream
- oracle
- png
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:37:20+08:00'
  notes: 已对照原文与图42-46核对：S[i]=~i、key rc4!2025、C=(P^X)+A、全0/全255 oracle解A/X、200x200 RGBA与flag一致
url: /docs/ctf/reverse/ctf-reverse-rc4-inverted-sbox-add-xor-oracle-keystream/
draft: false
kb_aliases:
- Get_My_Emoji
- RC4 变种
- S[i]=~i
- 255..0 倒序 S 盒
- (P XOR X)+A
- 加密 oracle 恢复 keystream
---

## 一句话结论

PNG 加密器 `emoji_encoder` 使用 RC4 的变种：KSA 初始化 `S[i] = ~i`（即 255..0 倒序）而不是 `S[i]=i`，PRGA 标准，但每个明文字节消耗两个 keystream 字节并按 `C = (P XOR X) + A mod 256` 加密；由于二进制本身可作为加密 oracle，分别加密全 0 与全 255 的 RGBA 图，得到 `E0`、`EFF` 后可解出 `A = ((E0+EFF+1) mod 256)/2`、`X = (E0-A) mod 256`，再对密文做 `P = (C-A) XOR X` 恢复原图并读出 flag。

## 原理

- **RC4 变种**：标准 RC4 KSA 初始化 `S[i]=i`；本题 `S[i] = ~i`（255,254,...,0），其余 KSA（`j = j + S[i] + key[i%len]`、swap）与 PRGA（`i++`、`j+=S[i]`、swap、输出 `S[(S[i]+S[j])&0xff]`）保持标准。密钥写死 `"rc4!2025"`（8 字节）。
- **双字节消耗**：每加密一个明文字节，PRGA 连续取两个字节 `X`（第一份流）与 `A`（第二份流），计算 `C = (P XOR X) + A mod 256`。
- **oracle 反推**：把同一张 200×200 RGBA 图分别填成全 0 与全 255，运行二进制得到 `E0` 与 `EFF`：
  - `E0 = (0 XOR X) + A = X + A`
  - `EFF = (255 XOR X) + A = (255-X) + A`
  - 两式相加 `E0+EFF = 255 + 2A`，所以 `A = ((E0+EFF+1) mod 256) / 2`（注意模 256 的除法需按奇偶处理；原文用 `(E0+EFF+1)%256 // 2`）。
  - 再由 `E0 = X + A` 得 `X = (E0 - A) mod 256`。
- **解密**：`P = ((C - A) mod 256) XOR X`；对整张图逐字节应用即可恢复 RGBA 像素，保存为 PNG 后用肉眼看/OCR 读 flag。
- **为什么 oracle 可行**：加密程序固定输入输出文件名（`my_emoji.png` → `enc_emoji.png`），可以对任意明文运行；全 0/全 255 是两个极端明文，足以解出每个位置的 `X`、`A`，不需要知道 RC4 内部状态或密钥。
- **为什么 S[i]=~i 不影响**：oracle 方法只依赖“同一密钥流对同一位置重复使用”和加密公式，不依赖 KSA/PRGA 的具体实现；即使 S 盒初始化被改，只要密钥固定、流可复现，就能用两个已知明文解出两字节流。
- **边界**：如果每次加密使用随机 IV/密钥，oracle 不成立；如果加密公式是 `C=(P+A) XOR X` 等不同组合，需要重新推导（可用第三个常量明文验证）。

## 触发条件

- 有一个可反复运行的加密程序/接口，密钥固定，输入输出可控制，输出可读取。
- 加密公式已知或可推断为 `(P XOR X)+A`（或类似双字节流组合）。
- 能构造全 0/全 255 的输入（或任意两个已知明文），并拿到对应密文。
- 目标密文与 oracle 使用同一密钥/同一流位置（无随机 IV、无 per-run 随机化）。

## 利用步骤

1. **确认算法**：逆向发现 RC4 KSA 的 `S[i]=~i`、密钥 `rc4!2025`、PRGA 标准、加密 `C=(P^X)+A`。
2. **准备 oracle 输入**：生成 200×200 RGBA 全 0 图与全 255 图，分别命名 `my_emoji.png` 并运行程序，得到 `enc_emoji.png`。
3. **提取 E0/EFF**：读取两张输出图的 RGBA 数组。
4. **解 A/X**：按上述公式逐像素计算 `add`、`xor` 数组。
5. **解密目标**：读取题目给的 `enc_emoji.png`，`P = ((C - add) % 256) ^ xor`，保存为 PNG。
6. **读 flag**：打开恢复图，识别文字/二维码；原文得到 `flag{c0ngr47ul473_y0u_c4n_u53_my_3m0ji_n0w}`。

## PoC

```python
import subprocess, tempfile
from pathlib import Path
import numpy as np
from PIL import Image

def encode_constant(binary, value, h, w):
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        plain = np.full((h, w, 4), value, dtype=np.uint8)
        Image.fromarray(plain, "RGBA").save(td / "my_emoji.png")
        subprocess.run([str(binary)], cwd=str(td), check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        enc = Image.open(td / "enc_emoji.png").convert("RGBA")
        return np.array(enc, dtype=np.uint8)

cipher = np.array(Image.open("enc_emoji.png").convert("RGBA"), dtype=np.uint8)
h, w = cipher.shape[:2]
e0 = encode_constant("emoji_encoder", 0, h, w)
eF = encode_constant("emoji_encoder", 255, h, w)

add = ((e0.astype(np.uint16) + eF.astype(np.uint16) + 1) % 256 // 2).astype(np.uint8)
xor = ((e0.astype(np.int16) - add.astype(np.int16)) % 256).astype(np.uint8)
plain = ((cipher.astype(np.int16) - add.astype(np.int16)) % 256).astype(np.uint8)
plain = np.bitwise_xor(plain, xor).astype(np.uint8)
Image.fromarray(plain, "RGBA").save("1.png")
```

原文输出：`flag{c0ngr47ul473_y0u_c4n_u53_my_3m0ji_n0w}`。

## 变体与关联

- 变体：`C=(P+A) XOR X`、`C=(P XOR X)+A`、`C=(P+A) XOR (X+1)` 等组合；每字节消耗 1/2/4 个流字节；KSA 改 S 盒/密钥长度；加密前有 PNG 行过滤/字节序转换。
- 关联：[[ctf-reverse-go-pic-rc4-short-key-png-header-bruteforce]]（标准/轻改 RC4 + 短密钥 + PNG 头已知明文）、[[crypto-prng-time-seeded-rand-rc4-auth-forge]]（RC4 密钥流复用/可预测）、[[ctf-reverse-android-apk-environment-state-derived-keystream]]（环境派生 keystream 的逆向）。
- 同题：`Get_My_Emoji` 的 200×200 RGBA、`row_bytes=800`、密钥 `rc4!2025`。

## 检测与防御

- **不要用固定密钥流加密多份数据**：同一 keystream 复用会让已知明文攻击/两明文异或恢复成立；应使用随机 nonce/IV 的 AEAD。
- **不要依赖自定义 RC4 变种**：RC4 本身已不安全，改 S 盒初始化不改变流复用的根本问题。
- **CTF 之外**：加密工具应使用标准库（AES-GCM/ChaCha20-Poly1305），每次加密随机 nonce，密钥不写死。
- **检测**：对二进制中出现 RC4 KSA/PRGA 常量、固定 key、`S[i]=~i` 等特征标记为弱加密；对同一密钥加密的多份文件做流复用检测。
