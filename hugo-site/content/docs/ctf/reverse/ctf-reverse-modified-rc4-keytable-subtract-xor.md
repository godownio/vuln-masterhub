---
id: ctf-reverse-modified-rc4-keytable-subtract-xor
title: 魔改 RC4 逆运算：20 字节密钥表重复 256、PRGA 后先减 0x71 再异或 keystream
type: scenario
domain: ctf
path: ctf/reverse
technique: modified-rc4-keytable-subtract-xor
tags:
- ctf
- reverse
- rc4
- modified-crypto
- key-table
- xor
- subtraction
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V222
  verified_at: '2026-11-07T06:30:59+08:00'
  notes: 已对照原文 New-RC4 核对：20 字节 key20、重复 256、KSA/PRGA、10 个 int+int16 共 42 字节密文与 P=(C-113)^K 逆变换均与原文 exp 一致；原文明示输出 flag。
url: /docs/ctf/reverse/ctf-reverse-modified-rc4-keytable-subtract-xor/
draft: false
kb_aliases:
- New-RC4
- 魔改 RC4
- 20 字节密钥表
- 减 113 异或
- RC4 变种
- aNbgvzyhebfgcv8
---

## 一句话结论

样本的校验逻辑是一个魔改 RC4：KSA 用 20 字节密钥表按模 20 重复成 256 字节，PRGA 生成 keystream 后不是标准 XOR，而是 `C = (P ^ K) + 0x71`（8 位溢出）；按 `P = (C - 0x71) ^ K` 逆运算，并用 `.rodata` 中 10 个 int + 一个 int16 拼出 42 字节密文，即可还原 flag。

## 原理

- **KSA 使用短密钥表**：程序里 `aNbgvzyhebfgcv8` 对应 20 字节密钥表 `14 18 3D 0C 00 03 32 1F 18 3C 3D 19 2C 42 1B 0F 23 15 0B 1F`；初始化时按 `key256[i] = key20[i % 20]` 重复成 256 字节，再做标准 RC4 KSA：`j = (S[i] + j + key[i]) & 0xFF; swap(S[i], S[j])`。
- **PRGA 标准**：`i=(i+1)&0xFF; j=(j+S[i])&0xFF; swap; K=S[(S[i]+S[j])&0xFF]`。
- **非标准后变换**：加密/校验时对每个明文字节做 `C = (P ^ K) + 0x71`（113），不是标准 RC4 的 `C = P ^ K`；因此解密要反过来 `P = (C - 0x71) & 0xFF ^ K`。
- **密文布局**：`.rodata` 中 `Buf1` 是 10 个 32-bit int（小端），加一个 int16 `10008`（0x2718），共 `10*4+2=42` 字节，与明文长度一致；按小端拆字节后逐字节逆变换。
- **识别要点**：看到 256 字节 S 盒初始化 + 两次 swap + `S[(S[i]+S[j])]` 取流，基本可判定 RC4；再看输出前是否有加减/异或常量，按实际表达式反向即可。
- **根因/价值**：CTF 逆向中常见的“标准算法 + 一处变形”；不要直接套标准 RC4 解密，要以反编译出的实际运算顺序和常量为准。

## 触发条件

- 逆向题样本中存在 RC4 KSA/PRGA 特征：256 字节 S 盒、`j=(j+S[i]+key[i])&0xFF`、`swap`、`S[(S[i]+S[j])]`。
- 密钥不是 16 字节标准 key，而是短表重复/自定义长度。
- 输出前存在 `+/-` 常量或额外 XOR；密文为小端 int 数组或字节数组。
- 可静态提取密文与常量。

## 利用步骤

1. 在反编译代码中定位 KSA：确认 S 盒长度 256、密钥表内容与重复方式。
2. 定位 PRGA：确认 `i/j` 更新与 `S[(S[i]+S[j])]` 取流。
3. 记录输出变换：原文为 `C=(P^K)+0x71`，则解密为 `P=(C-0x71)^K`；注意 8 位溢出。
4. 从 `.rodata` 提取密文常量（10 个 32-bit 小端 int + 1 个 int16 = 42 字节）。
5. 用 Python 复现 KSA/PRGA 并逐字节逆变换，打印 ASCII。
6. 若结果乱码，检查字节序、密钥重复方式、变换顺序（先 XOR 后减 vs 先减后 XOR）。

## PoC

```python
key20 = [
    0x14, 0x18, 0x3D, 0x0C, 0x00, 0x03, 0x32, 0x1F, 0x18, 0x3C,
    0x3D, 0x19, 0x2C, 0x42, 0x1B, 0x0F, 0x23, 0x15, 0x0B, 0x1F
]
key256 = [key20[i % 20] for i in range(256)]

S = list(range(256))
j = 0
for i in range(256):
    j = (S[i] + j + key256[i]) & 0xFF
    S[i], S[j] = S[j], S[i]

def rc4_prga(state, n):
    S = state[:]
    i = j = 0
    out = []
    for _ in range(n):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 0xFF])
    return out

K = rc4_prga(S, 42)

buf1_ints = [
    0xBE7D51AF, 0x7EEEE1C6, 0x4FD3C578, 0xB89BFBA1, 0x25B28FEF,
    0xAAF725CD, 0xED399B71, 0x8C807901, 0xAE63C11C, 0xEFF75BDF
]
cipher = []
for v in buf1_ints:
    cipher += [(v >> (8 * k)) & 0xFF for k in range(4)]
v15 = 10008  # 0x2718
cipher += [v15 & 0xFF, (v15 >> 8) & 0xFF]
assert len(cipher) == 42

plain = bytes(((c - 113) & 0xFF) ^ k for c, k in zip(cipher, K))
print(plain.decode('ascii'))
```

原文输出：`flag{590CF439-E304-4E27-BE45-49CC7B02B3F3}`。

## 变体与关联

- 后变换变体：`C=(P^K)+const`、`C=(P+const)^K`、`C=rol(P^K,n)`；按反编译表达式逆序。
- 密钥变体：20 字节短表重复、Base64 解码后作 key、S 盒初始值被改。
- 密文变体：小端 int 数组、int16 尾部、字节串；注意长度与对齐。
- 关联卡片：[[ctf-reverse-brotli-embedded-js-rc4-xtea-xor]]、[[ctf-reverse-android-embedded-python-sitecustomize-aes-rc4]]、[[ctf-reverse-custom-aes-sbox-shiftrows-c2-traffic-decrypt]]、[[code-analysis-reverse-windows-dridex-rc4-base64-aplib-shellcode-extract]]。
- 边界：若样本在 RC4 前还有一层解密/解压，需要先还原外层；本卡只覆盖单层魔改 RC4。

## 检测与防御

- 这是 CTF/逆向分析场景，不涉及生产系统防御；企业侧关注恶意样本使用 RC4 混淆载荷。
- 检测：定位 256 字节 S 盒初始化与 swap 循环、短密钥表重复、输出前的加减/XOR 常量。
- 分析：以反编译实际表达式为准，逐步复现 KSA/PRGA/后变换；用已知明文（如 flag 前缀）验证字节序与常量。
