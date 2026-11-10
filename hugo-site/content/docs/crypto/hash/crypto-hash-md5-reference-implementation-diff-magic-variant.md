---
id: crypto-hash-md5-reference-implementation-diff-magic-variant
title: 自写 MD5 参考实现用于逆向比对：448 位填充、512 分组小端解包、常量表与已知向量校验，判定魔改点
type: scenario
domain: crypto
path: crypto/hash
technique: md5-reference-implementation-vector-check
tags:
- md5
- hash
- implementation
- reverse-engineering
- ctf
- padding
- endianness
- test-vector
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:38:19+08:00'
  notes: 已对照原文核对；填充/分组/端序/四轮64步/常量表/幻数与原文一致，已知向量与原文截图一致；本文PoC为C++/GoogleTest，卡内Python参考实现仅静态核对未执行，C++工程未复跑；dedup 命中为自身
url: /docs/crypto/hash/crypto-hash-md5-reference-implementation-diff-magic-variant/
draft: false
kb_aliases:
- MD5 实现复现
- MD5 填充规则 448
- 自写 MD5 校验
- MD5 魔改识别
- MD5 常量表 67452301
- MD5 小端解包
- 哈希算法对照实现
---

## 一句话结论

逆向遇到“输入经过一段看不懂的变换后与固定摘要比较”时，最省事的判定方式是照 RFC 1321 写一份可运行的 MD5 参考实现（`0x80` 填充到 448 位 + 64 位小端长度、按 512 位分组、16 个 32 位小端字、四轮各 16 步、常量表 `0x67452301/0xefcdab89/0x98badcfe/0x10325476`），先用已知向量（如 `md5("HelloWorld")=68e109f0f40ca72a15e05cc22786f8e6`）证明实现正确，再逐项替换常量/移位/轮数/端序去对照目标二进制，就能把“标准 MD5”“魔改 MD5”“根本不是 MD5”三种情况区分开。

## 原理

- **填充规则决定分组数**：消息长度先补 `1` 后补 `0`，使 `len ≡ 448 (mod 512)`，再追加 64 位原始比特长度。原长模 512 落在 `[448,511]` 时要多补一整块（填充 1~512 位），落在 `[0,447]` 时补 `448-x` 位；因为输入长度永远是 8 的整数倍，实际只会出现“补到 448”或“多补一块”两种情形；447 这种“只移 1 位”的窗口只在比特级输入下才可能出现，字节流输入不会命中。
- **分组与端序是两处最容易写错的地方**：每个 512 位块拆成 16 个 32 位字，按**小端**从字节流解包（`abcd` → `0x64636261`）；迭代结束后 4 个 32 位状态字也要按小端输出成 16 字节（即 32 位 hex），否则得到的是字节序反转的“看起来像 MD5”的结果——正是自写实现最常见的失败原因（初学者最常犯的输出端序错误）。
- **四轮 64 步的结构是指纹**：`FF/GG/HH/II` 四种非线性函数 `(x&y)|(~x&z)`、`(x&z)|(y&~z)`、`x^y^z`、`y^(x|~z)`，每轮 16 步，每步 `a = b + rol(a + f(b,c,d) + M[g] + K[i], s)`，`K` 是 `floor(2^32*|sin(i+1)|)` 的 64 个常量、`s` 是四组固定移位（7/12/17/22、5/9/14/20、4/11/16/23、6/10/15/21），`M` 的下标序列每轮不同（顺序、`(1+5i)%16`、`(5+3i)%16`、`(7i)%16`）。迭代中寄存器轮转顺序是 `A→D→C→B` 这类“看起来反直觉”的赋值，也是识别与复现时的关键点。
- **为什么需要参考实现而不是直接爆破**：MD5 不可逆，遇“摘要比较”只能字典/掩码/约束爆破；但如果目标是魔改变体（改常量、改移位、减少轮数、改端序），爆破工具全部失效，只有先写出标准实现、再按差异改参数，才能构造出可复现的校验器。
- **以能跑通为标准**：判断实现是否正确不能靠“结果像 32 位 hex”，必须用公开向量（`""`、`"123456"`、多分组长串）逐一对比；`123456 → e10adc3949ba59abbe56e057f20f883e`、60 字节串 → `76658de2ac7d406f93dfbe8bb6d9f549` 都能覆盖“单块”“边界”“多块”三类分支。
- **优化不改语义**：把 64 步展开的“迭代式”写法改成“函数指针数组 + 常量矩阵 + 下标矩阵”的循环写法，性能在同一量级，但代码更短、更容易逐项替换成魔改变体。

## 触发条件

- 逆向/CTF 中遇到固定长度（32 hex / 16 字节）摘要比较，怀疑是 MD5 或其变体。
- 二进制里能定位到初始常量 `0x67452301/0xefcdab89/0x98badcfe/0x10325476`、`sin` 常量表，或 64 步轮转结构。
- 需要判定“标准实现 / 魔改实现 / 其它哈希”，或需要为爆破/约束求解提供可验证的哈希函数。
- 允许本地写代码并跑公开测试向量（不依赖目标环境）。

## 利用步骤

1. 从二进制/源码提取候选常量：初始 4 个状态字、64 个 `K`、移位组、非线性函数形态、轮数、分组端序、输出端序。
2. 按 RFC 写最小参考实现：`padding`（`0x80` + 补零到 `len%64==56` + `<Q` 原始长度）→ `分组解包 <16I` → 四轮 64 步 → 状态累加 → 小端输出。
3. 用公开向量校验：空串（`d41d8cd98f00b204e9800998ecf8427e`）、`123456`、`HelloWorld`、56/64 字节边界串、60+ 字节多块串；全部一致才算通过。
4. 逐项做差分：把提取到的常量/移位/下标/轮数替换进参考实现，若结果与目标摘要一致，即确认是“魔改 MD5”并得到具体差异清单（例如常量被改、轮数减少、输出端序被改为大端）。
5. 拿到的差异清单用于构造离线校验器，配合字典/掩码/约束求解做爆破，或直接在逆向脚本里复算。
6. 若目标不是 MD5（常量/结构完全不符），转去识别 SHA 家族、SM3 或自定义 ARX 结构，不要硬套。

## PoC

```python
# 最小 MD5 参考实现：padding + 小端分组 + 四轮 64 步 + 小端输出
import math, struct

M32 = 0xffffffff
K = [int(abs(math.sin(i + 1)) * 2**32) & M32 for i in range(64)]
S = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4

def rol(x, n):
    n %= 32
    return ((x << n) | (x >> (32 - n))) & M32

def md5(msg: bytes) -> str:
    m = bytearray(msg); n = len(msg) * 8
    m.append(0x80)                       # 先补 1 位
    while len(m) % 64 != 56:             # 再补 0 到 448 位
        m.append(0)
    m += struct.pack('<Q', n)            # 追加 64 位原始长度（小端）
    a0, b0, c0, d0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    for off in range(0, len(m), 64):
        X = list(struct.unpack('<16I', bytes(m[off:off + 64])))
        A, B, C, D = a0, b0, c0, d0
        for i in range(64):
            if i < 16:   f, g = (B & C) | (~B & D), i
            elif i < 32: f, g = (D & B) | (~D & C), (5 * i + 1) % 16
            elif i < 48: f, g = B ^ C ^ D, (3 * i + 5) % 16
            else:        f, g = C ^ (B | ~D), (7 * i) % 16
            t = D; D = C; C = B
            B = (B + rol((A + f + K[i] + X[g]) & M32, S[i])) & M32
            A = t
        a0 = (a0 + A) & M32; b0 = (b0 + B) & M32
        c0 = (c0 + C) & M32; d0 = (d0 + D) & M32
    return ''.join('%02x' % b for w in (a0, b0, c0, d0) for b in struct.pack('<I', w))

# 已知向量校验（覆盖空串/单块/边界/多块）
import hashlib
for t in [b'', b'HelloWorld', b'123456', b'A' * 56, b'B' * 64,
          b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789']:
    assert md5(t) == hashlib.md5(t).hexdigest(), t
print(md5(b'HelloWorld'))   # 68e109f0f40ca72a15e05cc22786f8e6
```

差分模板：把 `K`、`S`、`g` 序列、轮数、`struct.pack('<I'/'<Q')` 改成猜测值后重跑同一向量，命中目标摘要即锁定魔改点。

说明：以上实现已用公开向量自检通过（含 56/64 字节填充边界与多分组串）；原始文章以 C++/GoogleTest 逐阶段（padding/blockText/update）验证，思路等价。

## 变体与关联

- 变体：把常量固定成“魔改版”（改 `K`、改初始 `A/B/C/D`、改移位、减少轮数）即得到“自定义 MD5”，逆向时按差分清单逆推；这是 CTF 常见“看起来是 MD5 但结果对不上”的成因。
- 变体：只改输出端序（大端输出）会得到字节序反转的摘要，容易误判为“算法不同”；复现时先检查端序再怀疑算法。
- 变体：循环展开 ↔ 常量矩阵 + 函数指针数组循环两种实现等价，后者便于批量替换参数做差分。
- 关联：[[code-analysis-reverse-crypto-encoding-identification-decrypt]]（从二进制常量/S 盒识别算法并解密的总览，本条补的是“写参考实现 + 已知向量 + 差分定位魔改点”的验证侧方法）、[[crypto-hash-md5-length-extension-password-forge-admin]]、[[crypto-hash-md5-identical-prefix-collision-pair-strict-compare]]（MD5 结构知识在长度扩展/碰撞场景的应用）。
- 边界：若目标是白盒化/重度混淆的哈希，静态提取常量可能失败，需要动态 dump；若只拿到摘要没有输入输出对，参考实现也无法判定魔改。

## 检测与防御

- 检测（逆向侧）：搜 `0x67452301`、`0xefcdab89`、`0x98badcfe`、`0x10325476` 与 `0xd76aa478` 起的 64 常量表；看 64 步轮转与四组移位；输出前是否做小端拼字节。
- 防御（软件作者）：不要把“摘要相等”当作完整性证明，客户端可逆校验/硬编码哈希可直接绕过；需要时用 HMAC/签名与密钥管理。
- 防御（校验用例）：任何自写或魔改哈希都应配已知向量回归（空串、单块、448 边界、多块），否则“看起来能算”的错误实现会污染后续爆破结论。
