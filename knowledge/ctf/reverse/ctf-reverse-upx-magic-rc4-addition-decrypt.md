---
id: ctf-reverse-upx-magic-rc4-addition-decrypt
title: 改版 UPX 壳 + 加法收尾 RC4：修补 magic 后同构解密
type: scenario
domain: ctf
path: ctf/reverse
technique: upx-magic-rc4-addition-decrypt
aliases:
- baby_rc4
- 魔改 UPX
- UPX magic 修复
- 55 50 58 21
- RC4 加法变体
- KSA/PRGA
tags:
- ctf
- reverse
- rc4
- upx
- stream-cipher
- ksa
- prga
- unpacking
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:53:45+08:00'
  notes: 已对照原文baby_rc4核对：UPX magic改回55 50 58 21、标准KSA/PRGA、末步加法(c+k)&0xFF、key happynewyear与30字节密文一致；未验证点：PoC未本机执行，原文未给明文结果。
---

## 一句话结论

题目用改版 UPX 壳掩盖 RC4 解密逻辑：UPX 的 4 字节 magic 被改坏，先改回 `55 50 58 21`（`UPX!`）再用 `upx -d` 脱壳；RC4 的 KSA/PRGA 与标准一致，但最后一步把「密文异或密钥流」换成了「密文加密钥流（mod 256）」，解密必须照抄同一个可逆运算，不能套标准 RC4 的异或。

## 原理

- **UPX magic**：标准 UPX 文件头/打包信息中有 `UPX!` 标识（字节 `55 50 58 21`），`upx -l/-d` 依赖它识别与解包。改版壳会把该序列改成别的字节（或同时改节名/头字段）以逃避自动脱壳；把 magic 恢复成 `55 50 58 21` 后，若压缩 stub 本身未改，标准 `upx -d` 就能解压出原始程序。若 stub 也被改，则恢复 magic 后仍会失败，需要按 OEP 手动 dump 或仿真。
- **RC4 KSA（密钥调度）**：初始化 `S[i]=i`（0..255），`j=0`；对 `i=0..255` 执行 `j=(j+S[i]+key[i % keylen]) & 0xFF`，交换 `S[i],S[j]`。结果是一个依赖 key 的 256 字节置换。
- **RC4 PRGA（伪随机生成）**：每字节执行 `i=(i+1)&0xFF`、`j=(j+S[i])&0xFF`、交换 `S[i],S[j]`，输出 `k=S[(S[i]+S[j])&0xFF]`。
- **标准 RC4**：`c = p ^ k`，解密同为 `p = c ^ k`（异或自逆）。
- **本题魔改点**：KSA/PRGA 不变，最后的合并步骤改为模 256 加法。题目的解密脚本是 `p = (c + k) & 0xFF`，对应的加密方向就是 `c = (p - k) & 0xFF`。模 256 加法/减法同样可逆，但方向必须是加密的逆运算；如果把 `+` 当 `^`，密钥流正确也会得到乱码。
- **为什么容易看错**：反编译或伪代码里 RC4 的 S 盒交换、取下标结构很显眼，分析者容易直接套标准 RC4 模板；真正的差异只在循环末尾一个 `+`/`-` 与 `^` 的选择，需要逐行对照。

## 触发条件

- 样本是 UPX 壳（节名 `UPX0`/`UPX1`、入口处解压 stub、`UPX!` 特征），但 `upx -l`/`upx -d` 报「不是 UPX 文件」或直接失败。
- 脱壳后代码中存在 256 字节 S 盒初始化、两次 256 次循环、`%256` 交换与密钥流取字节。
- 循环末尾的合并运算不是异或，而是加法/减法/旋转等可逆操作。
- 密文与 key 均已从二进制或数据段提取。

## 利用步骤

1. 用 `strings`、PE 节表、`upx -l` 判断壳类型；若 `upx -d` 失败，在文件头与打包信息中定位被改写的 4 字节 magic，改回 `55 50 58 21`。
2. 重试 `upx -d sample.exe`；仍失败则按 UPX 手动脱壳流程在 OEP dump，或对 stub 做仿真。
3. 在脱壳后的程序中定位 KSA：`S=0..255`、`j=(j+S[i]+key[i%len])&0xFF`、交换。确认没有额外轮数或 S 盒初始化改动。
4. 定位 PRGA：`i=(i+1)&0xFF`、`j=(j+S[i])&0xFF`、交换、取 `k=S[(S[i]+S[j])&0xFF]`。
5. 逐行确认最后的合并方向：是 `c ^ k`、`c + k`、`c - k` 还是其它可逆运算；解密时使用其逆运算。
6. 用提取到的 key 与密文按同一变体解密，先看字节是否可打印，再按 UTF-8/ASCII 解码；必要时用同一函数把明文加密回去比对密文。

## PoC

```python
key = b"happynewyear"
cipher = bytes([
    0x19, 0x9D, 0xDF, 0x8D, 0xED, 0x42, 0xAB, 0x52, 0x7E, 0x25,
    0xC8, 0xD2, 0x48, 0x56, 0xEA, 0xAB, 0x60, 0x94, 0xCF, 0x7E,
    0x66, 0x4D, 0x1C, 0xE2, 0x62, 0x21, 0xC7, 0xAE, 0xFD, 0x39,
])

# KSA：标准 RC4 密钥调度
S = list(range(256))
j = 0
for i in range(256):
    j = (j + S[i] + key[i % len(key)]) & 0xFF
    S[i], S[j] = S[j], S[i]

# PRGA + 本题的加法收尾：plain = (cipher + keystream) & 0xFF
i = j = 0
plain = bytearray()
for c in cipher:
    i = (i + 1) & 0xFF
    j = (j + S[i]) & 0xFF
    S[i], S[j] = S[j], S[i]
    k = S[(S[i] + S[j]) & 0xFF]
    plain.append((c + k) & 0xFF)

print(plain.decode())
```

```python
# 通用化：按二进制实际方向选择收尾运算
def rc4_combine(cipher, key, op):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for c in cipher:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) & 0xFF]
        out.append((c - k) & 0xFF if op == "sub" else (c + k) & 0xFF)
    return bytes(out)
```

说明：以上为按题目变体重写的结构化 PoC，未在本机执行；题目未展示解密后的明文，需以实际运行结果为准。

## 变体与关联

- **收尾运算变体**：`c ^ k`（标准）、`c + k`/`c - k`（本题）、按 16/32 位字做加法、先旋转再合并；解密时一律取对应逆运算。
- **KSA/PRGA 变体**：轮数改为 128/16、S 盒初值或 `j` 公式微调、交换顺序变化、密钥按块轮转；这些改动也必须逐处同步到解密脚本。
- **壳变体**：UPX magic 被改、节名被改、stub 被改；前者可修补 magic，后者需手动 dump/仿真（参见 UPX 脱壳卡）。
- **关联卡片**：[[ctf-reverse-modified-rc4-rounds-sbox]]（轮数/S 盒初始化改动）、[[ctf-reverse-miniprogram-variant-rc4-reverse-ksa]]（反向 KSA 变体）、[[code-analysis-reverse-unpacking-modified-upx-unicorn-stub-emulation]]（改版 UPX 的仿真脱壳）、[[code-analysis-reverse-unpacking-upx-manual]]（UPX 手动脱壳）。
- **边界**：若壳同时修改了压缩算法或加了反调试，仅修 magic 不足以解包；若 RC4 的 S 盒初始化被改成密钥相关且不可复现，需动态提取运行时 S 盒。

## 检测与防御

- **CTF/验证**：解密结果应为可打印 ASCII；把结果按同一变体加密回去应得到原密文；若 `+`/`-` 方向写反，字节会呈现均匀随机分布。
- **检测信号**：256 字节数组、两次 256 循环、`%256` 交换、`S[(S[i]+S[j])&0xFF]` 取流；循环末尾的合并指令是 `add`/`sub` 而不是 `xor`；PE 中 `UPX!` 被替换或节名异常。
- **防御视角**：RC4 本身已有密钥流偏差，不应在新系统中使用；改轮数、改收尾运算、加 UPX 壳都不构成安全增强。真实产品不应把密钥或核心算法只放在客户端壳内。
- **加固边界**：壳与算法混淆只提高逆向成本；关键逻辑应放服务端，配合签名、完整性校验与密钥轮换。
