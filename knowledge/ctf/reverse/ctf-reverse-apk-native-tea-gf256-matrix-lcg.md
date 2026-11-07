---
id: ctf-reverse-apk-native-tea-gf256-matrix-lcg
title: APK native 三段校验逆解：TEA 16 轮 + GF(2^8) 矩阵求逆 + LCG 异或流
type: scenario
domain: ctf
path: ctf/reverse
technique: apk-native-tea-gf256-matrix-lcg
aliases:
- APK native 三段
- TEA 逆运算
- GF(2^8) 矩阵求逆
- LCG 异或流
- cipher1/2/3.bin
- puzzle.bin
- 密码验证
tags:
- ctf
- reverse
- apk
- android
- tea
- gf256
- matrix
- lcg
- native
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:21:32+08:00'
  notes: 已对照原文核对：Java 层只校验 ISCC{} 长度/前后缀；native 三组 16 字节静态表 decode((b-0x13)^0x5A)、x/y/z 派生、16 轮 TEA delta 0x9E3779B9、GF(2^8) 0x1B 矩阵求逆、LCG 0x5851F42D4C957F2D/0x14057B7EF767814F 取 >>24、puzzle.bin 4 行校验与字符映射、最终 ISCC{fPmuXTY)...} 均与卡片/exp 一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

APK 的 Java 层只检查 `ISCC{...}` 的长度与前后缀，native 把 30 字节主体拆成 8+12+10 三段，分别由 16 轮 TEA、GF(2^8) 上的 4×4 矩阵变换和 LCG 异或流约束；密钥、矩阵与种子由 native 内置的三组 16 字节静态表按统一规则解码派生，按当前 APK 的 `assets/cipher*.bin` 逆解并通过 `puzzle.bin` 一致性校验即可恢复 flag。

## 原理

- **三段独立可逆**：前 8 字节走 TEA 逆运算后再异或 8 字节掩码；中间 12 字节是 GF(2^8) 矩阵乘法的逆变换（3 行 4 列，按 4 字节一行处理）；最后 10 字节是 64 位 LCG 伪随机流异或。
- **静态表解码**：native 中三组 16 字节表先做 `((byte - 0x13) & 0xFF) ^ 0x5A`，再由它们生成 `x`（TEA 密钥来源）、`y`（矩阵）、`z`（掩码/种子）：`x = t1 ^ t3` 后循环左移 3 字节，`y` 由 `t2` 与 `x` 的 GF(2^8) 矩阵乘再重排行得到，`z` 由 AES S-box 查表 + 前缀异或链得到。
- **TEA**：16 轮、delta `0x9E3779B9`、大端 32 位字；解密从 `total = delta * 16` 开始，反向更新 `v1`/`v0`。
- **GF(2^8)**：乘法用 AES 的 `0x1B` 约简多项式；矩阵求逆用高斯-约当消元，每步乘以乘法逆元。
- **LCG**：`state = state * 0x5851F42D4C957F2D + 0x14057B7EF767814F`（64 位），每字节取 `(state >> 24) & 0xFF`；种子是 `z[:8]` 大端。
- **一致性约束**：`puzzle.bin` 前 16 字节是 4×4 矩阵、后 4 字节是校验值；另有前 8 字节整体异或映射到字符集、前 20 字节 xor/sum 映射到第 10/11 字节，确保三段来自同一合法输入。

## 触发条件

- APK 含 `libnativecrypto.so`（或同类 native 库）与 `assets/cipher1.bin`、`cipher2.bin`、`cipher3.bin`、`puzzle.bin`。
- Java/Kotlin 层只做格式校验，真实逻辑在 `NativeBridge.verifyFlag`。
- native 中存在三组 16 字节静态表与固定解码规则。

## 利用步骤

1. 解压 APK，读 `assets/cipher*.bin` 与 `puzzle.bin`；用 jadx/ghidra 定位 `NativeBridge.verifyFlag` 与 native 静态表。
2. 按 `decode_static_table` 解码三组表，构造 `x`、`y`、`z`。
3. `tea_decrypt_block(cipher1, x)` 后与 `z[1:9]` 异或，得第 1 段 8 字节。
4. 对 `y` 求 GF(2^8) 逆矩阵，按 4 字节一行作用到 `cipher2`，得第 2 段 12 字节。
5. 以 `z[:8]` 大端为种子跑 LCG 流，与 `cipher3` 异或，得第 3 段 10 字节。
6. 用 `puzzle.bin` 的 4 行有限域校验、第 2 段首字节字符映射、第 3 段末两字节 xor/sum 映射做一致性校验；全部通过后拼 `ISCC{seg1+seg2+seg3}`。
7. 再正向用 `y` 乘 `seg2` 应等于 `cipher2`，作为逆变换正确性的回验。

## PoC

```python
def gf_mul(a, b):
    out = 0
    while b:
        if b & 1: out ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return out

def tea_decrypt_block(block, key):
    v0 = int.from_bytes(block[:4], "big"); v1 = int.from_bytes(block[4:], "big")
    w = [int.from_bytes(key[i:i+4], "big") for i in range(0, 16, 4)]
    delta = 0x9E3779B9; total = (delta * 16) & 0xFFFFFFFF
    for _ in range(16):
        v1 = (v1 - (((v0 << 4) + w[2]) ^ (v0 + total) ^ ((v0 >> 5) + w[3]))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + w[0]) ^ (v1 + total) ^ ((v1 >> 5) + w[1]))) & 0xFFFFFFFF
        total = (total - delta) & 0xFFFFFFFF
    return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")

def lcg_stream(seed, length):
    state, out = seed, bytearray()
    for _ in range(length):
        state = (state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & 0xFFFFFFFFFFFFFFFF
        out.append((state >> 24) & 0xFF)
    return bytes(out)
```

## 变体与关联

- **算法变体**：TEA 可能换成 XTEA/XXTEA，轮数可能不是 16；GF(2^8) 多项式可能不是 `0x1B`；LCG 参数/取字节位置可能变化。
- **布局变体**：三段长度可能不同；静态表可能被拆成多组或做二次异或；`puzzle.bin` 约束可能换成哈希/CRC。
- **关联卡片**：[[ctf-reverse-apk-chacha20-counter-one-native]]（APK native 计数器流）、[[ctf-reverse-apk-knapsack-chacha20-vault]]（APK 背包+流密码）、[[ctf-reverse-sm4-constant-recognition-little-endian-decrypt]]（常量识别）。
- **边界**：若 native 表被强混淆或运行时解密，需要先 dump 内存；若 Java 层也参与校验，需同时满足两侧约束。

## 检测与防御

- **CTF 验证**：先确认静态表解码后 TEA 解密结果能通过 puzzle 校验，再正向回验矩阵乘法；最后检查 flag 字符是否都在可打印范围。
- **防御**：不要把密钥、矩阵、种子与密文全部放在客户端；关键校验放服务端；native 代码混淆并做完整性校验；避免使用固定静态表。
- **检测信号**：APK assets 中出现多个固定长度 `.bin`；native 中存在 S-box、TEA delta、LCG 常数等特征常量。
