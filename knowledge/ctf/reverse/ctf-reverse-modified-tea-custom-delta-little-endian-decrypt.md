---
id: ctf-reverse-modified-tea-custom-delta-little-endian-decrypt
title: 魔改 TEA 逆向：自定义 delta 0x897354D2 + 密钥 [2,0,2,2] 的 32 轮小端解密
type: scenario
domain: ctf
path: ctf/reverse
technique: modified-tea-custom-delta-little-endian-decrypt
aliases:
- cookie
- 上海市大学生网络安全大赛
- 魔改 TEA
- 自定义 delta
- TEA 解密
- 小端分组解密
tags:
- ctf
- reverse
- tea
- block-cipher
- custom-delta
- little-endian
- decryption
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V243
  verified_at: '2026-11-07T13:40:06+08:00'
  notes: 已对照原文与14张图核对：delta=0x897354D2、key=[2,0,2,2]、32 轮、标准 TEA 更新顺序（先 v0 后 v1；解密先逆 v1 再逆 v0）、sum 从 delta*32 递减、小端 <II 拼块，与原文 exp 一致；已实际运行 PoC 复现 b3d06a66f8aa86e3e6390f615e389e55，并验证非标准 v1-first 加密无法匹配 v7，已修正卡内原“先 v1 后 v0”误述。dup-scan 与 GetTickCount TEA、XXTEA 等卡为 related，非同一链。未验证点：未运行原始二进制；无 sources/版本。
---

## 一句话结论

`JUMPOUT_` 指向的函数是一个 64 位分组、32 轮的 TEA 变体：`delta = 0x897354D2`、密钥 `[2,0,2,2]`，每轮按标准 TEA 顺序先更新 `v0` 再更新 `v1`；解密时 `sum` 从 `delta*32` 开始递减，把 8 个 32 位密文字按 4 个块套用逆轮公式，再按小端拼回字节，即可得到 `b3d06a66f8aa86e3e6390f615e389e55`。

## 原理

- **TEA 骨架**：输入按 64 位分组（两个 32 位字 `v0,v1`），密钥 4 个 32 位字 `k0..k3`；每轮 `sum += delta`，`v0 += ((v1<<4)+k0) ^ (v1+sum) ^ ((v1>>5)+k1)`，`v1 += ((v0<<4)+k2) ^ (v0+sum) ^ ((v0>>5)+k3)`。识别特征是 `delta` 常量、`sum` 累加、移位/异或/加法混合、固定 4 字密钥。
- **本题的魔改点**：`delta` 不是标准 `0x9E3779B9` 而是 `0x897354D2`；密钥硬编码为 `[2,0,2,2]`；轮数 32（`0x1F + 1`）；每轮更新顺序与标准 TEA 一致（先 `v0` 后 `v1`），因此逆运算先逆 `v1` 再逆 `v0`（原文 exp 与卡内 PoC 均为此顺序）。
- **小端装字**：加密前把 8 字节明文按小端解释为两个 32 位字，解密后也要用 `<II` 打包回 8 字节，否则字节序会错。
- **为什么可以逆**：每轮的加法、异或、移位都是可逆操作；只要从最后一轮开始，用当前的 `sum` 先逆 `v1` 再逆 `v0`，然后 `sum -= delta`，循环 32 次即可回到初始 `v0,v1`。
- **密文来源**：main 中 `v7[8]` 存放目标密文（负数按 32 位补码解释），`v6[4]={2,0,2,2}` 是密钥；循环比较加密结果与 `v7`，因此只需解密 `v7`。

## 触发条件

- 二进制中存在固定 `delta` 常量、32 轮循环、4 个 32 位密钥字和 `sum` 累加/递减，但常量/轮数与标准 TEA 不同。
- 密文与密钥硬编码在 `.data/.rdata` 或栈上，程序用加密结果做比较。
- 可静态反编译，能确定块大小、端序、轮数与每轮更新顺序。

## 利用步骤

1. 在 IDA 中定位比较逻辑，记录密文数组、密钥数组、`delta`、轮数与分组方式（本例 4 个 64 位块）。
2. 按加密顺序写出单轮公式；确认每轮更新顺序（本例为标准 TEA 的“先 v0 后 v1”）。
3. 对每个 64 位块，初始化 `sum = delta * 32`；循环 32 次：先用当前 `sum` 逆 `v1`，再用同一 `sum` 逆 `v0`，最后 `sum -= delta`。
4. 用 `struct.pack('<II', v0, v1)` 拼回 8 字节，按块顺序拼接。
5. 验证输出是否为可打印 flag/十六进制串；若乱码，检查 delta、轮数、密钥字序、端序与更新顺序。

## PoC

```python
import struct

v7 = [
    1452940357, -282301936 & 0xFFFFFFFF, -79426602 & 0xFFFFFFFF,
    1469576221, 1379922627, 1211333849, 907455533, 112603437
]
key = [2, 0, 2, 2]
delta = 0x897354D2
k0, k1, k2, k3 = key
out = b""

for i in range(4):
    v0, v1 = v7[2 * i], v7[2 * i + 1]
    s = (delta * 32) & 0xFFFFFFFF
    for _ in range(32):
        t1 = (((v0 << 4) & 0xFFFFFFFF) + k2) & 0xFFFFFFFF
        t2 = (v0 + s) & 0xFFFFFFFF
        t3 = (((v0 >> 5) & 0xFFFFFFFF) + k3) & 0xFFFFFFFF
        v1 = (v1 - ((t1 ^ t2) ^ (t3 ^ s))) & 0xFFFFFFFF

        t1 = (((v1 << 4) & 0xFFFFFFFF) + k0) & 0xFFFFFFFF
        t2 = (v1 + s) & 0xFFFFFFFF
        t3 = (((v1 >> 5) & 0xFFFFFFFF) + k1) & 0xFFFFFFFF
        v0 = (v0 - ((t1 ^ t2) ^ (t3 ^ s))) & 0xFFFFFFFF

        s = (s - delta) & 0xFFFFFFFF
    out += struct.pack('<II', v0, v1)

print(out.decode())   # b3d06a66f8aa86e3e6390f615e389e55
```

## 变体与关联

- 变体：XTEA 的密钥索引依赖 `sum`（`key[sum&3]`/`key[(sum>>11)&3]`）；XXTEA 是多块循环 `6+52/n` 轮，不能用两字 TEA 公式直接套。
- 变体：delta 可能被改成任意 32 位常量，轮数可能为 8/16/32；逆向时以循环次数与立即数为准。
- 变体：端序可能是大端；若 `struct.pack('>II')` 才得到可打印结果，说明装字顺序相反。
- 关联：[[ctf-reverse-apk-native-tea-gf256-matrix-lcg]]（TEA 变体）、[[ctf-reverse-cpp-vtable-modified-tea-mask-xor]]（魔改 TEA + 掩码）、[[code-analysis-reverse-crypto-encoding-identification-decrypt]]（从 delta 常量识别 TEA 系列）。
- 边界：若 `sum` 初值不是 `delta*rounds`、或每轮 `sum` 更新在加密/解密中的位置不同，需按实际代码调整；若密钥由输入派生，需先还原派生逻辑。

## 检测与防御

- 检测（逆向侧）：搜索 `0x9E3779B9` 或异常 delta 常量、32 轮循环、4 个密钥字、`sum` 累加与移位/异或混合；连续两段对称的 `v0/v1` 更新即为 TEA 家族。
- 防御（CTF/软件）：不要用自创分组密码；需要对称加密时使用 AES-GCM/ChaCha20-Poly1305 并正确管理密钥/nonce。
- 分析侧：先确认加密/解密顺序与端序，再套公式；不要直接复制标准 TEA 脚本。
