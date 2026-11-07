---
id: ctf-reverse-xxtea-custom-delta-derived-key
title: XXTEA 魔改 delta 0x87654321 + 异或循环移位派生密钥：按自定义 mix 与 42 轮逆推
type: scenario
domain: ctf
path: ctf/reverse
technique: xxtea-custom-delta-derived-key-decrypt
tags:
- ctf
- reverse
- xxtea
- tea
- symmetric-crypto
- custom-delta
- key-derivation
- decrypt
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V235
  verified_at: '2026-11-07T09:35:24+08:00'
  notes: 已对照原文与内联图03/04核对：数据段 128 位密钥常量、delta=0x87654321、42 轮、派生密钥 rol32(x^0x13579BDF,7)；复跑卡片 PoC 得 flag{cbee3251-9cff-4542-bf15-337bb8df7f3f}，原始密钥解出乱码。未验证点：未在目标二进制上复现完整逆向。frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-xxtea-custom-delta-derived-key/
draft: false
kb_aliases:
- XXTEA 自定义 delta
- XXTEA 密钥派生
- 魔改 XXTEA 解密
- delta 0x87654321
- rol32(key ^ 0x13579BDF, 7)
- Dragon XXTEA
---

## 一句话结论

逆向题中的 XXTEA 可以把 `delta` 从标准 `0x9E3779B9` 改成 `0x87654321`、把轮数改成 42，并在密钥使用前做 `derived = rol32(key ^ 0x13579BDF, 7)`；照抄二进制中的 `mix` 结构（`(z<<4)^(y>>5)`、`(y<<4)^(z>>5)`、`key[(p&3)^e]`）写逆轮并逐字减去混合值，用派生密钥解密即可得到 flag，直接用数据段里的原始密钥会失败。

## 原理

- **XXTEA 结构**：XXTEA 把输入切成 32 位字数组，加密时 `sum = 0`，每轮 `sum += delta`，对每个字 `data[p]` 用相邻字 `y=data[(p+1)%n]`、`z=data[(p-1)%n]` 计算混合值：
  `t = ((z << 4) ^ (y >> 5)) + ((y << 4) ^ (z >> 5))`；
  `idx = ((p & 3) ^ ((sum >> 2) & 3)) & 3`；
  `data[p] += t ^ ((sum ^ y) + (key[idx] ^ z))`。
- **魔改点**：标准 XXTEA 的 `delta` 是 `0x9E3779B9`、常用轮数 32；本题 `delta=0x87654321`、轮数 42。`delta` 只参与 `sum` 的累加，因此解密时只需从 `sum = rounds * delta` 开始，按相反顺序逐字减去同一个 `mix`，每轮 `sum -= delta`。
- **密钥派生**：数据段中直接可见的是 4 个 32 位原始密钥（原文为 `0x12345678, 0x9ABCDEF0, 0xFEDCBA98, 0x76543210`），但程序在传入 XXTEA 前对每个字做了 `rol32(x ^ 0x13579BDF, 7)`；用原始密钥解密得到乱码，用派生密钥才解出 flag。逆向时必须找到这段派生逻辑，否则会误判算法或以为密文损坏。
- **为什么可逆**：XXTEA 的轮函数只有加、异或、循环移位，全部可逆；逆轮使用相同的 `y/z` 与 `key[idx]`，只是把 `+=` 改成 `-=` 并按 `p` 从尾到头处理，保证 `y/z` 仍是加密时的相邻值。
- **字节序**：密文和数据段按 32 位字读取；原文按小端 `struct.pack('<I', word)` 还原字节并去掉尾部 `\x00`。

## 触发条件

- 拿到逆向题二进制，数据段或栈上出现 4 个 32 位密钥与一段 32 位字密文。
- 反编译/汇编中出现 `<<4`、`>>5`、`<<4`、`>>5` 与 `(sum >> 2) & 3`、`key[(p & 3) ^ e]` 等 XXTEA 特征。
- `delta` 常量与标准值不同（本题 `0x87654321`），或轮数不是 32（本题 42）。
- 密钥在进入算法前经过异或/循环移位等派生；需要从调用点或数据交叉引用确认。

## 利用步骤

1. 在 IDA 中定位输入读取与比较逻辑，找到 32 位字数组密钥、密文与轮数/`delta` 常量。
2. 确认密钥派生：本题为对每个 32 位字 `x` 执行 `rol32(x ^ 0x13579BDF, 7)`。
3. 按二进制的 `mix` 写法实现解密：`sum = rounds * delta`；每轮 `e=(sum>>2)&3`；`p` 从 `n-1` 到 0，`data[p] -= mix(y,z,sum,key,p,e)`；`sum -= delta`。
4. 先用原始密钥、再用派生密钥各解一次；用可打印字符/flag 格式判断哪一个是正确密钥。
5. 按小端把 32 位字转回字节，去掉尾部 `\x00`，得到明文 flag。

## PoC

```python
import struct

def rol32(x, r):
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

def mix(y, z, s, key, p, e):
    t = (((z << 4) ^ (y >> 5)) + ((y << 4) ^ (z >> 5))) & 0xFFFFFFFF
    idx = ((p & 3) ^ e) & 3
    u = (((s ^ y) + (key[idx] ^ z))) & 0xFFFFFFFF
    return (t ^ u) & 0xFFFFFFFF

def xxtea_decrypt(data, key, rounds=42, delta=0x87654321):
    n = len(data)
    out = data[:]
    s = (rounds * delta) & 0xFFFFFFFF
    for _ in range(rounds):
        e = (s >> 2) & 3
        for p in range(n - 1, -1, -1):
            y = out[(p + 1) % n]
            z = out[(p - 1) % n]
            out[p] = (out[p] - mix(y, z, s, key, p, e)) & 0xFFFFFFFF
        s = (s - delta) & 0xFFFFFFFF
    return out

enc = [0x0EB4D6CE, 0x521DDE8B, 0x21ED24FD, 0xBA10EC26,
       0x3339931C, 0x46DC0E7D, 0xCC469F44, 0x64BA7079,
       0x64777977, 0xB2151C98, 0xDBCC5AA1]
raw_key = [0x12345678, 0x9ABCDEF0, 0xFEDCBA98, 0x76543210]
derived_key = [rol32(x ^ 0x13579BDF, 7) for x in raw_key]

plain = xxtea_decrypt(enc, derived_key)
text = b"".join(struct.pack("<I", w) for w in plain).rstrip(b"\x00")
print(text.decode(errors="replace"))
```

## 变体与关联

- **delta/轮数变体**：只改 `delta`、轮数或 `sum` 初始值；逆轮结构不变，照抄常量即可。
- **密钥派生变体**：异或固定值、循环移位、MD5/SHA 截断、字节反转；关键是从调用点确认派生后的 4 个字。
- **算法变体**：TEA/XTEA/RC5/RC6 都有相似的 ARX 结构，注意移位组合与 `sum` 更新方式不同。
- **关联**：[[ctf-reverse-vm-tea-interpreter-recovery]]（VM 中魔改 delta 的 TEA）、[[mobile-android-jni-xxtea-blocktea-aes-sbox-multilayer]]（Android JNI 中的 XXTEA 运行时取 key）、[[ctf-reverse-pyarmor-pyinstaller-custom-xtea-carlotta]]（自定义 XTEA）。

## 检测与防御

- **CTF 性质**：这是逆向题的解法，不是可修复的真实漏洞；非标准常量不提供额外安全性，只增加逆向成本。
- **真实场景**：不要把硬编码密钥/非标准 `delta` 当作保密手段；密钥应使用 KMS/安全存储并定期轮换。
- **检测**：对样本中的 XXTEA 特征（移位 4/5、`key[(p&3)^((sum>>2)&3)]`）做静态识别，可快速定位加密逻辑。
