---
id: ctf-forensics-repeating-xor-png-header-key-recovery
title: 循环异或加密的 PNG：用已知明文（8 字节魔数 + IHDR 长度/类型，共 16 字节）反推重复密钥，再整文件异或解密
type: scenario
domain: ctf
path: ctf/forensics
technique: repeating-xor-known-plaintext-png-header-key-recovery
aliases:
- XORed picture
- flag_enc.png 解密
- 已知明文恢复异或密钥
- PNG 文件头 16 字节
- itertools.cycle 异或
tags:
- ctf
- forensics
- xor
- known-plaintext
- png
- repeating-key
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4
  verified_at: '2026-11-08T20:52:02+08:00'
  notes: 已对照原文核对：原文 key=urandom(16) 循环异或 PNG，前 16 字节已知明文为 8 字节魔数+IHDR 长度 00 00 00 0D+IHDR，PoC 的 known_pt 拼接与 ct[:16] 异或再整体异或解密与原文脚本一致。本次核对未读取图片，仅依据正文；未验证点：未实际解密样本文件，密钥 16/8/32 的尝试顺序为原文未涉及的推广。
---

## 一句话结论

文件被"按固定长度密钥循环异或"加密、且明文是 PNG/JPG/ZIP 这类有固定头部的格式时，不需要爆破密钥：PNG 前 16 字节是完全确定的（`89 50 4E 47 0D 0A 1A 0A` + `00 00 00 0D` + `49 48 44 52`，即魔数 + IHDR 长度 + `IHDR`），把密文前 16 字节与它异或即得密钥；若密钥长度恰好 16，一次就够，然后 `xor(ct, cycle(key))` 整体解密。

## 原理

- XOR 自反：`C = P ⊕ K` 故 `K = C ⊕ P`；只要知道明文任意一段，就能得到对应位置的密钥流。
- 循环异或（`itertools.cycle(key)`）意味着密钥流是周期性的：密钥长度 16 时，前 16 字节的已知明文刚好覆盖整整一个周期，`K` 被完整求出。
- PNG 头部为什么可预测：8 字节签名固定；紧接着是第一个 chunk，长度字段恒为 13（`00 00 00 0D`）、类型恒为 `IHDR`；因此前 16 字节（8 + 4 + 4）100% 确定。
- 恢复后如何验证：解密结果前 8 字节应等于 PNG 签名，且能看到 `IHDR`、`IDAT`、`IEND` chunk 结构；若只解出部分可读内容，多半是密钥长度估计错（把 16 当 8 或反之），应按已知明文长度重算。
- 该手法对任意"已知固定头部"的容器通用：ZIP `50 4B 03 04`、JPEG `FF D8 FF E0`、PE `4D 5A`、PDF `%PDF-1.`、SQLite `SQLite format 3\0`。

## 触发条件

- 有密文文件与"加密脚本/算法说明"，确认是定长密钥循环异或（或可推测为循环）。
- 明文格式已知（扩展名或题目暗示），且头部长度 ≥ 密钥长度。
- 密钥可以是不可见字符 —— 只要能打印出来看到 hex 即可，无需人眼可读。

## 利用步骤

1. 读密文前 N 字节（N = 估计的密钥长度，PNG 常见 16 / 8 / 32）。
2. 拼出对应长度的已知明文（PNG 用 16 字节头；不确定就先用 8 字节魔数试）。
3. `key = xor(known_pt, ct[:len(known_pt)])`，打印 hex 检查是否为有意义的周期（例如 16 字节内没有明显重复）。
4. `pt = xor(ct, cycle(key))` 写回文件，用 `file`/图片查看器校验。
5. 若解出的图仍异常，尝试密钥长度 8/16/32 与"头 8 字节 + 偏移"组合。

## PoC

```python
import itertools

def xor(data, key):
    return bytes(a ^ b for a, b in zip(data, itertools.cycle(key)))

with open("flag_enc.png", "rb") as f:
    ct = f.read()

# 8 字节魔数 + IHDR chunk 长度(13) + "IHDR"
known = bytes.fromhex("89504e470d0a1a0a") + (13).to_bytes(4, "big") + b"IHDR"
key = xor(known, ct[:len(known)])
print(key)                              # 16 字节密钥，可能含不可见字符

with open("flag_dec.png", "wb") as f:
    f.write(xor(ct, key))
```

## 变体与关联

- 密钥长度未知且明文头部短于密钥：只能用头部长度反推密钥前缀，再用"图片结构约束"（如 `IHDR` 的宽高字段合理、CRC 正确）迭代扩展密钥。
- 密钥由另一个文件给出（等长掩码）：直接两文件异或，验证结果是否为已知魔数。
- 若加密不是异或而是"逐字节加常数"或"位置相关变换"，改用对应逆运算；异或的特殊之处在于密钥可由任一段已知明文直接取出。
- 相关：two-time pad（两段密文异或消密钥）、已知明文恢复 ZIP 密码哈希（bkcrack 走的是不同原理，需要明文补丁字节）。

## 检测与防御

- 检测：文件头熵异常、`file` 识别失败但长度与图片接近；CTF 之外可用"魔数扫描 + 已知明文异或"批量识别简单加密。
- 防御：不要用循环异或做任何真实加密（密钥可被已知明文直接取出）；需加密请用带认证的 AEAD（AES-GCM/ChaCha20-Poly1305），并对密钥做 KDF。
