---
id: ctf-misc-crc32-four-byte-preimage-gf2-linear
title: CRC32 四字节原像：GF(2) 线性矩阵求逆从已知 CRC 还原 ZIP 未知内容
type: scenario
domain: ctf
path: ctf/misc
technique: crc32-four-byte-preimage-gf2-linear
aliases:
- CRC32 逆运算
- CRC32 原像
- CRC32 线性代数
- GF(2) 矩阵求逆
- ZIP CRC 还原
- 4 字节 CRC 爆破
tags:
- ctf
- misc
- crc32
- linear-algebra
- gf2
- matrix-inverse
- zip
- preimage
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V155
  verified_at: '2026-11-06T07:49:01+08:00'
  notes: 已对照原文与images 28-39核对：PNG修复/LSB导出pass*.zip、每包4字节、CRC32 GF(2) 32×32矩阵求逆、列向量crc(ej)^crc(0)、x=M^-1(crc^const)、小端拼接均与原文代码一致。未验证点：未复跑CRC求解，原文未附最终flag明文。
---

## 一句话结论

CRC32 对固定长度输入是 GF(2) 上的仿射变换；当一个 ZIP 条目只含 4 字节内容、CRC32 已知时，可构造 32×32 的线性矩阵并求逆，从 `CRC ^ CRC(0000)` 直接解出这 4 个字节，无需爆破 2^32 空间；把多个条目的 4 字节结果按序拼接即可还原隐藏消息。

## 原理

- CRC32 的更新过程只包含异或与移位，对消息比特是线性的：对固定长度 `L`，存在 32×32 的 GF(2) 矩阵 `M`，使 `CRC(m) = M·m ⊕ c`，其中 `c = CRC(0^L)`。
- 对 4 字节消息，`m` 有 32 个比特，`M` 是 32×32 方阵；标准 CRC32 多项式下该映射是双射，因此 `M` 可逆。
- 构造方法：令 `e_j` 为“第 j 位为 1、其余为 0”的 4 字节消息，计算 `col_j = CRC(e_j) ⊕ CRC(0000)`，得到 `M` 的 32 个列向量；再用高斯消元求 `M^{-1}`。
- 已知 `CRC(m)` 后，`m = M^{-1}·(CRC(m) ⊕ CRC(0000))`；按位拼回 4 字节即可。
- 为什么不是“哈希破解”：CRC32 不是密码学哈希，没有抗原像性；32 位输入/32 位输出的线性映射可以被精确求逆，计算量只有一次 32×32 矩阵求逆（O(32^3) 位运算）。
- 原文场景：`pass*.zip` 每个条目只含 4 字节文件内容，ZIP 中央目录给出 CRC32；按上述方法逐条还原 4 字节，按文件名编号拼接得到隐藏消息/下一层密码。

## 触发条件

- 已知某个 ZIP 条目的 CRC32（ZIP 目录中直接可见），且该条目内容长度固定为 4 字节（或可枚举的分段长度）。
- 使用标准 CRC32（ZIP/PNG/zlib 常见多项式 `0xEDB88320`，初值/最终异或按实现）；多项式或初值不同则需按实际参数重建矩阵。
- 内容不是必须为 ASCII；若是，可在解出后按可打印性验证。
- 有多个条目时，每个条目独立求逆，最后按文件名/编号排序拼接。

## 利用步骤

1. 用 `zipfile` 读取每个条目的 `CRC` 与 `file_size`；筛出 `file_size == 4` 的条目。
2. 计算 `const = zlib.crc32(b"\x00" * 4) & 0xffffffff`。
3. 对 `j=0..31` 构造只含第 j 位为 1 的 4 字节消息，计算 `col_j = crc32(msg) ^ const`，得到 32 个列向量。
4. 把列向量拼成 32×32 矩阵，用 GF(2) 高斯消元求逆（原文把矩阵行扩展为 `row | (1<<(32+i))`，消元后右半即逆矩阵）。
5. 对每个条目计算 `vec = crc ^ const`，用逆矩阵左乘得到 32 位值 `x`，`plain = x.to_bytes(4, "little")`。
6. 拼接所有 `plain`，按 ASCII/文件头验证；若结果乱码，检查 CRC 参数（多项式、初值、最终异或）与字节序。

## PoC

```python
import glob, os, re, zipfile, zlib

files = sorted(glob.glob("pass*.zip"),
               key=lambda p: int(re.search(r"(\d+)", os.path.basename(p)).group(1)))

const = zlib.crc32(b"\x00" * 4) & 0xffffffff

# 构造 CRC32 的 32x32 GF(2) 矩阵并求逆
cols = []
for j in range(32):
    x = bytearray(4)
    x[j // 8] = 1 << (j % 8)
    cols.append((zlib.crc32(bytes(x)) & 0xffffffff) ^ const)

rows = [0] * 32
for j, col in enumerate(cols):
    for i in range(32):
        if (col >> i) & 1:
            rows[i] |= 1 << j

aug = [rows[i] | (1 << (32 + i)) for i in range(32)]
r = 0
for c in range(32):
    pivot = next(i for i in range(r, 32) if (aug[i] >> c) & 1)
    aug[r], aug[pivot] = aug[pivot], aug[r]
    for i in range(32):
        if i != r and ((aug[i] >> c) & 1):
            aug[i] ^= aug[r]
    r += 1
inv_rows = [(aug[i] >> 32) & 0xffffffff for i in range(32)]

parts = []
for f in files:
    with zipfile.ZipFile(f) as zf:
        info = zf.infolist()[0]
        if info.file_size != 4:
            continue
        vec = info.CRC ^ const
        x = 0
        for i, row in enumerate(inv_rows):
            x |= ((row & vec).bit_count() & 1) << i
        parts.append(x.to_bytes(4, "little"))

print(b"".join(parts))
```

## 变体与关联

- 变体：8 字节内容需要 64×64 矩阵；更长内容无法仅凭 32 位 CRC 唯一还原，需结合已知前缀/可打印约束或更多校验。
- 变体：CRC16/CRC64 或其他多项式，按实际参数重建矩阵；初值/最终异或只需并入 `const`。
- 变体：若内容限定 ASCII，可把 32 位解再按每字节 0x20–0x7e 过滤/枚举多个解。
- 关联：[[ctf-misc-nested-zipcrypto-base32-crc32-overlap-chain]]（用 CRC32 作修复 oracle 的暴力版本）；[[ctf-forensics-png-ihdr-width-height-crc32-brute-force]]（PNG 头字段的 CRC 校验）；[[ctf-misc-zip-local-header-repair-pseudo-encryption]]（ZIP 结构修复）。
- 关联：CRC32 只用于检错，不应作为完整性/认证机制；需要抗篡改时用密码学 MAC/签名。

## 检测与防御

- 检测（分析侧）：ZIP/PNG 等格式中已知 CRC 且内容长度很短（4/8 字节）时，优先尝试线性代数求逆，而不是 2^32 爆破。
- 检测（防御侧）：不要把 CRC32 当作隐藏数据或身份校验的安全边界；攻击者可利用其线性性直接构造/还原内容。
- 防御：需要完整性时使用 HMAC-SHA256、数字签名或 AEAD；不要用 CRC32 保护敏感配置。
- 响应：若发现业务用 CRC32 校验短密钥/令牌，视为可伪造，立即更换为密码学校验并轮换相关凭据。
