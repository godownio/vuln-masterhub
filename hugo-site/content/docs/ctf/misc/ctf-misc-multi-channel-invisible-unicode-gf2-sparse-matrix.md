---
id: ctf-misc-multi-channel-invisible-unicode-gf2-sparse-matrix
title: 多通道不可见 Unicode 隐写 + GF(2) 稀疏矩阵求解：Tag 字符藏 manifest、变体选择符藏 nonce、零宽字符藏 RHS
type: scenario
domain: ctf
path: ctf/misc
technique: multi-channel-invisible-unicode-gf2-sparse-matrix-solve
tags:
- ctf
- misc
- unicode
- invisible
- tag-character
- variation-selector
- zero-width
- gf2
- gaussian-elimination
- blake2s
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:52:25+08:00'
  notes: 已对照原文 AI1 一节核对：Tag 字符 U+E0000 区还原 manifest、变体选择符 U+FE00 区拼 nonce、U+2062/U+2064 解 512 位 RHS、SHA256("spring-review:"+nonce) 前 16 字节 seed、BLAKE2s 稀疏矩阵（degree=3+byte%14、2 字节取模 336）、512×336 GF(2) 消元、MSB-first 42 字节 flag 均一致。未验证点：PoC 未在本机复跑；CTF 题无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/misc/ctf-misc-multi-channel-invisible-unicode-gf2-sparse-matrix/
draft: false
kb_aliases:
- 无声审稿
- AI1
- Unicode Tag manifest
- 变体选择符 nonce
- 零宽字符 RHS
- GF(2) 稀疏矩阵
- BLAKE2s 矩阵生成
---

## 一句话结论

AI 审稿备忘录把三类数据分别藏进三种不可见 Unicode 通道：Tag 字符（U+E0000–U+E007F）藏协议 manifest、变体选择符（U+FE00–U+FE0F）藏 nonce、零宽字符（U+2062/U+2064）藏 512 位右端项；用 nonce 经 SHA-256 派生 seed，按 BLAKE2s 规则生成 512 行稀疏矩阵，在 GF(2) 上高斯消元解出 336 个 bit，按 MSB-first 还原 42 字节 flag。

## 原理

- **多通道分工**：同一份文本里可以同时嵌入多种不可见字符，各自用不同码位区间，互不干扰。本题 `[review-token]` 用 Tag 字符编码 ASCII（`chr(ord(ch)-0xE0000)` 直接还原）；`[style-token]` 用变体选择符编码十六进制 nibble（`ord(ch)-0xFE00`，两两拼字节）；`[margin-notes]` 用 U+2062 表示 0、U+2064 表示 1，U+200B 作为可忽略填充，得到 512 位 RHS。
- **确定性矩阵生成**：`seed = SHA256(b"spring-review:" + nonce_hex)[:16]`；对第 i 行，`degree = 3 + (BLAKE2s(seed + u32be(i))[0] % 14)`；再用 `BLAKE2s(seed + u32be(i) + u16be(counter))` 的每 2 字节取模 336 选列，去重直到凑够 degree，得到该行的稀疏位掩码。
- **GF(2) 求解**：把 512 行掩码与 RHS 拼成增广矩阵，逐列选主元、异或消元；本题秩恰好 336，方程数 512 > 未知数 336，解唯一。若秩不足或出现 `0=1` 行，说明数据/矩阵参数不一致。
- **编码顺序**：336 bit 按 8 位一组、MSB-first 转 42 字节，恰好是 `flag{...}` 的 UUID 长度；用 `flag{`/`}` 与可打印性做校验。
- **为什么可行**：不可见字符在 UTF-8 中保留原始码点，复制/保存/解析链路不丢弃；确定性哈希让矩阵可由 nonce 复现，不需要额外传矩阵。

## 触发条件

- 拿到一段“看起来正常”的文本/文档，字符统计显示大量 Tag 字符、变体选择符或零宽字符。
- 文本按 UTF-8 原样保存，解析器不剥离这些码点。
- 隐藏数据包含可识别的协议字段（manifest、nonce、RHS 等），且参数足以复现矩阵。
- 明文为 ASCII/flag，长度与 bit 数匹配。

## 利用步骤

1. 用 Python 按 UTF-8 读取文件，按码位区间分别提取 Tag 字符、变体选择符、零宽字符。
2. Tag 字符：`chr(ord(ch)-0xE0000)` 还原 manifest/协议字段。
3. 变体选择符：`nibbles=[ord(ch)-0xFE00 ...]`，两两拼字节得到 nonce。
4. 零宽字符：U+2062→0、U+2064→1，忽略 U+200B，得到 512 位 RHS。
5. 用 `SHA256("spring-review:"+nonce_hex)[:16]` 派生 seed，按 BLAKE2s 规则生成 512 行稀疏矩阵。
6. GF(2) 高斯消元解出 336 bit，MSB-first 转 42 字节，校验 `flag{...}`。

## PoC

```python
import hashlib

def decode_tag_ascii(s):
    return "".join(chr(ord(ch) - 0xE0000) for ch in s if 0xE0000 <= ord(ch) <= 0xE007F)

def decode_nonce(s):
    nib = [ord(ch) - 0xFE00 for ch in s if 0xFE00 <= ord(ch) <= 0xFE0F]
    return bytes((nib[i] << 4) | nib[i + 1] for i in range(0, len(nib), 2))

def decode_rhs(s):
    return [0 if ord(ch) == 0x2062 else 1
            for ch in s if ord(ch) in (0x2062, 0x2064)]

def make_rows(seed, n_bits=336, m_rows=512):
    rows = []
    for i in range(m_rows):
        degree = 3 + (hashlib.blake2s(seed + i.to_bytes(4, "big")).digest()[0] % 14)
        used, idxs, counter = set(), [], 0
        while len(idxs) < degree:
            d = hashlib.blake2s(seed + i.to_bytes(4, "big") + counter.to_bytes(2, "big")).digest()
            for off in range(0, len(d) - 1, 2):
                idx = int.from_bytes(d[off:off + 2], "big") % n_bits
                if idx not in used:
                    used.add(idx); idxs.append(idx)
                    if len(idxs) == degree:
                        break
            counter += 1
        rows.append(sum(1 << idx for idx in idxs))
    return rows
```

GF(2) 消元与 bit→bytes 见原文 `solve_gf2`/`bits_to_bytes`；原文实测得到 `flag{17b8bbaf-1e0d-4d40-8a22-8c39c6e58bb0}`，未在本库复跑。

## 变体与关联

- **通道变体**：Tag 字符、变体选择符、零宽字符、双向控制符、Unicode 空白；可单独或组合使用。
- **矩阵变体**：确定性 PRNG 生成稀疏/稠密矩阵、LFSR、纠错码；只要参数可复现即可。
- **求解变体**：GF(2) 高斯消元、信息集解码、LPN 求解；本题秩恰好满，直接消元即可。
- **关联卡片**：[[ctf-misc-zero-width-unicode-binary-quinary-stego]]（零宽字符二/五进制隐写）、[[ai-security-prompt-injection-invisible-unicode-tag-variation-selector-smuggling]]（同类不可见 Unicode 通道用于提示词注入/数据外传）。

## 检测与防御

- **检测**：统计 `Cf` 类与 Tag 区块字符；对 Tag/变体选择符/零宽字符异常数量告警；用 `xxd` 或 Python 检查原始码点。
- **清洗**：对不可信文本做 NFKC 规范化并移除 Tag、变体选择符、零宽、双向控制符；显示/日志/搜索前统一清洗。
- **协议设计**：不要把秘密只藏在不可见字符里；需要隐写时使用带密钥的编码并加密，矩阵参数不要与密文放在同一通道。
- **分析**：多通道分别提取、分别解码，再按协议字段组合；先验证每个通道的长度/字符集，避免把填充字符当成数据。
