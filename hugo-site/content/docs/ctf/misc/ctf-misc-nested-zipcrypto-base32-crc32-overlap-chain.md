---
id: ctf-misc-nested-zipcrypto-base32-crc32-overlap-chain
title: 嵌套 ZipCrypto BOX 链：密码=编号、Base32 短片段 CRC32 修复、9 字节重叠拼接 zlib
type: scenario
domain: ctf
path: ctf/misc
technique: nested-zipcrypto-base32-crc32-repair-overlap-chain
tags:
- ctf
- misc
- zip
- zipcrypto
- base32
- crc32
- error-repair
- overlap
- zlib
- data-recovery
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:52:29+08:00'
  notes: 已对照原文 MISC2 一节核对：外层 BOX-* 内层 ZipCrypto 密码=编号（两位数补零/三位原样）、记录 BOX-n|data=Base32|crc32、仅 48 字符短片段、CRC32 单/双字节修复、9 字节首尾重叠建唯一链（27 个 BOX，BOX-04→…→BOX-49）、78 da zlib 流、manifest final flag 均一致。未验证点：PoC 未在本机复跑；CTF 题无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/misc/ctf-misc-nested-zipcrypto-base32-crc32-overlap-chain/
draft: false
kb_aliases:
- 失序货栈
- MISC2
- BOX 链
- ZipCrypto 密码=编号
- Base32 片段 CRC32 修复
- 9 字节重叠拼接
- zlib 流重组
---

## 一句话结论

“失序货栈”外层 ZIP 里有很多 `BOX-*`，每个内层都是传统 ZipCrypto，密码就是编号（`BOX-04` 用 `04`、`BOX-127` 用 `127`）；解开后得到 `BOX-编号 | data=<48 字符 Base32> | crc32=<8 hex>`。对短片段 Base32 解码，用 CRC32 暴力修复 1–2 个坏字节，再按 9 字节首尾重叠拼成唯一链，拼接得到以 `78 da` 开头的 zlib 流，解压即得 manifest 与 flag。

## 原理

- **嵌套 ZipCrypto**：外层 ZIP 只负责装 `BOX-*` 条目；每个内层 ZIP 使用传统 ZipCrypto 加密，密码规则直接来自条目编号（两位数补零、三位数原样），不需要爆破。这属于“口令可预测/由元数据派生”的典型。
- **记录格式**：解密后是单行 `BOX-<n> | data=<Base32> | crc32=<hex>`；`data` 长度 48 的片段才是 manifest 链的一部分，长片段可能自身 CRC 不匹配，是干扰项。
- **Base32 解码 + CRC32 校验**：`base64.b32decode(data_text)` 得到二进制片段；用记录里的 `crc32` 校验。若不匹配，说明片段有 1–2 个字节被改坏；CRC32 是线性的，可以对单个位置枚举 256 个值、或对两个位置组合枚举，找到使 CRC 匹配的修复。
- **9 字节重叠**：每个片段与下一个片段有 9 字节的首尾重叠；把所有片段两两比较 `a[-9:] == b[:9]` 建图，入度为 0 的节点是链首，沿唯一后继走完所有片段，拼接时去掉后一片段的前 9 字节。
- **zlib 流**：拼接结果以 `78 da` 开头（zlib 默认压缩头），`zlib.decompress` 得到 manifest，里面含 `final=flag{...}`。
- **为什么成立**：CRC32 提供可验证的修复 oracle；重叠提供确定性的顺序约束；zlib 头/解压成功提供最终校验，三层约束把“失序”变成唯一解。

## 触发条件

- 外层压缩包包含大量编号条目，内层压缩包密码可由编号/元数据推导。
- 解密后的记录含 Base32/hex 数据与 CRC32 校验值，片段长度固定且有重叠。
- 片段中有少量坏字节，但 CRC32/重叠/zlib 头足以定位并修复。
- 明文为 zlib/JSON/文本，可用 magic、解压成功和 flag 格式校验。

## 利用步骤

1. 遍历外层 ZIP 的 `BOX-*`，用编号作为内层 ZipCrypto 密码解密。
2. 解析 `BOX-n | data=<Base32> | crc32=<hex>`，只保留长度为 48 的短片段。
3. Base32 解码，计算 CRC32；不匹配则枚举单字节/双字节修改，找到匹配的修复版本。
4. 对所有片段两两比较 9 字节首尾重叠，建 `next` 图；找入度为 0 的唯一链首，沿后继走完全部片段。
5. 按链顺序拼接（后一片段去掉前 9 字节），得到 zlib 流；`zlib.decompress` 解出 manifest。
6. 从 manifest 中提取 `final=flag{...}`。

## PoC

```python
import base64, itertools, re, zipfile, zlib

def crc32(b):
    return zlib.crc32(b) & 0xFFFFFFFF

def repair(data: bytearray, target: int):
    if crc32(data) == target:
        return bytes(data)
    for pos in range(len(data)):
        old = data[pos]
        for v in range(256):
            if v == old:
                continue
            data[pos] = v
            if crc32(data) == target:
                return bytes(data)
        data[pos] = old
    for p1, p2 in itertools.combinations(range(len(data)), 2):
        for v1 in range(256):
            data[p1] = v1
            for v2 in range(256):
                data[p2] = v2
                if crc32(data) == target:
                    return bytes(data)
    raise ValueError("repair failed")

# 片段链：a[-9:] == b[:9]
frags = {...}  # n -> bytes
nxt = {}
for a, b in itertools.permutations(frags, 2):
    if frags[a][-9:] == frags[b][:9]:
        nxt[a] = b
start = (set(frags) - set(nxt.values())).pop()
chain = [start]
while chain[-1] in nxt:
    chain.append(nxt[chain[-1]])
stream = bytearray(frags[chain[0]])
for n in chain[1:]:
    stream.extend(frags[n][9:])
manifest = zlib.decompress(bytes(stream))
print(re.search(rb"flag\{[^}]+\}", manifest).group(0))
```

原文实测链为 27 个 BOX（`BOX-04 -> BOX-14 -> ... -> BOX-49`），最终 flag `flag{dffc94e8-0571-4e68-bbc3-f1534766f794}`；未在本库复跑。

## 变体与关联

- **口令派生变体**：编号、文件名、时间戳、元数据字段作为 ZipCrypto 密码；先尝试可预测规则，再考虑字典/掩码。
- **纠错变体**：CRC32、CRC16、Adler32、SHA-1 截断；单字节/双字节枚举，或利用 CRC 线性性直接解出错误位置。
- **拼接变体**：固定重叠、de Bruijn 链、哈希前缀链、文件系统碎片；核心是构造“唯一后继”图。
- **关联卡片**：[[ctf-forensics-fat16-deleted-noncontiguous-extent-recovery]]（碎片恢复与 CRC32 校验）、[[ctf-misc-zero-width-unicode-binary-quinary-stego]]（编码层隐写）。

## 检测与防御

- **检测**：大量编号条目 + 可预测口令 + CRC32 字段是明显的 CTF/数据恢复结构；对异常嵌套 ZIP、重复短片段、固定重叠长度告警。
- **防御**：不要用可预测编号/元数据作为压缩包口令；对归档内容做完整性签名，而不是仅 CRC32。
- **取证**：保留原始 ZIP 与每个 BOX 的解密结果；先用 CRC32 修复，再用重叠/zlib 头验证顺序，避免手工猜测。
