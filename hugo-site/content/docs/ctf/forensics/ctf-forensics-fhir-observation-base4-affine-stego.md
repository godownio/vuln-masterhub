---
id: ctf-forensics-fhir-observation-base4-affine-stego
title: FHIR Observation 生命体征隐写：血压四档编码四元符号 + GF(2) 仿射映射还原 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: fhir-observation-base4-affine-stego
tags:
- ctf
- forensics
- fhir
- hl7
- steganography
- base4
- affine-cipher
- gf2
- uuid
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:32+08:00'
  notes: 对照 Misc240：422 entry、血压四档、nib=s*4+d、0x27 短横线、仿射 0x8629 一致
url: /docs/ctf/forensics/ctf-forensics-fhir-observation-base4-affine-stego/
draft: false
kb_aliases:
- 四元生命信号
- FHIR Observation 隐写
- 血压四档 base-4
- GF(2) 仿射映射
- nibble 替换
- q-vital-capture
---

## 一句话结论

FHIR Bundle 的 420 个 Observation 中，心率/呼吸/血氧/体温恒定，只有收缩压与舒张压各取四档；把 `(收缩压-110)/4` 与 `(舒张压-70)/4` 合成四元符号、每两个符号组成一个 nibble，84 个时间点正好得到 42 字节，再对 nibble 做 GF(2) 仿射逆映射即可还原 `flag{UUID}`。

## 原理

- pcapng 中只有一条明文 HTTP 会话，响应体是 FHIR Bundle（id=q-vital-capture），共 422 个 entry：1 个 Patient、1 个 Device、420 个 Observation（84 个时间点 × 5 项体征）。
- 统计 5 项体征取值：心率恒 72、呼吸频率恒 18、血氧恒 97、体温恒 36.6，只有血压在动——收缩压 `{110,114,118,122}`、舒张压 `{70,74,78,82}` 各恰好 4 档，天然对应 2 bit。
- 每路血压一个四元符号：`s=(收缩压-110)/4`、`d=(舒张压-70)/4`，`nib=s*4+d`，取值 0..15。84 个时间点给 84 个 nibble = 42 字节，恰好是 `flag{`（5）+ 36 位 UUID + `}`（1）的长度。
- 42 字节直接按 ASCII 读是乱码，说明每个 nibble 被替换过。按骨架 `flag{...}` 列出已知密文 nibble→明文 nibble 的对应；另一个关键细节：密文 `0x27` 只在第 13、18、23、28 字节出现，正是 UUID 四个短横线的位置，所以 `0x27` 必解成 `0x2d`。
- 该替换不是查表而是 GF(2) 上的仿射映射：4×4 位矩阵加常量偏移。用已知对枚举全部 2^20 个仿射映射：完全相容的 16 个、整体可打印的 6 个、合法 `flag{UUID}` 的唯一 1 个。
- 命中矩阵 `0x8629`、偏移 0，明文 nibble = `c ^ ((c&4)>>1) ^ ((c&1)<<3)`，该映射是对合的。解出的字符串是合法 UUIDv4（第三段以 4 开头、第四段以 a 开头符合 variant 10xx），两个结构特征充当最后校验。

## 触发条件

- 流量/数据中存在结构化医疗或监控数据（FHIR Observation、JSON/XML 体征记录），部分字段取值离散且数量有限。
- 恒定字段与变化字段可区分，变化字段的档位数量构成 2 的幂（如四档）。
- 样本数量 × 每样本符号数恰好匹配目标明文长度（如 84×1 nibble=42 字节）。
- 已知明文格式（flag/UUID/时间戳）可用于恢复替换/编码映射。

## 利用步骤

1. 解析 pcapng 中的 HTTP 响应，提取 FHIR Bundle 的所有 Observation。
2. 统计每项体征的取值分布，找恒定项与离散变化项；确定档位到 0..k-1 的映射。
3. 按时间点把变化字段编码成四元符号/bit，拼成 nibble/字节流；检查长度与 flag 格式是否吻合。
4. 用 `flag{`、`}`、UUID 短横线位置等 crib 建立密文 nibble→明文 nibble 的已知对。
5. 枚举 GF(2) 仿射映射（矩阵 2^16 × 偏移 2^4），用已知对过滤，再用可打印性/UUID 结构选出唯一解。
6. 应用逆映射还原 42 字节明文，校验 UUIDv4 版本/variant。

## PoC

```python
import re

def apply(mat, off, x):
    y = 0
    for i in range(4):
        if (x >> i) & 1:
            y ^= (mat >> (4 * i)) & 0xF
    return y ^ off

UUID_RE = re.compile(rb'^flag\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$')

# known: {密文 nibble: 明文 nibble}，来自 flag{...} 骨架与 UUID 短横线位置
for mat in range(1 << 16):
    for off in range(16):
        if any(apply(mat, off, c) != p for c, p in known.items()):
            continue
        out = bytes(
            apply(mat, off, nib[2*j]) * 16 + apply(mat, off, nib[2*j+1])
            for j in range(len(nib) // 2)
        )
        if UUID_RE.match(out):
            print(mat, off, out.decode())
```

```text
# 命中：mat=0x8629, off=0
# 明文 nibble = c ^ ((c & 4) >> 1) ^ ((c & 1) << 3)   （对合）
```

## 变体与关联

- 变体：四元符号可来自其他离散字段（设备状态、告警等级、采样档位）；映射可换成查表、置换、线性/仿射、LFSR；字节序与符号顺序需按时间戳确认。
- 变体：若没有足够 crib，可枚举所有 4×4 可逆矩阵（或放宽到任意 4-bit 置换），用明文可打印性和格式约束筛选。
- 关联：[[ctf-forensics-midi-shared-tick-register-stego]]（结构化媒体字段隐写）、[[ctf-forensics-openigtlink-position-trajectory-pixel-font]]（轨迹数据恢复文本）。
- 边界：档位映射需与字段实际取值一致；UUID 版本/variant 特征可能因题目生成器不同而变；仿射枚举在 4-bit 域可行，8-bit 域需改用已知明文/统计方法。

## 检测与防御

- 检测：医疗/监控数据中恒定字段与离散字段的异常分布、样本数与文本长度吻合、字段取值集中在 2 的幂个档位；流量中出现与业务无关的 UUID/flag 结构。
- 防御/取证：对 FHIR 数据做完整性校验与来源认证；保留原始 pcapng 与时间戳；统计字段熵与取值集合；对导出数据进行规范化/重采样可破坏隐写。
- 加固（若用于隐蔽通信）：不要用固定档位直接编码明文；加入随机化与认证；限制数据导出接口的字段精度。
