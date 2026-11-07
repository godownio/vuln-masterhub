---
id: ctf-crypto-sparse-group-fingerprint-mitm-xor-path
title: 稀疏分组指纹覆盖 + meet-in-the-middle：从 7 组告警恢复 14 列异或路径
type: scenario
domain: ctf
path: ctf/crypto
technique: sparse-group-fingerprint-mitm-xor-path
aliases:
- 分组指纹
- 告警覆盖
- meet-in-the-middle XOR
- 稀疏路径恢复
- syndrome_shadow
tags:
- ctf
- crypto
- fingerprint
- exact-cover
- meet-in-the-middle
- xor
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:51:01+08:00'
  notes: 已对照原文 syndrome_shadow 一节核对：GROUPS=7/WIDTH=20/PICK=2/140 列/72-bit、每组 6 个 5-bit 告警、good 依赖真实列对、fake=echo:group:nonce:shadow:columns[idx] 可复现、32 维计数精确覆盖、190 列对、3+4 组 MITM、layer-04 KDF、flag 值均一致。未验证点：PoC 未在本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

当 140 个 72-bit 列被分成 7 组、每组选 2 列，目标 `shadow` 是所选 14 列的异或；每组给出 6 个 5-bit 告警，其中 1 个依赖真实列对、5 个只依赖公开数据时，可以先枚举每组可能的真实指纹，用 7 组告警多重集做精确覆盖恢复每组指纹；再枚举每组匹配指纹的列对，用 3+4 组 meet-in-the-middle 找到异或等于 `shadow` 的完整路径。

## 原理

- **问题结构**：`GROUPS=7`、`WIDTH=20`、`PICK=2`，共 140 列；每组选 2 列，`shadow = XOR(14 列)`。`target` 给出 shadow。
- **告警生成**：每组 6 个告警；`good = mark(f"{group}:{a}:{b}:{shadow}", 5)` 依赖真实列对；`fake = mark(f"echo:{group}:{nonce}:{shadow}:{columns[idx]}", 5)` 只依赖公开的 `group/nonce/shadow/columns`，可枚举复现。5-bit 指纹只有 32 种。
- **精确覆盖**：对每组枚举 190 个列对，计算可能的 `good`（去重后 ≤32 种）；对每个候选 `good` 构造该组应产生的 6 个告警 bag（1 个 good + 按公开规则生成的 5 个 fake，去重），得到一个 32 维计数向量。7 组的 bag 相加必须等于远端给出的 `noise` 多重集；用 DFS/精确覆盖求出每组真实 `good`。
- **路径恢复**：每组 `good` 对应若干候选列对；前 3 组与后 4 组分别枚举组合，计算 XOR 和，用字典做 meet-in-the-middle：`need = shadow XOR right_xor`，在左表中查 `need`，合并得到 14 列路径。
- **派生密钥**：`raw=",".join(map(str,path))`，`key=sha256(b"layer-04:"+raw)`，HMAC-SHA256 计数器流异或 `box` 得到 flag。
- **为什么成立**：5-bit 指纹 + 6 告警/组提供了足够的统计约束；假告警可复现，排除后每组只剩真实指纹；MITM 把 `190^7` 降到 `190^3 + 190^4` 量级。
- **边界**：指纹冲突/告警重复、`pick≠2`、假告警生成规则未知时，需要调整 bag/枚举；MITM 内存随组合数增长。

## 触发条件

- 已知 `GROUPS/WIDTH/PICK`、140 个 72-bit 列、`target=shadow`、每组 6 个 5-bit 告警。
- 假告警生成规则公开/可复现（本题 `echo:...` 规则）；真实指纹只依赖组内列对。
- `shadow` 是所选列异或；列向量维度/异或运算明确。
- 能实现多重集精确覆盖与 MITM 搜索。

## 利用步骤

1. 解析 `payload` 为 140 个列向量（72-bit），`shadow=target`，`noise` 为告警多重集。
2. 对每组枚举 `C(20,2)=190` 个列对，计算 `good` 指纹（5-bit），去重得到候选集。
3. 对每个候选 `good`，按公开规则生成该组 6 个告警 bag（1 good + 5 fake，去重），转成 32 维计数向量。
4. 用 DFS 在 7 组候选 bag 中做精确覆盖，使总计数等于 `noise` 多重集；得到每组真实 `good`。
5. 对每组枚举所有匹配该 `good` 的列对，记录 `(xor_value, pair)`；前 3 组与后 4 组分别枚举组合，用字典做 MITM 找 `left_xor XOR right_xor = shadow`。
6. 合并路径（14 个列下标），按 `sha256(b"layer-04:"+path)` 派生密钥解密 `box`，得到 flag。
7. 本题得到 `flag{660c2856-1b86-46ea-82ff-78fda08d243f}`（示例）。

## PoC

```python
from collections import Counter
from functools import lru_cache
from itertools import combinations, product

def mark(data: bytes, bits: int) -> int:
    return int.from_bytes(__import__("hashlib").sha256(data).digest(), "big") & ((1 << bits) - 1)

def bag_for_good(group, good, shadow, columns, check_bits, check_count):
    bag = [good]
    nonce = 0
    while len(bag) < check_count:
        idx = (group * 17 + nonce * 11) % len(columns)
        fake = mark(f"echo:{group}:{nonce}:{shadow}:{columns[idx]}".encode(), check_bits)
        nonce += 1
        if fake not in bag:
            bag.append(fake)
    return Counter(bag)

def good_sequences(groups, width, noise_counter, shadow, columns, check_bits, check_count):
    domain = 1 << check_bits
    target = tuple(noise_counter.get(i, 0) for i in range(domain))
    bags = []
    for group in range(groups):
        group_bags = []
        for good in {
            mark(f"{group}:{a}:{b}:{shadow}".encode(), check_bits)
            for a, b in combinations(range(group * width, (group + 1) * width), 2)
        }:
            counts = [0] * domain
            for value, count in bag_for_good(group, good, shadow, columns, check_bits, check_count).items():
                counts[value] = count
            group_bags.append((good, tuple(counts)))
        bags.append(group_bags)

    @lru_cache(None)
    def dfs(group, remaining):
        if group == groups:
            return ((),) if all(x == 0 for x in remaining) else ()
        out = []
        for good, bag in bags[group]:
            if all(bag[i] <= remaining[i] for i in range(domain)):
                nxt = tuple(remaining[i] - bag[i] for i in range(domain))
                for suffix in dfs(group + 1, nxt):
                    out.append((good,) + suffix)
        return tuple(out)

    return list(dfs(0, target))

# 对每组 good 枚举匹配列对；前 3 组/后 4 组 MITM：
# left[x] = [path...]；right 计算 need = shadow ^ x，查 left[need]。
```

## 变体与关联

- **变体（指纹位数/告警数）**：位数越大冲突越少但枚举越慢；告警数/假告警规则变化需重写 bag。
- **变体（PICK≠2）**：枚举组合数增大，MITM 分组需调整。
- **变体（无假告警规则）**：只能靠统计/约束求解，难度上升。
- **关联卡片**：[[ctf-crypto-sparse-error-linear-system-nullspace-enumeration]]（稀疏错误枚举）、[[crypto-prng-mt19937-seed-recovery-lfsr-noise-batch-alignment]]（噪声分类/对齐）、[[ctf-crypto-small-discrete-log-crt-channel-selection]]（组合枚举 + 格式筛选）。
- **边界**：指纹冲突、告警重复、列数/组数过大时枚举爆炸；MITM 需内存与去重。

## 检测与防御

- **CTF 识别**：看到“每组选 k 个、目标为异或、告警含真实/假两种”，先复现假告警规则，再做精确覆盖 + MITM。
- **密码设计**：不要用低位数指纹 + 可复现假告警构造路径秘密；使用标准承诺/零知识证明与足够熵。
- **实现**：多重集覆盖用计数向量 + DFS 剪枝；MITM 用字典按 XOR 分组，注意重复路径/顺序。
