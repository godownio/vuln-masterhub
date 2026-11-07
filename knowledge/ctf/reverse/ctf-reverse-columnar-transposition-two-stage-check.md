---
id: ctf-reverse-columnar-transposition-two-stage-check
title: 列换位（columnar）密钥派生与双阶段输入校验逆向：HDB3 统计的全零绕过
type: scenario
domain: ctf
path: ctf/reverse
technique: columnar-transposition-key-chain-two-stage-check
aliases:
- 手忙脚乱
- columnar 换位
- 列换位
- 双阶段校验
- HDB3
tags:
- ctf
- reverse
- classical
- transposition
- columnar
- two-stage
- hdb3
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:26:46+08:00'
  notes: 已对照原文核对：K3=a~1、K6=XU?g)、A=columnar(K6,K3)、24=4×6、两段 encryptPart2(columnar(input,A),K6)^mask 比较、HDB3 全零绕过、input1 与 input2 均与卡片一致；encryptPart2 逆表生成原文未展开，卡片已注明需从二进制补出。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

程序把 24 字节输入按 4×6 矩阵做 `columnar` 列换位，并用 `K6` 经 `K3` 列换位得到二级 key `A`；两段输入都走 `encryptPart2(columnar(input,A),K6) ^ mask` 比较，第二段再用 HDB3 统计判断，关键绕过是把异或结果凑成全零串使统计校验通过，再逆向换位与替换得到两段输入。

## 原理

- **columnar 列换位**：`n=len(key)`，`rows=len(data)//n`，按行填入 `rows×n` 矩阵；`order=sorted(range(n), key=lambda i: key[i])` 决定列输出顺序，按 `order` 逐列从上到下读出。它是纯置换，逆变换只需按同样的 `order` 把密文填回矩阵，再按行读出。
- **key 链式派生**：`K3` 是 3 字节、`K6` 是 6 字节；先算 `A = columnar(K6, K3)`，得到 6 字节二级 key（本例 `?\XgU)`）。之后所有换位都用 `A` 作 key，而不是直接用 `K6`；如果只看 `K6` 会得到错误的列顺序。
- **两阶段校验**：第一阶段 `encryptPart2(columnar(input1,A),K6) ^ MASK1 == TARGET1`；通过后程序不输出 PASS，而是继续读第二段 24 字节。第二阶段形式类似，但异或结果还要经过 HDB3（High Density Bipolar 3）线路编码统计判断。
- **HDB3 全零绕过**：HDB3 统计对全零串有特定结果；把 `encryptPart2(columnar(input2,A),K6)` 取成 `MASK2 ^ TARGET_T`，异或结果即为全零，统计校验自然满足。这样第二阶段也化归为“逆替换 + 逆换位”。
- **为什么可逆**：`columnar` 是置换；`encryptPart2` 由 `K6` 生成替换表，若表是双射（每个输入字节映射到唯一输出字节），则逐字节求逆即可。原文给出了两段结果与 PASS 事实，但没有展开 `encryptPart2` 的表生成细节，实际复现需从二进制补出该逆表。

## 触发条件

- 程序连续读取两段固定长度（本例 24 字节）输入，第一段通过后才读第二段。
- 二进制中出现两个关键常量（本例 `K3=a~1`、`K6=XU?g)\`），以及按 key 字符排序生成列顺序的循环。
- 第二段校验后跟 HDB3 相关统计/计数逻辑，而不是直接 `memcmp`。

## 利用步骤

1. 从字符串/立即数恢复 `K3`、`K6`；确认输入长度能被 key 长度整除（24 = 4 行 × 6 列）。
2. 实现 `columnar`/`inv_columnar`，先算 `A = columnar(K6, K3)` 并核对列顺序。
3. 第一阶段：计算 `TARGET1 ^ MASK1`，逆 `encryptPart2` 得 `columnar(input1,A)`，再 `inv_columnar(...,A)` 得 input1。
4. 第二阶段：令 `encryptPart2(columnar(input2,A),K6) = MASK2 ^ TARGET_T`，同样逆替换、逆换位得 input2；此时 HDB3 统计面对全零串应通过。
5. 把 input2 输入程序确认进入 PASS；input1 只能过第一阶段，不是最终 flag。

## PoC

```python
def get_order(key):
    return sorted(range(len(key)), key=lambda i: key[i])

def columnar(data, key):
    n, rows = len(key), len(data) // len(key)
    order = get_order(key)
    matrix = [data[i * n:(i + 1) * n] for i in range(rows)]
    out = bytearray()
    for col in order:
        for row in range(rows):
            out.append(matrix[row][col])
    return bytes(out)

def inv_columnar(data, key):
    n, rows = len(key), len(data) // len(key)
    order = get_order(key)
    matrix = [[0] * n for _ in range(rows)]
    p = 0
    for col in order:
        for row in range(rows):
            matrix[row][col] = data[p]; p += 1
    return bytes(b for row in matrix for b in row)

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

K3 = b"a~1"
K6 = b"XU?g)\\"          # 反斜杠需转义
A = columnar(K6, K3)
print("A =", A)          # b'?\\XgU)'

# 原文给出的两段 24 字节输入（已通过各自校验）
input1 = b"B*:ZVV74SF{M^*c{tm}?UMcm"
input2 = b"m@jq`hCp>jfd{1l042;S=#@f"
print(input1.decode(), input2.decode())
# 第二阶段输入可触发 PASS；encryptPart2 的逆表需从二进制提取
```

## 变体与关联

- **key 链式变体**：用一把 key 对另一把 key 做换位/哈希/异或再作为二级 key；务必按程序顺序复算，不要跳步。
- **列换位变体**：带 padding 的不完整列、按列写入按行读出、按 key 排序后反向读取；先用小样例（如 2×3 矩阵）验证方向。
- **统计校验变体**：HDB3 之外还可能是游程、奇偶、零字节计数、CRC 分布；先判断“什么输入使统计恒满足”（通常是全零/全同字节），再逆推。
- **替换层变体**：`encryptPart2` 可能是 S 盒、按 key 生成的置换表、或逐字节加减；只要双射就能逐字节求逆。
- **关联卡片**：[[ctf-crypto-vigenere-caesar-digit-letter-branch-counter-scope]]（古典替换/换位复合）、[[ctf-reverse-modified-rc4-rounds-sbox]]（自定义 S 盒逐处同步）。

## 检测与防御

- **检测特征**：固定长度输入被按 key 长度分组、`sorted(range(n), key=...)` 形态的列顺序、两段 `read` 调用、校验后接统计而非比较。
- **分析建议**：先写正向 `columnar` 与 `inv_columnar` 并用自造数据互逆验证；`encryptPart2` 若复杂，优先在调试器里 dump 其生成的替换表再求逆。
- **防御视角**：列换位 + 自定义替换只是提高逆向成本，无法抵抗已知明文/调试 dump；关键校验不应把“全零/特殊统计”当作通过条件。
