---
id: ctf-reverse-multi-stage-cube-fnv1a-linear-system-dynamic-maze
title: 三关串联校验逆向：魔方公式密钥 + FNV1a32、五元线性方程组与 seed 派生动态迷宫
type: scenario
domain: ctf
path: ctf/reverse
technique: multi-stage-cube-fnv1a-linear-system-dynamic-maze
aliases:
- 拆弹专家
- 魔方公式
- FNV1a32
- 动态迷宫
- 多关卡
tags:
- ctf
- reverse
- multi-stage
- fnv1a
- linear-equations
- maze
- seed
- xor-string
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:27:04+08:00'
  notes: '已对照原文核对：enc[11]^0x5A 得 Flag: ISCC{、enc_key 解出 R U F R'' D2、第一关 k1c7+FNV1a32 MASK 0xA5A5A5A5/EXPECT 0xD9BDB554 答案 IXMEHAVZ、第二关 9 位拆 5 数五元方程 8/55/32/19/32=855321932、seed=atoi(pw2)^(h*0x9E3779B1) 生成 4×4 迷宫路径 RDRDRD、flag ISCC{IXMEHAVZ855321932RDRDRD} 均与卡片一致；原文未展开第一关 FNV 前像恢复，卡片已注明。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。'
---

## 一句话结论

三关密码逐级派生：第一关 8 字符经魔方公式 `R U F R' D2`（XOR 0x5A 隐藏）加密后做 FNV1a32 比较，第一关哈希用于生成第二关五元线性方程组系数，第二关数字异或黄金比例常量作 seed 生成第三关 4×4 动态迷宫；必须按顺序解，不能跳关。

## 原理

- **XOR 隐藏字符串**：程序把明文字符串逐字节 `^ 0x5A` 存成数组；例如 `enc[11]={0x1C,0x36,0x3B,0x3D,0x60,0x7A,0x13,0x09,0x19,0x19,0x21}` 解出 `Flag: ISCC{`。密钥数组 `enc_key[i]` 同样解出魔方公式 `R U F R' D2`。
- **第一关：可逆置换 + 哈希校验**：输入长度 8、可打印字符；`cipher=k1c7(input,key)` 是自定义魔方置换，`h=fnv1a32(cipher)`，校验 `(h ^ 0xA5A5A5A5) == 0xD9BDB554`。FNV1a32 本身不可逆，但 `k1c7` 若可逆，可先对候选明文正向计算；原文直接给出第一关答案 `IXMEHAVZ`，未展开从哈希目标反推的过程（8 个可打印字符空间 95^8，纯爆破不可行）。
- **哈希作为后续 KDF**：第一关通过后保存 `g_stage1_hash=h`，调用 `d4n7(h)` 生成第二关的系数 `g_a[0..4]` 与目标值。后续关卡参数依赖前关结果，不能独立求解。
- **第二关：五元线性方程组**：9 位数字拆成 `x1=x[0]`、`x2=x[1]*10+x[2]`、`x3=x[3]*10+x[4]`、`x4=x[5]*10+x[6]`、`x5=x[7]*10+x[8]`；五个方程形如 `g_a[0]*x1 + x2 + x5 = b1`、`x1 + g_a[1]*x2 + x3 = b2`、……，解出 `(8,55,32,19,32)`，拼接为 `855321932`。
- **第三关：seed 派生迷宫**：`seed = atoi(password2) ^ (g_stage1_hash * 0x9E3779B1u)`（`0x9E3779B1` 是黄金比例 32 位常量），`b5k8(seed)` 用确定性 PRNG 生成 4×4 迷宫；从 (0,0) 到 (3,3)，字符 L/R/U/D，路径 `RDRDRD`。
- **最终输出**：`h5b5()` 依次打印 XOR 隐藏的 `Flag: ISCC{`、三段密码和 `}`。

## 触发条件

- 程序连续读取三段输入，前一段通过后才读下一段；每段长度/字符集不同（8 可打印、9 数字、方向字符）。
- 二进制中出现 XOR 0x5A 的字符串数组、FNV1a32 常量（offset basis `0x811C9DC5`、prime `0x01000193`）、5×5 线性方程、4×4 迷宫与 PRNG seed 混合常量。
- 第二关系数/目标不是硬编码，而是由第一关哈希经函数生成。

## 利用步骤

1. 先解 XOR 隐藏字符串：找 `^ 0x5A` 的数组，恢复魔方公式、输出前缀、提示文本。
2. 第一关：还原 `k1c7` 的置换规则；若可逆则从目标哈希做定向搜索/约束，若不可逆则结合题面/字典；原文样本答案为 `IXMEHAVZ`。
3. 记录第一关计算出的 `h`，复刻 `d4n7(h)` 得到第二关系数与目标。
4. 第二关：按 9 位数字拆分规则建 5 个线性方程，用高斯消元/z3 求解；把解按 x1..x5 拼成 9 位数字。
5. 第三关：按 `seed = atoi(pw2) ^ (h * 0x9E3779B1)` 复刻 PRNG，生成迷宫；BFS/DFS 求 (0,0)→(3,3) 的合法路径。
6. 拼接 `ISCC{pw1+pw2+pw3}`，用原程序验证。

## PoC

```python
def xor_str(enc, k=0x5A):
    return bytes(b ^ k for b in enc).decode()

print(xor_str([0x1C,0x36,0x3B,0x3D,0x60,0x7A,0x13,0x09,0x19,0x19,0x21]))
# "Flag: ISCC{"

def fnv1a32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xffffffff
    return h

# 第二关：给定系数矩阵 A 与目标 b，解 A x = b
# 方程组形状（系数由 d4n7(stage1_hash) 动态生成）：
# g0*x1 + x2 + x5 = b1
# x1 + g1*x2 + x3 = b2
# x2 + g2*x3 + x4 = b3
# x3 + g3*x4 + x5 = b4
# x1 + x4 + g4*x5 = b5
from z3 import Ints, Solver, sat
def solve_stage2(g, b):
    x1, x2, x3, x4, x5 = Ints("x1 x2 x3 x4 x5")
    s = Solver()
    s.add(g[0]*x1 + x2 + x5 == b[0])
    s.add(x1 + g[1]*x2 + x3 == b[1])
    s.add(x2 + g[2]*x3 + x4 == b[2])
    s.add(x3 + g[3]*x4 + x5 == b[3])
    s.add(x1 + x4 + g[4]*x5 == b[4])
    s.add(x1 >= 0, x1 <= 9, x2 >= 0, x2 <= 99, x3 >= 0, x3 <= 99,
          x4 >= 0, x4 <= 99, x5 >= 0, x5 <= 99)
    if s.check() != sat:
        raise ValueError("no solution")
    m = s.model()
    vals = [m.eval(v).as_long() for v in (x1, x2, x3, x4, x5)]
    return f"{vals[0]}{vals[1]:02d}{vals[2]:02d}{vals[3]:02d}{vals[4]:02d}"

# 原文样本：解为 8,55,32,19,32 -> "855321932"
# 第三关：seed 派生迷宫后 BFS/DFS，路径为 RDRDRD
# flag: ISCC{IXMEHAVZ855321932RDRDRD}
```

## 变体与关联

- **哈希作为 KDF 变体**：MD5/SHA1/SHA256/CRC32/FNV 的输出被截断/异或后生成系数、seed、S 盒；按程序顺序复算，不要试图反哈希。
- **线性方程变体**：变量可能按位/按字节拆分，系数矩阵可能稀疏；z3 或高斯消元均可，注意整数范围与除法。
- **动态迷宫变体**：PRNG 可能是 MT19937、xorshift、LCG；先确认 seed 混合常量与生成顺序，再 BFS。
- **多关卡变体**：后关参数可能依赖前关哈希、前关输入、时间/环境；用调试器记录中间值比纯静态更快。
- **关联卡片**：[[ctf-reverse-z3-constraint-equation-solve]]（z3 解线性方程）、[[ctf-reverse-zhie-map-vm-search]]（地图状态机 + 搜索）、[[ctf-reverse-upx-vm-rolling-hash-per-char-inversion]]（滚动哈希/逐字符校验）。

## 检测与防御

- **检测特征**：多段 `read`/输入提示、XOR 0x5A 的字符串数组、FNV1a32 常量、5 个线性方程、4×4 迷宫与 seed 混合常量。
- **分析建议**：先解 XOR 字符串拿提示和公式；第一关哈希不可逆时，优先找可逆置换/字典/调试器中间值，不要盲目爆破 95^8。
- **防御视角**：多关卡串联只是增加分析步骤；把哈希输出当 KDF、把迷宫 seed 依赖前关结果都不能替代密钥保护。FNV1a 不是密码学哈希，容易被定向搜索/约束求解。
