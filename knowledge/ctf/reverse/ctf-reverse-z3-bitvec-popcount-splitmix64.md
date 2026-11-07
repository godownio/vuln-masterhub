---
id: ctf-reverse-z3-bitvec-popcount-splitmix64
title: Z3 BitVec 建模复杂 flag 校验：字节变换 + SWAR popcount + SplitMix64 哈希约束求解
type: scenario
domain: ctf
path: ctf/reverse
technique: z3-bitvec-popcount-splitmix64-solve
aliases:
- Z3 BitVec 逆向
- SWAR popcount Z3
- SplitMix64 约束求解
- Prover Z3
- 22 字节 flag 校验
tags:
- ctf
- reverse
- z3
- bitvec
- constraint-solving
- splitmix64
- popcount
- hash
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V235
  verified_at: '2026-11-07T09:35:27+08:00'
  notes: 已对照原文脚本核对全部变换表、SWAR popcount、SplitMix64 finalizer 与目标常量；复跑卡片 PoC 得 flag{7ac1d3e59f0b2468}。未验证点：未在原始二进制上复现静态分析。frontmatter 无 sources/source_url。
---

## 一句话结论

当逆向题的校验器对 22 字节 flag 做“乘法/异或/循环移位 → 打包成 6 个 32 位字 → popcount/加权和/异或和/16 位和 → 多轮 32 位混合 → SplitMix64 式 64 位哈希”时，用 Z3 的 `BitVec(8/32/64)` 逐位精确复刻每一步（`Extract` 截断、`ZeroExt` 扩展、`RotateLeft`、`LShR`、SWAR popcount），把目标常量作为等式约束，即可在秒级解出 `flag{7ac1d3e59f0b2468}`。

## 原理

- **位宽必须精确**：C 的 `uint8_t` 乘法/加法会按 8 位回绕，`uint32_t` 会按 32 位回绕；Z3 里要用 `BitVec(..., 8/32/64)` 并用 `Extract(7,0, x)` / `Extract(31,0, x)` 显式截断，否则解会偏移或不可满足。
- **可逆与不可逆操作都要建模**：字节变换 `temp = (a[i%5]*c + (19*i+79)) & 0xff`、`^ table[i%7]`、`rol8(i%5)`；打包为 24 字节（补 2 个零）后按小端拼 6 个 32 位字。每一步都照抄二进制，不要手工化简。
- **统计量**：程序计算所有 dword 的 popcount 之和低 8 位、变换字节的 16 位和、8 位异或和、按位置加权的 8 位和、字节 popcount 和的低 8 位；这些都可直接写成 Z3 表达式。
- **SWAR popcount**：32 位 popcount 可用标准 SWAR：`a=x-(LShR(x,1)&0x55555555)`、`b=(a&0x33333333)+(LShR(a,2)&0x33333333)`、`c=(b+LShR(b,4))&0x0F0F0F0F`、`d=c*0x01010101`、`LShR(d,24)`；Z3 的位向量乘法/移位与 C 一致。
- **32 位混合与 SplitMix64**：程序用 `0x9E3779B9`、`0xDEADBEEF`、`0xA5A5A5A5`、`0x5A5AA5A5`、`0x13579BDF` 等常量做旋转/加减/异或；64 位哈希先用 `v5=0x243F6A8885A308D3`，每字节 `mixed=v5 ^ (byte << (8*(i&7)))`、`v5=rol64(mixed*0x9E3779B185EBCA87,13)`，再做 SplitMix64 finalizer：`tmp=0xBF58476D1CE4E5B9*(v5^(v5>>30))`、`v3=0x94D049BB133111EB*(tmp^(tmp>>27))`、`n161=v3^(v3>>31)`。把这些等式都加入 solver，并附加 `n161`、低 32 位、`n191`、`v34`、`n172`、各统计量等目标约束。
- **唯一性**：输入格式约束（`flag{`、`}`、中间 16 个十六进制小写字符）加上多个哈希/统计量等式，使解唯一。
- **为什么可行**：校验器是纯确定性位运算，没有随机数/时间依赖；Z3 的位向量求解器可以对这种规模的约束做位爆破与传播。

## 触发条件

- 逆向题给出一个 22 字节 `flag{16 hex}` 的校验器，内部大量使用 8/32/64 位整数、循环移位、popcount 与哈希常量。
- 目标常量和变换表可从反编译/数据段直接读取。
- 校验器无外部依赖（网络/时间/随机数），或已把这些输入固定。
- 有 Python + `z3-solver` 环境。

## 利用步骤

1. 静态分析定位输入长度、格式检查、变换表（原文 `BYTE_6085=[3,5,9,11,13]`、`BYTE_608A=[0xA5,0x5C,0xC3,0x96,0x3E,0xD7,0x21]`）与目标常量。
2. 用 `BitVec('char_i', 8)` 建立 22 个变量，加入 `flag{`、`}` 与十六进制字符范围约束。
3. 按二进制逐步复刻字节变换、24 字节打包、6 个 dword、各统计量与 32/64 位混合；注意每一步的位宽与截断。
4. 把所有目标值（`n161`、`n172`、`n191`、`v34`、`v32+v33` 异或、`v42/v50/v51/v52/v53`）作为等式加入 solver。
5. `solver.check()`，按变量列表顺序 `model[flag_chars[i]].as_long()` 取字符，得到 flag。

## PoC

```python
from z3 import BitVec, BitVecVal, Solver, RotateLeft, LShR, Extract, ZeroExt, Or, And, sat

def rol8(x, r):  return RotateLeft(x, r % 8)
def rol32(x, r): return RotateLeft(x, r % 32)
def rol64(x, r): return RotateLeft(x, r % 64)

def popcount32(x):
    a = x - (LShR(x, 1) & BitVecVal(0x55555555, 32))
    b = (a & BitVecVal(0x33333333, 32)) + (LShR(a, 2) & BitVecVal(0x33333333, 32))
    c = (b + LShR(b, 4)) & BitVecVal(0x0F0F0F0F, 32)
    d = c * BitVecVal(0x01010101, 32)
    return LShR(d, 24)

MUL = [0x03, 0x05, 0x09, 0x0B, 0x0D]
XOR = [0xA5, 0x5C, 0xC3, 0x96, 0x3E, 0xD7, 0x21]

s = Solver()
ch = [BitVec(f'c{i}', 8) for i in range(22)]
for i, v in enumerate(b"flag{"):
    s.add(ch[i] == v)
s.add(ch[21] == ord('}'))
for i in range(5, 21):
    s.add(Or(And(ch[i] >= 0x30, ch[i] <= 0x39), And(ch[i] >= 0x61, ch[i] <= 0x66)))

tb = []
for i in range(22):
    t = Extract(7, 0, BitVecVal(MUL[i % 5], 8) * ch[i] + BitVecVal((19 * i + 79) & 0xFF, 8))
    t = t ^ BitVecVal(XOR[i % 7], 8)
    tb.append(rol8(t, i % 5))
padded = tb + [BitVecVal(0, 8), BitVecVal(0, 8)]

dw = []
for i in range(0, 24, 4):
    x = ZeroExt(24, padded[i]) | (ZeroExt(24, padded[i+1]) << 8) | \
        (ZeroExt(24, padded[i+2]) << 16) | (ZeroExt(24, padded[i+3]) << 24)
    dw.append(Extract(31, 0, x))

v42 = Extract(7, 0, sum([popcount32(d) for d in dw], BitVecVal(0, 32)))
v53 = BitVecVal(0, 16); v52 = BitVecVal(0, 8); v51 = BitVecVal(0, 8); v50 = BitVecVal(0, 8)
for j in range(22):
    v53 = Extract(15, 0, v53 + ZeroExt(8, tb[j]))
    v52 = v52 ^ tb[j]
    v51 = Extract(7, 0, v51 + Extract(7, 0, tb[j] * BitVecVal(j + 1, 8)))
    v50 = Extract(7, 0, v50 + Extract(7, 0, popcount32(ZeroExt(24, tb[j]))))

# 32 位混合（与原文同序）
g = lambda k: dw[k % 6]
v37 = (g(2) - BitVecVal(1640531527, 32)) ^ rol32(g(0), 5)
n172 = (rol32(g(7), 11) + (g(4) ^ BitVecVal(0xDEADBEEF, 32)) + v37) ^ BitVecVal(0xA5A5A5A5, 32)
v16 = BitVecVal(0xFFFFFFFF & (-2048144789), 32) * g(1)
v35 = rol32(g(5), 13) + v16
v13 = (BitVecVal(668265261, 32) * g(3)) ^ (g(8) + BitVecVal(2135587861, 32)) ^ v35
v34 = (rol32(g(9), 17) + v13) ^ BitVecVal(0x5A5AA5A5, 32)
v33 = g(3) ^ g(0) ^ BitVecVal(0x13579BDF, 32)
v32 = rol32(g(2), 7) + g(1)
for m in range(2):
    v9 = rol32((BitVecVal(m, 32) ^ BitVecVal(0x9E3779B9, 32)) - BitVecVal(2048144789, 32) * v32, 5 * m + 5)
    v30 = rol32(v32, 11) ^ v32 ^ v9 ^ v33
    v33, v32 = v32, v30
n191 = (rol32(v32, 11) + rol32(v33, 3)) ^ BitVecVal(0x5A5AA5A5, 32)

# 64 位 SplitMix64
v5 = BitVecVal(0x243F6A8885A308D3, 64)
for i in range(22):
    v5 = rol64(BitVecVal(0x9E3779B185EBCA87, 64) * (v5 ^ (ZeroExt(56, tb[i]) << (8 * (i & 7)))), 13)
tmp = BitVecVal(0xBF58476D1CE4E5B9, 64) * (v5 ^ LShR(v5, 30))
v3 = BitVecVal(0x94D049BB133111EB, 64) * (tmp ^ LShR(tmp, 27))
n161 = v3 ^ LShR(v3, 31)

s.add(n161 == BitVecVal(0x9B30518C600D26DD, 64))
s.add(Extract(31, 0, n161) == BitVecVal(1611474653, 32))
s.add(n191 == BitVecVal(1911915815, 32))
s.add(((v32 + v33) ^ BitVecVal(0xA5A5A5A5, 32)) == BitVecVal(2323396502, 32))
s.add(v34 == BitVecVal(4019606934, 32))
s.add(n172 == BitVecVal(1727223967, 32))
s.add(v42 == 0x50, v50 == 0x50, v51 == 0x43, v52 == 0x55, v53 == 0x0913)

assert s.check() == sat
m = s.model()
print(''.join(chr(m[c].as_long()) for c in ch))
```

## 变体与关联

- **建模变体**：`Int` 适合线性方程；带溢出/移位/循环移位必须用 `BitVec`；涉及有符号除法时用 `SDiv`。
- **哈希变体**：SplitMix64、MurmurHash、FNV、自定义 xtime 等都可按位复刻；关键是常量与移位顺序。
- **校验变体**：popcount、加权和、CRC、异或和、SIMD 风格聚合都可写成约束；约束越多解越唯一。
- **关联**：[[ctf-reverse-z3-constraint-equation-solve]]（Int 线性方程组版）、[[ctf-reverse-linux-junk-xor-embedded-elf-nand-circuit-z3]]（Z3 解 NAND 电路）、[[ctf-reverse-electron-asar-wasm-license-hash-collision-z3]]（Z3 联立哈希约束）。

## 检测与防御

- **CTF 性质**：这是逆向题求解方法，不是真实漏洞。
- **真实软件**：不要用可逆的位运算校验作为授权依据；使用带密钥的签名/MAC，并避免在客户端暴露完整校验逻辑。
- **检测**：对客户端校验器中的大量位运算与哈希常量，可评估其是否可被 SMT 求解；提高逆向成本不能替代服务端校验。
