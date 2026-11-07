---
id: ctf-reverse-time-seed-shuffle-mix-bruteforce-mtime
title: time(0) 时间种子 + 双轮 65537 次洗牌与自定义 mix：按样本 mtime 窗口爆破 seed 并逆变换
type: scenario
domain: ctf
path: ctf/reverse
technique: time-seeded-shuffle-mix-inverse-bruteforce
aliases:
- Interstellar
- 时间戳种子爆破
- mtime 恢复 seed
- 逆置换 + 逆混合
- 48 字节 flag 变换
tags:
- ctf
- reverse
- prng
- lcg
- permutation
- timestamp
- md5
- bruteforce
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T11:47:10+08:00'
  notes: 已对照原文 Interstellar 及图39/41/43/45/47/49/51/53/55 核对：time(0) 种子、48 字节小端 int32、staralgoiU K 三常量 LCG、两轮各 65537 次交换、4 组三元组 65537 轮 mix、mtime ±1h 爆破、seed 1764108097 与 flag 均一致。未验证点：未编译运行 Rust/Python solver。
---

## 一句话结论

加密只依赖 `time(0)` 种子：48 字节输入被拆成 12 个 int32，先做两轮各 65537 次的 LCG 驱动交换，再对 4 组三元组做 65537 轮自定义可逆 mix。种子本身不可从密文直接恢复，但密文是在样本生成时运行的，按二进制文件 mtime 取 ±1 小时窗口枚举 `time(0)`，对每个候选逆置换、逆 mix，再用 MD5 目标值验证即可得到唯一 seed 和明文。

## 原理

- **seed 来源**：`main_program_0` 调用 `time(0)` 并通过 `get_int` 读取，存入全局变量，后续洗牌全部依赖它；种子只有约 31 位，且与样本生成/运行时刻强相关。
- **数据打包**：读入 48 个字符，按小端打包成 12 个 int32：`packed = c0 | c1<<8 | c2<<16 | c3<<24`；后续所有变换都以 int32 为单位。
- **LCG 变体**：常量来自字符串 `"staralgoiU K"` 的小端 4 字节切分：
  - `a = 0x72617473`（`star`）
  - `c = 0x6f676c61`（`algo`）
  - `m = 0x4b205569`（`iU K`）
  - 状态更新：`tmp = (a*state + c) mod 2^32`（按 int32 溢出），`state = tmp % m`，负数修正到 `0..m-1`。
- **两轮洗牌**：每轮连续调用两次 LCG，得到 `i = state % 12`、`j = state % 12`，交换 `idx[i]` 与 `idx[j]`，重复 65537 次；两轮使用同一 LCG 状态链。记录交换顺序即可得到最终置换 `new[pos] = old[idx[pos]]` 及其逆。
- **自定义 mix**：12 个 int 分成 4 组（`a[0..2]`、`a[3..5]`、`a[6..8]`、`a[9..11]`），每组独立做 65537 轮：
  - 每轮先更新常量 `t*=p0; p0*=p1; p1*=t`（32 位回绕）；
  - 再依次更新 A、B、C，每次使用乘常数、C 语义的截断除法（`/13`、`/29` 等）与 XOR；A/B/C 的更新顺序使每步都依赖前一步结果。
- **可逆性**：洗牌是置换，逆置换即可还原；mix 每轮只是“加上一个由当前变量计算出的值”，逆过程按 C→B→A 的顺序减回即可，除法只依赖尚未被该步修改的变量，因此可精确复算。
- **为什么用 mtime**：样本作者生成密文时必然运行过程序，运行时刻通常接近文件编译/打包时间；`LastWriteTime` 给出秒级线索，±1 小时窗口通常只有几千个候选，逐个逆变换 + MD5 验证成本很低。
- **MD5 作用**：作为唯一的“是否正确”判据；没有它，逆变换结果可能看起来像随机字节，无法确定哪个 seed 命中。

## 触发条件

- 二进制中调用 `time(0)`/`time(NULL)` 并用其返回值初始化 PRNG 或置换。
- 加密过程只包含可逆的置换、加减、XOR、乘法与除法，没有单向哈希（哈希只用于最终校验）。
- 程序或样本带有可读的文件时间、编译时间戳，或已知密文生成的大致日期。
- 校验端保存固定长度的 MD5/SHA 目标值。

## 利用步骤

1. 反编译入口，确认 `time(0)` 被读入并参与后续所有变换；记录迭代次数（示例 65537）与数组维度（12）。
2. 从字符串/常量恢复 LCG 参数与 mix 常量，注意 int32 回绕和 C 的向零截断除法（Python `//` 是向下取整，负数时会不同）。
3. 实现正向变换，用任意 seed 验证能与程序行为一致；再实现逆置换与逆 mix。
4. 读取样本文件的 `LastWriteTime`，转 UNIX 秒后取 `±3600` 窗口；若文件被压缩包解压导致时间漂移，扩大窗口或改用 PE 编译时间戳、样本目录时间。
5. 对窗口内每个 seed 执行逆变换，计算 MD5 与目标比较；命中后输出 seed 与明文。
6. 若 MD5 不匹配，检查：种子是否被 `& 0xFFFFFFFF`/符号扩展、洗牌轮数是否两轮、mix 除法是否截断、字节序是否小端。

## PoC

```python
import hashlib, struct

CT = [961328601, 940839751, 705572502, -1296360751, 1510741316, -746016568,
      1758503669, -312360224, 1117958716, -1263168281, -1534151026, -1968871781]
TARGET_MD5 = bytes.fromhex("2887941ed3ea0f6b7ca870cd11f0de13")
ITERS = 0x10001

def s32(x):
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x & 0x80000000 else x
def u32(x): return x & 0xFFFFFFFF
def add(a, b): return s32(u32(a) + u32(b))
def sub(a, b): return s32(u32(a) - u32(b))
def mul(a, b): return s32(u32(a) * u32(b))
def xor(a, b): return s32(u32(a) ^ u32(b))
def div0(a, d):                      # C 语义：向零截断
    q = abs(a) // abs(d)
    return q if (a >= 0) == (d >= 0) else -q

def lcg(state):
    a, c, m = 0x72617473, 0x6f676c61, 0x4b205569
    return s32(u32(a * s32(state) + c)) % m

def perms(seed):
    def one(st):
        idx = list(range(12))
        for _ in range(ITERS):
            st = lcg(st); i = st % 12
            st = lcg(st); j = st % 12
            idx[i], idx[j] = idx[j], idx[i]
        return st, idx
    st, idx1 = one(s32(seed)); st, idx2 = one(st)
    def inv(idx):
        r = [0] * 12
        for pos, old in enumerate(idx):
            r[old] = pos
        return r
    return inv(idx1), inv(idx2)

def unshuffle(arr, inv):
    return [arr[inv[i]] for i in range(12)]

STATES = []
t, p0, p1 = 1924939505, 396307405, 1601708927
for _ in range(ITERS):
    t, p0, p1 = mul(t, p0), mul(p0, p1), mul(p1, t)
    STATES.append((t, p0, p1))

def unmix(a, b, c):
    for t, p0, p1 in reversed(STATES):
        s0 = xor(add(mul(406831633, a), div0(b, 17)), add(mul(1648306586, a), div0(b, 23)))
        s1 = xor(add(p1, a), sub(b, p1))
        c = sub(c, xor(s0, s1))
        s0 = xor(add(mul(666086835, c), div0(a, 11)), add(mul(1361690111, c), div0(a, 19)))
        s1 = xor(add(p0, c), sub(a, p0))
        b = sub(b, xor(s0, s1))
        s0 = xor(add(mul(1126760380, b), div0(c, 13)), add(mul(660328234, b), div0(c, 29)))
        s1 = xor(add(t, b), sub(c, t))
        a = sub(a, xor(s0, s1))
    return a, b, c

def decrypt(seed):
    inv1, inv2 = perms(seed)
    arr = unshuffle(CT, inv2)
    for base in (0, 3, 6, 9):
        arr[base:base + 3] = unmix(*arr[base:base + 3])
    arr = unshuffle(arr, inv1)
    return b"".join(struct.pack("<i", x) for x in arr)

# t0 由样本 mtime 转成 UNIX 秒；示例窗口 ±1 小时
for seed in range(t0 - 3600, t0 + 3600 + 1):
    pt = decrypt(seed)
    if hashlib.md5(pt).digest() == TARGET_MD5:
        print("seed =", seed)
        print(pt.decode())
        break
```

示例中最终 seed 为 `1764108097`，明文为 `flag{4waK1nG_1nTh3_L1gH7_0fA1LThE_s74r5_a1igNeD}`。

## 变体与关联

- 本库已有“勒索样本 CRC32 ^ time(0) 作为 MT19937 种子、从加密文件 mtime 恢复时间”的卡片；本卡的区别是种子直接来自 `time(0)`，且核心在双轮洗牌与三轮 mix 的逆变换。
- 其他时间源：`GetTickCount`、`clock()`、`rdtsc`、`std::chrono::system_clock`；若种子由多个值组合，先恢复各分量的可能范围再爆破。
- 若种子是 `srand(time(0))` + `rand()`，直接复刻 glibc/MSVC 的 PRNG 实现；若种子被哈希包裹，先确认哈希是否可逆（通常不可逆，只能爆破）。
- 文件时间可能被 ZIP 解压、Git checkout、容器拷贝改写；可同时尝试 PE `TimeDateStamp`、样本内嵌日期字符串、题目发布日期作为窗口中心。

## 检测与防御

- 检测特征：程序调用 `time()` 后紧接 PRNG/置换初始化；循环次数为 65536/65537 等 2 的幂附近；密文长度固定且校验端保存 MD5。
- 防御（真实系统）：不要把时间戳直接当密钥或种子；使用 CSPRNG 生成随机密钥，并对密文做 HMAC；若必须用时间，至少混入高熵 secret 并避免可预测的窄窗口。
- CTF 中遇到“逆变换结果无法判定”时，优先寻找最终哈希/比较目标，用其作为爆破 oracle；不要试图目测明文。
