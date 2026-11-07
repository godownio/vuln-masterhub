---
id: crypto-prng-glibc-rand-small-seed-bruteforce
title: glibc rand() 小种子空间爆破：复现 31/3 状态初始化，逐字节匹配首个输出还原 flag
type: scenario
domain: crypto
path: crypto/prng
technique: glibc-rand-small-seed-bruteforce
tags:
- prng
- glibc
- rand
- seed-bruteforce
- ctf
- reversing
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:40:34+08:00'
  notes: 已对照原文与图片24/26核对：scanf %c→srand、check 数组、31/3 初始化与首输出>>1 一致；PoC 未在本库复跑。
url: /docs/crypto/prng/crypto-prng-glibc-rand-small-seed-bruteforce/
draft: false
kb_aliases:
- glibc random 种子爆破
- srand 1 字节种子
- rand() 首个输出匹配
- 31/3 状态数组
- FlagCasino
---

## 一句话结论

当二进制用 `srand(seed)` 播种 glibc `rand()`，而 seed 只有 1 字节（或很小）时，可以复现 glibc 的 31/3 加法反馈初始化算法，对每个目标输出枚举 0–255 的 seed，找到“首个 `rand()` 输出等于该目标值”的 seed，再把 seed 当作 ASCII 字符拼出 flag；不需要破解 31 位状态，只需穷举 256 个种子。

## 原理

- **glibc `random()` 状态初始化**：`srand(seed)` 把种子写入 31 个 32 位状态；简化实现（Peter Selinger）为：
  - `r[0] = seed`
  - `r[i] = (16807 * signed(r[i-1])) % 2147483647`（i=1..30；`signed` 把 32 位无符号转有符号）
  - `r[31..33] = r[0..2]`
  - `r[i] = (r[i-31] + r[i-3]) mod 2^32`（i=34..344）
  - 首个输出 `rand() = r[344] >> 1`
- **种子空间小**：本例 `seed` 通过 `scanf("%c", &seed)` 读入 1 字节（0–255），然后 `srand(seed)`；程序循环 `if (rand() != check[i])` 检查每个目标值。目标 `check` 数组的 32 位值超出 0x7FFFFFFF，说明不是简单的 31 位 LCG，而是 glibc `random()` 的完整状态。
- **逐字符匹配**：对每个 `check[i]`，枚举 `seed=0..255`，计算 `first_random_output(seed)`，与目标比较；命中即得到该字符的 ASCII（seed 本身）。所有目标唯一对应一个种子字符，拼接即 flag。
- **为什么可行**：种子只有 8 位，穷举成本 256 × 29 次计算；PRNG 确定性使“同种子 → 同首输出”，目标值就是 seed 的指纹。
- **与输出序列预测的区别**：输出预测需要 ≥31 个连续输出恢复内部状态；本手法是“已知目标输出、穷举小种子”，适用于种子宽度小、输出可对照的场景。

## 触发条件

- 目标使用 glibc `rand()`/`random()`，`srand(seed)` 的 seed 来自小空间（1 字节、时间窗口、PID 范围等）。
- 程序把 `rand()` 输出与硬编码/可观察的目标值比较（如 check 数组、验证码、口令）。
- 能拿到二进制/反汇编，确定 seed 读取宽度与比较逻辑；或能黑盒枚举种子并观察是否通过。
- 目标 libc 的 `rand()` 算法与 glibc 一致；不同 libc 需调整初始化参数。

## 利用步骤

1. 反汇编/反编译，定位 `srand`/`rand` 调用，确认 seed 来源（`%c`、`atoi`、`time`、`getpid`）与取值范围。
2. 找到比较逻辑（如 `if (rand() != check[i])`）与 `check` 数组；提取所有目标值。
3. 按 glibc 算法实现 `first_random_output(seed)`：31 个初始状态、31/3 反馈、`>>1`。
4. 对每个目标值枚举 seed 范围（0–255 或更宽），记录匹配的 seed；若多个 seed 命中，用第二个输出/上下文消歧。
5. 把命中的 seed 转成 ASCII 字符，按 `check` 数组顺序拼接；检查 `HTB{...}`/`flag{...}` 格式。
6. 若程序直接接受 seed 作为输入而非比较输出，可反向用目标字符构造输入序列。

## PoC

```python
MOD31 = 2147483647
MOD32 = 2 ** 32

def first_random_output(seed: int) -> int:
    r = [0] * 345
    r[0] = seed & 0xFFFFFFFF
    for i in range(1, 31):
        prev = r[i - 1]
        signed_prev = prev - (1 << 32) if prev & (1 << 31) else prev
        r[i] = (16807 * signed_prev) % MOD31
    for i in range(31, 34):
        r[i] = r[i - 31]
    for i in range(34, 345):
        r[i] = (r[i - 31] + r[i - 3]) % MOD32
    return (r[344] & 0xFFFFFFFF) >> 1

check_hex = [
    "244B28BE", "0AF77805", "110DFC17", "07AFC3A1", "6AFEC533",
    "4ED659A2", "33C5D4B0", "286582B8", "43383720", "055A14FC",
    "19195F9F", "43383720", "63149380", "615AB299", "6AFEC533",
    "6C6FCFB8", "43383720", "0F3DA237", "6AFEC533", "615AB299",
    "286582B8", "055A14FC", "3AE44994", "06D7DFE9", "4ED659A2",
    "0CCD4ACD", "57D8ED64", "615AB299", "22E9BC2A",
]
checks = [int(x, 16) for x in check_hex]

flag = "".join(
    chr(next(s for s in range(256) if first_random_output(s) == target))
    for target in checks
)
print(flag)  # HTB{r4nd_1s_v3ry_pr3d1ct4bl3}
```

## 变体与关联

- **时间种子**：seed 为 `time(NULL)` 时，枚举时间窗口（如比赛前后数小时）而非 0–255；见 [[crypto-prng-srand-time-seed-2fa-code-prediction]]。
- **PID 种子**：seed 为 `getpid()` 时，枚举进程号范围；可结合 `/proc` 或服务重启时间缩小窗口。
- **输出序列预测**：若拿得到 ≥31 个连续输出，用 31/3 递推恢复状态，不必穷举种子；见 [[crypto-prng-glibc-rand-output-sequence-prediction]]。
- **其他 libc**：musl/BSD 的 `rand()` 算法不同，需按其状态初始化重写。
- **关联卡片**：[[crypto-prng-urandom-open-fail-fixed-srand-sequence]]（种子退化）；[[ctf-pwn-unseeded-rand-array-oob-bound-overwrite-ret2win]]（未播种 rand 门控）。

## 检测与防御

- **不要用小种子**：安全敏感值使用 CSPRNG（`getrandom`/`/dev/urandom`/`secrets`），不要用 `rand()`/`srand(time)`。
- **种子空间**：若必须用 PRNG，使用至少 128 位随机种子；不要用 1 字节/PID/时间等可枚举值。
- **检测**：二进制出现 `srand`/`rand` 且 seed 来自 `%c`/`time`/`getpid`；验证码/口令/令牌可被枚举匹配；对关键比较做速率限制。
- **加固**：把校验放在服务端，使用 HMAC/签名而非可预测随机数；不要硬编码可枚举的目标输出。
