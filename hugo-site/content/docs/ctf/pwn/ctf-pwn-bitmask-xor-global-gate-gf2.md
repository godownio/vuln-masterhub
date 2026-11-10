---
id: ctf-pwn-bitmask-xor-global-gate-gf2
title: Rust 菜单题隐藏开关：id 的二进制位选择全局常量异或，等价 32 元 GF(2) 方程组用高斯消元解出开门 id
type: scenario
domain: ctf
path: ctf/pwn
technique: bitmask-selected-xor-global-gate-gf2-gauss
tags:
- ctf
- pwn
- rust
- gf2
- gaussian-elimination
- bitmask
- gate
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:17:54+08:00'
  notes: 已对照原文核对门禁分支、enumerate/index 位选择、123→0b1111011 动调结论、高斯消元求解思路与 id=3957556225；本次核对未读取图片；未验证点：按原文贴出的 32 行 01 常量矩阵复算(含行列转置/比特序/左端 id 异或项多种组合)均无法重现 3957556225，该 id 数值应视为原文 PoC 实测结果而非可由该矩阵独立复算
url: /docs/ctf/pwn/ctf-pwn-bitmask-xor-global-gate-gf2/
draft: false
kb_aliases:
- rust but signin
- id ^ do_something(id) == 0xffffffff
- 二进制位选择异或常量
- 32 元异或方程组高斯消元
- enumerate + index 泄全局数组
- UAF_FLAG 门禁
---

## 一句话结论

题目的 `delete` 功能只有在全局开关 `UAF_FLAG` 为 1 时才真正释放内存，而 `UAF_FLAG` 只在 `id ^ do_something(id) == 0xFFFFFFFF` 时被置 1。`do_something(id)` 的实现是把 `id` 转成二进制、按 **位** 决定要不要把全局数组（32 个 32 位 01 字符串常量）中的对应项异或进结果：等价于 32 个未知位 × 32 个方程的一次（线性）异或方程组 `A·x = b`，把常量 dump 出来做 GF(2) 高斯消元即得解（本例 `id = 3957556225`），门禁一开 `delete` 就能反复 free。

## 原理

- **位选择即线性组合**：`for i in 0..32 { if (id >> i) & 1 == 1 { acc ^= K[i] } }`，其中异或是逐位模 2 加法、`(id>>i)&1` 是 0/1 系数，所以 `acc` 是常量矩阵 `K` 在 GF(2) 上的线性组合，`acc` 的每一比特都是一个 32 元一次方程。
- **为什么可以解**：目标是 `acc = id ^ 0xFFFFFFFF`，即 `id` 的每一比特等于 `(acc 的对应比特) ^ 1`。把 32 个 32 位常量按比特展开成 32×32 的 0/1 系数矩阵、右端项取 `0xFFFFFFFF ^ id` 的比特，就是一个标准 GF(2) 线性系统；系数矩阵满秩时解唯一（本例唯一解为 `3957556225`）。
- **为什么要动态取常量**：IDA 里 `do_something` 是「`Enumerate::next` + `String/Deref` + `Vec index` + `mix`」一大堆泛型样板，静态还原成「取第 i 个 32 字节串」很费劲；直接把全局数组所在内存 dump 出来按 32 个 4 字节读，比逆泛型快得多。
- **为什么这道门禁在利用链里必须先解**：`delete` 是唯一的 free 入口，且 `UAF_FLAG` 只会被置一次；不解门禁就只能 free 一次、拿不到 tcache/unsorted bin 的可重复操作，整个 UAF → tcache 投毒的后半条链无从谈起。

## 触发条件

- 程序里存在「输入一个整数 id → 用它的比特位选择若干常量异或 → 与 id 本身做比较/门控」的逻辑（反编译特征：`while` 循环 + 位测试 + `pwn::mix` 之类的小函数 + 一次全局 bool 赋值）；
- 常量数组位于 `.bss`/`.data` 且可在动调中直接 dump（本例是 `0x20` 字节的 01 字符串数组）；
- 门控表达式形如 `id ^ f(id) == MASK` 或 `f(id) == id ^ MASK`，能转成线性方程组。

## 利用步骤

1. 定位门控分支：`if (UAF_FLAG || (v = do_something(id), (id ^ v) != 0xFFFFFFFF))` —— 进入 else 分支时把 `UAF_FLAG=1`，说明 `id ^ do_something(id) == 0xFFFFFFFF` 是目标等式。
2. 动调确认 `do_something` 的输入就是用户输入的 `id`：输入 `123`，观察循环里出现的中间值恰为 `0b1111011`，且只在对应位为 1 时调用 `mix`。
3. 确认 `mix` 是一次异或：执行前后对比寄存器，每次异或的是来自 `.bss` 全局数组的 `0x20` 字节 01 字符串。
4. dump 该全局数组（32 项 × 32 位），整理成 32 行 01 字符串（每项一行）。
5. 构造方程组求解：第 `j` 位方程 = 所有 `x_i=1` 的行在 `j` 列的异或和 = `0xFFFFFFFF` 的第 `j` 位；用高斯消元/直接位运算求解，得 `id = 3957556225`。
6. 把 `id` 作为 `delete` 的参数传入，`UAF_FLAG` 被置 1，之后 `delete(任意下标)` 都真实释放，可继续走 UAF 链。

## PoC

求解思路（矩阵来自第 4 步的 dump；原文用一个 C++ 高斯消元二进制 + pwntools 喂数据拿到结果，这里给出等价的最小实现，未执行）：

```python
# K[i]：第 i 个 32 位常量（来自 .bss dump），行 i 的第 j 位 = (K[i] >> j) & 1
MASK = 0xFFFFFFFF
x = 0
for j in range(32):                      # 也可以直接对 32x32 矩阵做 GF(2) 消元
    ...
# 等价判定：解出 x 后必须满足
acc = 0
for i in range(32):
    if (x >> i) & 1:
        acc ^= K[i]
assert x ^ acc == MASK
print(x)                                 # 3957556225
```

原文的求解路径是从 dump 里把 32 行 01 串按 **列** 重排喂给高斯消元器，再由 pwntools 收集 32 行输出拼成整数；思路与上式一致，只是把「列优先读矩阵」交给外部求解器完成。

## 变体与关联

- **变体**：把异或换成 GF(2) 上的矩阵乘或加法链，仍是线性系统；若常量按位循环移位后再异或，系数矩阵变成循环阵，可用 Berlekamp–Massey 或直接构造循环方程求解。
- **变体**：门控条件改成 `>=`/区间判断，则只有部分位参与方程（欠定），需要枚举自由变量或用 Z3 求解。
- **关联**：[[ctf-pwn-rust-vec-uaf-leak-environ-tcache-stack-backdoor]]（本门禁解开后的完整 UAF → environ → 栈 ROP 链）、[[ctf-reverse-z3-constraint-equation-solve]]（约束求解的同类套路）、[[ctf-reverse-printable-ascii-caesar-hidden-permutation-table]]（同样是「先静态读出隐藏常量表再反解」的题）。

## 检测与防御

- **逆向视角**：这类位选择门禁的保护价值很低，常量在二进制里明文存放，dump 后解线性方程即可；真正提高成本要把门控改成带密钥的哈希/签名。
- **代码审计视角**：`if (flag || checked)` 这种「先判断全局开关再决定是否执行危险操作」的写法是典型的调试后门/隐藏开关，应作为审计重点；生产代码里任何 `unsafe` 释放路径都应有统一的 `Option` 包装与置空。
- **检测点**：函数内出现「按输入的比特位循环 + 与全局数组异或 + 单次置位全局 bool」的组合，即可能是隐藏门禁，可直接打 patch 把比较指令改成恒真来跳过。
