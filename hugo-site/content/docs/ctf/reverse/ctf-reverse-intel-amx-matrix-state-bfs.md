---
id: ctf-reverse-intel-amx-matrix-state-bfs
title: Intel AMX 矩阵乘法实现的状态机逆向：64 符号转移 + 行和约束 BFS
type: scenario
domain: ctf
path: ctf/reverse
technique: intel-amx-matrix-state-bfs
tags:
- ctf
- reverse
- intel-amx
- matrix
- state-machine
- bfs
- obfuscation
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:11:31+08:00'
  notes: 已对照原文 tiles+ai 段核对：AMX 指令、0x40f800/0x409000/0x40a000/0x40b000 表、64 符号、0x401b16 行和<2、0x412380 目标位均一致；BFS 结果未本机复现。
url: /docs/ctf/reverse/ctf-reverse-intel-amx-matrix-state-bfs/
draft: false
kb_aliases:
- tiles + ai
- AMX 逆向
- tdpbssd 矩阵状态机
- 稀疏状态 BFS
- Intel AMX 混淆
---

## 一句话结论

程序用 Intel AMX 指令（`ldtilecfg`/`tileloadd`/`tdpbssd`/`tilestored`）把输入 token 映射成 16×16 矩阵乘法，状态是一个 3 块的稀疏矩阵；每个 token 是 `[0-9a-fA-F][0-3]` 共 64 种，校验要求目标单元为 1 且前 36 行每行和 <2；把 AMX 更新逻辑重写成 NumPy 的 `step(state, token)` 后，用 BFS 即可搜出每轮的最短合法输入。

## 原理

- 二进制中可见 AMX 指令与硬编码矩阵表：`0x40f800` 三轮初始状态（每轮 `0x300` 字节）、`0x409000` 16 个 16×16 选择矩阵、`0x40a000` 16 个辅助矩阵、`0x40b000` 72 个 16×16 转移矩阵（2×4×3×3）。
- 输入解析：每行按两个字符一组，第一个是 hex digit（16 种），第二个只能是 `0-3`（4 种），共 64 个符号。
- 每个 token 执行 `0x40142b~0x401ae7` 的 AMX 更新：以 3×(16×16) block 状态为输入，选择一组矩阵做乘法，生成 next state 后覆盖 current state。
- 校验在 `0x401b16~0x401c50`：扫描状态前 `0x240` 字节（36 行），每行 16 字节求和必须 <2（near one-hot 约束）；再检查 `0x412380`（相对状态起点 `0x110`）是否为 1。
- 行和约束大幅剪枝，使 BFS 可行；不能只盯目标位，否则会找到不满足确定性约束的路径。

## 触发条件

- 拿到使用 AMX 的二进制，CPU 支持 AMX（否则程序直接 `Cannot run on this CPU`）。
- 能从反汇编/数据段提取初始状态与转移矩阵，或能在支持 AMX 的机器上动态跑 `step`。
- 输入字母表与校验逻辑可逆出。

## 利用步骤

1. `strings`/反汇编确认 AMX 指令与 `incorrect`、`flag.txt` 等字符串。
2. 定位输入解析（`0x401366`）、AMX 更新（`0x40142b~0x401ae7`）、校验（`0x401b16~0x401c50`）。
3. 提取初始状态与矩阵表，按 AMX 语义实现 `step(state, token)`（可用 NumPy 矩阵乘）。
4. 对每轮以初始状态为起点，64 个 token 为边做 BFS；丢弃行和 ≥2 的状态。
5. 找到满足目标单元 ==1 且确定性约束的路径，按顺序输入远端取 flag。

## PoC

```python
# 伪代码：AMX 更新等价为矩阵状态转移
state = init_state[round]          # 3 x (16x16) blocks
for tok in tokens:
    state = step(state, tok)       # 选择矩阵 -> block matmul -> next state
ok = (state_flat[0x110] == 1) and all(sum(row) < 2 for row in rows36(state))
```

```python
# BFS 框架
from collections import deque
q = deque([(init_state, b"")])
seen = {init_state}
while q:
    st, path = q.popleft()
    if accept(st):
        return path
    for tok in ALL_64_TOKENS:
        ns = step(st, tok)
        if valid(ns) and ns not in seen:
            seen.add(ns); q.append((ns, path + tok))
```

## 变体与关联

- 同类混淆可换成 AVX-512/VNNI、GPU shader 或自定义矩阵乘法；核心是“把指令语义翻译成状态转移 + 搜索”。
- 也可用 SAT/SMT 对状态转移建模，代替 BFS。
- 关联：[[ctf-reverse-custom-vm-masked-opcode-inverse-witness-recovery]]（自定义 VM 逆向）、[[ctf-reverse-self-modifying-vm-bytecode-z3-symbolic-execution]]（符号执行）。

## 检测与防御

- 这是逆向题型；防御上可提高状态空间、加入非线性/随机化，或使用不常见 ISA 增加分析成本。
- 检测：二进制中出现 AMX tile 指令与大量硬编码 16×16 矩阵。
