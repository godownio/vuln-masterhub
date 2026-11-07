---
id: ctf-reverse-int3-basic-block-cfg-recovery
title: int3 调度基本块的控制流混淆：父进程 ptrace 转储结构体并重建 CFG
type: scenario
domain: ctf
path: ctf/reverse
technique: int3-basic-block-cfg-recovery
tags:
- ctf
- reverse
- obfuscation
- int3
- ptrace
- cfg
- anti-debug
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:02:39+08:00'
  notes: 已对照原文与图 14-16 核对：fork+ptrace+SIGALRM、181×32 结构体、状态转移语义、拓扑排序与 int3 替换、AES 假随机一致；未复跑样本。
url: /docs/ctf/reverse/ctf-reverse-int3-basic-block-cfg-recovery/
draft: false
kb_aliases:
- int3 控制流
- 基本块结构体
- 父进程 ptrace
- 控制流恢复
- state_transfer_func
- tradre
---

## 一句话结论

样本把每个基本块的结尾换成 `int3`，由父进程通过 `ptrace` 观察子进程的 SIGTRAP，再按 32 字节结构体 `{false_branch, true_branch/call_addr, state_transfer_func, block_addr}` 决定下一步跳转，静态 CFG 因此被压成一条直线；把结构体数组从数据段转储出来、按状态转移函数做拓扑排序，再把每个 `int3` 替换为对应的 `ret/jmp/call/jcc` 并重定位 RIP 相对寻址，即可恢复原始控制流。

## 原理

- 主函数 `fork` 后父进程 `ptrace` 子进程；子进程执行到块尾 `int3` 触发 SIGTRAP，父进程 `wait` 后 `PTRACE_PEEKDATA(rip-1)` 检查是否为 `0xCC`，不是就 kill，形成反调试/反篡改。
- 每个基本块对应一个结构体：`false_branch`、`true_branch`/`call_addr` 联合、`state_transfer_func`、`basic_block_addr`。状态转移函数返回值含义：`1/0` 条件跳转的真/假分支；`2` 作者模拟的 `ret`（额外维护一个栈）；`3` 兼容原版的库函数 `call`；`4` 作者实现的 `call`；`5` `switch`。
- 因为跳转由父进程根据结构体决定，子进程代码里只有直线执行 + `int3`，反编译器看不到分支；恢复时必须先转储结构体，把每个块的“后继”还原成图。
- 恢复算法：从结构体数组按地址建图；`ret` 为叶子，`call` 只沿返回路径走；DFS 排拓扑序。逐块反汇编，遇到 `int3` 时按 `state_transfer` 生成 `ret/jmp/call/jcc`；若拓扑序后继与原 fallthrough 不同，插入一条 `jmp`。最后重定位所有 RIP 相对操作数与跳转目标，写回可执行文件。
- 本题恢复后看到 `srand(0x10000)` 生成的假随机 XOR 掩盖的标准 AES，再按 `rand()` 序列还原 key 与密文。

## 触发条件

- 样本使用 `int3`/信号/`ptrace` 调度基本块，代码呈“直线 + 大量 int3”形态。
- 数据段存在固定布局的结构体数组（本题 181×32 字节），每个结构体含两个分支指针、状态函数与块地址。
- 可以静态 dump 数据段或动态读内存，并允许 patch/重定位生成可执行文件。

## 利用步骤

1. 先补丁 `alarm(60)` 等反调试（如把超时改成 `0xffffffff`），便于单步/静态分析。
2. 定位结构体数组（本题 `0x606AC0`），按 `<Q false_branch, Q true/call, Q state_fn, Q block_addr>` 解析 181 项。
3. 建立 `state_fn` 地址到语义的映射（如 `0x401EB4→CALL`、`0x401EA5→EXT_CALL`、`0→JMP`、`0x401CA6→JLE`、`0x401D22→JNE` 等）。
4. DFS 拓扑排序：`CALL/EXT_CALL` 走 `false_branch`（返回路径），`JMP` 走 `true_branch`，`RET` 停止，条件跳转先 `false` 后 `true`。
5. 反汇编原 `.text`；对每个块末尾 `int3`，用 Keystone 生成对应指令（`ret/jmp/call/jcc`），目标先写占位符并记录重定位。
6. 若下一拓扑块不是原 fallthrough，插入 `jmp`；随后重定位 RIP 相对操作数与分支目标，把恢复字节写回文件并 NOP 掉旧代码。

## PoC

```python
import struct
from capstone import Cs
from keystone import Ks

buf = open("dump.bin", "rb").read()
bbs = {}
for off in range(0, 32 * 181, 32):
    false_br, true_br, state_fn, addr = struct.unpack_from("<QQQQ", buf, off)
    bbs[0x606AC0 + off] = dict(false=false_br, true=true_br, fn=state_fn, addr=addr)

# 状态函数 -> 指令语义（按实际样本映射）
CALL, EXT_CALL, JMP, RET = 0x401EB4, 0x401EA5, 0x0, 0x401E96
JCC = {0x401CA6: "jle", 0x401D22: "jne", 0x401D5B: "je",
       0x401DCD: "jns", 0x401F0C: "jg", 0x401C31: "jl"}

topo, seen = [], set()
def dfs(bb):
    if bb["addr"] in seen:
        return
    seen.add(bb["addr"]); topo.append(bb)
    if bb["fn"] == RET:
        return
    if bb["fn"] in (CALL, EXT_CALL):
        dfs(bbs[bb["false"]])
    elif bb["fn"] == JMP:
        dfs(bbs[bb["true"]])
    else:
        dfs(bbs[bb["false"]]); dfs(bbs[bb["true"]])

for bb in bbs.values():
    dfs(bb)

# 之后：逐块反汇编，遇 int3 按 bb["fn"] 生成指令；
# 用 ks.asm 写占位目标，记录 (new_va -> target) 重定位；
# fallthrough 不一致时插入 jmp；最后统一回填分支/RIP 相对位移。
```

说明：这是原文恢复脚本的最小骨架；完整实现还需要 Capstone 反汇编、Keystone 汇编、RIP 相对操作数替换与目标地址重定位。未在本机复跑原样本。

## 变体与关联

- **控制流平坦化**：OLLVM 等用 dispatcher 状态变量 + switch 实现，思路相同但结构体/状态机不同；本卡是“信号驱动 + 结构体表”的变体。
- **VM 保护**：若块由字节码解释器调度，应提取 opcode/VM ISA；见 [[ctf-reverse-custom-python-vm-bytecode-disassembler]]。
- **反调试**：`SIGALRM` 超时、`ptrace` 自调试、`int3` 检测常组合出现；先补丁再恢复。
- **重定位**：恢复后必须处理 RIP 相对寻址与 `call/jmp` 目标，否则打补丁后的程序仍会崩溃。

## 检测与防御

- 检测：代码中出现大量 `0xCC`、父进程 `ptrace` 子进程、SIGTRAP 处理、数据段存在函数指针/块地址表。
- 分析：先 dump 调度结构体，再按语义重建 CFG；动态调试时注意父进程的反篡改检查。
- 防御（对恶意样本）：此类混淆会显著增加分析成本，但不是不可逆；应结合动态轨迹与结构体转储。
