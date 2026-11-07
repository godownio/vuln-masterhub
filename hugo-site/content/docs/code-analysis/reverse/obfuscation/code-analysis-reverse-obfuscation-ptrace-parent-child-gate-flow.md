---
id: code-analysis-reverse-obfuscation-ptrace-parent-child-gate-flow
title: ptrace 父进程改写子进程门函数控制流：int3 gate + 加密节点表调度
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: ptrace-parent-child-gate-obfuscation
tags:
- reverse
- obfuscation
- ptrace
- int3
- control-flow
- parent-child
- anti-analysis
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T01:59:50+08:00'
  notes: 已对照原文Yield段与图10/12核对：fork+PTRACE_TRACEME+raise(SIGSTOP)、父进程PTRACE_PEEKDATA校验RIP-1为0xCC、byte_403140解密公式与12字节raw_node、action 1-6分派、成功/失败路径均一致。未验证点：解密PoC未本机复跑，原文未给完整180字节密文；frontmatter无sources/source_url。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-ptrace-parent-child-gate-flow/
draft: false
kb_aliases:
- Yield
- 父子进程 ptrace
- int3 gate 调度
- 父进程改写 RIP
- 加密节点表
- 门函数控制流
- PTRACE_SETREGS
---

## 一句话结论

程序 fork 后子进程 `PTRACE_TRACEME` 并 `SIGSTOP`，父进程接管并在每个 `int3` gate 的 `SIGTRAP` 处用 `PTRACE_GETREGS/SETREGS` 改写子进程 RIP 与栈顶返回地址，按加密节点表 `byte_403140` 决定下一条 gate、调用哪个 op、成功或失败；静态看到的 `gate0→gate1→…` 线性控制流是假的，真实控制流要解密节点表后重建。

## 原理

- 子进程先 `ptrace(PTRACE_TRACEME)`，再 `raise(SIGSTOP)`；父进程 `waitpid` 等到停止后 `PTRACE_CONT` 让子进程继续。
- 每个 `gateX` 只是 `int3; ret` 的 stub；执行到 `int3` 触发 `SIGTRAP`，父进程 `waitpid` 拿到状态，`PTRACE_GETREGS` 读取子进程寄存器。
- 父进程先验证 `RIP-1` 处的字节是否为 `0xCC`（`PTRACE_PEEKDATA`），防止子进程被其他断点/信号干扰。
- 节点表 `byte_403140` 加密存储，解密公式：`key = (0x6D + i*37 + ((i>>1) ^ 0x5A)) & 0xFF; plain[i] = enc[i] ^ key`；每 12 字节解析为一个 `raw_node {gate_id, op_id, ret_gate, action, next_true, next_false, imm16, imm32}`。
- 父进程按 `action` 分派：
  - `1`：调用 `op_id` 对应的 op，设置下一条 gate；
  - `2`：比较 `(RAX & 3) == imm16`，真/假走不同 next；
  - `3`：比较 `(uint32_t)RAX == imm32`；
  - `4`：执行运行时 patch；
  - `5`：失败；`6`：成功。
- 改写 `RIP`/栈顶后 `PTRACE_SETREGS` + `PTRACE_CONT`，子进程从父进程指定的下一条 gate 继续；因此真实路径是节点表驱动的图，而不是源码顺序。
- 解题时先 dump/解密节点表，重建 gate 图，识别各 op 的变换，再逆向 op 链求输入。

## 触发条件

- Linux ELF，`main` 中可见 `fork`、`ptrace(PTRACE_TRACEME)`、`raise(SIGSTOP)`、`waitpid`、`PTRACE_GETREGS/SETREGS/CONT`。
- 子进程包含多个只执行 `int3; ret` 的 gate 函数，源码顺序与真实路径不符。
- 有一张加密/混淆的节点表（本例 `byte_403140`）与 op 函数表。
- 调试器/静态分析看到的是线性调用，但运行时行为由父进程决定。

## 利用步骤

1. 在 `main` 中定位 fork/ptrace 逻辑，确认父子进程角色与 gate 列表。
2. 找到节点表地址/长度与解密函数，按公式解密出 `raw_node` 数组。
3. 以 `gate_id` 为节点、`next_true/next_false` 为边重建控制流图，标出 action=1/2/3/4/5/6 的语义。
4. 从成功节点（action=6）反向回溯，得到成功路径上的 op 序列与比较条件。
5. 逆向每个 op（本例 op_a/op_b/op_c/op_d/op_e），注意可逆变换、环形加法/异或的自由度与 checksum 条件。
6. 从目标值反向执行 op 链，枚举 1 字节自由度，用可打印 ASCII、`flag{` 前缀、`}` 结尾、checksum 低两位等条件筛选唯一解。
7. 动态验证：在 gate 处下断点或 patch 父进程调度，观察实际 op 调用顺序与寄存器值。

## PoC

```python
def decrypt_nodes(enc, n=15):
    plain = bytes(
        enc[i] ^ ((0x6D + i * 37 + ((i >> 1) ^ 0x5A)) & 0xFF)
        for i in range(n * 12)
    )
    nodes = []
    for i in range(n):
        b = plain[i*12:(i+1)*12]
        nodes.append({
            "gate": b[0], "op": b[1], "ret": b[2], "action": b[3],
            "next_true": b[4], "next_false": b[5],
            "imm16": int.from_bytes(b[6:8], "little"),
            "imm32": int.from_bytes(b[8:12], "little"),
        })
    return nodes

# 从 action=6 的成功节点反向遍历 next_true/next_false，得到 op 链
# 再按 op 的逆变换从 target 反推输入
```

案例成功路径：`gate0→op_a→gate1→op_b→gate2→op_c→gate3→checksum→gate4→gate5→patch→gate6→op_d→gate7→op_e→gate8→compare→gate9→gate10→success`；失败路径为 gate11/12/13 的 fake op。

## 变体与关联

- 变体：父进程也可用 `PTRACE_POKETEXT` 直接改子进程代码，而不只是改寄存器；或使用 `process_vm_writev`。
- 变体：节点表可能用多层 XOR/RC4/哈希混淆；先定位解密函数再 dump。
- 变体：其他父子进程控制流隐藏（fork+pipe、信号、共享内存）可用类似“找调度器→还原图”的思路。
- 关联：[[code-analysis-reverse-obfuscation-x86-64-instruction-overlap-dual-stream]]（控制流隐藏）、[[code-analysis-reverse-obfuscation-jz-skip-e8-junk-ida-repair]]（花指令）、[[binary-pwn-stack-sigaltstack-ucontext-sigreturn-hijack]]（信号/上下文劫持）。

## 检测与防御

- 防御：不要用 ptrace 父子进程作为唯一保护；结合代码完整性校验、反调试检测与控制流平坦化。
- 防御：节点表加密密钥不要硬编码；对关键比较使用密码学哈希而非可逆变换。
- 检测：进程出现 `PTRACE_TRACEME`/`PTRACE_SETREGS` 与大量 `SIGTRAP`；父子进程共享内存/管道异常；gate 函数只含 `int3; ret`。
- 响应：发现控制流混淆后，动态跟踪父进程调度并 dump 节点表；评估是否有反调试/反虚拟机逻辑。
