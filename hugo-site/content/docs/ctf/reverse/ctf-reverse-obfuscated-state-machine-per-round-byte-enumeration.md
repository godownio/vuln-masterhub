---
id: ctf-reverse-obfuscated-state-machine-per-round-byte-enumeration
title: 混淆校验函数逐轮字节枚举：复刻状态机匹配目标字节表
type: scenario
domain: ctf
path: ctf/reverse
technique: obfuscated-state-machine-per-round-byte-enumeration
tags:
- ctf
- reverse
- state-machine
- byte-enumeration
- emulation
- obfuscation
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T10:01:20+08:00'
  notes: 已对照原文与图 08/10/12/14/16 核对：32 字节长度、KCTF{/}、sub_401890 前后缀检查、sub_401590 的 var_61 OR 归零条件、sub_401550 三段目标表（12+10+10）、逐轮枚举 0..255 均一致。卡片 PoC 为骨架（step 未实现），完整状态机需按原文/汇编复刻；未复跑。
url: /docs/ctf/reverse/ctf-reverse-obfuscated-state-machine-per-round-byte-enumeration/
draft: false
kb_aliases:
- 逐轮字节枚举
- 状态机复刻
- 混淆校验函数
- KrackM3
- 每轮目标字节
---

## 一句话结论

当校验函数是一个高度混淆的 32 轮状态机、但每轮只把当前输入字节与滚动状态混合成一个目标字节时，可以按汇编逐条复刻状态更新：对第 `i` 位枚举 `0..255`，计算该轮的输出低字节，使其等于从 `.rodata` 三段数组拼出的 `target[i]`，然后固化该字节和状态进入下一轮；复杂度只有 `32×256`。

## 原理

- **整体校验**：`main` 要求输入长度 32，`KCTF{` 前缀、`}` 结尾；`sub_401890` 检查前缀/后缀，`sub_401590` 是真正的混淆校验。
- **目标表**：`sub_401550(i, a2, a3, a4)` 按 `i<=11`、`12..21`、`22..31` 从三段 rodata 数组取值，拼成一张 32 字节目标表；`sub_401590` 调用 4 次（4 组常量），把每组结果按位 OR 到 `var_61/62/63/64`。
- **返回 1 的条件**：结尾 `cmp [var_61],0; setz al`，即 `var_61==0`；每轮 `xor eax, r13d; or [var_61], al`，所以每轮输出低字节必须等于 `target[i]`。
- **状态依赖**：每轮计算只依赖当前滚动状态（`r8/r9`、16 字节 `var48`、若干 lane）和当前输入字节；没有跨位置的全局哈希，因此可按位置贪心枚举。
- **为什么可行**：每轮 256 个候选，32 轮共 8192 次模拟；只要复刻的状态更新正确，正确字节一定使输出匹配。若某轮无解，说明状态更新/字节序/常量抄错，而不是需要回溯。
- **本题**：初始 `r8=0xB1EB4606F35CF7F9`、`r9=0x881DB3E005D90DFF`、`var48=xmmword_4022C0`；`sub_401320` 用 xorshift32（seed `0xF5A4ADA5`）做 Fisher-Yates 生成 256 置换/逆表；`sub_401480` 用固定 seed 生成 256 字节流；`sub_401590` 每轮混合 `stream`、`perm`、`rol8`/`ror8`、`×0x100000001B3` 等。

## 触发条件

- 输入长度固定（32），有 `KCTF{`/`}` 形式；`main` 里出现 `sub_xxx(s) == 1` 的真校验。
- 校验函数循环次数等于输入长度，每轮把当前字节与滚动状态混合，最后 OR 到一个变量并与 0 比较。
- `.rodata` 中能找到与输入等长的目标字节表（可能拆成多段）。
- 混淆很重，但每轮逻辑是确定性的、无随机/无外部输入。

## 利用步骤

1. 从 `main` 定位真校验函数、成功字符串和输入长度；确认前缀/后缀。
2. 找到 `sub_401550` 类“分段取表”函数，提取 32 字节 `target`。
3. 按汇编逐条复刻每轮状态：初始寄存器/16 字节状态、每轮的置换表/流表索引、rol8/ror8、乘法/异或、状态更新，以及下一轮 lane 的装载索引。
4. 对 `i=0..31`：
   - 已知位置（`KCTF{`、末尾 `}`）固定候选；
   - 其余枚举 `b=0..255`，用模拟器算 `v15_low`，等于 `target[i]` 则选定；
   - 固化 `b`，用该轮 `next_state` 进入下一轮。
5. 拼接输出；用程序本地运行/符号执行复验；若某轮无解，检查 `xmmword` 内存序、常量、`&0xF` 索引和状态更新顺序。
6. 动态调试可作为捷径：在比较分支读 `v16-v20`/目标字节，直接得到每轮期望值。

## PoC

```python
def step(state, i, b):
    """按汇编复刻一轮；返回 (v15_low, next_state)。"""
    # 这里只给骨架：具体状态更新需按题目汇编逐条翻译
    # r8/r9/var48/lanes -> 混合 -> v15_low
    # next_state 中的 lane 索引按 asm 的 (i+1)/(i+8)/(i+12)/(i+6)/(i+14) & 0xF
    raise NotImplementedError

def solve(target, prefix=b"KCTF{"):
    state = initial_state()          # 初始 r8/r9/var48/lanes
    out = bytearray()
    for i in range(32):
        if i < len(prefix):
            cand = [prefix[i]]
        elif i == 31:
            cand = [ord('}')]
        else:
            cand = range(256)
        for b in cand:
            v15, nxt = step(state, i, b)
            if v15 == target[i]:
                out.append(b); state = nxt; break
        else:
            raise RuntimeError(f"no solution at {i}")
    return bytes(out)
```

说明：PoC 是逐轮枚举骨架；完整 `step` 需按原文/汇编逐条复刻（包括 xorshift 置换表、256 字节流、`rol8/ror8`、`×0x100000001B3` 和 `xmmword` 端序）。未在本机对附件复跑。

## 变体与关联

- **动态捷径**：在每轮比较/写 `var_61` 处下断点，读目标/中间值；或 dump `v16-v20` 直接得到每轮字节。
- **符号执行**：angr 可对 32 轮状态机做符号求解，但复刻/动态通常更快。
- **目标表拆分**：`sub_401550` 的三段数组（12+10+10）要按索引正确拼接；边界 `<=`/`<` 容易错。
- **关联**：[[ctf-reverse-fjm-rv32-state-machine]]（状态机 + DFS）、[[ctf-reverse-memcmp-length-bug-state-machine-reward]]（菜单状态机 + reward 变换）。

## 检测与防御

- 识别：固定长度循环、每轮 `xor/or` 到累加变量、最后与 0 比较；`.rodata` 有等长目标字节表。
- CTF 防守：逐轮独立可枚举的状态机等价于 32 个独立 8-bit 约束，强度很低；应使用整体哈希/签名或 native 校验。
- 真实系统：混淆不能替代密码学；关键校验应在服务端/受保护硬件完成。
