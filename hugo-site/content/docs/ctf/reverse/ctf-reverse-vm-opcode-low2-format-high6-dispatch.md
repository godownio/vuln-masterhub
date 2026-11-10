---
id: ctf-reverse-vm-opcode-low2-format-high6-dispatch
title: VM 题 opcode 编码还原：首字节低 2 位选操作数解析格式（1 字节/2 字符/字符+qword/3 字节大端拼装）、高 6 位选 handler
type: scenario
domain: ctf
path: ctf/reverse
technique: vm-opcode-low2-format-high6-dispatch
tags:
- ctf
- reverse
- vm
- opcode
- ida
- struct-recovery
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:53:26+08:00'
  notes: 已对照原文核对 mmap 三段固定地址、主循环 (*s&3) 分派与 memset 0xC、menu 中 b2=b1&3 分支赋 int1-int2、fmt=0 的 3 字节大端循环拼装、function_3 的 switch(b1>>2) 各 case 语义(case3 reg=imm、12~14 读 data、15~17 写 data、1/2 比较置 FLAG)均与原文伪代码一致；未验证点：fmt=3 的 int1>>5 合法性校验系按伪代码推理、编码器为作者重写未实测。另修正 1 处失效关联链接指向本批 heap 卡。
url: /docs/ctf/reverse/ctf-reverse-vm-opcode-low2-format-high6-dispatch/
draft: false
kb_aliases:
- VM opcode 逆
- 低两位 bit 解析
- opcode 高六位 case
- VM 结构体修复
- 反编译伪代码修复成 st 结构
- vmcode 解析格式
---

## 一句话结论

这类 VM 题的操作码是「首字节自描述」的：`opcode = (case << 2) | fmt`，**低 2 位 `fmt`** 决定后面跟多少字节、按什么方式拼成操作数（`fmt=0` 取 3 字节大端拼成一个整数、`fmt=1` 取 1 字节、`fmt=2` 取 2 个字节、`fmt=3` 取 1 字节索引 + 8 字节 qword 立即数），**高 6 位 `case`** 决定分派到哪个 handler（寄存器运算 / 数据段读写 / 建表调用）；只要把「取码函数」按这个规律重建成一个 `{b1,b2,b3,int1,int2}` 结构体，几百行的 `*(a1+8)` 地址运算伪代码会立刻变成可读的 `mov reg, imm`、`add reg, imm` 之类，随后就能自己写编码器生成任意 opcode 流。

## 原理

- IDA 看不清的原因是编译器把结构体访问摊平成指针偏移：`*(a1 + 8)` 是 `vmcode_pos`、`a1->reg[...]` 是寄存器数组、`a1->FLAG` 是标志位、`a1->data[...]` 是虚拟数据段。伪代码里满屏 `v2 = *(unsigned __int8 **)(a1 + 8); *(_QWORD *)(a1 + 8) = v2 + 1;` 其实就是「读一字节并 `vmcode_pos++`」。
- 取码函数的真实结构：先取 1 字节到 `s->b1`，`s->b2 = s->b1 & 3`（格式位）；再按 `s->b2` 分支填充 `int1`/`int2`。`fmt=3` 里还有一层 `if (!shr_5(int1))` 判断——那是「高 5 位为 0 时才是合法的 fmt=3 形态」，否则拒绝/退出，说明作者用 `int1>>5` 做了合法性校验。
- `fmt=0` 的拼装是**大端**循环：`for i in 0..2 { int1 <<= 8; int1 |= *vmcode_pos++; }`，于是 3 字节 `[hi][mid][lo]` 拼成一个 24 位以内的整数；编码时顺序必须是 `p8(int1>>16) + p8((int1>>8)&0xff) + p8(int1&0xff)`。
- handler 侧用 `case = b1 >> 2` 做 `switch`：`case 3` 是 `reg[i] = imm`（mov）、`4` 是 `reg[i] ^= imm`、`5` 是 `or`、`6` 是 `and`、`7` 是 `shl`、`8` 是 `shr`、`10` 是 `add`、`11` 是 `sub`、`12..14` 是「从 data 段读」、`15..17` 是「向 data 段写」，`case 1/2` 是比较并置标志位（`FLAG = reg < imm` 或 `2`）。
- 为什么这套编码必然存在「格式位」：一个 VM 既要支持「寄存器 + 立即数」（需要大立即数，如指针/qword）又要支持「寄存器 + 寄存器」（只需小索引），用一个字节塞不下两种宽度，于是把「宽度/形态」塞进首字节的低 2 位，把「语义」塞进高 6 位——这是自定义 VM 最常见的自描述编码，看到 `& 3` 和 `>> 2` 的配对基本就能确认。
- 为什么「修好一个函数」就够：分派函数（`menu`）只负责**解码**，真正的语义在几个 handler 函数里；解码格式一旦还原，后面每个 handler 都只剩「对 `reg/data/stack` 做什么运算」，逐个看 `switch` 分支即可，不需要逐指令跟 gdb。
- 还原完成后必须写一个「编码器」并做**往返校验**：用 Python 按 `(case<<2)|fmt` 拼字节，喂给原程序观察日志/行为；或把编码器产物与 gdb 里 `vmcode_pos` 的实测字节逐条对比，避免字节序/字段顺序写反。

## 触发条件

- 目标是一道 VM 题：程序 `mmap` 若干段（code/data/stack）并从输入读取 opcode 流后解释执行（本例为 `mmap(0x7063000)` 的 code 段 + `mmap(0x64617461000)` 的 data 段 + `mmap(0x73746163000)` 的 stack 段）。
- 能在 IDA 中定位取码函数（通常是从 `main` 循环里被反复调用的那个 `xxx(a1, s)`），且能看到 `& 3` 与 `>> 2` 的位运算特征。
- 允许在本地用 gdb 做少量验证（可选），但主要靠静态还原；不需要完整的动态跟踪。
- 目标是「自己生成 opcode 流」，因此需要确切的字节级编码，而非仅理解语义。

## 利用步骤

1. 从 `main` 找 VM 主循环：`malloc(0xC)` 的小结构 + `menu(a1, s)` + `switch(*s & 3)` + 每轮 `memset(s,0,0xC)`，这一段直接暴露「首字节低 2 位决定走哪个函数」。
2. 进 `menu` 看逐字节取码：记录下来「哪一字节进入 `b1`、哪一字节进入 `int1`、哪一字节进入 `int2`」，尤其注意 `int2` 是 8 字节 qword 还是 1 字节。
3. 在 IDA 里新建结构体 `st { char b1,b2,b3,b4; int int1; int int2; }`，把 `a2` 参数改成 `st *`，把 `*(a1+8)` 改成 `a1->vmcode_pos`，把 `*(a1+64)` 改成 `a1->stack_pos` 之类，按访问偏移逐个命名；重编译伪代码后复查是否只剩位运算与赋值。
4. 归纳四个格式分支并写成表：`fmt=0 → 3 字节大端拼 int1`、`fmt=1 → 1 字节 int1`、`fmt=2 → 1 字节 int1 + 1 字节 int2`、`fmt=3 → 1 字节 int1 + 8 字节 qword int2`。
5. 归纳 handler 表：`case` 从 `b1>>2` 取值，逐个 case 记录语义（寄存器赋值/异或/与/或/移位/加减/从 data 读写/建表/比较置 FLAG）。
6. 写 Python 编码器：`enc(fmt, case, int1, int2)` 按格式拼字节，并用 `hexdump` 或原程序日志校验首条指令的字节序。
7. 用编码器复现题目自带的那段 vmcode（原题给的 12 条指令）作为回归测试：编码结果要逐字节对上，才能确认编码器正确。

## PoC

```python
# 编码器骨架：与原文 menu() 的四个分支一一对应
import struct

def enc(fmt, case, int1=0, int2=0):
    b = (case << 2) | (fmt & 3)
    if fmt == 0:
        # 3 字节大端拼 int1：a1[0] 是 opcode，a1[1..3] 是 int1 的三个字节
        return bytes([b, (int1 >> 16) & 0xff, (int1 >> 8) & 0xff, int1 & 0xff])
    if fmt == 1:
        return bytes([b, int1 & 0xff])
    if fmt == 2:
        return bytes([b, int1 & 0xff, int2 & 0xff])
    if fmt == 3:
        return bytes([b, int1 & 0xff]) + struct.pack('<Q', int2)   # qword 立即数
    raise ValueError

def mov_reg(reg, val):   return enc(3, 3, reg, val)   # case 3: reg[i] = imm
def add_imm(reg, val):   return enc(3, 10, reg, val)  # case 10: reg[i] += imm
def xor_imm(reg, val):   return enc(3, 4, reg, val)   # case 4: reg[i] ^= imm
```

```text
# 原文用同一套解码逻辑实现的"解析器"输出（可作为回归对照）：
# 01 : fun_3 -> case : 0x3 (0,1)
# 02 : fun_3 -> case : 0x3 (1,0)
# 04 : fun_0 -> case : '5' (1)
# 06 : fun_1 -> case : 0x20 (0)
# 09 : fun_2 -> case : 0x4 (0)
```

## 变体与关联

- 变体：把 `fmt` 位放到**高** 2 位、把 `case` 放到低 6 位（有些 VM 这么排），判别方法是看分派用的 `switch` 操作数是 `>> 2` 还是 `& 3`；两者成对出现但方向可反。
- 变体：`fmt=0` 的拼装方向可能是小端（`int1 |= *p << (8*i)`），必须按伪代码里的移位方向判断，不要凭经验写死。
- 变体：`fmt=3` 的合法性校验不止 `int1>>5`，可能还查 `int1` 上限/寄存器编号范围，编码器要避开非法值否则直接在 VM 里 `_exit`。
- 变体：有些 VM 用「变长 + 指令表偏移」而不是位域，此时做法是还原跳转表（见 `ctf-reverse-custom-stack-vm-bytecode-constraint-recovery`）。
- 关联：[[ctf-pwn-vm-opcode-heap-primitive-wrapper-uaf-leak]]（本卡还原出编码器后，如何在 pwn 里用 opcode 调堆原语）、[[ctf-reverse-custom-vm-masked-opcode-inverse-witness-recovery]]（opcode 带掩码/加密的另一类）、[[ctf-pwn-custom-vm-opcode-native-memory-got-restart-onegadget]]（VM 直接暴露宿主内存读写的一类）。
- 边界：位域编码只在「作者自己设计的 VM」里成立；若 opcode 表来自真实 CPU（x86/ARM）或加密字节码，需先解密/反汇编而非做格式还原。

## 检测与防御

- 检测（作为出题/防守方）：VM 题若 opcode 首字节自描述且 handler 无边界检查，攻击者可在还原后任意生成指令流；应给寄存器/数据段/栈加越界检查与合法 opcode 白名单校验。
- 检测（作为分析方）：`& 3` + `>> 2` 成对出现、`mmap` 固定三段（code/data/stack）、主循环 `memset` 12 字节小结构，是自描述 VM 的强指纹。
- 防御：VM 指令流执行前做「解码 → 语义校验 → 权限检查」三段，而不是边解边执行；对 data/stack 范围做显式边界检查（本例 handler 里有 `if_big_than_0x3000` 检查，但仍存在可绕的点）。
