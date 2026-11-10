---
id: ctf-pwn-custom-risc-vm-offset-width-mismatch-oob-rw
title: 自定义 32 位定长指令集 VM 的访存指令边界检查位宽不一致导致栈越界读写
type: scenario
domain: ctf
path: ctf/pwn
technique: vm-offset-width-mismatch-oob-rw
tags:
- ctf
- pwn
- vm
- bytecode
- oob-read-write
- bounds-check
- reverse-engineering
- stack
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-10
  verified_at: '2026-11-08T01:17:30+08:00'
  notes: 已对照原文核对；图 01-08 的 32 位定长指令、高 4 位 opcode、BYTE2(v3) 检查 8 位 vs HIWORD 与 0xFFF 取 12 位地址与卡内完全一致，越界读写原语在图 13/14/16 中已被用于 getshell、全文最终危害已打通；dedup_review 成立（6 个候选为不同 VM 越界根因）；与同篇 vm-arith-bootstrap-rop 卡为原语层/利用层分工，互不在对方 dedup 候选，非同一场景改写；未验证点：未在本地复现 avm 二进制
url: /docs/ctf/pwn/ctf-pwn-custom-risc-vm-offset-width-mismatch-oob-rw/
draft: false
kb_aliases:
- VM 访存越界读写
- 边界检查位宽不一致
- BYTE2 检查 12 位 offset
- 自定义指令集逆向
- 栈上虚拟内存 OOB
---

## 一句话结论

自定义 VM 的 mov_in/mov_out 访存指令把 12 位 offset 用于地址计算，边界检查却只取指令字第 2 个字节（8 位）参与比较，两者位宽不一致；攻击者用大 offset 即可通过检查、访问栈上「虚拟内存」缓冲区之外的数据，获得相对栈基址的越界读/写原语。

## 原理

- 指令格式逆向：每个 handler 末尾都有 `ip += 4`、且用 `code_addr + ip` 取 4 字节 → 定长 32 位指令；dispatcher 里 `index = fetch32 >> 28` → 高 4 位为 opcode，经 `funcs[index]` 分发表调用；算术指令中 `reg1 = instr & 0x1f`、`reg2 = (instr >> 5) & 0x1f`、`reg3 = (instr >> 16) & 0x1f` → 各 5 位寄存器号（共 32 个寄存器），高位剩余位在访存指令里作 12 位 offset。在 IDA 导入 `struct { __int64 reg[32]; __int64 ip; __int64 *code_addr; __int64 code_size; }` 即可还原 dispatcher 与各 handler。
- 虚拟内存是栈上的 `memset(s, 0, 0x100)` 缓冲，`s` 即访存基址 `buf`；12 位 offset 理论可索引 0x1000，远超实际 0x100。
- 漏洞根因：检查表达式是 `if ((unsigned __int8)(reg[reg2] + BYTE2(instr)) < (unsigned __int8)range)`，只取指令字的第 2 字节（8 位）作为偏移参与上界判断；而真实地址表达式是 `&buf[(unsigned __int16)(reg[reg2] + (HIWORD(instr) & 0xFFF))]`，取的是 16~27 位共 12 位立即数。检查值与使用值来自不同位域、且被截断成 8 位，于是 0x100~0xfff 的 offset 能通过检查却访问到缓冲外。
- 为什么是可读可写原语：mov_in 用同样的越界地址读 8 字节并写入 `reg[reg1]`，mov_out 把 `reg[reg1]` 写到该越界地址。相对 `buf` 基址正向 0x1000 范围内的栈内存因而都可读可写。
- 为什么是「栈」越界：虚拟内存直接分配在 run 函数的栈帧里，`buf` 高地址方向依次是 canary、保存的 rbp、run 返回地址，以及更高处残留的 libc 运行时指针，所以越界能触达控制数据与地址材料。

## 触发条件

- 程序实现自定义字节码/VM 解释器，且访存类指令带立即数 offset；
- 边界检查与实际地址计算使用了指令字的不同位域或不同截断宽度（如 8 位检查 vs 12 位使用）；
- 虚拟内存分配在栈上且小于 offset 可表示范围；
- 解释器循环允许多条指令连续执行，便于组合读写。

## 利用步骤

1. 逆向 dispatcher：确认定长 4 字节、高 4 位 opcode、位域拆出 reg1/reg2/reg3 与 12 位 offset；导入结构体还原 handler。
2. 逐一对比访存 handler 的「检查表达式」与「地址表达式」所用位域/类型，找出位宽与截断不一致。
3. 构造 mov_in/mov_out 指令，offset 取大于实际缓冲大小的值（本例 0x118~0x498），观察能否读到/写到栈上的 canary、返回地址或残留指针。
4. 用 mov_in 把目标栈槽读入寄存器、用 mov_out 把寄存器值写回目标栈槽，得到稳定的相对栈基址任意读写。

## PoC

```python
from pwn import p32
def mov_out(offset, reg2, reg1):   # reg[reg1] -> buf[reg2+offset]
    return p32((9 << 28) | (reg1 & 0x1f) | ((reg2 & 0x1f) << 5) | ((offset & 0xfff) << 16))
def mov_in(offset, reg2, reg1):    # buf[reg2+offset] -> reg[reg1]
    return p32((10 << 28) | (reg1 & 0x1f) | ((reg2 & 0x1f) << 5) | ((offset & 0xfff) << 16))
# offset 取 0x118 即越过 0x100 缓冲，命中 run 函数返回地址槽
payload = mov_in(0x498, 2, 1) + mov_out(0x118, 2, 1)
```

## 变体与关联

- 变体：检查用 `int8` 而索引用 `int16/uint16`、检查只看低字节、头部 mem_size 字段与实际分配不一致、有符号负 offset 下溢、操作数栈索引无下界检查——同属「边界检查与实际访问不一致」族。
- 关联：用越界原语自举 ROP（见同篇另一卡）、ret2libc、canary 泄漏与回填。

## 检测与防御

- 防御：检查与实际地址计算必须用同一个经范围校验后的索引变量——先算 `idx = reg[reg2] + offset`，再 `if (idx >= mem_size) reject`，最后才用 `idx` 访问；不要把「截断后的 8 位值」拿去做 12 位访问的守卫。
- 类型：避免 `unsigned __int8` 隐式截断，用无符号宽类型并显式上界；用 UBSan/ASan 验证解释器。
- 检测：对解释器做差分 fuzz（随机构造访存指令，比对检查值与实际访问地址）；运行期监控 VM 访问超出声明内存区的槽位；把 VM 内存放堆上并加 guard page，避免越界直接触达返回地址。
