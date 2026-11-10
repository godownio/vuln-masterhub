---
id: ctf-pwn-vm-arith-bootstrap-rop-residual-libc-pointer
title: 无泄漏且无 pop rdi gadget 时，用 VM 越界读栈残留 libc 指针并算术自举 ROP
type: scenario
domain: ctf
path: ctf/pwn
technique: vm-residual-libc-pointer-arith-bootstrap-rop
tags:
- ctf
- pwn
- vm
- rop
- ret2libc
- libc-base
- oob-read-write
- no-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-10
  verified_at: '2026-11-08T01:17:32+08:00'
  notes: 已对照原文核对；图 09-16 的栈残留 _dl_lookup_symbol_x+321 指针、0x498/0x118/0x140 偏移、sub/add 算术自举算 libc_base 与 system/pop_rdi/bin_sh、末尾常量经 mov_in 载入、覆盖 run 返回地址与卡一致，图 16 拿到 shell 且 cat flag 成功，最终危害打通，非半链；dedup_review 成立；未验证点：残留指针偏移依赖具体 libc 版本，卡内边界已注明
url: /docs/ctf/pwn/ctf-pwn-vm-arith-bootstrap-rop-residual-libc-pointer/
draft: false
kb_aliases:
- 栈残留 libc 指针算 base
- VM 算术自举 ROP
- 无泄漏 ret2libc
- 寄存器内构造绝对地址
---

## 一句话结论

在自定义 VM 只有越界读写原语、程序既无输出函数可泄漏 libc、二进制里又缺少 `pop rdi; ret` 之类 gadget 时，可先用越界读把「栈高地址残留的 libc 运行时指针」和输入末尾的常量载入 VM 寄存器，用 VM 的 sub/add 算出 libc_base 与 system/pop_rdi/bin_sh 绝对地址，再用越界写把 ROP 链放到 run 函数返回地址处，指令报错退出函数时劫持控制流拿 shell。

## 原理

- 为什么不需要泄漏函数：VM 的越界读本身就是泄漏原语，且栈上高地址常残留动态加载器/libc 的返回地址（本例为 `_dl_lookup_symbol_x+321`，值 = libc_base + 固定偏移）；该偏移在给定 libc 下是常量，可从调试器量出。
- 为什么用残留指针而不是 GOT：GOT 需要知道绝对地址并解析符号，栈残留指针只需「相对虚拟内存基址的偏移」（本例 0x498）即可定位，不依赖任何绝对地址知识。
- 算术自举 ROP：VM 的 add/sub 是 `reg[reg1] = reg[reg2] ± reg[reg3]` 的 64 位寄存器运算。先 `sub(libc+offset, offset, libc_base)`，再 `add(libc_base, system_offset, system)`、`add(libc_base, pop_rdi_offset, pop_rdi)`、`add(libc_base, bin_sh_offset, bin_sh)`，直接得到可用的绝对地址，无需二进制里有 gadget、也无需先破 PIE。
- 常量如何进寄存器：VM 没有「立即数载入寄存器」指令，于是把各常量（libc 内偏移、固定偏移、栈对齐 ret 桩）拼在输入 payload **末尾**；指令循环按 4 字节取指，末尾数据不会被当作指令执行（循环在遇到非法 opcode 时退出，正好触发函数返回），再用 mov_in 以「输入区相对 buf 的偏移」（本例 0x140 起每 8 字节一个）越界读入各寄存器。
- 为什么覆盖 run 返回地址：mov_out 的越界是从 buf 基址**正向**寻址，只够得到比 buf 高的栈地址；run 的返回地址在 `buf+0x118`，而 mov_out 自身的返回地址在 buf 低地址方向够不到，所以选 run（或 main）的返回槽。写 `pop_rdi; bin_sh; ret; system` 四段，指令循环报错退出 run 时弹栈即执行。
- 为什么需要 `ret` 桩：满足 `movaps` 的栈对齐要求，插一段纯 ret 平衡栈，否则 system 内可能崩溃。

## 触发条件

- 已有相对栈基址的越界读/写原语（见「访存指令位宽不一致」卡）；
- 程序无 `puts/write` 之类可主动泄漏的函数，或 gadget 不足以常规 ret2libc；
- 栈上高地址存在与 libc_base 固定偏移的残留指针，且该偏移已知/可量；
- VM 提供 64 位寄存器加减与「内存→寄存器 / 寄存器→内存」指令；
- 能在输入末尾附加常量数据，且指令循环会在其后退出并触发函数返回。

## 利用步骤

1. 调试确定三处偏移：残留 libc 指针相对 buf 的偏移、输入常量区相对 buf 的偏移、目标函数返回地址相对 buf 的偏移。
2. 用 mov_in 把残留 libc 指针载入某寄存器。
3. 把常量（system/pop_rdi/bin_sh/ret 的 libc 内偏移、固定偏移、ret 桩）放在 payload 末尾，用 mov_in 逐个载入寄存器。
4. 用 sub 计算 libc_base；用 add 计算 system/pop_rdi/bin_sh 绝对地址。
5. 用 mov_out 依次把 pop_rdi、bin_sh、ret、system 写到返回地址槽及其后续栈槽。
6. 让指令流执行到非法 opcode 报错退出 run 函数，触发 ROP，得到交互 shell。

## PoC

```python
from pwn import p32, p64
# mov_in/mov_out/add/sub 的指令编码见「访存指令位宽不一致」卡
P = b''
P += mov_in(OFF_RESIDUAL, 2, 1)                 # 残留 libc 指针 -> reg1
for i, off in enumerate([O_SYSTEM, O_POP_RDI, O_OFFSET, O_BINSH, O_RET]):
    P += mov_in(OFF_CONST + 8*i, 2, 3+i)        # 末尾常量 -> reg
P += sub(1, 5, 1)                               # reg1 = libc_base
P += add(1, 3, 10)                              # reg10 = system
P += add(1, 4, 11)                              # reg11 = pop_rdi
P += add(1, 6, 12)                              # reg12 = bin_sh
P += mov_out(OFF_RET,     2, 11)                # 返回地址 = pop_rdi
P += mov_out(OFF_RET + 8, 2, 12)                # +8 = bin_sh
P += mov_out(OFF_RET +16, 2, 7)                 # +16 = ret(对齐)
P += mov_out(OFF_RET +24, 2, 10)                # +24 = system
P += p64(SYSTEM_OFF) + p64(POP_RDI_OFF) + p64(FIXED_OFFSET) + p64(BINSH_OFF) + p64(RET_STUB)
# 发送后指令循环报 Unsupported instruction 退出 run，ROP 执行 system("/bin/sh")
```

## 变体与关联

- 变体：残留指针也可来自 `__libc_start_main+xxx` 返回地址、栈上 environ/IO 结构指针；无 add/sub 时可用多次 xor/移位组合；写 main 返回地址（更高偏移）同样可行；seccomp 下改 ORW 链。
- 关联：自定义 VM 访存越界原语、ret2libc、栈对齐 ret 桩、canary 回填（若越界写路径经过 canary 槽需先读回原值写回）。
- 边界：残留指针偏移依赖具体 libc 版本；若开启 PIE 且无栈地址信息，需先越界读保存的 rbp/返回地址推算栈基址。本例 canary 位于返回地址之前，ROP 只写返回地址及其后栈槽，未破坏 canary，故无需回填。

## 检测与防御

- 防御：根因在解释器越界（见关联卡）——统一索引校验、把访存限制在声明内存区；对「VM 内存」与「宿主栈」做隔离（VM 内存放堆上并加 guard page），避免越界直接触达返回地址。
- 加固：开启 PIE/ASLR、canary、Full RELRO、栈不可执行；解释器遇到非法 opcode 应终止进程，而不是正常返回到已被攻击者写入 ROP 的栈。
- 检测：输入中出现成组的 4 字节 RV 风格指令且随后附带 8 字节常量区；进程在 `Unsupported instruction` 后立即 `execve("/bin/sh")`。
