---
id: binary-pwn-rop-magic-gadget-csu-bss-write-orw-no-libc-leak
title: 无 libc 泄露 + seccomp 禁 execve：magic gadget（add [rbp-0x3d], ebx）配合 CSU 写 BSS 伪造参数，调用 fopen/fread/send 读 flag
type: scenario
domain: binary
path: binary/pwn/rop
technique: magic-gadget-csu-bss-write-no-libc-leak-orw
aliases:
- magic gadget 写 BSS
- CSU 写 BSS
- 无 libc 泄露 ROP
- seccomp ORW
- add dword ptr [rbp-0x3d], ebx
- minihttpd setmode 栈溢出
- BSS 任意 dword 写
tags:
- pwn
- rop
- ret2csu
- magic-gadget
- bss
- no-libc-leak
- seccomp
- orw
- stack-overflow
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T13:37:41+08:00'
  notes: 已对照原文与 9 张图核对：setmode_handler memcpy(mode_value[22],v12+1,param_name_len) 栈溢出（0x440）、seccomp 禁 execve/execveat、非 PIE、0x40169c magic gadget、0x402fea csu pop6、BSS 0x406a40 逐 dword 加写、图09 flag{1111} 均一致；已修正 0x402C87 为 input() 内 call fopen@plt 指令地址而非 PLT 桩；未在本机复跑
---

## 一句话结论

在非 PIE、无 libc 泄露原语、seccomp 又禁止 `execve/execveat` 的 64 位栈溢出题中，可用 CSU 的 `pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret` 设置 `rbx/rbp`，再用 magic gadget `add dword ptr [rbp-0x3d], ebx; nop; ret` 反复向 BSS 的指定偏移加写受控 32 位值，伪造文件名、指针与调用参数，最后直接调用固定地址的 `fopen/fread/send`（或 `open/read/write`）读出 flag，全程不需要泄露 libc。

## 原理

- **溢出点**：minihttpd 的 `setmode_handler` 中，`memcpy(mode_value, v12 + 1, param_name_len)` 的 `param_name_len` 由请求体长度（`a3`）与 `=` 位置计算，`mode_value` 只有 22 字节；POST `/setmode` 发送长 body 即可覆盖保存的 rbp 与返回地址（原文偏移 `0x440` 到返回地址附近）。
- **seccomp 限制**：`server_init()` 用 `seccomp_init(SCMP_ACT_ALLOW)` 后只添加 `execve(59)`、`execveat(322)` 的 KILL 规则；`system`、`execve` 路线不可用，但 `open/read/write`、`fopen/fread/send` 等系统调用仍被允许，因此目标是 ORW（open-read-write）而非 getshell。
- **无 libc 泄露**：二进制非 PIE，代码地址固定；GOT 中虽有 `fopen/fread/send` 等函数，但程序没有方便的输出/任意读原语来泄露 libc 基址。与其强行找泄露，不如只用二进制自身的 PLT/固定地址函数，避免依赖 libc 偏移。
- **为什么需要写 BSS**：要调用 `fopen("flag","r")`/`fread`/`send`，需要在可写内存里准备文件名字符串、缓冲区指针或 `FILE*` 相关参数；而栈溢出只能控制返回链，不能直接摆放任意数据。`recv`/`read` 到 BSS 看似可行，但 `recv` 需要控制 `rcx` 标志位，且返回后的 gadget 片段较长、容易受栈帧/返回值影响，原文多次尝试不稳定。
- **magic gadget 提供任意 dword 加写**：
  `magic_gadget = add dword ptr [rbp - 0x3d], ebx; nop; ret`
  只要控制 `rbp`（目标地址 + 0x3d）与 `ebx`（加数），就能对任意可写地址做一次 32 位加法。BSS 初值已知（或可控），选择加数即可把目标 dword 改成想要的值；重复多次即可逐 dword 伪造数据。
- **CSU 的 pop 段负责设置寄存器**：`csu_pop6 = pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret`（原文 `0x402FEA`）从栈上取 6 个值，正好设置 `rbx`（加数）与 `rbp`（目标 + 0x3d），其余寄存器填 0 后接 magic gadget。这样每个 magic 写只占 8 个 qword，链结构稳定。
- **完整链**：溢出 → `p64(bss)` 作为新 rbp/栈迁移目标 → 多次 `csu_pop6 + 加数 + (bss+offset+0x3d) + 0*4 + magic_gadget` 写 BSS → `pop rdi; ret` 指向 BSS 中的文件名 → `pop rsi; pop r15; ret` 指向 `"r"` → `fopen@plt` → 后续 `fread`/`send` 输出 flag。原文最终 exp 在本地读出 `flag{1111}`，证明链可用。
- **为什么“全版本通用”**：即使编译器剔除了完整 CSU 的 `call [r15+rbx*8]` 段，只要还能控制 `rbx` 并找到 `pop rbx; pop rbp; ...; ret` 或类似的寄存器装载 gadget，magic gadget 的加写仍然成立；它不依赖 `__libc_csu_init` 的间接调用部分。

## 触发条件

- 非 PIE 的 64 位 ELF，存在可控栈溢出与可写 BSS；NX 开启（不能执行栈）。
- 程序中存在 `add dword ptr [rbp - 0x3d], ebx`（或等价的“寄存器控制的 32 位内存加写”）magic gadget，以及可设置 `rbx/rbp` 的 pop 链。
- seccomp 只禁止 `execve/execveat`（或类似），允许文件读写系统调用；若连 `open/read/write` 也禁，需要改用已打开 fd 或其它原语。
- 没有可靠的 libc 泄露/长写原语，或 `recv/read` 写 BSS 不稳定。
- 目标 BSS 初值可预测（非 PIE、无随机化写入），或可先用其它请求影响 BSS 内容。

## 利用步骤

1. 逆向下发请求的 HTTP 解析逻辑，确认 POST body 的 `Content-Length` 与 `mode=` 前缀如何进入 `setmode_handler`；构造 `create_post_request_raw` 以发送原始字节（不能经过字符串编码）。
2. 确定溢出偏移（原文 `0x440` 到返回地址前），先用 `p64(0xdeadbeef)` 验证返回地址可控。
3. 找 gadget：`pop rdi; ret`、`pop rsi; pop r15; ret`、`pop rbp; ret`、`pop rsp` 等；找 `add dword ptr [rbp - 0x3d], ebx; nop; ret` 与 `pop rbx; pop rbp; ...; ret`。
4. 选定 BSS 地址（如 `0x406a40`），规划要伪造的数据：文件名字符串、`"r"` 模式串、读缓冲区/参数指针；计算每个 dword 的初值与目标值之差，作为 magic gadget 的 `ebx` 加数。
5. 构造链：溢出填充 + 新 rbp/栈迁移地址 + 若干组 `csu_pop6 + addend + (target+0x3d) + 0*4 + magic_gadget`；最后接 `pop rdi; bss`、`pop rsi; mode`、`fopen@plt`，以及后续 `fread`/`send` 或 `open/read/write`。
6. 发送请求，观察是否输出 flag；若崩溃，检查栈对齐、BSS 初值、加数溢出（32 位回绕）与 gadget 地址。

## PoC

核心链形状（地址按原题）：

```python
from pwn import *

csu_pop6   = 0x402FEA  # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
magic      = 0x40169C  # add dword ptr [rbp - 0x3d], ebx; nop; ret
pop_rdi    = 0x402FF3
pop_rsi_r15= 0x402FF1
ret        = 0x40101A
bss        = 0x406A40
fopen_callsite = 0x402C87  # input() 内 call fopen@plt，跳入后继续 fread/send 循环

def magic_write(addend, target):
    return flat(csu_pop6, addend, target + 0x3D, 0, 0, 0, 0, magic)

pay  = b"A" * 0x440 + p64(bss)
pay += magic_write(0x612C22C6, bss + 0x00)
pay += magic_write(0x00000067, bss + 0x04)
# ... 继续按目标 dword 逐次加写，伪造文件名/参数
pay += flat(pop_rdi, bss, pop_rsi_r15, bss + 0x10, 0, ret, fopen_callsite)
```

原文最终 exp 的调用序列（`0x402C87` 是 `input()` 内 `call fopen@plt` 的指令地址，不是 PLT 桩；rdi=`0x406a40` 指向 `"flag"`，rsi=`0x4041b7` 指向 `"r"`）跳入后继续执行 `input()` 的 `fread`/`send` 循环，将 `flag{1111}` 写回连接，验证成功。

## 变体与关联

- **用 `recv`/`read` 写 BSS**：若能控制 `rcx`（flags）且返回后的 gadget 尾巴可控，可直接把 `"flag"`/参数写入 BSS；原文因 `recv` 的寄存器与栈帧问题不稳定，改用 magic gadget 加写。
- **用完整 CSU 调用 `read`**：`csu2` 的 `mov rdx,r13; mov rsi,r14; mov edi,r15d; call [r12+rbx*8]` 可调用 `read@got` 写 BSS，但需要 `r12/rbx` 指向 GOT 且能控制长度；适合有稳定二次读的场景。
- **ORW 替代 fopen**：若只想用系统调用，可接 `open/read/write` + `syscall` gadget；seccomp 允许这些调用时同样可行。
- **其它写 gadget**：`mov [reg], reg`、`add [reg], reg`、`xchg` 等任意写/加写 gadget 都可替代 magic gadget；核心是“用固定地址 + 已知初值构造数据”，不依赖 libc。
- **关联**：[[binary-pwn-rop-ret2csu-bss-binsh-libc-offset-mismatch]]（ret2csu 写 `/bin/sh` 到 BSS，但有 libc 泄露并调 system）、[[binary-pwn-stack-bss-pivot-write-gadget-chunked-orw]]（BSS 栈迁移 + 分块 ORW，但有 libc 泄露）、[[binary-pwn-stack-fake-rbp-check-seccomp-orw]]（seccomp ORW 的栈帧校验绕过）、[[binary-pwn-stack-ret2dlresolve-partial-relro-64-fake-reloc]]（无 libc 时的另一条解析路线）。

## 检测与防御

- **二进制加固**：开启 PIE + ASLR，使 BSS/代码地址随机化；开启 Canary、Full RELRO、NX；用 `-fstack-protector-strong`、`-D_FORTIFY_SOURCE=2`。
- **seccomp 策略**：不仅禁 `execve/execveat`，还按业务需要限制 `open/read/write`、`fopen` 等文件访问；对 CTF 题而言，禁 execve 不足以阻止 ORW 读 flag。
- **输入校验**：`setmode_handler` 的 `param_name_len` 必须以 `mode_value` 容量为上限，且校验 `Content-Length` 与实际 body 长度；不要用请求长度直接做 `memcpy` 长度。
- **编译选项**：不必刻意保留 CSU/magic gadget；但移除它们不是可靠防护，攻击者仍可用其它写 gadget。核心防御是消除栈溢出与地址可预测性。
- **检测**：进程崩溃时栈中出现 BSS 地址、`add [rbp-0x3d]` 类 gadget 地址、`fopen/fread/send` 调用链；异常 POST `/setmode` body 长度远超字段容量；CTF 环境外出现读取 flag/敏感文件的 ORW 行为。
