---
id: binary-pwn-rop-bss-stdout-pointer-magic-gadget-leak-orw
title: Full RELRO 无输出栈题：magic gadget 加写 .bss 中的 stdout 指针合成 libc 输出函数泄露 libc（ret2csu + add [rbp-0x3d], ebx）
type: scenario
domain: binary
path: binary/pwn/rop
technique: bss-saved-libc-pointer-add-gadget-synthesize-output-leak
aliases:
- 鹏程杯 silent
- bss stdout 指针改写
- stdout 指针加偏移
- add dword ptr [rbp-0x3d], ebx
- add [rbp-0x3d], ebx
- Full RELRO 泄露 libc
- 无输出函数泄露 libc
- ret2csu 指针改写
tags:
- pwn
- rop
- ret2csu
- magic-gadget
- bss
- stdout
- full-relro
- libc-leak
- seccomp
- orw
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V667
  verified_at: '2026-11-13T08:36:05+08:00'
  notes: 已对照原文 4 图核对：img/01 pwndbg tele 0x601020 显示 stdout@GLIBC_2.2.5 指针已变为 (write)，与卡内 .bss stdout 指针加固定差值合成输出函数的结论一致；magic gadget 0x4007e8 add dword ptr [rbp-0x3d], ebx 与 ret2csu pop6 0x40095A、csu 调 read(0,bss+0x100,0x100)、随后 csu(0,1,0x601020,0x50,read@got,1,0x4008DC) 调 write(1,read@got,0x50)、libc 2.27 delta 表达式与 pl3 open/read/write ORW 均与原文 exp 一致；修正 1 处：首段 csu 调用按 exp 实为 read(0, bss+0x100, 0x100)（rdx=0x100），原描述 rdx=0 有误。dedup 对 binary-pwn-rop-magic-gadget-csu-bss-write-orw-no-libc-leak 为 related（cosine 0.9156）非 duplicate，'目标相反'理由成立：该卡不泄 libc、加写伪造数据调 fopen/fread/send，本卡改造 .bss libc 指针制造泄露，PoC 与链条不同，两卡并列互补。magic2/magic3 跳过理由经核对属实（分别与 binary-pwn-heap-freehook-setcontext61-bridge-orw、binary-pwn-heap-house-of-apple2-chunk-header-svcudp-reply-xdr-ops-orw 同链，均 verified）。img/02-04 为 magic3/House of apple2 现场，非本卡链。未验证点：PoC 未本机复跑；CTF 题无组件版本，未设 affected_versions；无 CVE；frontmatter 无 sources/source_url。
---

# 一句话结论

非 PIE、Full RELRO 且没有任何输出函数的 64 位栈溢出题里，GOT 虽然只读，但 `.bss` 中的 `stdout` 等全局变量仍保存着 libc 内的 `FILE*` 地址（`_IO_2_1_stdout_`）；用 ret2csu 设置 `rbx/rbp` 后借 `add dword ptr [rbp - 0x3d], ebx ; nop ; ret` 给该指针低 32 位加一个固定的 libc 内差值，把它改造成 libc 的 `write` 函数（文章调试器截图确认 `0x601020` 由 `_IO_2_1_stdout_` 变为 `write`），再以 `rdi=1、rsi=read@got、rdx=n` 调用即可输出 GOT 内容、泄露 libc，随后按常规 open/read/write ORW 读 flag（文章案例：2023 鹏程杯 silent，libc 2.27）。

# 原理

- **困境**：题目 `read(0, buf, 0x100)` 只有栈溢出、没有输出函数，Full RELRO 让 GOT 不可写，无法用 ret2dlresolve/改写 GOT 的方式造泄露；看似“无泄露、无输出”死局。
- **可加写的对象不止 GOT**：Full RELRO 只保护 `.got`/`.got.plt`，`.bss` 里的全局变量仍可写。程序链接 libc 时，`stdout`/`stdin`/`stderr` 这类全局变量在 `.bss` 中保存的是 libc 内 `FILE` 结构地址（案例 `stdout` 位于 `0x601020`、`stdin` 位于 `0x601030`）。这些指针天然携带 libc 基址信息。
- **magic gadget 提供 32 位任意加写**：`0x4007e8: add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret`。只要控制 `rbp = 目标地址 + 0x3d`、`ebx = 加数`，就能对任意可写地址的低 32 位做一次加法；配合 ret2csu 的 `pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret`（案例 `0x40095A`）很容易同时控制这两个寄存器。
- **为什么加固定差值能“变成另一个函数”**：`stdout` 指针的值是 `libc_base + _IO_2_1_stdout_`，目标函数（如 libc 的写函数）是 `libc_base + offset`；两者之差 `target_offset - stdout_offset` 只取决于 libc 版本、与 ASLR 无关。对指针低 32 位加上这个固定差值，只要不发生 32 位进位，得到的就是目标 libc 地址（高 32 位不变）。案例 libc 2.27 用加数 `0xffffffffffd24620 - 0xd80 + 0xf0`（32 位截断）把 stdout 指针改成可当输出函数调用的地址。
- **调用改造后的指针**：ret2csu 的 `call [r12 + rbx*8]` 可直接 call 内存中的指针。把 `r12` 指向 `0x601020`（已被改造成输出函数），`edi=1`（stdout）、`rsi=read@got`、`rdx=0x50`，即调用“输出函数(1, read@got, 0x50)”，把 `read` 的真实地址写到标准输出，泄露 libc 基址。
- **后续利用**：拿到 libc 后按常规构造 `pop rdi/rsi/rdx` + `open("flag")/read/write` 的 ORW 链（案例 seccomp 只限制 execve，open/read/write 可用），再次 `read` 把 ORW 链写入 `.bss` 后跳转执行，输出 flag。
- **注意 ret2csu 的寄存器顺序**：csu 前端 `mov rdx,r13; mov rsi,r14; mov edi,r15d; call [r12+rbx*8]`，即参数顺序是 `r12=函数指针槽、r13=rdx、r14=rsi、r15=rdi`；`rbx` 为 0 时调用 `[r12]`，调用后 csu 尾部还会 `add rsp,8` 并弹出 6 个寄存器，payload 需为这 7 个 qword 留位置。

# 触发条件

- 非 PIE 的 64 位 ELF、存在可控栈溢出、NX 开启；Full RELRO（GOT 不可写）且程序无可用输出/泄露原语。
- `.bss`（或其它可写数据段）中存在保存 libc 指针的全局变量（`stdout/stdin/stderr` 等），且目标 libc 版本已知，能计算该指针与目标输出函数的固定差值。
- 二进制内存在 `add dword ptr [rbp - 0x3d], ebx` 类“寄存器控制的 32 位加写”gadget，以及可设置 `rbx/rbp` 的 pop 链（如 `__libc_csu_init` 的 pop6）。
- 低 32 位加法不产生跨 4GB 进位（否则高 32 位错误）；案例环境满足。
- seccomp 允许 open/read/write 等文件读写调用（案例只禁 `execve`），否则需改为输出已有 fd 内容或其它路线。

# 利用步骤

1. 溢出并确认返回地址偏移（案例 `buf` 在 `rbp-0x40`，返回地址偏移 0x48）。
2. 第一段链：先用 ret2csu 做一次 `read(0, bss+0x100, 0x100)` 调用，顺带在 csu 尾部把 `rbx=差值`、`rbp=stdout+0x3d` 装好，ret 进入 magic gadget，完成对 `0x601020`（stdout 指针）的低 32 位加写。
3. 第二段链：再次 `read` 写入 payload，用 csu 以 `r12=0x601020`（改造后的函数指针）、`r15d=1`、`r14=read@got`、`r13=0x50` 调用，泄露 `read` 地址。
4. 由 `read` 真实地址求 libc base，取 `pop rdi; ret`、`pop rsi; ret`、`pop rdx; ret` 与 `open/read/write` 偏移。
5. 第三段链：把 `"flag"` 等字符串/参数布置到 `.bss`（案例再用一次 read 写入 `0x601200` 区域），执行 `open("flag") → read(3, buf, n) → write(1, buf, n)` 输出 flag。

# PoC

```python
magic     = 0x4007E8   # add dword ptr [rbp-0x3d], ebx ; nop dword ptr [rax+rax] ; ret
csu_pop6  = 0x40095A   # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
csu_front = 0x400940   # mov rdx,r13; mov rsi,r14; mov edi,r15d; call [r12+rbx*8]; ...
read_got  = 0x600FE0
stdout    = 0x601020   # .bss 中保存 _IO_2_1_stdout_ 指针
delta     = 0xffffffffffd24620 - 0xd80 + 0xF0   # 案例 libc 2.27：stdout(_IO_2_1_stdout_) → write（32 位截断）

# csu 尾部把 rbx=delta、rbp=stdout+0x3d 装好，ret 到 magic → [stdout] 低 32 位加 delta
# 随后 csu(r12=stdout, rdx=0x50, rsi=read_got, rdi=1) 调用改造后的函数，泄露 read 地址
pl2 = b"\x00" * 0x48 + csu(0, 1, stdout, 0x50, read_got, 1, 0x4008DC)
# 收到 read 真实地址后：libc_base = read_addr - libc.sym['read']，再构造 open/read/write ORW
```

（`csu(rbx, rbp, r12, rdx, rsi, rdi, last)` 为文章按案例地址封装的 helper；完整 ORW 链略。）

# 变体与关联

- 与库内 `binary-pwn-rop-magic-gadget-csu-bss-write-orw-no-libc-leak` 使用同一 magic gadget，但目标相反：那张卡是“不泄露 libc，加写伪造字符串/参数后调固定地址的 fopen/fread/send”；本卡是“加写改造 `.bss` 中保存的 libc 指针，制造输出原语后泄露 libc”。两卡的触发条件（非 PIE、无泄露、seccomp ORW）相近，但 PoC 与链条不同，可组合使用：先按本卡造泄露，再按那张卡减少对 libc 的依赖。
- 与 `binary-pwn-rop-alarm-got-syscall-ret2csu-orw`（单字节把 `alarm@GOT` 改成 `alarm+9` 的 syscall）思路同源：都是“对已保存的指针/代码地址做小改造获得新能力”；区别是本卡在 Full RELRO 下改的是 `.bss` 数据指针，不是 GOT。
- 同类可改造目标：`stdin`/`stderr`、`.bss` 中其它 libc 指针（如 `__libc_argv`）；同类加写 gadget 还有 `adc DWORD PTR [rbp+0x48], edx` 等。
- 若 32 位加写出现进位或需要更稳定的写，可改用 8 字节任意写 gadget 或两次加写；若目标 libc 的符号差超过 32 位范围则不适用。

# 检测与防御

- CTF 出题/加固：开启 PIE 让 `.bss` 与代码地址随机化；Full RELRO 之外仍需处理“数据段保存 libc 指针”的泄露面；开启 Canary、NX；seccomp 不仅禁 `execve`，还按需限制 `open/read/write`，否则 ORW 仍可读 flag。
- 移除 magic gadget 不是可靠防护：攻击者可用其它 `add [reg], reg`/`mov [reg], reg` 写 gadget 替代，核心防御是消除栈溢出与地址可预测性。
- 检测/取证（CTF 环境外）：崩溃栈中出现 `.bss` 地址作为 rbp、`add dword ptr [rbp-0x3d], ebx` gadget 地址、随后对 `stdout` 全局指针的写与 GOT 内容外发，都是此类“数据段指针改造”链的特征；可结合 core dump 观察 `.bss` 中指针值被加写。
