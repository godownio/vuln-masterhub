---
id: binary-pwn-stack-rbp-arbitrary-write-got-read-write-dlresolve-chunked-rop
title: 栈溢出后用可控 rbp 逐轮任意写：GOT 改写 read→write 泄露 libc、_dl_runtime_resolve 重解析恢复 read、0x30 分块 ROP 完成 seccomp ORW
type: scenario
domain: binary
path: binary/pwn/stack
technique: rbp-controlled-arbitrary-write-got-read-write-dlresolve-chunked-rop
aliases:
- rbp 控制任意地址写
- read@got 改成 write gadget
- GOT 改写任意读
- _dl_runtime_resolve 恢复 read
- 0x30 分块 ROP
- seccomp ORW
- 栈迁移分块 ROP
tags:
- pwn
- stack-overflow
- partial-relro
- got-overwrite
- arbitrary-read
- arbitrary-write
- dl-runtime-resolve
- lazy-binding
- rop
- seccomp
- orw
- stack-pivot
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:55:39+08:00'
  notes: 已对照原文核对；rbp 任意写、read@got→write gadget、_dl_runtime_resolve 恢复、0x30 分块 ROP 与 seccomp ORW 一致；PoC 为骨架，bss 高处二次栈迁移/48 字节布局需按目标补全
---

## 一句话结论

当栈溢出只能覆盖 `saved rbp + saved rip`、且程序在函数体内用 `read(0, rbp-0x20, 0x30)` 时，可以先跳到函数体内 prologue 之后，把 `rbp` 当作任意写指针，每一轮向 `rbp-0x20` 写 0x30 字节并 `leave; ret` 继续下一轮；随后把 `read@got` 改成 `mov edi,1; call write@plt` 把 `read` 调用变成 `write(1, rbp-0x20, 0x30)` 完成任意读，泄露 libc 后再用 `_dl_runtime_resolve` 重解析恢复 `read@got`，最后用 0x30 字节一轮的分块 ROP 迁移到 bss 完成 seccomp 下的 ORW。

## 原理

- **溢出形状决定原语**：`vuln` 中 `char buf[0x20]; read(0, buf, 0x30);` 多写 0x10 字节，正好覆盖 `saved rbp` 与 `saved rip`；函数 epilogue 是 `leave; ret`，因此 `rbp` 和 `rip` 都完全可控。
- **rbp 即写指针**：跳到 `vuln` 函数体内、prologue 之后的地址（本例 `0x40122b`）会执行 `read(0, rbp-0x20, 0x30)`，然后固定 `write(1, "Goodbye!shell.", 9)`，最后 `leave; ret`。`leave` 执行 `rsp=rbp; rbp=[rsp]; rsp+=8`，所以下一轮的 `rbp` 和 `rip` 来自上一轮写入的 `[A]` 与 `[A+8]`。只要每轮把 `[A]=A_next`、`[A+8]=0x40122b` 写好，就能把“单次 0x10 溢出”变成“无限轮、每轮写任意地址 0x30 字节”的任意写。
- **GOT 改写把 read 变成 write**：Partial RELRO 下 `.got.plt` 可写。`read@got` 原本指向 libc `read`；把它改成二进制内的 `0x401250`（`mov edi,1; call write@plt`），下一轮 `call read@plt` 实际执行 `write(1, rbp-0x20, 0x30)`（因为 block 刚设置 `rsi=rbp-0x20`、`rdx=0x30`，而 gadget 把 `edi` 设为 1），于是任意地址读。改写时让 `rbp-0x20 = read@got`（即 `rbp=read@got+0x20`），0x30 字节只覆盖 `read@got` 及其后的 pivot 区，不会破坏 `write@got`，否则同一 block 末尾固定调用的 `write(1,"Goodbye!shell.",9)` 会崩溃。
- **泄露轮不读取输入**：`read@got` 已被换成 write gadget 后，再进入 block 时 `call read@plt` 不再消费 stdin，而是直接 `write(1, rbp-0x20, 0x30)` 把目标内存打出来；该轮 `leave; ret` 用的 `[A]/[A+8]` 必须由上一轮预先写在目标地址上，因此泄露后还能继续走。
- **泄露 libc**：取 `rbp=0x404040`，读 `0x404020..0x404050`，其中 `0x404028` 是 libc `write` 的 GOT 值，减去已知偏移即可算 libc 基址；同时能看到 `seccomp_rule_add`/`seccomp_load` 的 GOT，用于确认布局。
- **用 PLT 桩恢复 read**：`read@got` 被改坏后不能直接调用 `read`，但 `read@plt` 桩还在：`0x401070: push 4; jmp 0x401020`，PLT0 会 `push link_map; jmp _dl_runtime_resolve`。`ret` 到 `0x401070` 时解析器重新解析 `read`、把真实地址回填 `read@got`，再按当前寄存器调用 `read(rdi,rsi,rdx)`。此时 `rdi=1`（泄露 gadget 留下的）、`rsi=0x404020`、`rdx=0x30`；靶场里 fd 0/1/2 是同一个 socket，fd1 可读，因此可以直接喂 48 字节把 GOT 恢复并继续。
- **解析器栈空间坑**：`_dl_runtime_resolve` 的 xsave 保存区很大（本机约 2.5KB），栈必须放在 bss 页高处（如 `0x404e00`）；放在 `0x404040` 会向下写到 RELRO 只读页 `0x403000-0x404000`，触发 `SEGV_ACCERR`。
- **0x30 分块 ROP**：每轮只有 0x30 字节，第 5、6 个 qword 还被下一轮控制流占用。做法是每块 `[q0][q1][q2][pop r13; pop r14; ret][A_next][0x40122b]`：ROP 执行到 `pop r13; pop r14; ret` 时把两个控制 qword 弹掉，再 ret 到下一块开头，于是每 0x30 字节得到 3 个可用 ROP qword。4 块引导链把 `read(0, BIGBUF, 0x400)` 调起来并用 `pop rsp; BIGBUF` 迁到 bss，之后就是无长度限制的普通 ROP。
- **seccomp 下只能 ORW**：沙箱只杀 `execve/execveat`，其它 syscall 放行，因此最终链是 `open(path,0) -> read(fd,FLAGBUF,0x80) -> write(1,FLAGBUF,0x80)`。注意 libc `open()` 会覆盖 `rdx`（caller-saved），`pop rdx` 必须放在 open 之后，否则 read/write 长度为 0。

## 触发条件

- 存在栈溢出，能覆盖 `saved rbp` 与 `saved rip`；函数 epilogue 为 `leave; ret`。
- 程序在函数体内存在 `read(0, rbp-0x20, 0x30)` 这类以 `rbp` 为基址的固定长度写，且能跳到 prologue 之后的地址重复执行。
- `.got.plt` 可写（No/Partial RELRO），且能找到“把某次调用改造成 write”的短 gadget（如 `mov edi,1; call write@plt`）。
- 有可用的 PLT 桩与 `_dl_runtime_resolve`（动态链接、lazy binding），且栈空间可迁移到 bss 高处。
- seccomp 允许 `open/read/write`，禁止 `execve`；flag 路径可读。

## 利用步骤

1. 确认保护与溢出形状：Partial RELRO、无 canary、无 PIE；记录 `vuln` 函数体内 `read(0, rbp-0x20, 0x30)` 的地址（本例 `0x40122b`）与 `read@got` 地址（`0x404038`）。
2. 第一轮溢出：0x20 填充 + `saved rbp = 0x404040` + `saved rip = 0x40122b`，进入“rbp 任意写”循环。
3. 把 `read@got` 改成 `0x401250`（`mov edi,1; call write@plt`）；把 `[0x404040]=0x404e00`、`[0x404048]=0x40122b` 布置下一轮。
4. 以 `rbp=0x404040` 再走一轮，`call read@plt` 变成 `write(1, 0x404020, 0x30)`，泄露 `write@got` 等；用 libc `write` 偏移算基址。
5. `ret` 到 `read@plt` 桩（`0x401070`），让 `_dl_runtime_resolve` 重新解析 read；同时喂 48 字节恢复 `0x404020..0x404038` 的 GOT 槽（含真实 `read` 地址），并把栈迁到 `0x404e00`。
6. 用 4 块 0x30 分块 ROP 调 `read(0, BIGBUF, 0x400)` 并 `pop rsp` 到 BIGBUF；随后布置 ORW：`open("/flag",0)` → `pop rdx` → `read(3,FLAGBUF,0x80)` → `write(1,FLAGBUF,0x80)`。
7. 触发链读取 flag；若崩溃，优先检查 `_dl_runtime_resolve` 的栈位置、`pop rdx` 是否在 open 之后、以及每块最后两个 qword 是否被正确弹掉。

## PoC

以下为按原文结构重写的最小骨架（地址为原题示例，需按目标重算；原文附录 EXP 为空，未在本库复跑）。关键是先让 `rbp-0x20 = read@got`，这样 0x30 字节的写入只覆盖 `read@got` 及其后的 pivot 区，不会破坏 `write@got`：

```python
from pwn import *

VULN_BODY    = 0x40122b   # read(0, rbp-0x20, 0x30); ...; leave; ret
READ_GOT     = 0x404038
WRITE_GADGET = 0x401250   # mov edi, 1; call write@plt
READ_PLT     = 0x401070   # push 4; jmp plt0 -> _dl_runtime_resolve
BSS_HIGH     = 0x404e00
BIGBUF       = 0x404800

# 1) 溢出进入任意写循环，令 rbp-0x20 = read@got
p.send(b"A" * 0x20 + p64(READ_GOT + 0x20) + p64(VULN_BODY))

# 2) 覆盖 read@got = WRITE_GADGET；同时布置 leak 轮的 pivot：
#    0x404040/0x404048 是 leak 轮 leave;ret 要用的下一个 rbp/rip
#    0x404058/0x404060 是本轮 leave;ret 要用的下一个 rbp/rip（指向 leak 轮）
payload = flat(
    WRITE_GADGET,  # 0x404038 read@got
    BSS_HIGH,      # 0x404040 -> leak 后迁移到 bss 高处
    READ_PLT,      # 0x404048 -> 进入 read 的 PLT 桩恢复 read
    0x401241,      # 0x404050 -> resolver 返回后的续点（按目标版本核对）
    READ_GOT + 8,  # 0x404058 -> 下一轮 rbp=0x404040（leak 轮）
    VULN_BODY,     # 0x404060 -> 下一轮 rip
)
p.send(payload[:0x30])

# 3) leak 轮：rbp=0x404040，read@got 已是 write gadget，不再读取输入，
#    直接 write(1, 0x404020, 0x30)；随后 leave;ret 走 0x404040/0x404048
leak = p.recvn(0x30)
write_addr = u64(leak[8:16])          # 0x404028 write@got -> libc base
# libc = ... 由 write 偏移计算

# 4) 恢复阶段：ret 到 READ_PLT，_dl_runtime_resolve 重解析 read 并调用
#    read(1, 0x404020, 0x30)；喂 48 字节恢复 GOT（read@got 需填回 libc read）并
#    设置后续 pivot。具体 48 字节布局随目标 libc/栈布局调整，此处省略。
```

分块 ROP 每块的形状（0x30 字节一轮，最后两个 qword 用于下一轮控制流）：

```text
[q0][q1][q2][pop r13; pop r14; ret][A_next][0x40122b]
```

## 变体与关联

- **任意写变体**：若函数体内没有 `rbp-0x20` 写，但有 `leave; ret` 与可控 rbp，可寻找其它以 rbp 为基址的读写 gadget；或直接用 `leave; ret` 做栈迁移。
- **GOT 改写变体**：把 `read` 改成 `write` 只是其中一种；也可把其它函数改成 `write`/`puts`/`system`，或把 `printf` 改成 `system`。
- **恢复变体**：`_dl_runtime_resolve` 重解析依赖 PLT 桩仍存在；若桩被破坏，可改用 `ret2dlresolve` 构造假 reloc/link_map，或直接用 libc 地址恢复 GOT。
- **关联卡片**：[[binary-pwn-setuid-got-plt-lazy-binding-hijack]]（GOT/PLT lazy binding 劫持）、[[binary-pwn-stack-pivot-leave-ret-bss]]（leave;ret 栈迁移）、[[binary-pwn-stack-ret2dlresolve-partial-relro-64-fake-reloc]]（ret2dlresolve 构造假重定位）。

## 检测与防御

- **编译加固**：开启 Full RELRO（`-z relro -z now`）使 GOT 只读；开启 canary、PIE；用 `-D_FORTIFY_SOURCE=2` 与编译器栈保护。
- **代码修复**：`read` 长度必须不超过缓冲区大小（本例 0x20 而非 0x30）；不要用 `rbp` 作为用户可控的写基址；对关键函数指针/GOT 做完整性校验。
- **沙箱**：seccomp 只允许必要 syscall；即便只能 ORW，也要限制可打开路径与文件权限。
- **检测**：监控进程对 `.got.plt` 的写、`_dl_runtime_resolve` 在非正常调用点的触发、`open/read/write` 连续读取敏感文件，以及栈指针跳到 bss/堆等非栈区域。
