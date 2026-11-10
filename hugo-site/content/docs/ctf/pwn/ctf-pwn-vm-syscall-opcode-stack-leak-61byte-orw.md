---
id: ctf-pwn-vm-syscall-opcode-stack-leak-61byte-orw
title: VM 合法指令集即攻击面：用 syscall opcode（rax/rdi/rsi/rdx 全可控）配合「取栈地址」opcode 绕过 PIE，纯字节码拼出 open/read/write，61 字节读出 flag
type: scenario
domain: ctf
path: ctf/pwn
technique: vm-opcode-syscall-stack-address-orw
tags:
- ctf
- pwn
- vm
- opcode
- syscall
- orw
- pie-bypass
- seccomp
- sandbox
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:44:22+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文；cmp 0x21 边界、mov ax,[offset+rcx*2]+add rax,rcx+push+ret 的 0x123a+offset[i] 分派、0x21~0x32 各 handler 的文字功能、0x30 的 rax/rdi/rsi/rdx 可控、[rbx+rdi*8-8] 取址绕过 PIE、open/read/write 三段语义化字节码与 61 字节结果均与正文一致；已把「19 条以上 handler」修正为正文原话「从 0x21 起 19 个」；未复跑题目二进制
url: /docs/ctf/pwn/ctf-pwn-vm-syscall-opcode-stack-leak-61byte-orw/
draft: false
kb_aliases:
- SCTF vmcode
- VM 自实现 syscall 指令
- 字节码构造 ORW
- VM 取栈地址绕过 PIE
- opcode 0x30 syscall
- 无内存破坏的 VM pwn
- 61 字节 ORW
---

## 一句话结论

当自定义 VM 的指令集里存在「读程序栈上的值并按它跳转」「把栈上数据当作地址/参数」「按 `rax/rdi/rsi/rdx` 发起 `syscall`」这几条**设计者本意是给正常程序用的指令**时，攻击者根本不需要越界：只用合法字节码就能在 VM 内拼出 `open('./flag')` → `read(3, addr, 0x100)` → `write(1, addr, 0x100)`，并借助「取栈上数据的地址」这条 opcode 现算出 `"flag"` 字符串与读缓冲区的真实地址，从而在开启 PIE 的情况下也不需要任何地址泄露。

## 原理

- **VM 把宿主 syscall 暴露成了指令**：本题从 0x21 起共有 19 个 handler，其中 0x30 对应「读取 4 个操作数当作 `rax/rdi/rsi/rdx` 后执行 `syscall`」。一旦确认这条 handler 的参数来源是 VM 自己的操作数栈（而不是硬编码常量），攻击者就等价于拿到了**一次完整的系统调用原语**，并且可以任意次调用。这是整条链的根，不需要任何内存破坏。
- **VM 的分派方式本身就是可利用的信息**：程序用 `mov ax, word ptr [offset + rcx*2]` 取一条 2 字节偏移，再 `add rax, rcx`（`rcx` 存的是固定的返回地址）后 `ret`，即**通过合法指令把控制流送到 `$0x123a + offset[i]`**。这解释了为什么「输入 0x21 以上的值就能触发对应功能」——它本质是一个用相对偏移实现的分派表，只要 opcode 落在表内就是合法路径（这也意味着表外的值会让 `ret` 落到任意位置，是另一条更强的但非必要路径）。
- **地址从哪来**：程序开 PIE，`"flag"` 字符串与读缓冲区都在 VM 的栈上，写死绝对地址不可用。但 0x31（把 `stack[v1-1]` 复制到 `stack[v1]`）、0x32（把 code 地址偏移 `rsi` 后写入 VM 栈）与 0x2d/0x23 等算术指令给了「在 VM 栈内搬运与计算」的能力；更关键的是 **VM 允许把栈上的值本身当作一个「地址」来用**（`[rbx + rdi*8 - 8]` 形式取操数时，得到的就是该槽位的真实地址）。于是 `push_4_byte('flag')` 之后用「取栈地址」的 opcode 就能拿到这个字符串在宿主栈上的真实指针，既用于 `open` 的 `rdi`，也用于 `read` 之后的缓冲区基址。
- **为什么 61 字节够**：VM 的每条指令编码很短（opcode + 1~4 字节立即数），且不需要 ROP gadget、不需要 leak、不需要回跳；`open` 4 条 + `read` 8 条左右 + `write` 4 条即可，原文实测 61 字节。
- **为什么必须抬高读地址**：`read` 的缓冲区如果离当前栈顶太近，后续继续 push 参数时会把已读入的 flag 覆盖掉（参数是从栈顶往下/往上压的）。原文明说「再复制并下压 6 次把 rdi 抬高」就是为了留出参数空间，避免读入的 flag 被自己压栈覆盖。
- **seccomp 的作用**：程序建立了沙箱规则，`execve` 不可用，但 `open/read/write` 放行，所以只能走 ORW 而不是 `system("/bin/sh")`；这也解释了为什么必须让 VM 的 syscall 原语可控——它是唯一可用的系统调用出口。

## 触发条件

- 目标是自定义 VM/字节码解释器，输入即字节码，且解释器把某些 opcode 直接映射到宿主 `syscall`，或至少提供「读写宿主内存」「取地址」「算术」这类原语。
- 该 syscall handler 的 `rax`（调用号）与 `rdi/rsi/rdx` 来自 VM 自己的数据栈，可被字节码完全控制。
- 沙箱（seccomp）允许 `open/read/write`（或 `openat`），禁止 `execve`；flag 文件名已知或可枚举（如 `./flag`）。
- 不需要地址泄露：VM 提供「取栈上数据地址」或等价的地址计算能力，否则需先泄露 PIE/栈。

## 利用步骤

1. **定位分派逻辑**：逆向 `main`，找 `cmp rax, 0x21` 之类的边界比较，读随后的 `mov ax,[offset+rcx*2]; add rax,rcx; push; ret`——把 `offset[]` 表与「`0x123a + offset[i]`」的对应关系建出来，得到每个 opcode 的入口地址，逐个反编译成功能表。
2. **筛出可用的三件套**：`syscall`（`rax/rdi/rsi/rdx` 可控）、`取栈地址`（把某栈槽的真实地址压栈）、`push 立即数`（4/8 字节）。
3. **规划寄存器**：`rax=2`（open）、`rdi=&"flag"`、`rsi=0`、`rdx=0`；随后 `rax=0`（read）、`rdi=3`、`rsi=缓冲区地址`、`rdx=0x100`；最后 `rax=1`（write）、`rdi=1`、`rsi=同缓冲区`、`rdx=0x100`。
4. **先压字符串再取址**：`push_4_byte('flag')` → 取栈地址得到指针 → 用它当 `open` 的 `rdi`（`./flag` 需补 `0` 或 `./`）。
5. **抬高缓冲区**：用「复制栈顶」的 opcode 连按 6 次把读地址抬离栈顶，避免后续压参数覆盖读入内容。
6. **按 opcode 编码规则拼字节码**，用题目给的交互脚本送出，观察 `write` 的输出即为 flag。

## PoC

原文用语义化函数表示字节码构造（不是最终二进制串，需按题目编码规则落到字节）：

```python
# open("./flag", 0, 0)
code  = push_4_byte(reversed_string_to_int(b'flag'))   # 压入 "flag"
code += push_rsp()                                     # 取该字符串在宿主栈上的真实地址
code += push_4_byte(0)                                 # rdx = 0
code += swap_8_10()                                    # 调整操作数顺序
code += push_4_byte(2)                                 # rax = 2 (open)
code += syscall()                                      # syscall opcode 0x30

# read(3, addr, 0x100) —— 先把地址抬高，避免读入的 flag 被后续压栈覆盖
code += push_rsp() + copy_and_push() * 6
code += push_4_byte(0x100) + swap_8_10()
code += push_4_byte(3) + push_4_byte(0)                # rdi = 3, rax = 0
code += syscall()

# write(1, addr, 0x100)
code += pop() + copy_and_push() + push_4_byte(0x100) + swap_8_10()
code += push_4_byte(1) + push_4_byte(1)                # rdi = 1, rax = 1
code += syscall()
```

对应的功能语义（按原文功能表归纳，opcode 值需按目标题重算）：

```text
0x21  把输入值与常量相加，作为后续 code 索引
0x23  两栈槽异或
0x24  交换 stack[v1] 与 stack[v1-0x10]
0x25  交换 stack[v1] 与 stack[v1-0x8]
0x2a  stack[v1] -> stack[v1+8]（复制栈顶）
0x2d  循环右移
0x2f  位与
0x30  syscall：rax/rdi/rsi/rdx 全部来自栈（本链核心）
0x31  stack[v1-1] -> stack[v1]（复制，配合取址抬高缓冲区）
0x32  把 code 偏移 rsi 后的地址压入栈（取 code 内地址）
```

## 变体与关联

- **变体（无 syscall opcode）**：若只有「按栈上值计算地址并读写」的 opcode，则退化为任意读写，可改 GOT/`__free_hook` 或写 shellcode（见关联卡）；但那条需要先泄露 libc。
- **变体（分派表越界）**：`0x123a + offset[i]` 的 `ret` 用 2 字节有符号偏移，opcode 超出表范围会落到相邻代码；这条比「合法指令拼 ORW」更强，但需要精确控制落点，本题未用到。
- **变体（flag 名字未知）**：`open("./flag")` 失败时改用 `openat` + 目录遍历、或用 `getdents64`（若沙箱放行）枚举文件名；也可先 `read(0,...)` 从 stdin 读入文件名到栈上再由 VM 取址。
- **关联**：[[ctf-pwn-vm-operand-stack-index-unbounded-push-canary-leak-orw-rop]]（同是 VM 栈原语，但那条靠 push 无上界越界改返回地址走 ROP）、[[ctf-pwn-custom-vm-opcode-native-memory-got-restart-onegadget]]（VM 暴露宿主内存读写）、[[ctf-pwn-vm-arith-bootstrap-rop-residual-libc-pointer]]（无泄漏时用 VM 算术自举）、[[ctf-pwn-vm-stack-index-signed-underflow-got-system]]（VM 负下标打 GOT）、[[binary-pwn-sandbox-escape-alpha3-visible-shellcode-seccomp-orw]]（同为 seccomp 下 ORW 的思路）。
- **边界**：本链**无内存破坏**，因此任何「输入长度/指令合法性校验」都拦不住——它用的就是设计功能；反之若 VM 的 syscall handler 对调用号做白名单（只放行 `read`/`write`），链就断在 `open`；若沙箱禁用 `open` 而只留 `openat`，需换调用号。

## 检测与防御

- **设计层**：VM 指令集不要把「syscall」暴露成可由字节码任意指定调用号的 opcode；必须暴露时对调用号做白名单（只允许业务需要的 `read`/`write`），并在 VM 内做指针合法性校验（操作数地址必须落在 VM 自己的数据段范围内）。
- **沙箱层**：seccomp 应同时收紧 `open/openat`（只允许白名单路径或用 `openat2` 的 `RESOLVE_BENEATH`），不要假设「禁了 `execve` 就安全」——ORW 一样能读走 flag。
- **检测**：字节码里出现连续三次以上 `syscall` opcode 且 `rax` 依次为 2/0/1（open/read/write 的典型序列）；`rdi` 指向栈上由立即数构造的字符串；同一连接内无任何业务语义的短字节码（原文仅 61 字节）就产生大量系统调用。
- **加固**：解释器对每条指令的操作数做类型与范围校验（栈索引不得越界、地址必须在自己分配的栈/数据段内），并把 `syscall` 指令的调用号在编译期固定，不接受运行时输入。
