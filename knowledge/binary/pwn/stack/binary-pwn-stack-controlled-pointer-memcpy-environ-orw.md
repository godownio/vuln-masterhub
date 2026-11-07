---
id: binary-pwn-stack-controlled-pointer-memcpy-environ-orw
title: 64 位受控 heap_backup 指针 + memcpy 写栈：environ 泄露、空字节整形 ROP 与 seccomp ORW
type: scenario
domain: binary
path: binary/pwn/stack
technique: controlled-pointer-memcpy-stack-rop-environ-zero-write
aliases:
- 受控指针 memcpy 写栈
- environ 泄露栈
- 空字节写整形
- heap_backup 任意指针
- 配置管理器 ORW
- seccomp 只杀 execve
tags:
- pwn
- stack
- rop
- 64bit
- arbitrary-write
- environ-leak
- null-byte-write
- seccomp
- orw
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V181
  verified_at: '2026-11-06T17:43:16+08:00'
  notes: 已对照原文核对：off 偏移写全局 heap_backup、exchange 的 memcpy+对齐空字节写、environ-0x1f8 泄露栈、pay 逐槽写栈与只杀 execve 的 seccomp ORW 均与原文一致。未复跑，environ 偏移、pay 公式与 fd 需按目标栈布局核对。
---

## 一句话结论

64 位配置管理程序允许把输入中任意偏移的 8 字节写入全局 `heap_backup` 指针，并在 `exchange` 选项执行 `memcpy(heap_backup, config_data, strlen(config_data))` 加一次对齐地址的空字节写；先用 `view` 读取 `environ` 泄露栈地址，再把 `heap_backup` 指向栈、用 memcpy 把 ROP 链写到栈上，配合空字节写整形 gadget 地址，最终在只杀 `execve` 的 seccomp 下用 open/read/write 读取 flag。

## 原理

- **任意指针写**：`handle_edit` 的备份分支在输入长度不超过 0xFF 时读取一个 `off`，执行 `fake_addr = *(void **)&buf_backup[off]; *heap_backup = fake_addr;`。`buf_backup` 是同一份用户输入，`heap_backup` 是全局指针，因此选择 `off` 就能把输入中任意 8 字节写入 `heap_backup`；输入长度超过 0xFF 时则取 `buf_backup[0x100]`。这给出了“设置任意目标指针”的原语。
- **任意写 + 空字节写**：`exchange`（选项 4）执行 `ptr = heap_backup; memcpy(ptr, config_data, strlen(config_data)); actual_length = strlen(config_data); ptr = (ptr + actual_length) & ~7;`，若用户再输入 `y` 和整数 `n`，则 `ptr[n] = 0`。于是可以：(a) 把 `config_data` 整段写到 `heap_backup` 指向的任意地址；(b) 在写完后的 8 字节对齐位置再写一个 `\x00`，用来清零某个字节/低字节，调整 gadget 地址或字符串终止。
- **任意读泄露栈**：选项 2 取 `config_data` 的前 8 字节作为地址，`handle_view(addr)` 执行 `write(1, addr, 8)`。把该 8 字节设为 `environ` 符号地址，即可读出 libc 保存的环境指针，减固定偏移得到栈上 `rbp`/返回地址附近的位置。
- **把 ROP 链写到栈上**：先设置 `heap_backup = stack`，再让 `config_data` 携带“填充 + 目标值”的布局，`memcpy` 到栈上的已知地址；由于多次写会相互覆盖，利用 `ptr[n]=0` 的空字节写在每次写入后修正低字节/对齐，使最终栈上形成连续的 ROP 链（文章按 `pay(offset, value)` 从高地址向低地址逐槽写入）。
- **seccomp 只杀 execve**：文章定制的沙盒过滤器只在 `sys_nr == __NR_execve` 时返回 KILL，其余 ALLOW；因此不需要绕 execve，直接用静态二进制里的 `open`/`read`/`write`（或 syscall gadget）构造 ORW 链读取 `/flag`（示例用 `////flag`）。
- **为什么不用 free_hook**：该定制题刻意保留 seccomp、去掉可劫持 hook 的简单路径，逼迫走“指针设置 + memcpy 写栈 + ROP”的路线；静态非 PIE 使 PLT/gadget 地址固定，不需要先泄露代码基址。

## 触发条件

- 64 位静态/非 PIE 配置管理程序，具有 edit/view/exchange/exit 菜单；`handle_edit` 的备份分支允许用输入偏移设置全局 `heap_backup`，`exchange` 用该指针做 `memcpy` 并允许对齐空字节写。
- 选项 2 可按 `config_data` 前 8 字节解引用并输出 8 字节（任意读 8 字节），且二进制含 `environ` 符号。
- seccomp 只杀 `execve`，允许 open/read/write；或目标存在等价的 ORW 路径。
- 已知/可泄露栈地址；能多次交互构建 ROP。

## 利用步骤

1. `edit(p64(environ))` 把 `config_data` 前 8 字节设为 `environ` 地址，选择选项 2 读取 8 字节，得到栈指针；减去固定偏移（示例 `-0x1f8`）得到 `rbp`/链落点。
2. 构造长度 > 0xFF 的输入，在偏移 0x100 放 `p64(stack)`，触发备份分支把 `heap_backup` 设为栈地址。
3. 通过 `exchange`（选项 4）把 `config_data` memcpy 到栈上；按需用 `set(n)` 的空字节写修正低字节/对齐。
4. 用 `pay(offset, value)` 模式在栈上逐槽写入 `/flag` 字符串、`pop rdi/pop rsi/pop rdx`、`open/read/write` 地址与返回地址。
5. 选择退出/返回选项（示例选项 5 `return 0`）触发栈上 ROP；open 打开 `/flag`，read 读入缓冲区，write 输出。
6. 若地址/偏移不同，先用 gdb 确认 `environ` 偏移、栈链起始与 `memcpy` 对齐位置。

## PoC

关键原语与链骨架（完整脚本较长，偏移取自文章示例）：

```python
from pwn import *

environ = 0x4F32D0          # 静态二进制中的 environ 符号
edit(p64(environ))
cmd(2)                       # view: write(1, environ, 8)
rt(b'\n'); rt(b'\n')
stack = u64(io.recv(6).ljust(8, b'\x00')) - 0x1f8

# 输入 > 0xFF，buf_backup[0x100] 被写入全局 heap_backup -> stack
edit(b'a' * 0xf8 + b'@' * 8 + p64(stack))
exchange()                   # memcpy(stack, config_data, strlen(config_data))

# 逐槽写 ROP：pay(n, value) 生成 "填充 + value" 的 config_data，再靠空字节写整形
def pay(n, value):
    pd = b'a' * (0xc8 - n + 0x28) + p64(value)
    edit(pd); set()

pay(0x30, 0)
pay(0x38, 0x20)
pay(0x40, pop_rdx_rbx)
pay(0x48, stack + 0xa00)
pay(0x50, pop_rsi)
pay(0x58, 1)
pay(0x60, pop_rdi)
pay(0x68, read_addr)
# ... 继续布置 open("/flag") / read / write

cmd(5)                       # 触发返回，执行栈上 ORW
io.interactive()
```

`pay` 的偏移公式、`set(n)` 的 `n` 与 `/flag` 字符串位置强依赖目标栈布局，必须按实际二进制重算；文章用 `////flag` 和 `stack+0xc8+8` 等常量适配示例环境。

## 变体与关联

- **任意读变体**：选项 2 的 8 字节读可用于读 GOT、libc 指针、`environ`、栈 canary 等；把 `config_data` 前 8 字节设为目标地址即可。
- **写原语变体**：若程序没有 `exchange`，但备份分支能直接写 `*heap_backup`，则可在一次调用内完成任意 8 字节写；若有 `memcpy` 但没有空字节写，可用多次覆盖或改用已对齐地址。
- **无 seccomp**：可直接把链改成 `system("/bin/sh")`，或用 free_hook 路线（见 [[binary-pwn-stack-string-overflow-adjacent-heap-backup-freehook]]）。
- 关联：[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]（environ 泄露 + 栈 ROP 的堆侧版本）、[[binary-pwn-stack-rbp-arbitrary-write-got-read-write-dlresolve-chunked-rop]]（可控 rbp 任意写的分块 ROP）、[[binary-pwn-stack-fake-rbp-check-seccomp-orw]]（seccomp ORW 栈迁移）。

## 检测与防御

- 代码修复：备份分支不要接受用户提供的偏移并写入全局指针；`memcpy` 前校验目标指针范围与长度；`exchange` 只允许写预分配的缓冲区，禁止任意指针；对 `config_data` 的前 8 字节做类型/范围校验。
- 缓解：PIE + 完整 ASLR 使栈地址不可预测；栈 canary；`environ` 符号可通过 `-z noexecstack`/静态链接裁剪减少泄露面；seccomp 用 allowlist（只允许必要的 read/write/open）而不是“只杀 execve”。
- 检测：进程读取 `environ` 后紧接大量 edit/exchange 请求、`memcpy` 目标落在栈地址、退出时栈返回地址异常；异常的对齐空字节写序列。
- 事件响应：任意写栈通常直接导致 ROP/RCE，需重启并排查持久化。
