---
id: ctf-pwn-cpp-exception-catch-hidden-shell
title: 输入 0 触发除零异常，进入 catch 分支里隐藏的 shell() 后门
type: scenario
domain: ctf
path: ctf/pwn
technique: cpp-exception-handler-hidden-shell
aliases:
- C++ 异常处理后门
- 除零触发 catch
- __cxa_throw 路径
- catch 里调用 shell
tags:
- pwn
- cpp
- exception
- cxa-throw
- logic-bug
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:48:47+08:00'
  notes: 已对照原文核对；本次核对未读取图片；login() 中 v2==0 时 __cxa_allocate_exception+__cxa_throw、catch 内 __cxa_begin_catch 后 call _Z5shellv、PoC 发送 0 两次均与正文一致
---

## 一句话结论

`login()` 里 `scanf("%d",&v2)` 后若 `v2 == 0` 就 `__cxa_allocate_exception` + `__cxa_throw("Division by zero condition!")`；异常捕获块里在 `__cxa_begin_catch` 之后无条件 `call _Z5shellv`，因此只要输入 `0` 触发异常，就会走 catch 分支执行隐藏的 `shell()`，不需要任何内存破坏。

## 原理

- 程序把“除零”写成显式 C++ 异常而不是 `SIGFPE`，异常路径完全由 Itanium ABI 的 `__cxa_throw` → 栈展开 → personality routine → landing pad 决定。
- 反汇编在 catch 块可见 `call ___cxa_begin_catch` 紧跟 `call _Z5shellv`（`shell(void)`），即“捕获即执行”，属于调试遗留后门。
- 触发只需要让被除数为 0：`return (v3 / v2);` 前的 `if (!v2)` 主动抛异常，比等真实除零信号更可控，也绕开了所有输入过滤。
- 该路径不涉及栈溢出或地址泄露，因此 PIE/Canary/NX 全开也照样触发，这也是此类后门在 CTF 中“看起来无洞却可 getshell”的原因。

## 触发条件

- 二进制为 C++ 且启用异常（`-fexceptions`），存在 `__cxa_throw`/`__cxa_begin_catch` 调用。
- 异常捕获块内存在敏感调用（`system`/`execve`/自定义 `shell()`）。
- 用户可控的触发条件（如除数为 0、越界索引、`std::stoi` 抛 `invalid_argument`）。

## 利用步骤

1. 在 IDA 中搜索 `__cxa_throw`，定位抛出点与对应的 `landing pad`（`catch`/`__cxa_begin_catch` 后续指令）。
2. 阅读 catch 块，确认其中调用的函数（本例 `shell(void)`，内部执行 `system("/bin/sh")`）。
3. 找到触发条件（`scanf("%d")` 得 0 → 主动 throw），输入 `0`。
4. 异常展开进入 catch，`shell()` 执行，拿 shell 读 flag。

## PoC

```python
from pwn import *
context(arch='amd64', os='linux')
p = process('./rhg8')
p.recvuntil(b'input your calc num')
p.sendline(b'0')     # v2 == 0 -> __cxa_throw -> catch -> shell()
p.interactive()
```

## 变体与关联

- 变体：`std::stoi("abc")` 抛 `std::invalid_argument`、`vector::at()` 抛 `out_of_range`、`dynamic_cast` 失败抛 `bad_cast`，只要 catch 侧有敏感调用都等价。
- 变体：异常对象内容可被攻击者影响（如把可控字符串塞进异常 payload），catch 里再当作命令执行——见关联卡。
- 关联：[[ctf-pwn-cpp-exception-payload-src-system-command]]（异常对象携带可控指针，catch 直接传给 `system`）、[[binary-pwn-stack-cpp-exception-unwind-landing-pad-canary-bypass]]（借异常展开绕过 Canary）。
- 边界：以 `-fno-exceptions` 编译、或 catch 分支已被裁掉时不存在该路径；若异常类型不匹配会继续展开到 `std::terminate`。

## 检测与防御

- 检测：`__cxa_throw` 附近的 catch 块是否含 `system`/`exec`/自定义 shell；发布版二进制里不应存在此类调试分支。
- 修复：删除调试后门；catch 中只做错误日志与安全降级，禁止任何命令执行。
- 加固：编译期禁用异常或删除未使用分支（`-ffunction-sections -Wl,--gc-sections`）；对异常对象做类型与长度校验。
