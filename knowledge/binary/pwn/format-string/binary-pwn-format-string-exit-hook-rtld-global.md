---
id: binary-pwn-format-string-exit-hook-rtld-global
title: exit_hook 劫持：把 _rtld_global 的 rtld lock/unlock 函数指针改成 system、_dl_load_lock 改成 /bin/sh（glibc < 2.34）
type: scenario
domain: binary
path: binary/pwn/format-string
technique: exit-hook-rtld-global-lock-pointers
aliases:
- exit_hook
- _rtld_global 劫持
- _dl_rtld_lock_recursive
- _dl_rtld_unlock_recursive
- _dl_load_lock
- exit 劫持
- 退出流程 getshell
tags:
- pwn
- format-string
- exit-hook
- rtld-global
- arbitrary-write
- libc
- glibc
- getshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: glibc < 2.34（原文标记：glibc-2.34 后失效）
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T17:12:30+08:00'
  notes: 已对照原文核对：exit→__run_exit_handlers→_dl_fini、_rtld_global 的 _dl_rtld_lock_recursive/_dl_rtld_unlock_recursive、_dl_load_lock 作 /bin/sh 参数、glibc-2.34 后失效与 2 字节分段写入模板均一致；原文写锁/解锁指针可'或'改一处，卡片建议两处都改写属合理扩展，未复跑
---

## 一句话结论

程序调用 `exit()`（而非 `_exit`/`sys_exit`）时会经 `__run_exit_handlers` 进入 `_dl_fini`，后者从 `_rtld_global` 中取出 `_dl_rtld_lock_recursive` / `_dl_rtld_unlock_recursive` 两个函数指针调用，并把 `_dl_load_lock` 的地址作为参数传入；在 glibc < 2.34 上只要有一次任意写，把这两个指针改成 `system`、把 `_dl_load_lock` 改成 `/bin/sh\0`，`exit()` 时就会执行 `system("/bin/sh")`。

## 原理

- **exit 的调用链**：`exit(status)` → `__run_exit_handlers` → 遍历 `__exit_funcs` 并调用 `_dl_fini`；`_dl_fini` 是动态链接器的析构入口，负责遍历已加载对象的 fini_array。
- **`_rtld_global` 中的两个锁函数指针**：`_dl_fini` 在持有/释放 loader 锁时调用 `_rtld_global._dl_rtld_lock_recursive` 与 `_dl_rtld_unlock_recursive`。这两个字段本质是函数指针，默认指向 `rtld_lock_default_lock_recursive` / `rtld_lock_default_unlock_recursive`；把它们改成 `system` 后，`_dl_fini` 的调用就变成 `system(...)`。
- **RDI 参数**：调试可见 `_dl_fini` 在 `call qword ptr [rip+...]` 前执行 `lea rdi, [rip+0x1cb97]`，得到的地址落在 `_rtld_global` 附近（`_dl_load_lock` 的地址）。把该地址处的内容改成 `/bin/sh\0`，再让锁函数指针指向 `system`，调用即 `system("/bin/sh")`。
- **偏移获取**：在 gdb/pwndbg 中 `p &_rtld_global` 得到结构基址，`x/500a` 或 `p &_rtld_global->_dl_rtld_lock_recursive` 得到字段地址，再与 libc/ld 基址相减；`_dl_load_lock` 的地址可通过在 `_dl_fini` 的 `call` 处断点看 RDI 得到。需要 patch 与远程一致的 libc/ld/libseccomp 才能算准偏移。
- **为什么可用**：`_rtld_global` 位于 ld/libc 的可写数据段，Full RELRO 只保护 ELF 自身的 GOT，不保护这里；`exit` 是程序正常结束的必经路径，攻击者不需要控制返回地址，只要有一次任意写即可把“退出”变成 getshell。
- **版本边界**：glibc 2.34 起对 `_dl_fini`/rtld 锁的处理发生变化（`__libc_csu_fini` 等也被移除/调整），该 exit_hook 在 2.34 后失效；不同发行版/补丁级别偏移不同，需按目标 libc/ld 核对。

## 触发条件

- 目标 glibc < 2.34，且程序会调用 `exit()`（不是 `_exit`/`sys_exit`），从而走到 `_dl_fini`。
- 攻击者已有一次任意写原语（格式化字符串 `%n`/`%hn`、UAF 写、GOT 写等），且知道 libc/ld 基址或能泄露。
- `_rtld_global`、`_dl_rtld_lock_recursive`、`_dl_rtld_unlock_recursive`、`_dl_load_lock` 相对 libc/ld 的偏移与目标环境一致（本地附件需 patch libc/ld/libseccomp）。
- 写入长度/次数足够（每个 8 字节指针拆成 4 个 2 字节写，或用 1 字节写更多轮）。

## 利用步骤

1. 泄露 libc/ld 基址（如格式化字符串 `%p`、GOT 泄露）。
2. 在本地用同版本 libc/ld 调试：`p &_rtld_global`、`p &_rtld_global->_dl_rtld_lock_recursive`、`p &_rtld_global->_dl_rtld_unlock_recursive`，并在 `_dl_fini` 的间接 call 处读 RDI 得到 `_dl_load_lock` 地址；计算相对基址偏移。
3. 计算远程地址：`exit_hook = libc_base + offset(_dl_rtld_lock_recursive)`，`rdi_addr = libc_base + offset(_dl_load_lock)`。
4. 用任意写把 `system` 地址按 2 字节分段写到 `_dl_rtld_lock_recursive` 与 `_dl_rtld_unlock_recursive`（两个指针都改，避免锁路径不同）。
5. 把 `/bin/sh\x00`（`0x68732f6e69622f`）按 2 字节分段写到 `_dl_load_lock` 地址。
6. 让程序执行 `exit(0)`；`_dl_fini` 调用被劫持的锁函数，执行 `system("/bin/sh")`，拿到 shell。
7. 若失败，检查 glibc 版本、偏移、写入是否覆盖完整 8 字节、是否走的是 `_exit` 而非 `exit`。

## PoC

```python
# 原文按 2 字节分段写入的模板（地址/偏移需按目标 libc/ld 重算）
for i in range(4):
    payload = fmtstr_payload(offset, {exit_hook + i*2: system & 0xffff}, write_size='short')
    fmt(payload)
    system >>= 16

rdi_value = 0x68732f6e69622f          # "/bin/sh\0"
for i in range(4):
    payload = fmtstr_payload(offset, {rdi + i*2: rdi_value & 0xffff}, write_size='short')
    fmt(payload)
    rdi_value >>= 16
```

```text
# 调试定位（pwndbg）：
p &_rtld_global
p &_rtld_global->_dl_rtld_lock_recursive
p _rtld_global->_dl_rtld_lock_recursive
# 在 _dl_fini 的 call qword ptr [rip+...] 处断点，读 RDI 即 _dl_load_lock 地址
```

说明：原文在 glibc < 2.34 的题目上使用该模板；本库未复跑，偏移与版本需按目标核对。

## 变体与关联

- 变体：只改 `_dl_rtld_lock_recursive` 或只改 `_dl_rtld_unlock_recursive`，取决于 `_dl_fini` 走 lock 还是 unlock 分支。
- 变体：把 `system` 换成 one_gadget，省去 `/bin/sh` 写入；或把 `_dl_load_lock` 换成其他可执行字符串地址。
- 变体：`exit` 的 GOT/PLT 劫持、`__run_exit_handlers` 的 `__exit_funcs` 链表劫持、`.fini_array` 循环（见 [[binary-pwn-format-string-non-stack-fini-array-loop-write]]）。
- 关联：[[binary-pwn-format-string-malloc-hook-one-gadget]]（另一类 hook 目标）、[[binary-pwn-format-string-got-hijack]]（GOT 覆写）、[[binary-pwn-setuid-got-plt-lazy-binding-hijack]]（PLT/GOT 劫持）。
- 边界：glibc ≥ 2.34 失效；目标使用 `_exit`/`sys_exit` 时不走 `_dl_fini`；Full RELRO 不影响 ld 数据段，但 PIE/ASLR 需要先泄露基址。

## 检测与防御

- **版本**：升级到 glibc 2.34+，或使用不暴露可写 rtld 锁函数指针的构建；及时应用发行版补丁。
- **完整性**：对 `_rtld_global` 中的锁函数指针做运行期完整性监控/只读映射；限制对 ld.so 数据段的写。
- **利用面**：修复任意写漏洞（格式化字符串、UAF、越界写）是根本；`printf("%s", buf)`、`-Wformat-security`、Full RELRO、PIE、ASLR、Canary 作为纵深防御。
- **检测**：进程退出阶段出现异常 `system`/`execve` 调用、`_dl_fini` 附近 RDI 指向 `/bin/sh`、`_rtld_global` 数据段被改写；监控格式化字符串大输出与 `%hn` 写入。
