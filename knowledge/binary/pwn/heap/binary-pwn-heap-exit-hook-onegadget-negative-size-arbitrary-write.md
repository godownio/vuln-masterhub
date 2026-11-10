---
id: binary-pwn-heap-exit-hook-onegadget-negative-size-arbitrary-write
title: 堆题/任意写场景 exit_hook one_gadget：负 size 邻接 libc 映射泄露 + 逐字节改写 _rtld_global
type: scenario
domain: binary
path: binary/pwn/heap
technique: exit-hook-onegadget-negative-size-arbitrary-write
aliases:
- exit_hook one_gadget
- _rtld_global 劫持
- _dl_fini hook
- libc 2.23 exit_hook 偏移
- libc 2.27 exit_hook 偏移
- ezheap exit_hook
- hctf2018_the_end
tags:
- pwn
- glibc
- exit-hook
- rtld-global
- one-gadget
- arbitrary-write
- negative-size
- heap
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: glibc < 2.34（原文给出 libc 2.23 与 2.27 的固定偏移）
verification:
  verified_by: verifier-V282
  verified_at: '2026-11-08T05:15:28+08:00'
  notes: 已对照原文与10张截图核对：exit→__run_exit_handlers→_dl_fini、_rtld_global 的 _dl_rtld_lock_recursive/_dl_rtld_unlock_recursive 指针、libc 2.23 偏移 0x5f0040+3848/3856 与 2.27 偏移 0x619060+3840/3848、ezheap 负 size malloc+8字节任意写、the_end 4轮逐字节写+exit(1337) 均一致。dedup top 候选均为相关堆题（刀 one_gadget hook 路线），与 binary-pwn-format-string-exit-hook-rtld-global 共享 sink 但写原语/目标不同，保留双卡；dup-scan 无本卡 pair。未验证点：未本地复跑，ezheap EXP 中 heap_addr 名称与 libc_base 关系按偏移推断，the_end 源码循环为 i<=4（5 次 read）而 EXP 只发 4 轮，按原文 EXP 记录。
---

## 一句话结论

glibc < 2.34 中 `exit()` → `__run_exit_handlers` → `_dl_fini` 会调用 `_rtld_global` 里的 `_dl_rtld_lock_recursive` / `_dl_rtld_unlock_recursive` 函数指针；只要有一次任意写，把这两个指针改成 one_gadget，程序正常退出时就会跳转到 one_gadget 拿 shell。原文给出 libc 2.23/2.27 的固定偏移，并用两道题演示两种写原语：负 `size` 的 `malloc` 把返回地址映射到 libc 附近以泄露基址后 8 字节任意写（ezheap），以及已知 libc 基址下 4 轮“8 字节地址 + 1 字节值”的逐字节写（hctf2018_the_end）。

## 原理

- **退出调用链**：`exit(status)` 进入 `__run_exit_handlers`，遍历 `__exit_funcs` 后调用 `_dl_fini`；`_dl_fini` 在加/解 loader 锁时通过 `_rtld_global` 中的函数指针调用 `_dl_rtld_lock_recursive` / `_dl_rtld_unlock_recursive`，默认指向 `rtld_lock_default_lock_recursive` / `rtld_lock_default_unlock_recursive`。
- **可写函数指针**：`_rtld_global` 位于 ld/libc 的可写数据段，Full RELRO 只保护 ELF 自身 GOT，不会保护该结构。把这两个指针覆盖为 one_gadget 地址后，`_dl_fini` 的间接调用即跳转到 one_gadget；one_gadget 的栈/寄存器约束需按目标 libc 选择。
- **固定偏移（原文实测）**：
  - libc-2.23：`exit_hook = libc_base + 0x5f0040 + 3848`，以及 `+ 3856`（两个锁函数指针）；
  - libc-2.27：`exit_hook = libc_base + 0x619060 + 3840`，以及 `+ 3848`。
  不同发行版/补丁级需重新在 gdb 中用 `p &_rtld_global` 与 `x/20gx &_rtld_global+偏移` 核对。
- **负 size 的堆利用（ezheap）**：程序把用户输入的有符号 `int size` 直接交给 `malloc(size)`；输入负值会在转换成 `size_t` 后变成巨大请求，触发 `mmap` 式大块映射，返回地址落在 libc 附近而不是普通堆区。程序随后打印该地址，攻击者用泄露值加上固定差值得到 libc 基址/exit_hook 地址。
- **题目还提供 8 字节任意写**：主逻辑读入 8 字节目标地址，再读入 8 字节数据写入，最后 `exit(0)`；因此可直接把 `exit_hook` 指针写成 one_gadget，无需改返回地址或走 IO 链。
- **4 字节写题目（hctf2018_the_end）**：程序先泄露 `&sleep` 并给出 libc，再循环 4 次，每次读 8 字节地址 + 1 字节值；把 one_gadget 的 4 个字节依次写到 `exit_hook` 的连续 4 个地址上，最后 `exit(1337)` 触发。
- **为什么选择一行 hook 而非 IO 链**：低版本 libc 的 `_IO_FILE` 利用受 vtable 检查/结构约束较多，而 `_rtld_global` 指针只做间接调用、不需要伪造复杂对象；一次写即可在程序正常退出时稳定触发，适合“只给任意写、没有其他原语”的题。

## 触发条件

- 目标使用 glibc < 2.34（2.34 起 `_dl_fini`/rtld 锁处理变化，exit_hook 失效）；
- 程序会调用 `exit()`（不是 `_exit`/`sys_exit`），从而走到 `_dl_fini`；
- 存在一次任意写原语（heap 溢出/UAF、任意地址写、格式化字符串等）且能算出 `_rtld_global` 中锁函数指针地址；
- one_gadget 的约束在当前栈/寄存器状态下满足；
- 偏移与目标 libc 版本一致（本地附件需用同版本 libc/ld 调试）。

## 利用步骤

**ezheap（负 size + 8 字节任意写）**

1. 完成 100 次猜数字（`srand(time(0))`，用同种子脚本复现），进入 `malloc(size)`。
2. 输入负 `size`（原文用 -10），使 `malloc` 返回 libc 附近的映射地址；程序打印该地址。
3. 由打印值加固定差值得到 `libc_base`（原文 `heap_addr = leak + 0x100000ff0`）。
4. 计算 `exit_hook = libc_base + 0x619f60 + 8`（按目标 libc 版本选择偏移）与 one_gadget（原文 `heap_addr + 0xe585f`，等价于 libc 基址 + one_gadget 偏移）。
5. 程序读入地址时写 `exit_hook`，读入数据时写 one_gadget 的 8 字节；随后 `exit(0)` 触发 `_dl_fini` → one_gadget。

**hctf2018_the_end（4 字节逐字节写）**

1. 接收 `here is a gift %p` 泄露的 `&sleep`，减去 libc 中 `sleep` 偏移（原文 `-0xcc2b0`）得到 libc 基址。
2. 计算 `target_addr = libc_base + 0x5f0040 + 3848`（libc 2.23 的 exit_hook）。
3. 选择 one_gadget（原文 `0xf03a4`，也可尝试 `0x4527a`/`0xf1247`），按字节拆成 4 份。
4. 循环 4 次：先发 `p64(target_addr)`，再发 `p8(gadget & 0xff)`；每次 `target_addr += 1`、`gadget >>= 8`。
5. `exit(1337)` 触发，`_dl_fini` 调用被覆盖的锁函数指针跳转 one_gadget。

## PoC

原文 EXP 关键片段（偏移/one_gadget 需按目标 libc 重算，未在本机复跑）：

```python
# ezheap：负 size 泄露 + 8 字节写 exit_hook
rl("input size you want to malloc\n")
sl(str(-10))
heap_addr = int(mx.recv(14), 16) + 0x100000ff0   # 由泄露值推算 libc 附近地址
ogg = heap_addr + 0xe585f
exit_hook = heap_addr + 0x619f60 + 8

rl("input address: ")
s(p64(exit_hook))
s(p64(ogg))
inter()
```

```python
# the_end：libc 基址 + 4 轮逐字节写
libc_addr = int(re(14), 16) - 0xcc2b0
target_addr = libc_addr + 3848 + 0x5f0040        # libc 2.23 exit_hook
ogg = libc_addr + 0xf03a4
for i in range(4):
    s(p64(target_addr))
    s(p8(ogg & 0xff))
    target_addr += 1
    ogg >>= 8
inter()
```

偏移核对：

```text
# gdb/pwndbg 中
p &_rtld_global
p &_rtld_global->_dl_rtld_lock_recursive
p &_rtld_global->_dl_rtld_unlock_recursive
# 在 _dl_fini 的 call qword ptr [rip+...] 处断点，读 RDI 可得 _dl_load_lock 地址
```

## 变体与关联

- **变体**：目标指针可换成 `system` + 把 `_dl_load_lock` 写成 `/bin/sh`（见关联卡）；也可只改 lock 或 unlock 其中之一，取决于 `_dl_fini` 走哪个分支。
- **变体**：写原语可换成格式化字符串 `%hn`、UAF/fastbin dup、任意地址写等；目标可扩展到 `__exit_funcs` 链表、`.fini_array`、`__malloc_hook`/`__free_hook`（glibc 2.34 前）。
- **变体**：one_gadget 不满足约束时可换 `setcontext`/`svcudp_reply` 等栈迁移 gadget，或改回 `system("/bin/sh")`。
- **关联**：[[binary-pwn-format-string-exit-hook-rtld-global]]（同一条 `__run_exit_handlers`→`_dl_fini` 链，使用格式化字符串写 `system` + `/bin/sh`；本卡是堆/任意写 + one_gadget 且给出 2.23/2.27 固定偏移）、[[binary-pwn-heap-house-of-banana-link-map-dl-fini]]（同样借 `_dl_fini`，但伪造 link_map 的 `DT_FINI_ARRAY`）、[[binary-pwn-heap-calloc-tcache-overlap-realloc-hook-onegadget]]（低版本 hook + one_gadget 的同类目标选择）、[[binary-pwn-heap-glibc223-uaf-fastbin-dup-malloc-hook-realloc-onegadget]]（2.23 堆题 one_gadget 实践）。

## 检测与防御

- **版本边界**：升级 glibc ≥ 2.34 可直接消除该 exit_hook；无法升级时避免 `_rtld_global` 可写（强化 RELRO/只读映射需发行版支持）。
- **利用面收敛**：修复有符号 `size` 直接传入 `malloc`/`calloc` 的整数转换问题（负值应先校验并拒绝）；对所有用户可控长度做上界与符号检查，避免超大映射泄露 libc 附近地址。
- **任意写防护**：堆题/真实程序启用 ASLR、Full RELRO、Safe-Linking、FORTIFY，减少可写函数指针；消除“任意地址写 8 字节”类原语。
- **检测**：监控 `_rtld_global` 数据段写入（需内核/EDR 支持）、异常大尺寸 `mmap` 返回地址与 libc 段相邻、`exit` 前对 `_dl_rtld_*_recursive` 指针完整性校验；CTF 环境可用 glibc 2.34+ 或 seccomp 限制。
- **分析辅助**：在 `_dl_fini` 的间接 call 处下断点，检查目标是否指向非 `rtld_lock_default_*` 区域；对 one_gadget 常见偏移（如 2.23 的 `0x4527a/0xf03a4/0xf1247`）做二进制扫描。
