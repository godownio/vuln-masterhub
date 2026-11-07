---
id: binary-pwn-heap-scanf-scratch-buffer-malloc-sorting
title: scanf 数字解析触发内部 malloc(0x800)：固定大小堆题中强制 unsortedbin 排序的分配原语
type: scenario
domain: binary
path: binary/pwn/heap
technique: scanf-scratch-buffer-malloc-sorting
tags:
- pwn
- heap
- glibc
- scanf
- scratch-buffer
- unsortedbin
- largebin
- ctf
cve: []
severity: medium
confidence: high
affected_versions: glibc 2.32
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V183
  verified_at: '2026-11-06T20:00:36+08:00'
  notes: 已对照 90762 原文核对：scratch_buffer 初始 0x400、首次扩容 malloc(0x800)、超 0x800 走 realloc；0x401-0x800 数字串触发一次 0x800 分配，原文以 0x700 个 1 实测。未复跑 exp；affected_versions 记录原文靶场 libc-2.32（源码机制参照 2.39）。
url: /docs/binary/pwn/heap/binary-pwn-heap-scanf-scratch-buffer-malloc-sorting/
draft: false
kb_aliases:
- scanf 内部分配
- scratch_buffer malloc
- char_buffer 扩容
- 0x800 malloc
- scanf 触发 sorting
- 固定 size 堆题额外分配
---

## 一句话结论

当堆题只允许固定大小（如 0x320）的 `malloc`、无法主动申请大块来触发 bin 排序时，可以让程序用 `scanf("%d", ...)` 解析一段超过 0x400 字节的数字串：glibc 的 `vfscanf` 内部 `scratch_buffer` 会从栈上 0x400 缓冲区扩容为一次堆上的 `malloc(0x800)`，这次库内分配会驱动 `_int_malloc` 处理 unsortedbin，从而把已有的 unsortedbin chunk 排序进 smallbin/largebin，制造后续泄露或重叠的机会。

## 原理

- **scanf 的字符缓冲**：glibc `__vfscanf_internal` 为数字转换（`%d`/`%u`/`%f` 等）准备 `struct char_buffer`，内部是 `struct scratch_buffer`。初始化时 `scratch_buffer_init` 把 `data` 指向结构体内的栈缓冲区 `__space.__c`，长度 1024（0x400）。
- **逐字符追加与扩容**：解析数字时每个字符经 `char_buffer_add` 写入；当 `current == end`（0x400 填满）时调用 `char_buffer_add_slow`，再调用 `scratch_buffer_grow_preserve`。第一次扩容时 `data` 仍指向栈缓冲区，函数执行 `malloc(2 * 0x400) = malloc(0x800)`，把原内容 memcpy 到堆上并继续解析。
- **第二次扩容走 realloc**：若输入继续超过 0x800，`scratch_buffer_grow_preserve` 走 `realloc(data, 0x1000)`；成功后会复制数据并释放旧的 0x800 堆块，这个旧块进入 unsortedbin（0x800 大于 tcache 默认上限 0x410），会进一步扰动 bin 状态。
- **为什么会触发 sorting**：`malloc(0x800)` 进入 `_int_malloc` 后会先扫描 unsortedbin。若 unsortedbin 中存在一个大小合适的 chunk，`_int_malloc` 会把它从 unsortedbin 摘下并按大小归入 smallbin/largebin（或切分使用）。这一步不需要程序提供大块分配接口，因此能突破“只允许固定 size”的限制。
- **为什么输入数字串可行**：`%d` 在转换前会先把所有数字字符读入 `char_buffer`，即使数值本身溢出 `int` 也不影响字符累积；因此发送 0x401–0x800 个 `'1'` 就能稳定触发一次 0x800 的库内 `malloc`。超过 0x800 时则触发 `realloc` 和旧块释放。
- **边界**：`scratch_buffer` 在 `scanf` 返回时会被释放（`scratch_buffer_free`），所以这是“解析期间的临时分配”，不是持久堆块；但它对 bin 的排序/切分副作用在返回后仍然存在。目标 unsortedbin chunk 的大小要适配这次 0x800 请求；原文实测 0x660 的 chunk 可被排序进 largebin，而合并后的 0x990 chunk 未按预期排序，具体需在调试器中确认。

## 触发条件

- 程序使用 `scanf` 的数字转换（`%d`/`%u`/`%ld`/`%f` 等）读取用户输入，且输入点可达、不会在解析前被长度检查截断。
- 堆题只提供固定大小的 `malloc`/`calloc`，无法直接申请 0x800 级别的大块；需要一次“额外分配”来驱动 unsortedbin 排序或消耗 bin。
- 已存在 unsortedbin chunk（例如释放多个大于 tcache 上限的 chunk 并避免与 top 合并），且其大小与 0x800 请求的排序行为匹配。
- 目标为带 `scratch_buffer` 机制的 glibc（原文靶场 libc-2.32；不同版本内部常量需复核）。
- `scanf` 返回后程序仍继续运行（即使长数字导致 `%d` 溢出或落入 default 分支，也不能直接 `exit`）。

## 利用步骤

1. 逆向确认菜单/输入使用 `scanf` 的数字格式，并确认长数字串不会被 `read` 长度或 `strlen` 检查提前截断。
2. 堆风水：填满目标 size 的 tcache，释放若干大于 tcache 上限的 chunk 进入 unsortedbin；在 chunk 后保留 guard，避免与 top 合并。
3. 向 `scanf("%d")` 发送 0x401–0x800 个数字字符（如 `b"1" * 0x700`）。解析过程中触发 `malloc(0x800)`，`_int_malloc` 会处理 unsortedbin。
4. 在调试器中断在 `malloc` 或 `_int_malloc`，用 `bins`/`largebins`/`heapinfo` 确认目标 chunk 已从 unsortedbin 排入 smallbin/largebin，且残留的 `fd`/`bk` 指向 `main_arena` 或堆地址。
5. 随后用程序允许的固定 size 分配复用该 chunk（或其中一部分），通过 `print`/`show` 读取未清零的 `fd`/`bk`，计算 libc/heap 基址。
6. 若发送超过 0x800 字节，注意 `realloc` 会释放旧的 0x800 块进入 unsortedbin；这既可用来制造额外的 unsortedbin chunk，也会改变后续 tcache/unsortedbin 布局，需在 exp 中计入。
7. `scanf` 返回后 `scratch_buffer` 被释放，继续操作前用调试器确认最终 bin 状态，再执行 TSU/poisoning 等下一步。

## PoC

```python
from pwn import *

# 前提：程序用 scanf("%d", &choice) 读菜单；只允许固定 size 的 add
# 1) 先通过 add/delete 构造 unsortedbin chunk（伪代码）
# for i in range(9): add(2, b"A")          # 0x330 chunk
# free 前 7 个填 tcache，再 free 2 个进入 unsortedbin（留 guard 防合并）

# 2) 发送 0x700 个数字字符，触发 vfscanf 内部 malloc(0x800)
io.sendlineafter(b"choice: ", b"1" * 0x700)

# 3) 该次 malloc 会把 unsortedbin chunk 排序进 largebin；
#    随后申请一个固定 size chunk 复用残留 fd/bk 并 show 泄露
add(1, b"")          # 伪代码：申请 0x320
show()
leak = io.recvuntil(b"\n", drop=True)
```

```c
/* 机制等价示意（非漏洞代码） */
char stackbuf[0x400];
char *buf = stackbuf;          // scratch_buffer_init
size_t len = 0x400;
while (isdigit(c = getchar())) {
    if (len == used) {         // char_buffer_add_slow
        char *p = malloc(len * 2);   // 第一次：malloc(0x800)
        memcpy(p, buf, len);
        buf = p; len *= 2;
    }
    buf[used++] = c;
}
```

## 变体与关联

- **只触发一次 malloc**：输入长度在 0x401–0x800 之间时只发生一次 `malloc(0x800)`；这是最可控的排序原语。
- **触发 realloc 与旧块释放**：输入超过 0x800 后，`realloc` 会把旧 0x800 块释放到 unsortedbin，可用来制造 0x800 的 unsortedbin chunk 或消耗 tcache。
- **其它 scanf 转换**：`%d`/`%u`/`%ld`/`%f` 等数字转换都会走 `char_buffer`；`%s` 通常直接写入目标缓冲区，不一定走同一路径，需按 glibc 源码确认。
- **关联卡片**：[[binary-pwn-heap-tcache-stashing-unlink-plus-tcache-perthread-entries]]（排序后接 TSU+）、[[binary-pwn-heap-tcache-stashing-unlink-largebin-fake-chunk-arbitrary-write]]（largebin/TSU 组合）、[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（unsortedbin 泄露）。
- **限制**：`scratch_buffer` 的初始大小和扩容倍数属于 libc 实现细节，换版本必须重新确认；若程序用 `fgets`/`read` 自行解析数字，则没有这个原语。

## 检测与防御

- **利用侧识别**：堆题中出现 `scanf("%d")` 且只允许固定 size 分配时，先检查是否能用长数字串制造库内 `malloc(0x800)`；在调试器中观察 `_int_malloc` 调用栈即可确认。
- **防御侧**：不要用 `scanf` 解析不受信任的长输入；使用 `fgets` + 有界缓冲 + `strtol`，并在解析前限制长度。对堆完整性要求高的程序可考虑禁用 tcache 或使用 hardened allocator。
- **检测**：监控进程中出现与业务无关的 0x800/0x1000 级堆分配、或 `scanf` 返回后 unsortedbin/largebin 状态异常变化，可作为堆利用的辅助线索。
