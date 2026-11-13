---
id: binary-pwn-stack-thread-large-overflow-tls-stack-guard
title: 线程栈大溢出直达 TLS：用同一填充值同时覆盖栈 Canary 与 tcbhead_t.stack_guard 绕过检查
type: scenario
domain: binary
path: binary/pwn/stack
technique: thread-stack-large-overflow-tls-stack-guard-bypass
tags:
- pwn
- stack
- canary
- tls
- thread
- pthread
- large-overflow
- rop
- i386
- amd64
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V647
  verified_at: '2026-11-13T03:59:26+08:00'
  notes: 已对照原文与8张截图核对：图3 bfnote checksec=i386/Partial RELRO/Canary/NX/No PIE、图7 babystack=amd64/Full RELRO/Canary/NX/No PIE 与卡片一致；图1/2 为无/有 canary 的 checksec，图5 为 unk_804A060 bss，图4=图6（md5 相同，同一张 bfnote exp+cat flag 终端，flag{3973a678-...}），图8 为 babystack 泄露后交互取 shell。原文核心（pthread 线程栈顶端 TLS、0x7b8<一页、同值填充同时覆盖栈 Canary 与 fs:0x28/gs:0x14）与卡一致。核对中修正卡片三处：1) 原文 exp 的 0x216FC 是 title size 参数，原文未展开其与 gs:0x14 距离的推导，原卡“0x216FC 溢出长度覆盖 gs:0x14”属过度推断，已按原文改写；2) 利用步骤 3 的 payload 构造改为“填到 Canary 槽→槽值 X→saved_rbp/返回地址→继续 X 写到 stack_guard”，原文表述有歧义；3) PoC 注释“dist_to_canary 足够大”改为“溢出总长度越过返回地址继续写到 fs:0x28”。dedup 将既有 binary-pwn-stack-tls-stack-guard-overwrite-canary-rop 标为 likely_duplicate(0.9391)，但该卡 conclusion 明确入口是“数据写进线程 TLS 区域（如 __thread 缓冲区）”并需维护 tcb/dtv/self，本卡入口是线程栈大溢出写穿到栈顶 TLS、偏移从漏洞缓冲区算起、PoC 为 babystack 0x950/bfnote，触发条件与偏移计算不同，非同链，按独立卡保留；dup-scan 无涉及 pair。原文未标注 glibc/系统受影响版本，affected_versions 留空正确。未复跑 exp；原文 exp 中 notebook/title 尺寸与 note read 长度的配合存在疑点，已在卡中按原文记录并注明未展开。
url: /docs/binary/pwn/stack/binary-pwn-stack-thread-large-overflow-tls-stack-guard/
draft: false
kb_aliases:
- TLS bypass canary
- 线程栈溢出打 TLS
- 大溢出绕过 canary
- fs:0x28 同值覆盖
- gs:0x14 覆盖
- tcbhead_t stack_guard
- babystack 2018
- gyctf_2020_bfnote
---

# 一句话结论

在 glibc/Linux 中，`pthread_create` 创建的线程其 TCB/TLS 位于线程栈高地址顶端，距当前栈帧通常小于一页；当栈溢出长度足够大时，攻击者用同一个填充值同时覆盖栈上的 Canary 槽和 TLS 中的 `tcbhead_t.stack_guard`（x86-64 的 `fs:0x28` / i386 的 `gs:0x14`），函数返回前比较两边都是同一值，Canary 校验自然通过，无需泄露 Canary。

# 原理

- **Canary 的来源与校验**：开启栈保护后，函数序言执行 `mov rax, qword ptr fs:[0x28]; mov [rbp-8], rax`，把 TLS 中的 `stack_guard` 拷到栈上；返回前执行 `mov rdx, [rbp-8]; xor rdx, qword ptr fs:[0x28]; jz ...; call __stack_chk_fail`。校验的是"栈上副本"与"TLS 原值"是否相等。
- **TLS 位于线程栈顶端**：`pthread_create` 为线程分配栈（mmap 或缓存），栈向下增长；glibc 在栈的高地址初始化 TCB（`tcbhead_t`），`fs`（i386 为 `gs`）指向该结构，`stack_guard` 在 x86-64 的 `+0x28`、i386 的 `+0x14`。从当前栈帧继续向高地址写，越过保存的 rbp/返回地址后最终会写到 TCB 区域。
- **同值覆盖**：普通栈溢出必须在 Canary 槽写入"原 Canary"才能通过校验；但若溢出长度足以继续写到 TLS，把 `stack_guard` 改成与填充值相同（例如全 `'a'`，x64 `0x6161616161616161`、i386 `0x61616161`），则比较时栈上是 `'a'*8`、TLS 也是 `'a'*8`，异或为 0，校验通过。
- **距离与布局**：示例中当前栈帧到 TCB 约 `0x7b8`（小于一页），因此"至少一页"的溢出即可覆盖；具体偏移取决于缓冲区位置、线程栈大小和 glibc 版本。i386 用 `gs:0x14`，布局类似；`gyctf_2020_bfnote` 的 exp 里出现 `1024*130`（notebook size）与 `0x216FC`（title size）两个尺寸参数，原文未展开其与 TLS 距离的精确推导，按原文记录。
- **副作用**：向 TLS 方向写会顺带覆盖 `tcb`、`dtv`、`self`、`multiple_threads` 等字段，线程退出/`pthread_join` 或后续 TLS 访问可能崩溃。因此利用通常在同一个线程内立即完成 ROP（泄露 libc + `system`/one_gadget），在回到线程清理路径前拿到 shell；必要时像 `__thread` 缓冲覆盖那样把 `tcb`/`dtv`/`self` 写回合法地址。
- **与 `__thread` 缓冲覆盖的区别**：本卡是"栈溢出本身写穿到 TLS"；另一种是程序提供了可写 `__thread` 缓冲区（如 `read(0, tls_buf, len)`），直接写 TLS 再配合栈溢出（见 [[binary-pwn-stack-tls-stack-guard-overwrite-canary-rop]]）。两者最终都改 `stack_guard`，但入口和偏移计算不同。

# 触发条件

- Linux 程序使用 pthread 创建线程，漏洞函数在线程栈上，且存在长度足够大的线性溢出（通常 ≥ 一页，具体以到 `fs:0x28`/`gs:0x14` 的距离为准）。
- 程序开启栈 Canary，且溢出路径不会在写 TLS 前被长度检查截断。
- 能确定 TLS 与栈帧的距离（固定偏移、gdb、或程序自身泄露 `fs` 地址）。
- 溢出后能在同一次线程执行中完成 ROP/拿到 shell，避免回到线程清理路径时因 TCB 被破坏而崩溃（或能把 `tcb/dtv/self` 恢复）。

# 利用步骤

1. `checksec` 确认 Canary 开启，并确定架构（x64 `fs:0x28` / i386 `gs:0x14`）。
2. 计算缓冲区到 `stack_guard` 的距离：
   - gdb：在漏洞函数断点处 `p/x $fs_base`（或 `$gs_base`）与 `p/x &buf`，相减得到距离；
   - 或在程序里用 `arch_prctl(ARCH_GET_FS, &addr)` 获取 `fs` 基址，`__builtin_frame_address(0)` 取栈帧地址，`diff = (char*)fs - (char*)&frame[-1]`。
3. 构造 payload：从缓冲区填充到 Canary 槽（填充值 X）→ Canary 槽写 X → 覆盖 saved_rbp/返回地址（ROP 起点）→ 继续用 X 填充直到写入 `fs:0x28`/`gs:0x14` 的 `stack_guard`。关键是溢出总长度越过返回地址后仍继续写到 TLS，且写入 `stack_guard` 的值与栈上 Canary 槽相同。
4. 在 ROP 中完成信息泄露与 `system("/bin/sh")`/ORW；若线程会返回 `pthread_join`，优先在 ROP 内直接退出或把 `tcb/dtv/self` 等字段恢复。
5. 用两个典型题验证思路：
   - `starctf2018_babystack`（x64）：线程栈 `s[4104]`，发送约 `0x950` 字节覆盖到 TLS，ROP 调 `puts` 泄露 libc，再 `read` 写 one_gadget 并触发。
   - `gyctf_2020_bfnote`（i386）：main 中 `s[50]` 允许 `read 1536`，满足大溢出前提；exp 再以 notebook/title 尺寸（`1024*130`、`0x216FC`）配合栈迁移到 bss、伪造 `.rel.plt` 把 `read` 解析为 `system`（原文未给出 `0x216FC` 与 `gs:0x14` 距离的推导，该例题按原文记录）。

# PoC

```c
// 计算线程栈帧到 TCB 的距离（原文示例，用于确认偏移）
void *first(void *x) {
    unsigned long *addr;
    arch_prctl(ARCH_GET_FS, &addr);          // x86-64: fs 基址
    unsigned long *frame = __builtin_frame_address(0);
    unsigned long len = (char*)addr - (char*)&frame[-1] + fixup;
    void *exploit = malloc(len);
    memset(exploit, 0x41, len);              // 同一填充值覆盖栈 canary 与 TLS stack_guard
    void *ptr = &pwn_payload;
    memcpy((char*)exploit + 16, &ptr, 8);
    memcpy(&frame[-1], exploit, len);        // 线性溢出直达 TLS
    return 0;
}
```

```python
# x86-64 思路（偏移按目标实测调整）
payload  = b'a' * dist_to_canary      # 到栈 canary 槽
payload += p64(0x6161616161616161)    # 栈 canary 槽 = 填充值
payload += p64(saved_rbp)             # 保存的 rbp
payload += p64(rop_ret)               # 返回地址/ROP 起点
# 关键：溢出总长度要越过返回地址继续写到 fs:0x28，使 stack_guard 也变成 0x6161...
```

```text
说明：本文案例的 0x950（babystack x64）与 0x216FC（bfnote i386）均为原题实测偏移，
换目标需按线程栈布局、缓冲区位置和 glibc 版本重新计算。
```

# 变体与关联

- 与 [[binary-pwn-stack-tls-stack-guard-overwrite-canary-rop]]：该卡通过可写 `__thread` 缓冲区直接改 TLS，再栈溢出；本卡是栈溢出写穿到线程栈顶 TLS，触发方式与偏移计算不同。
- 与 [[binary-pwn-stack-tls-ssl-struct-overwrite-32bit-pie-heap-spray]]：同为 TLS 区域覆盖，但目标是 OpenSSL 结构体而非 stack_guard。
- 与 [[binary-pwn-stack-tls-stack-guard-overwrite-canary-rop]] 的变体：无法大溢出时，可用 `__stack_chk_fail` GOT 劫持/stack smash、fork 字节爆破、格式化字符串泄露 canary 等替代路线。
- 变体：i386 用 `gs:0x14`，x64 用 `fs:0x28`；若只溢出到 `stack_guard` 的低字节，可尝试部分覆盖（Canary 低字节通常为 0）。
- 工具：gdb `$fs_base`/`$gs_base`、`arch_prctl`、pwndbg `tls`/`canary` 命令。

# 检测与防御

- 检测：线程程序中出现超大长度栈写入（`read`/`memcpy` 长度接近或超过线程栈大小）、返回地址附近与 TLS 区域同时被同一字节填充；崩溃点集中在 `pthread_join`/线程退出或 `__stack_chk_fail`；CTF 环境可用 gdb 观察 `fs:0x28` 被改写。
- 防御：限制栈上 `read`/`memcpy` 长度并校验目标缓冲区大小；大缓冲区改用堆分配；启用 `-fstack-protector-all` 仅提高门槛，无法阻止写穿 TLS，需配合 `-fstack-clash-protection`、栈 guard page、线程栈与 TLS 隔离（把敏感 guard 放在不可线性溢出的区域）；使用 CET shadow stack/CFI；生产环境开启 ASLR、RELRO、PIE 并监控异常大写入。
