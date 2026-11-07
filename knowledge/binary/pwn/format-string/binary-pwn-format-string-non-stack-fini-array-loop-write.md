---
id: binary-pwn-format-string-non-stack-fini-array-loop-write
title: 非栈上格式化字符串通解：借 .fini_array 重启与参数链循环 %hn 写返回地址
type: scenario
domain: binary
path: binary/pwn/format-string
technique: format-string-non-stack-fini-array-loop-hn
aliases:
- 非栈上格式化字符串
- fini_array 格式化字符串
- 循环 %hn 写
- printf 参数链
- 格式化字符串通解
- 多轮格式化字符串
tags:
- pwn
- format-string
- fini-array
- arbitrary-write
- hn
- rop
- ret2libc
- linux
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V92
  verified_at: '2026-11-05T19:41:18+08:00'
  notes: 已对照原文'非栈上通解'关卡与图02（.fini_array/_DYNAMIC）核对：fini_array 重启、arg6→arg8 控返回、arg35→arg75 写目标、%hn 半字分段与收尾 pop rbp;ret 均与原文代码一致；已把原文顺序取参误写为 %35$hn/… 的表述改为'顺序取参落到参数区间'。原图为 GDB 现场，无独立成功输出；本卡未复跑 PoC。原文为 glibc 2.35 实验二进制，无组件影响版本，未设 affected_versions。frontmatter 无 sources/source_url。
---

## 一句话结论

当格式化字符串的目标地址不在栈上、无法直接用 `%k$n` 指向时，可以先改写 `.fini_array[0]`/`DT_FINI` 让 `main` 反复重启，拿到多轮输入；每轮用栈上现成的参数链（如 `arg6→arg8`）控制本轮返回地址，再用另一条参数链（如 `arg35→arg75`）把目标地址作为 `%hn` 的写入指针，逐轮写 2 字节，最终拼出 `ret` + `pop rdi` + `"/bin/sh"` + `system` 的 ROP 链。

## 原理

- **非栈上的难点**：格式化字符串写任意地址依赖“把目标地址放到某个参数槽里，再用 `%k$n` 写该槽指向的地址”。如果目标（例如更深调用帧里的返回地址、堆/全局区的函数指针）不在当前格式串可索引的栈范围内，直接 `fmtstr_payload` 找不到参数槽。
- **用 `.fini_array` 换取多轮执行**：`.fini_array[0]` 和 `DT_FINI` 指向程序退出时调用的函数。把它们改成 `main`（或 `main` 内调用 `vuln` 的地址），程序每次正常返回/退出都会再次进入 `main`，攻击者因此获得多轮 `printf(buf)` 机会；每轮都可以重新布置一次格式串。
- **用参数链控制本轮返回地址**：在固定栈布局下，`printf` 的第 6 个及之后的参数对应栈上连续 qword。样本利用 `arg6→arg8` 这条链：格式串按顺序消耗参数（原文 `dual_write` 中前四个 `%hn` 依次落到 arg5..arg8），使当前 `vuln` 的返回地址在本轮结束后落到 `main+0x21`（再次调用 `vuln`），从而稳定进入下一轮。
- **用另一条参数链写真正的目标**：样本把目标地址放到 `arg35→arg75` 这条更深的参数链上，同样靠顺序取参让后续 `%hn` 落到这些参数槽，对目标地址做 2 字节写。每轮只写一个半字（避免一次输出过长、也避免 `%n` 写 4/8 字节时的高位问题），多轮覆盖 `ret`、`pop rdi`、`"/bin/sh"`、`system` 四个槽位。
- **`%hn` 的计数控制**：`%n` 写入“到目前为止输出的字符数”，`%hn` 只写低 2 字节。用 `%<delta>c` 或普通 `%c` 调整当前计数到目标半字值，再触发 `%hn`；`delta` 为负数时按 0x10000 取模。这样每轮可以精确写任意 16 位值。
- **收尾**：最后一轮不再把返回地址续到 `main+0x21`，而是改成 `pop rbp; ret` 或直接进入已布好的 ROP 链，跳出循环并执行 `system("/bin/sh")`。
- **为什么可行**：`.fini_array` 在 Partial/No RELRO 下可写；`main` 重启会保留同一进程的栈布局与 libc 基址；`printf` 参数索引在每轮中相对稳定，因此可以重复使用同一条参数链。代价是需要精确的栈偏移与参数索引，且每轮只能写 2 字节，轮数较多。

## 触发条件

- 程序存在 `printf(buf)`/`fprintf(f, buf)` 等把用户输入当格式串的调用，且输入长度足够容纳 `%<delta>c` 与多个 `%hn`。
- 目标地址不在当前格式串直接可索引的栈槽中；需要写返回地址、`.fini_array` 或其他非栈位置。
- 二进制未开启 PIE（或已泄露代码基址），`.fini_array`/`DT_FINI` 可写（No RELRO 或 Partial RELRO），能确定 `main`/`vuln` 的地址作为重启锚点。
- 能泄露栈地址与 libc 基址（如 `%13$p`、`%29$p`）；每轮栈布局稳定，参数索引可预测。
- 程序退出流程会调用 `.fini_array`/`DT_FINI`（glibc 正常退出会执行），且重启不会清空已写入的 ROP 槽。

## 利用步骤

1. 第一轮泄露：发送 `%13$p|%29$p|` 一类格式串，读取栈地址（用于定位返回地址槽）与 libc 地址（用于计算 `system`、`/bin/sh`、`pop rdi` 等）。
2. 第一轮写入：用 `fmtstr_payload` 或手工 `%hn` 把 `.fini_array[0]` 与 `DT_FINI` 改为 `main`（或 `main+0x21`），使程序退出后重启；样本同时把 `fini_array` 的两个槽都写成 `main`，获得两次额外输入机会。
3. 第二轮起循环：每轮先用 `arg6→arg8` 链把当前 `vuln` 的返回地址续到 `main+0x21`，保证还能进入下一轮；再用 `arg35→arg75` 链（顺序取参）对目标 ROP 槽执行一次 `%hn` 写。
4. 按 `ret`、`pop rdi`、`"/bin/sh"`、`system` 的顺序逐槽写；每个 8 字节地址拆成两个半字，写两次。
5. 最后一轮把循环锚点改成 `pop rbp; ret`（或直接把返回地址改成 ROP 链首），停止重启并执行 ROP。
6. 验证：`system("/bin/sh")` 或执行 `cat flag`；若中途崩溃，用 GDB 检查参数索引与 `%hn` 计数是否偏移。

## PoC

核心写入函数（摘自原文模板，需按目标二进制调整参数索引与偏移）：

```python
def pad(delta):
    return b'' if delta == 0 else f'%{delta}c'.encode()

def dual_write(loop_low, loop_val, target_low, value_low):
    # arg6 -> arg8：控制本轮返回地址（续到 main+0x21）
    w1 = (loop_low - 4) & 0xffff
    if w1 == 0:
        w1 = 0x10000
    cur = (w1 + 4) & 0xffff
    pd = pad(w1) + b'%c' * 4 + b'%hn'
    delta = (loop_val - cur) & 0xffff
    pd += pad(delta) + b'%hn'

    # arg35 -> arg75：对真正的目标槽写半字
    cur = loop_val
    pd += b'%c' * 25
    cur = (cur + 25) & 0xffff
    pd += pad((target_low - cur) & 0xffff) + b'%hn'

    cur = target_low
    pd += b'%c' * 38
    cur = (cur + 38) & 0xffff
    pd += pad((value_low - cur) & 0xffff) + b'%hn'
    return pd + b'\x00'

def hwrites(addr, value):
    return [(addr, value & 0xffff), (addr + 2, (value >> 16) & 0xffff)]
```

第一轮泄露与 `fini_array` 改写：

```python
rt(b'hello world\n')
pd = b'%13$p|%29$p|%1$4619c%18$hn\x00'
s(pd)
# 读 leak13（栈）、libc；计算 ret_slot = leak13 - 0x220
```

后续按 `plan = hwrites(ret_slot+0x10, ret_libc) + hwrites(ret_slot+0x18, pop_rdi) + ...` 逐轮调用 `dual_write`，最后一轮把 loop 值改为 `pop rbp; ret` 的地址。原文使用 glibc 2.35 与自定义实验二进制，地址、`%18$hn` 以及 `arg6→arg8`/`arg35→arg75` 参数区间均为该样本的实测/注释值；本卡未在文档环境复跑。

## 变体与关联

- **目标地址在栈上**：直接 `fmtstr_payload(k, {addr: value})`，无需本条的循环；参见 [[binary-pwn-format-string-got-hijack]]。
- **一次写 4/8 字节**：用 `%n` 写 4 字节或 `%ln` 写 8 字节，但输出量巨大、易超时；常规做法仍是 `%hn`/`%hhn` 分段。
- **重启锚点变体**：`.fini_array[0]`、`DT_FINI`、`__libc_csu_fini`、`atexit` 处理函数、`exit` 的 GOT 项；不同 glibc/链接方式可用的锚点不同。
- **参数链变体**：`arg6→arg8`、`arg35→arg75` 只是原文样本的索引；实际需用 `%p` 扫描定位可控槽与目标槽，或借助 `fmtstr_payload` 的 `strategy` 选项。
- **与栈溢出的组合**：先用格式化字符串泄 Canary/libc，再栈溢出 ROP，参见 [[binary-pwn-format-string-canary-libc-leak-rop-system]]。
- **防护边界**：Full RELRO 使 `.fini_array`/GOT 只读，PIE 使地址未知，`-Wformat-security`/`_FORTIFY_SOURCE` 阻断 `printf(buf)`；这些都会使本条失效。

## 检测与防御

- **检测**：输入中出现大量 `%<数字>c`、`%hn`、`%hhn` 组合；进程在 `printf`/`vfprintf` 内部崩溃或输出异常长的填充；`.fini_array`/`DT_FINI`/GOT 在运行期被改写（运行时完整性监控）；反复重启 `main` 的异常执行模式。
- **修复**：所有格式化输出改为 `printf("%s", buf)`；编译加 `-Wformat-security -Werror=format-security` 与 `-D_FORTIFY_SOURCE=2`；避免把用户输入直接作为格式串。
- **加固**：Full RELRO + BIND_NOW 让 `.fini_array`/GOT 只读；PIE + ASLR 提高地址预测难度；启用 Canary/NX/CET 作为纵深防御；对 setuid/服务程序限制输入长度并过滤 `%n`（仅作补充）。
