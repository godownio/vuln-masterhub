---
id: binary-pwn-format-string-nonstack-pointer-chain-got-overwrite
title: 非栈上格式化字符串小输入约束：借栈指针链两级 %hn 中转，覆写 printf GOT 为 system
type: scenario
domain: binary
path: binary/pwn/format-string
technique: format-string-nonstack-pointer-chain-got-overwrite
aliases:
- 非栈上格式化
- 非栈上格式化 GOT
- 栈指针链中转
- 两级指针格式化写
- BSS 格式化字符串
- 小输入约束格式化
tags:
- pwn
- format-string
- non-stack
- pointer-chain
- got
- hn
- ll
- partial-relro
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-06T12:04:47+08:00'
  notes: V173 指出的触发条件不匹配/缺失 ak2 链步骤与长度不一致已修正并重新 verify
---

## 一句话结论

当格式化字符串本体位于 `.bss`/堆（如 `read(0, buf, 0x20); printf(buf)`）而不在栈上时，攻击者无法把目标地址直接放进格式串参数槽；可利用栈上已有的指针槽搭出两级指针链，用 `%hn` 先把某个栈指针改成 `printf@got`，再用下一次 `%lln`/`%hn` 把 `printf@got` 写成 `system@plt`，随后循环里的 `printf(buf)` 以 `"/bin/sh"` 为参数即执行 `system("/bin/sh")`。

## 原理

- **非栈上格式串的限制**：`printf(buf)` 的格式串在 `.bss`/堆，不在当前栈帧；`%n` 写入的目标地址必须来自栈上的参数槽（`%k$n` 取第 k 个参数槽里的指针）。攻击者不能像栈上格式串那样把 `p64(target)` 直接放在输入缓冲区尾部并让某个参数槽正好指向它。
- **栈上的指针链是替代入口**：`printf` 调用现场附近常有指向缓冲区、返回地址或调用者栈帧的指针槽。若存在 `argX -> 指向某栈槽的指针`、`argY -> 目标地址或可改写的指针`，就能分两步走：
  1. 用 `%X$hn` 修改一个栈指针槽的低 2 字节，使其指向 `printf@got`（或指向保存目标地址的槽）；
  2. 用下一次格式化写（`%Y$hn`/`%Y$lln`）通过被改好的指针把值写到 `printf@got`。
- **小输入约束**：`read` 每次只给 0x20 字节，payload 必须压缩到 `%<count>c%<idx>$hn` 这类短格式；地址不能附加在格式串末尾（空间不够，且格式串不在栈上也无法被参数槽引用），只能依赖程序栈上现成的指针。
- **写 GOT 拿执行**：Partial RELRO 下 `.got.plt` 可写。把 `printf@got` 改成 `system@plt`（无 PIE 时 PLT 地址固定，不需要 libc 泄露）后，循环下一轮 `printf(buf)` 会跳到 `system`，此时 `buf` 内容就是 `system` 的第一个参数；发送 `"/bin/sh"` 即得 shell。
- **无 PIE 的便利**：二进制无 PIE 时 `system@plt`、`printf@got` 都是固定地址，不需要先泄露 libc；若有 PIE 则需要先 `%p` 泄露代码/栈基址。
- **为什么成立**：`%n` 的写入语义是“把已输出字符数写到参数槽中的地址”，而参数槽内容可以被前一次 `%hn` 改写；两次写入组合即形成“改指针 + 写目标”的任意写，绕过了“格式串不在栈上”的限制。

## 触发条件

- 程序存在 `printf(buf)` 等把用户输入直接当格式串的调用，且 `buf` 位于 `.bss`/堆等非栈区域。
- 二进制无 PIE 或已泄露代码基址；Partial/No RELRO，GOT 可写。
- 程序提供多次输入循环（或至少两次 `printf(buf)`），允许分阶段“先改指针、再写值、再触发”。
- 栈上存在可用的指针链：某个参数槽指向栈上另一个槽，且该槽可被改指向 GOT/目标地址。
- 单次输入长度受限（如 0x20 字节），但仍足够容纳 `%<count>c%<idx>$hn` 形式的短格式串。
- 输入与格式串之间没有过滤 `%n`/`%hn` 等控制符，或过滤可绕过。

## 利用步骤

1. 用 `checksec` 确认 RELRO/PIE；用调试器在 `printf(buf)` 调用点查看栈，找出格式串参数槽与可用的指针链（哪些槽指向栈、哪些指向 `buf`/返回地址/GOT）。
2. 用 `AAAA.%p.%p...` 确认格式串参数索引，找到能间接触及目标指针槽的 `%k$hn`。
3. 第一阶段：发送短格式串，用 `%<low16>c%k$hn` 把某个栈指针槽的低 2 字节改为 `printf@got` 的低 2 字节（高 2 字节通常已相同或另行处理）。
4. 第二阶段：再发一次格式串，通过被改好的指针把 `system@plt` 的低 2/4 字节写入 `printf@got`；若需写全 8 字节，用 `%hn`/`%lln` 分段。
5. 第三阶段：发送 `"/bin/sh"`，让循环执行 `printf("/bin/sh")`；由于 GOT 已被改为 `system`，实际执行 `system("/bin/sh")`。
6. 若栈布局不允许直接改 GOT，可改为修改栈上的返回地址，再用 one_gadget 或 ROP 链接管控制流。
7. 记录每一步的栈偏移、参数索引与写入值；不同 libc/编译选项会改变偏移，需按目标样本重新定位。

## PoC

原文为 CTF 题（nostackfmt）的 wp，核心代码如下（按原文整理，原文代码存在 `%11$$lln` 双 `$` 等笔误，实际使用时需修正为 `%11$lln`，且 `read` 长度与 `ljust` 长度需按题目核对）：

```python
# 第一阶段：把栈上指针槽改为 printf@got
def ak1():
    global stack, pf_got
    stack = stack - 0x100
    pf_got = elf.got['printf'] + elf_base
    pd = b'%' + str(stack & 0xffff).encode() + b'c%13$hn'
    s(pd)

# 第二阶段：让另一个栈指针槽指向 printf@got
def ak2():
    global pf_got
    pd = b'%' + str(pf_got & 0xffff).encode() + b'c%43$hn'
    s(pd)

# 第三阶段：通过改好的指针把 printf@got 写成 system@plt
def ak3():
    system = elf.plt['system']
    pd = b'%' + str(system & 0xffffffff).encode() + b'c%11$lln'  # 原文写作 %11$$lln
    pd = pd.ljust(0x20, b'\x00')
    s(pd)
```

说明：原文未给出完整可运行的 exp 与成功 shell 截图，栈偏移（如 0x25、参数槽 13/43/11）与 `stack` 泄露方式需按目标重新调试；本卡片未在本机复跑。

## 变体与关联

- 变体：无 PIE 时直接写 `printf@got`；有 PIE 时先用 `%p` 泄露代码基址，再计算 GOT/PLT。
- 变体：把返回地址改为 one_gadget，避免写 GOT 后还要构造参数；或改 `__stack_chk_fail@got` 等“参数可控”的函数。
- 变体：单次输入更短时，用 `%hhn` 逐字节写，或用多轮小步修改指针。
- 关联：[[binary-pwn-format-string-got-hijack]]（栈上格式串直接 GOT 覆写）、[[binary-pwn-format-string-limited-nonstack-loop-condition-byte-rop]]（非栈上 + 有限次数 + 改循环条件 + 逐字节 ROP）、[[binary-pwn-format-string-non-stack-fini-array-loop-write]]（非栈上改 fini_array）。
- 边界：Full RELRO、格式化函数被替换为安全封装、`%n` 被过滤且无法绕过、输入长度不足以容纳格式串、栈上没有可用指针链时，该手法不成立。

## 检测与防御

- 修复：所有格式化输出改为 `printf("%s", buf)`；编译加 `-Wformat-security -Werror=format-security`、`-D_FORTIFY_SOURCE=2`。
- 加固：Full RELRO + BIND_NOW 使 GOT 只读；启用 PIE/ASLR；栈上不放可利用的指针链（如编译选项 `-fstack-protector` 不解决格式化，但可增加其它利用难度）。
- 输入过滤：拒绝含 `%n`/`%hn`/`%lln` 的输入只能作为补充，需同时限制 `%p`/`%s` 泄露与格式串长度。
- 检测：监控输入中的大量 `%p`/`%s`/`%n` 组合、异常短的格式化 payload、GOT 项运行期被改写（Full RELRO/完整性监控）、`printf` 内部崩溃或跳转到非 libc 地址。
- 响应：若已沦陷，检查进程是否被写入 shell、GOT 是否异常、是否有子进程 `sh`/`system` 调用；重启并升级加固后的二进制。

## 备注

原文为非栈上格式化 CTF 题讲解，图 02–04 为 pwndbg 栈/指针链截图（红色箭头标出指向 `main`、`printf@got[plt]` 的指针槽）；原文 wp 代码有笔误且未展示成功 shell，confidence 标 medium。
