---
id: binary-pwn-sandbox-escape-visible-shellcode-manual-construction-tricks
title: 纯可见字符 shellcode 手工构造技巧：NULL 默认指令倍数、地址低字节不变 xor、xor+add 组合与 push+ret 循环
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: visible-char-shellcode-manual-construction
aliases:
- 纯ASCII shellcode
- 可见字符 shellcode 手写
- NULL 指令 add byte ptr [rax],al
- 0x00 默认指令倍数
- 地址低字节不变异或
- xor+add 构造字节
- push ret 循环
- 手搓 alphanumeric shellcode
tags:
- pwn
- ctf
- shellcode
- alphanumeric
- visible-char
- encoding
- self-modify
- seccomp
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V529
  verified_at: '2026-11-11T15:35:52+08:00'
  notes: 已逐条核对原文 5 个手写技巧：NULL(00 00=add byte ptr [rax],al) 倍数构造 0xc3/0x41=3 次、地址低字节不变 xor 算式 0xa0^0x52^0x31=0xc3 正确、xor+add、push+ret、jz；原文 32/64 位公开 ASCII 串与卡内逐字符一致，未本机验证（卡内已注明）。按主题聚合为一张手工构造技巧卡，与 ALPHA3/AE64 编码器卡、字节白名单 imul 卡机制不同，非重复。已把低字节不变性精确为最低 3 个十六进制位（页内偏移）。
---

## 一句话结论

题目只允许输入 `[0-9A-Za-z]` 等可见字符时，可以不依赖 AE64/ALPHA3 编码器，利用 `0x00` 被 CPU 解析为 `add byte ptr [rax], al` 的默认指令、通过倍数控制构造任意字节（`0xc3/0x41=3` 次得到 `ret`）；再配合"函数地址低字节不变"的异或、`xor`+`add` 组合、`push`+`ret` 循环与 `jz` 短跳等技巧，纯手工把任意指令拼进白名单字节里。

## 原理

- **`0x00` 的双重身份**：单独出现时 `00 00` 解码为 `add byte ptr [rax], al`。它既是合法指令（不改变控制流），又是白名单检查常常忽略的"不可见但可执行"字节。若 `al` 可控（例如 `0x41`），每执行一次该指令就向 `[rax]` 指向处加 `0x41`；执行 3 次即可把目标字节构造成 `0xc3`（`ret`）。构造出的字节落在固定偏移处，其余位置用无意义但可见的指令填充。
- **地址低字节不变性**：`libc`/程序函数的地址在不同 ASLR 轮次中最低 3 个十六进制位（0x1000 页内偏移）不变。取某个函数地址的低字节（如 `0xa0`），寻找白名单字符 `a`、`b` 使 `0xa0 ^ a ^ b = 0xc3`（原文例：`0xa0 ^ 0x52 ^ 0x31 = 0xc3`，`0x52='R'`、`0x31='1'` 都是可见字符），用两次 `xor byte ptr [addr], imm8` 即可稳定写入 `ret`。
- **`xor` + `add` 组合**：白名单字符之间异或覆盖不到的值，可先用 `xor dword ptr [rax+0x54], ecx`（`0x54='T'` 为可见偏移）向目标位置异或出中间值，再控制 `al` 执行默认 `add` 指令补上差值；组合两种运算可大幅扩大可达值集合。
- **`push` + `ret` 流程控制**：把需要多次执行的代码放在 shellcode 末尾，构造其起始地址并 `push`，用 `ret` 跳过去；控制 `push` 次数即可实现循环。地址偏移常通过反复除以 2 并选择"便于构造的字节表示"来凑。
- **`jz` 短跳**：`74 xx` 中 `0x74='t'` 是可见字符，`jz $+0x50` 一类短跳在偏移字节也落在白名单时可用于跳转，但适用范围有限。
- **为什么能通过检查**：字节白名单只判断单字节是否属于允许集合，不做反汇编与控制流分析；上述技巧把危险指令拆成"可见的 XOR/ADD/PUSH/POP/JZ + 不可见的 0x00 默认指令"组合，运行时才在内存中拼出 `ret`/`syscall` 等目标。

## 触发条件

- 程序把输入读入可执行内存并跳转执行，且逐字节检查仅允许可见字符（如 `0x30-0x39`、`0x41-0x5A`、`0x61-0x7A`）。
- 可写可执行缓冲区，且能控制 `rax`/目标地址指向待构造字节的位置（或利用已知函数地址低字节不变性）。
- 输入长度足够容纳构造指令与载荷；若长度也受限，需要先按最小构造方案裁剪。
- 目标的 seccomp/权限允许最终要执行的 syscall（execve 或 ORW 组合）。

## 利用步骤

1. 确定白名单字符集与长度上限，确认可执行缓冲区地址及寄存器初值（尤其 `rax` 能否指向可写内存）。
2. 选取构造目标：先用 `0x00` 默认指令造出 `ret`/`syscall`/`int 0x80` 等关键字节，必要时利用地址低字节不变性异或。
3. 用 `push`/`pop` 设置寄存器（可见字符的 `P/Q/R/S/T/U/V/W` 是 push rax..rdi，`X/Y/Z` 是 pop rax/rcx/rdx），拼出 execve 或 open/read/write 的参数。
4. 把需要复用的代码放到 payload 末尾，构造其地址后用 `push`+`ret` 循环或 `jz` 短跳控制流程。
5. 本地用相同白名单校验脚本自测 payload（断言每个字节可见、长度不超限），再在调试器中单步确认构造出的指令正确。
6. 若手工构造成本过高，改用现成纯 ASCII shellcode（原文给出 32/64 位公开串）或 AE64/ALPHA3 编码器生成，并确认基址寄存器与入口一致。

## PoC

```text
# 原文给出的现成纯 ASCII shellcode（公开来源，未在本机验证，按目标环境自测）
# 32 位：
PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA

# 64 位：
Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t
```

```asm
; 手工构造思路示意（非完整可执行 payload）
; 1) 让 al = 0x41，rax 指向目标字节，执行 3 次 00 00：
;    add byte ptr [rax], al   ; +0x41
;    add byte ptr [rax], al   ; +0x82
;    add byte ptr [rax], al   ; +0xC3 -> 目标字节成为 ret
; 2) 地址低字节不变时用可见字符异或：
;    0xa0 ^ 0x52('R') ^ 0x31('1') = 0xc3  -> 两次 xor byte ptr [addr], imm8 构造 ret
; 3) 用 push 0x...; ret 跳到 payload 末尾的复用代码块，控制 push 次数实现循环
```

## 变体与关联

- 变体一：用 AE64/ALPHA3 自动编码（见关联卡），需要指定与跳转时一致的基址寄存器；本卡适用于无法使用编码器或需要手工微调长度的场景。
- 变体二：`call $+5; pop reg` 取当前地址后自修改；或把构造好的字节写在栈上再 `jmp rsp`。
- 变体三：只允许字母数字时，`push`/`pop` 单字节指令（`P-Z`）是主要构件；允许 `0x00` 时默认 `add` 指令是核心；允许重复字节时可先用 `xor` 生成中间值。
- 关联：[[binary-pwn-sandbox-escape-alpha3-visible-shellcode-seccomp-orw]]（ALPHA3 生成可见字符 ORW）、[[ctf-pwn-visible-char-ae64-rdx-base-openat-sendfile-orw]]（AE64 基址寄存器匹配）、[[binary-pwn-sandbox-escape-minimal-shellcode-byte-budget-nul-free-scanf-badchar]]（字节预算与 NULL/strlen 绕过）、[[binary-pwn-sandbox-escape-scanf-signed-negative-length-bypass]]（长度检查被负数绕过时可直接用现成 ASCII 串）。
- 边界：可执行缓冲区不可写时无法自修改构造；`0x00` 被输入函数（`scanf("%s")`、`strlen`）截断时默认指令技巧失效；地址低字节不变性依赖 ASLR 实现与模块版本，需实测。

## 检测与防御

- 检测（题目/防护侧）：提交内容全为可见字符但长度接近上限、含大量 `P-Z` 单字节指令与 `00` 序列、进程随后执行 `execve`/`openat`；可对可执行页中出现高熵可打印串告警。
- 防御：不要只用字节白名单判断 shellcode；执行前反汇编/模拟执行，拒绝含自修改写内存、`syscall` 构造的序列；使用 W^X（写入后 `mprotect` 只给 RX）。
- 加固：seccomp 白名单限制 syscall；固定输入长度并用实际读入值校验；ASLR 让地址低字节技巧不稳定（仅页内偏移不变，跨页仍可被利用，需结合其它缓解）。
