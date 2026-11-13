---
id: binary-pwn-stack-ret2reg-call-eax-stack-shellcode
title: ret2reg：溢出返回时 eax 指向可控缓冲区，EIP 改为 call eax 执行栈上 shellcode
type: scenario
domain: binary
path: binary/pwn/stack
technique: ret2reg-call-eax-stack-shellcode
tags:
- pwn
- stack
- shellcode
- ret2reg
- call-eax
- 32bit
- nx
- strcpy
- ret2shellcode
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V636
  verified_at: '2026-11-13T01:18:42+08:00'
  notes: 已对照原文全文与 10 张图片逐张核对：ret2reg 章节原文无图片，依据正文源码/汇编/终端输出核对：源码 evilfunction 用 char buffer[512]+strcpy，编译 -z execstack -m32 -fno-stack-protector；checksec 为 i386、NX disabled、Has RWX segments；反汇编 sub esp,0x208、lea eax,[ebp-0x208]、strcpy@plt、leave/ret；ret 断点处 EAX=0xffffccb0 --> '123'（EDX 同值）指向缓冲区；ROPgadget 找到 call eax @0x08048373；payload = shell + (0x20c-len(shell))*'A' + p32(0x08048373)，均与卡一致。已修正两处小问题（知识库与 staging 草稿同步）：原文 perl 示例 shellcode 逐字节计数为 25 字节而非 23 字节，且原文未注明 shellcraft.sh() 长度，故删除『23 字节』表述；`stricpy` 拼写改为 `strcpy`。dedup：首候选为自身；related 为 ctf-pwn-call-eax-stack-shellcode-byte-inc1（字节自增编码变体）、mprotect+bss shellcode、strcpy 截断 call rsp、ret2syscall、ret2win 等不同技术，无 likely_duplicate；dup-scan 无涉及。原文未标注组件版本，affected_versions 不设。未验证点：未本机复跑；0x20c 偏移按原文 disassembly 计算（buffer 起址 ebp-0x208 + saved ebp 4）。未执行文中任何指令或 PoC。
url: /docs/binary/pwn/stack/binary-pwn-stack-ret2reg-call-eax-stack-shellcode/
draft: false
kb_aliases:
- ret2reg
- call eax 栈上执行
- jmp eax shellcode
- 寄存器指向缓冲区
- ret2shellcode 变体
---

## 一句话结论

在未开启 NX（栈可执行）的 32 位程序中，若存在栈溢出且函数返回时某个寄存器（如 `eax`）仍指向被输入覆盖的缓冲区，同时二进制内有 `call eax`/`jmp eax` 等间接跳转 gadget，则可把返回地址覆盖成该 gadget，在缓冲区开头放 shellcode，`ret` 后直接落到栈上 shellcode 执行，无需泄漏 libc 或构造长 ROP 链。

## 原理

- **寄存器残留**：`strcpy(buffer, input)` 等函数调用前后，编译器常用 `lea eax, [ebp-0x208]` 把缓冲区地址放进 `eax` 并压栈传参；`strcpy` 调用返回后 `eax`/`edx` 往往仍保存缓冲区首地址，函数 `leave; ret` 返回时未被改写。原文在 `ret` 处断点确认 `EAX: 0xffffccb0 --> '123'`，即 `eax` 指向 buffer 起始。
- **控制流劫持**：`ret` 从栈上弹出被覆盖的返回地址到 `EIP`。若该地址指向 `call eax` 指令，CPU 会调用 `eax` 指向的地址——也就是可控缓冲区，从而把执行流交给栈上的 shellcode。
- **为什么需要栈可执行**：NX/DEP 开启后栈页不可执行，`call eax` 跳过去会触发保护异常；因此该手法适用于 `NX disabled`/`Has RWX segments`/`-z execstack` 编译的程序，或先用 `mprotect` 把栈改为可执行后再跳转。
- **偏移计算**：原程序 `sub esp, 0x208` 分配 0x208 字节缓冲区，缓冲区起始为 `ebp-0x208`；保存的 `ebp` 占 4 字节，返回地址在其后，故缓冲区首字节到返回地址的距离为 `0x208 + 4 = 0x20c`。与常规 `0x208+4(saved ebp)` 一致，注意不要漏掉保存的 ebp。
- **输入通道限制**：通过命令行参数（`argv[1]`）投递时字符串不能含 `\x00`，需使用无空字节的短 shellcode（原文脚本用 pwntools shellcraft.sh()，并给出 perl 无空字节 execve shellcode 示例）；通过 `gets`/`read` 投递则无此限制。

## 触发条件

- 32 位 ELF 存在栈溢出（如 `strcpy`、`gets`、`read` 无长度限制），可覆盖返回地址。
- 栈可执行：未开启 NX，或程序显式 `mprotect`/`mmap` 出 RWX 页。
- 返回前某个寄存器稳定指向可控缓冲区起始（需在 `ret` 断点实际确认）。
- 二进制中存在 `call eax`/`jmp eax`（或 `call edx` 等其他寄存器）gadget，且地址固定（无 PIE 或已泄漏基址）。
- shellcode 能放进缓冲区，且投递通道不破坏其字节（注意 `\x00` 与换行）。

## 利用步骤

1. `checksec` 确认 32 位、NX disabled/RWX segments、无 PIE/Canary；反汇编溢出函数确认 `lea eax,[ebp+buffer]` 与 `strcpy` 调用。
2. 在函数 `ret` 指令处下断点，运行后观察寄存器：确认 `eax`（或 `edx`/`ecx`）指向缓冲区起始。
3. `ROPgadget --binary <bin> --only 'jmp|call' | grep eax` 找 `call eax` 地址（原文 `0x08048373`）。
4. 计算偏移：缓冲区大小 + 保存 ebp（原文 `0x208 + 4 = 0x20c`）。
5. 构造 `shellcode + 填充至 0x20c + p32(call_eax)`；strcpy 场景通过 argv 或 stdin 发送。
6. `p.interactive()` 验证 shell；若 shellcode 含坏字节，改用编码器或换投递通道。

## PoC

```python
from pwn import *

context(arch='i386', os='linux')
call_eax = 0x08048373          # 二进制内 call eax 的地址，需按目标重算
shell = asm(shellcraft.sh())   # 无 NX 时可直接在栈上执行

# 缓冲区 0x208，加保存的 ebp 4 字节 => 0x20c 到返回地址
payload = shell + b'A' * (0x20c - len(shell)) + p32(call_eax)

p = process(argv=['./ret2reg', payload])   # 原文通过 argv[1] 传入
p.interactive()
```

说明：以上为原文流程的结构化复现，未在本机执行；仅用于授权测试。通过 argv 投递时需确保 payload 不含 `\x00`；原文另给出 perl 直接构造无空字节 shellcode 的命令行示例。

## 变体与关联

- **寄存器变体**：`edx`/`ecx` 指向缓冲区时用 `call edx`/`jmp ecx`；也可用 `push reg; ret` 把寄存器值当返回地址。
- **栈指针变体**：`jmp esp`/`call esp` 属于同类"寄存器指向栈"利用；若寄存器不指向缓冲区，可先 `pop`/`lea` 修正。
- **NX 开启变体**：先用 ROP 调 `mprotect(stack_page, 0x1000, 7)` 把栈改为可执行，再跳 shellcode；或把 shellcode 写到 `bss` 并 `mprotect`。
- **关联**：[[ctf-pwn-call-eax-stack-shellcode-byte-inc1]]（输入逐字节自增后 `call eax` 的编码绕过变体）、[[binary-pwn-stack-ret2shellcode-mprotect-bss-rwx-page]]（NX 下 mprotect 后执行 shellcode）、[[binary-pwn-stack-http-uri-unescape-overflow-stack-leak-shellcode]]（另一条栈 shellcode 落地链）、[[binary-pwn-stack-pivot-leave-ret-bss]]（寄存器不指向缓冲区时的栈迁移替代）。
- **边界**：开启 NX 且无 mprotect 原语、返回时寄存器已被覆盖/清空、无间接跳转 gadget、或 shellcode 因坏字节/长度无法放入缓冲区时，本链不成立。

## 检测与防御

- **编译加固**：默认开启 NX（`-z noexecstack`），配合 PIE、Canary、Full RELRO；禁止 `-z execstack`。
- **代码审计**：排查 `strcpy`/`sprintf`/`gets` 等无界拷贝；使用 `strncpy`/`snprintf`/`fgets` 并校验长度。
- **运行时**：CET/shadow stack 阻断 ret 劫持；EDR/沙箱监控栈页执行与 `call eax` 到栈地址的跳转（RWX 栈行为）。
- **检测**：崩溃转储中返回地址指向 `call reg` gadget、栈页含 shellcode 特征（`/bin/sh`、`int 0x80`）、进程异常派生 shell。
