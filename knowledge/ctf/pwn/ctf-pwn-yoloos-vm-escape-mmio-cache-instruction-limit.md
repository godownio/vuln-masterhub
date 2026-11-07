---
id: ctf-pwn-yoloos-vm-escape-mmio-cache-instruction-limit
title: 16 位 YOLOOS VM 逃逸：guest 越界写内核栈 + MMIO cache 映射宿主栈 + instruction limit 泄露 PIE
type: scenario
domain: ctf
path: ctf/pwn
technique: yoloos-guest-kernel-host-vm-escape
aliases:
- YOLOOS 虚拟机逃逸
- guest 到 kernel 到 host
- 内核栈覆盖
- MMIO cache 映射宿主栈
- instruction limit ASLR 泄露
- 16 位自定义 VM
tags:
- ctf
- pwn
- vm-escape
- seccomp
- kernel
- mmio
- aslr
- rop
- static-pie
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:59:47+08:00'
  notes: 已对照原文核对；guest 读越界写内核栈、MMIO cache 偏移 0x248 映射宿主栈、instruction limit PIE 泄露与 seccomp ORW 一致
---

## 一句话结论

static-PIE 的 16 位 YOLOOS 宿主模拟器允许 guest 通过 `read` 系统调用把 0x200 字节拷进内核自己的活动栈：v2 缓冲区校验只检查地址落在 0x3000-0xefff，却没限制拷贝长度，于是覆盖 0x3ffe 处的返回槽并枢轴到攻击者链；内核链再调用 cache store 循环，把数据写到 MMIO cache 偏移 0x248 之后——ZCACHE 实际映射宿主栈的 0xd00 字节，而内核只用前 0x200 字节，因此正好覆盖宿主 `main` 的保存返回地址；最后利用“用户指令数超限”错误状态里与 PIE 基址相关的 poison 恢复 ASLR，构造宿主 ROP 以 seccomp 允许的 open/read/write 读出 flag。

## 原理

- **目标架构**：宿主是 static-PIE x86-64 ELF，模拟 16 位自定义 VM YOLOOS，并安装只允许 `read/write/open/close/exit` 的 seccomp。guest 程序通过系统调用与宿主内核交互，攻击面在 guest→kernel→host 两层跨越。
- **第一阶段：guest 读越界写内核栈**。用 VM 内置汇编器写 guest 程序，调用读系统调用把 0x200 字节读入地址 0x3e00；内核的 v2 缓冲区校验允许 0x3000-0xefff 区间，于是这批数据被直接拷贝到内核自己的活动栈上，覆盖 0x3ffe 处的返回槽。把返回槽改写为内核 gadget `MOV SP,R3; RET`（地址 0x1ad1），栈就枢轴到攻击者控制的链上。
- **第二阶段：内核链写宿主栈**。内核链跳转到 cache store 循环 0x1331，向 MMIO cache 偏移 0x248 到 0xcff 连续写入；ZCACHE 实际映射了宿主栈的 0xd00 字节，而内核只使用前 0x200 字节，所以偏移 0x248 正好落在宿主 `main` 函数的保存返回地址上，后续 qword 构成宿主 ROP。
- **第三阶段：ASLR 绕过**。在同一个虚拟机进程内运行约五亿条指令的 guest 循环，触发 `user instruction limit reached`；该路径会把与 PIE 基址相关的 poison 写到 CPU state 加 0x20 的位置，下一次进入用户态时会把它混合，并向 guest 地址 0xe1e0 写出四个完整的 64 位值。guest 把这四个值 dump 出来，逆向混合过程即可恢复精确的 PIE 基址（虚拟机内约 26 秒，结果与调试器一致）。
- **第四阶段：宿主 ROP**。拿到基址后，用 `pop rdi/rsi/rdx/rax` 加 `syscall; ret` 的 gadget，在同一个宿主进程中从标准输入读取路径名，再 `open`、`read`、`write` 把文件内容打印出来；所有系统调用都在 seccomp 白名单内，不需要 execve。
- **关键点**：guest 越界写在宿主内核校验盲区里变成内核栈覆盖；内核的 MMIO cache 又恰好映射到宿主栈；ASLR 绕过利用的是虚拟机指令上限错误状态与进入用户态的混合逻辑。

## 触发条件

- 宿主为自定义 VM 模拟器，guest 可调用宿主内核系统调用，且内核缓冲区校验只检查基址/区间不检查长度。
- 内核活动栈与 guest 可控内存存在固定偏移，返回槽可被覆盖。
- 内核的 MMIO cache/ZCACHE 映射到宿主栈，且内核使用的范围小于映射范围。
- VM 有可触发的指令数上限错误路径，且错误状态中包含与 PIE 基址相关的 poison。
- 宿主 seccomp 允许 open/read/write（或至少允许能读文件的系统调用）。

## 利用步骤

1. 用 VM 汇编器写 guest 程序：`LDI R0,0; LDI R1,0x6000; LDI R2,0xab8; SYSCALL 0` 读入宿主 ROP 载荷，再 `LDI R0,0; LDI R1,0x3e00; LDI R2,0x200; SYSCALL 0` 触发内核栈覆盖，`LDI R3,2; SYSCALL 2` 退出。
2. 构造 0x200 字节第二阶段：在 0x1fc/0x1fe 写入枢轴目标和 `MOV SP,R3; RET`，在 0x3e00 处布置内核链（POP R1/R3、cache store loop、IRET）。
3. 先跑五亿条指令的 guest 循环触发 instruction limit，再启动第二个 guest 程序 dump 0xe1e0 的 32 字节；用 `core_inv`/`H_inv` 与逐位提升解出 PIE 基址。
4. 按基址计算 `pop rdi/rsi/rdx/rax`、`syscall; ret` 偏移，构造 `open(path)`、`read(fd,buf,0x100)`、`write(1,buf,0x100)` 链，放入第一阶段读取的宿主载荷。
5. 发送路径名（`/flag`、`flag`、`flag.txt`、`/flag.txt` 等），读取输出。

## PoC

ASLR 还原核心（与原文 `invert.py` 同构）：

```python
M64 = (1 << 64) - 1
C1, C2 = 0x9d3a6f5c2b7e184d, 0x5e8c1b47a3f9602d
C3, C4 = 0x3f1d9b7a5c2e8461, 0x6b2e8f4a9c5d1731
POISON_CONST, POISON_OFF = 0xc7e59b3d1f82640a, 0xc87d0

def inv_xorshr(x, s):
    y, shift = x, s
    while shift < 64:
        y ^= x >> shift
        shift += s
    return y & M64

def core_inv(y):
    a = inv_xorshr(y, 43)
    a = ((a >> 11) | (a << 53)) & M64
    a = inv_xorshr(a, 37)
    a = (a * pow(C2, -1, 1 << 64)) & M64
    a = inv_xorshr(a, 29)
    a = ((a >> 19) | (a << 45)) & M64
    a = (a * pow(C1, -1, 1 << 64)) & M64
    return inv_xorshr(a, 33)

def H_inv(y):
    a = core_inv(y)
    a = inv_xorshr(a, 47)
    return inv_xorshr(a, 29)
```

guest 阶段：

```text
LDI R0, 0; LDI R1, 0x6000; LDI R2, 0x0ab8; SYSCALL 0
LDI R0, 0; LDI R1, 0x3e00; LDI R2, 0x200;  SYSCALL 0
LDI R3, 2; SYSCALL 2
```

内核链关键常量：`K_MOV_SP_R3 = 0x1ad1`、`K_CACHE_LOOP = 0x1331`、cache 偏移 `0x248`、guest 物理 `0x3e00`。宿主 ROP 偏移（static PIE，原文环境）：`POP_RDI=0x9e29`、`POP_RSI=0xdeea`、`POP_RAX=0x33d03`、`POP_RDX=0x87aca`、`SYSCALL=0x1c576`。

## 变体与关联

- 若内核校验同时检查长度，可寻找其他越界写原语（MMIO 寄存器、DMA、共享内存环）。
- 若 MMIO cache 不映射宿主栈，可改为覆盖内核函数指针/IDT/宿主全局函数表。
- ASLR 泄露也可来自错误信息、日志、未初始化栈或 timing；本例的 instruction limit 是自定义 VM 的特有路径。
- 关联：QEMU 设备 MMIO 越界逃逸、VM guest→host 逃逸、static-PIE ROP 卡。

## 检测与防御

- 内核对 guest 传入的地址区间校验必须同时校验长度与边界，禁止把 guest 数据直接拷进内核栈；使用独立 bounce buffer 并做 copy_from_user 风格检查。
- MMIO cache/ZCACHE 映射范围要与内核实际使用范围一致，避免把宿主栈暴露给 guest；对 cache 偏移做白名单。
- 指令数上限等错误路径不要写入与基址相关的状态；错误处理统一清零，避免成为 ASLR oracle。
- seccomp 只允许必要系统调用，open/read/write 也应限制路径/目录（如只允许 flag 读一次）。
- 检测：guest 触发 instruction limit 后立即 dump 固定地址、MMIO 偏移 0x248 附近的大量写入、宿主进程异常 open/read 敏感文件。
