---
id: ctf-pwn-vm-operand-stack-index-unbounded-push-canary-leak-orw-rop
title: VM 操作数栈 push 无上界：越界回读 canary/返回地址并覆写栈帧，seccomp 下构造 ORW ROP
type: scenario
domain: ctf
path: ctf/pwn
technique: vm-operand-stack-unbounded-push-oob-canary-leak-orw-rop
tags:
- pwn
- vm
- virtual-machine
- operand-stack
- out-of-bounds-write
- out-of-bounds-read
- canary
- stack-overflow
- rop
- seccomp
- orw
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V177
  verified_at: '2026-11-06T17:21:39+08:00'
  notes: 已对照原文核对；90900 内嵌图 image-20251211105653787.png 未下发，栈布局按 IDA/源码核对；exp 未在本机复跑
url: /docs/ctf/pwn/ctf-pwn-vm-operand-stack-index-unbounded-push-canary-leak-orw-rop/
draft: false
kb_aliases:
- vm的stack溢出
- sp指针溢出修改stack
- VM 操作数栈上溢
- stack[rsp++] 无上界
- VM push 越界写返回地址
- VM 栈帧 canary 回读
---

## 一句话结论

自定义 VM 把操作数栈 `long stack[0x200]` 放在 `main` 的栈帧里，`push` 指令执行 `stack[rsp++] = reg[...]` 却没有任何上界检查，`pop` 也只检查 `rsp <= 0`；连续 push 即可把索引推到 canary 与返回地址所在的槽位，先 pop 越界读出 canary 和 libc 返回地址，再把 canary 写回、用 ROP 链覆盖返回地址，在 seccomp 禁止 `execve` 的环境下用 `open/read/write` 读 flag。

## 原理

- **指令格式**：程序用 `scanf("%ld")` 读入一个 8 字节整数，再由 `ret_code` 把低 4 个字节映射为四个 `int16` 字段 `{op, reg1, reg2, reg3}`。`op=7` 为 push、`op=8` 为 pop、`op=9` 结束解释循环；`reg` 是全局 `long reg[0x10]`。
- **栈布局**：`long stack[0x200]`（0x1000 字节）位于 `rbp-0x1010`；`rbp-0x08` 是 stack canary，对应下标 513；`rbp` 在 514，返回地址在 515。源码数组只有 512 个元素，下标 512 已经是数组后第一个槽位。
- **越界路径**：push 分支完全没有边界检查，只做 `stack[rsp++] = reg[reg1]`；pop 分支的 `if (rsp <= 0)` 只能挡住零下标，既不能挡上越界，也挡不住无符号 `rsp` 在 0 处自减回绕到 `0xffffffff`。
- **先越界读再越界写**：push 513 次只写到下标 0..512，`rsp` 变为 513（canary 未被破坏）；随后 `pop` 读到 `stack[513]` 即 canary。再 push 3 次把 `rsp` 推到 515（此时 canary 和 saved rbp 被临时写成 0），`pop` 读到 `stack[515]` 即 `__libc_start_call_main` 附近的返回地址，减去已知偏移（本题 0x29d90）得到 libc 基址。
- **恢复 canary**：在布置 ROP 前先 pop 4 次回到下标 512，再执行三次 `push(reg_canary)`，把下标 512、513、514 依次写回 canary 值；其中 513 正是 canary 槽，主函数返回时的 canary 校验可通过，ROP 从下标 515 开始覆盖返回地址。
- **无立即数加载**：该 VM 只有 add/sub/mul/div/shl/shr/xor 和 push/pop，没有 `mov reg, imm`。PoC 先用 `sub reg,reg,reg` 清零，再用小常数递增、移位拼接（`set_number_off_five`）把 libc gadget/system 地址逐 nibble 合成到寄存器；也可从 `.bss`/栈上残留值取初值。
- **沙箱约束**：`init` 里装了 seccomp，`execve` 被 `SCMP_ACT_KILL` 杀死，因此最终链不是 `system("/bin/sh")`，而是 `open("flag",0)`、`read(fd,buf,n)`、`write(1,buf,n)` 的 ORW ROP。

## 触发条件

- 自定义 VM 的操作数栈是数组（栈帧或 `.bss`），push/pop 用可变索引且只做单边/无检查；索引类型为无符号时还可能在下溢后回绕到极大值。
- 栈数组与 canary、saved rbp、返回地址或相邻关键变量在同一内存区域，越界窗口可达。
- 能连续提交指令并控制 push/pop 次数；VM 结束后回到宿主函数返回路径。
- 目标有 canary 和 libc（本题 PIE+canary），需要先泄露；若沙箱禁止 `execve`，最终要能构造 ORW 或等价文件读取链。

## 利用步骤

1. 逆向 `ret_code`/指令分发，还原结构体字段顺序与 opcode 语义，写指令编码器 `op | reg1<<8 | reg2<<16 | reg3<<24`。
2. 由反编译或调试确定 `stack` 基址、数组长度、canary/saved rbp/返回地址的下标（本题分别为 513/514/515）。
3. 执行 0x201=513 次 `push(0)`，使 `rsp=513` 且不触碰 canary；`pop(reg60)` 读出 canary。
4. 再 `push(0)` 3 次到 `rsp=515`，`pop(reg61)` 读出返回地址；按 libc 版本换算 `__libc_start_call_main` 偏移得到 libc 基址。
5. 清零无用寄存器，用加法/移位链合成 `pop rdi; ret`、`pop rsi; ret`、`pop rdx; pop rbx; ret`、`open`、`read`、`write` 的地址以及 flag 路径字符串常量。
6. `pop` 4 次回到下标 512，`push(reg60)` 3 次恢复 canary 槽；随后按栈增长方向依次 push ROP 链（pop rdi、flag 地址、pop rsi、0、pop rdx/pop rbx 占位、open、read、write）。
7. 执行 `op=9` 结束循环；`main` 通过 canary 校验后 `ret` 进入 ROP，打开并输出 flag。

## PoC

指令编码与泄漏骨架（未在本机复跑；完整地址需按目标 libc 与寄存器分配调整）：

```python
def ins(op, r1=0, r2=0, r3=0):
    return str(op | (r1 << 8) | (r2 << 16) | (r3 << 24))

PUSH, POP, EXIT = 7, 8, 9
sl = lambda s: io.sendline(s)

# 1) 推进到 canary 槽并回读
sl((ins(PUSH, 0) + "\n") * 0x201)   # stack[0..0x200] 被写 0，rsp=0x201
sl(ins(POP, 60))                    # reg[60] = stack[0x201] = canary
# 2) 推进到返回地址并回读
sl((ins(PUSH, 0) + "\n") * 3)       # rsp 从 0x201 到 0x204
sl(ins(POP, 61))                    # reg[61] = stack[0x204] = saved rip
# 3) 回退、恢复 canary、布置 ROP
sl((ins(POP, 0) + "\n") * 4)        # rsp 回 0x200
sl((ins(PUSH, 60) + "\n") * 3)      # stack[0x200..0x202]，canary 写回 0x201
# 之后继续 push 各 gadget 地址（arg 寄存器按本题 reg 分配），最后：
sl(ins(EXIT))
```

寄存器常量合成（无立即数加载时的 nibble 拼接思路）：

```python
def synth(target, base_reg):
    # 对 target 的每个 nibble: reg = reg + nibble; shl reg, 4; add 低位
    # 实际按题目寄存器编号展开，nibble 用 add(reg, reg, small) 累加
    ...
```

## 变体与关联

- **检查位置变体**：先写后查（`stack[++sp] = v; check(sp);`）与本题“只在 pop 查零”等价，都必须在访问前做双边界检查。
- **索引类型变体**：`unsigned int` 索引在下溢后回绕到极大值，可能从“上越界”变成远端写；`int` 索引则可能负向覆盖 `.bss` 中的 GOT（见关联卡）。
- **内存区域变体**：栈数组在栈帧时可打 canary/返回地址；在 `.bss` 时可打相邻 GOT、函数指针、命令缓冲区；在堆上时可打 chunk 元数据。
- **关联卡片**：[[ctf-pwn-custom-vm-opcode-native-memory-got-restart-onegadget]]（VM 直接暴露宿主内存读写）、[[ctf-pwn-bytecode-sandbox-header-memsize-stack-oob-rop]]（边界字段与真实缓冲尺寸脱钩）、[[ctf-pwn-vm-stack-index-signed-underflow-got-system]]（同篇文章的负下标 GOT 变体）。

## 检测与防御

- **双边界、访问前检查**：push/pop 必须先验证 `0 <= idx < ARRAY_LEN`，再做读写；索引与数组长度用同一符号类型比较，禁止先自增/自减再检查。
- **布局隔离**：VM 操作数栈不要放在宿主函数栈帧里；使用独立映射并设 guard page，至少与 canary/返回地址/关键全局变量隔离。
- **缓解措施**：PIE + canary + Full RELRO + CET/Shadow Stack，降低泄露与 ROP 成功率；VM 以最小权限运行并保留 seccomp。
- **检测特征**：同一 opcode 的 push 次数异常且连续、VM 执行后出现栈上 gadget 地址序列、进程读取 flag 或产生异常文件访问；对解释器做边界断言与 fuzz。
