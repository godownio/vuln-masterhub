---
id: ctf-forensics-ansi-terminal-emulator-screen-recovery
title: ANSI 终端控制序列模拟：从终端录像恢复被清屏/覆盖隐藏的 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: ansi-terminal-emulator-screen-recovery
aliases:
- 终端录像取证
- ANSI 转义序列
- CSI 光标控制
- 屏幕恢复
- terminal.bin
tags:
- ctf
- forensics
- ansi
- terminal
- csi
- tty
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:48:30+08:00'
  notes: 已对照原文「我的光标去哪了」核对：terminal.bin 含 ESC[2J、ESC[row;colH、ESC[2K、ESC7/ESC8、退格/回车/制表符，24x80 缓冲逐字节重放至 EOF，最终第 11 行为 flag{cursor_moves_but_truth_stays}；两个诱饵 flag{grep_is_not_rendering}/flag{close_but_transient} 在清屏前，卡片说明正确，PoC 与原文脚本等价。未验证点：未持附件复跑（卡内 PoC 省略了原文对 CSI 参数中 '?' 的替换，仅影响非标准参数场景）；无版本/CVE；frontmatter 无 sources/source_url。
---

## 一句话结论

当附件是一段包含 ANSI 转义序列的终端输出记录时，直接按文本搜索得到的 flag 往往是被后续 `ESC[2J` 清屏或光标覆盖前的假值；维护一个 24×80 的字符缓冲区，按 CSI 的光标定位/擦除/保存恢复与退格、回车、制表符逐字节模拟到 EOF，才能恢复最终屏幕上的真实 flag。

## 原理

- **终端是状态机**：终端输出不是简单文本流；`ESC[2J` 清屏、`ESC[row;colH` 移动光标、`ESC[2K` 擦除行、`ESC7`/`ESC8` 保存/恢复光标、`\b`/`\r`/`\t` 都会改变最终显示内容，但不会删除原始字节。
- **假 flag 的成因**：文件前部可能先打印一个完整 flag，随后用清屏/覆盖序列把它擦掉并写入真实内容；只用 `strings`/`grep` 会命中先出现的假值。本题 `flag{grep_is_not_rendering}` 与 `flag{close_but_transient}` 都是清屏前的诱饵。
- **模拟规则**：
  - CSI 以 `ESC [` 开始，参数字节 `0x30–0x3F`，中间字节 `0x20–0x2F`，最终字节 `0x40–0x7E`；
  - `H`/`f`：`row;col` 为 1-based，缺省/0 当 1；
  - `J` 参数 2：清整个屏幕；`K`：从光标清到行尾；
  - `A/B/C/D`：上/下/右/左移动，缺省 1；
  - `ESC 7`/`ESC 8`：保存/恢复光标；
  - 可打印字节写入当前光标位置并右移；`\n` 下移、`\r` 回列 0、`\b` 左移、`\t` 跳到下一个 8 列制表位。
- **为什么能恢复**：只要按终端语义重放所有字节，最终缓冲区就是用户当时看到的屏幕；被覆盖/擦除的内容不会出现在最终屏幕，但真实 flag 会留在某个位置（本题第 11 行）。
- **边界**：不同终端对 CSI 的支持/默认值可能不同；本题只用到常见子集。若记录包含 OSC、DCS、鼠标上报或 UTF-8 多字节字符，需要扩展解析器。

## 触发条件

- 拿到终端输出记录（`terminal.bin`、`typescript`、`script` 录制文件等），包含 `ESC`/CSI 控制序列。
- 已知终端尺寸（本题 24×80）；尺寸错误会导致换行/光标位置错乱。
- 记录从初始屏幕状态开始（或可假定全空）；若从中间开始，需要先恢复初始状态。
- 目标 flag 在最终屏幕的某一行，或被覆盖前的中间状态中。

## 利用步骤

1. 用十六进制查看确认存在 `1b 5b`（CSI）、`1b 37`/`1b 38`（保存/恢复）等序列；统计可见的假 flag 位置。
2. 初始化 `rows×cols` 的空字符缓冲区，光标 `(0,0)`，保存槽为空。
3. 逐字节解析：遇到 `ESC` 处理 CSI/保存恢复；遇到控制字符处理 LF/CR/BS/TAB；其余可打印字节写入缓冲区。
4. 解析完输出最终屏幕（可 `rstrip` 每行）；本题第 11 行出现 `flag{cursor_moves_but_truth_stays}`。
5. 若最终屏幕没有 flag，尝试在解析过程中定期 dump 屏幕/保留历史帧，检查被清屏前的中间状态。

## PoC

```python
from pathlib import Path

data = Path("terminal.bin").read_bytes()
ROWS, COLS = 24, 80
screen = [[" "] * COLS for _ in range(ROWS)]
row = col = 0
saved = None
i = 0

while i < len(data):
    b = data[i]
    if b == 0x1B and i + 1 < len(data):
        if data[i + 1] in (ord("7"), ord("8")):
            if data[i + 1] == ord("7"):
                saved = (row, col)
            elif saved:
                row, col = saved
            i += 2
            continue
        if data[i + 1] == ord("["):
            end = i + 2
            while end < len(data) and not (0x40 <= data[end] <= 0x7E):
                end += 1
            if end == len(data):
                break
            raw = data[i + 2:end].decode("ascii", "ignore")
            vals = [int(x) if x else 0 for x in raw.split(";")] if raw else []
            cmd = chr(data[end])
            n = vals[0] if vals and vals[0] else 1
            if cmd in "Hf":
                row = (vals[0] if vals and vals[0] else 1) - 1
                col = (vals[1] if len(vals) > 1 and vals[1] else 1) - 1
            elif cmd == "J" and vals and vals[0] == 2:
                screen = [[" "] * COLS for _ in range(ROWS)]
            elif cmd == "K":
                for p in range(col, COLS):
                    screen[row][p] = " "
            elif cmd == "A":
                row = max(0, row - n)
            elif cmd == "B":
                row = min(ROWS - 1, row + n)
            elif cmd == "C":
                col = min(COLS - 1, col + n)
            elif cmd == "D":
                col = max(0, col - n)
            i = end + 1
            continue

    if b == 10:
        row = min(ROWS - 1, row + 1)
    elif b == 13:
        col = 0
    elif b == 8:
        col = max(0, col - 1)
    elif b == 9:
        col = min(COLS - 1, (col // 8 + 1) * 8)
    elif b >= 32:
        if row < ROWS and col < COLS:
            screen[row][col] = chr(b)
        col += 1
    i += 1

print("\n".join("".join(line).rstrip() for line in screen))
```

## 变体与关联

- **变体（终端类型）**：`script`/`typescript` 录制、SSH 会话日志、Docker `docker attach` 输出都可用；注意 `\r\n` 与 UTF-8。
- **变体（历史帧）**：若 flag 在被清屏前短暂出现，需在解析时保留帧或记录每次清屏前的内容；本题真实 flag 在最终屏幕，诱饵在前。
- **变体（OSC/DCS）**：窗口标题、超链接、字体设置等序列可能包含隐藏数据，需扩展解析。
- **关联卡片**：[[defense-forensics-ansi-escape-log-poisoning]]（ANSI 转义日志投毒，防御视角）、[[defense-forensics-carriage-return-output-overwrite]]（回车覆盖输出）、[[ctf-misc-zero-width-unicode-binary-quinary-stego]]（另一种不可见编码）。
- **边界**：终端尺寸/初始状态未知时结果可能偏差；不支持的 CSI 可能被忽略导致光标错位；二进制中混入非 UTF-8 字节需按 Latin-1 处理。

## 检测与防御

- **取证**：不要只用 `strings`/`grep` 看终端录像；用终端模拟器或 `pyte` 等库重放，保留清屏前历史。
- **日志安全**：记录原始字节（含转义序列）而不是渲染后的文本，便于复现；对 ANSI 注入做转义/过滤，防止日志投毒。
- **CTF 识别**：看到 `terminal.bin`、`typescript`、`ESC[2J`、多个可疑 flag 时，按本卡模拟；用 `xxd` 确认控制序列。
