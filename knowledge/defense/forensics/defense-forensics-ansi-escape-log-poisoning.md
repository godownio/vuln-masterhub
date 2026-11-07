---
id: defense-forensics-ansi-escape-log-poisoning
title: ANSI 转义序列注入日志：清屏与隐藏文本篡改终端显示
type: scenario
domain: defense
path: defense/forensics
technique: ansi-escape-log-spoofing
aliases:
- ANSI 转义序列注入
- 终端日志投毒
- 清屏覆盖日志
- ESC[2J 隐藏告警
- ESC[8m 隐藏文本
tags:
- forensics
- log
- ansi-escape
- terminal
- anti-forensics
- spoofing
- csi
- osc
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:36:10+08:00'
  notes: 已对照原文与图08/09核对：投毒日志 cat 后仅显示伪造的正常行，hexdump 可见 1b 5b 32 4a 1b 5b 48（\e[2J\e[H），cat -v 暴露注入；\e[8m 隐藏文本变体原文亦有说明。显示层欺骗不影响磁盘原始字节的边界描述准确。未涉及版本区间。PoC 未在本机执行。
---

## 一句话结论

终端模拟器把 PTY 数据流中的 `ESC`（0x1B）当作控制指令而不是普通文本；攻击者在上游数据（HTTP 日志、SSH 用户名、文件名、容器终止日志、命令输出）中写入 `\e[2J\e[H` 或 `\e[8m`，管理员用 `cat` 查看时真实告警会被清屏覆盖或被隐藏，从而在取证第一步实现视觉欺骗。

## 原理

- 终端是一个逐字节解析的状态机：普通字符直接渲染，遇到 `0x1B` 进入 CSI/OSC/DCS 等转义序列解析，执行清屏、移动光标、设置颜色或隐藏属性。
- `\e[2J` 清空屏幕、`\e[H` 把光标移回左上角，随后的字符写入空白屏幕；`\e[8m` 则把后续文本渲染为与背景同色（隐藏），`\e[0m` 恢复。
- 终端不区分“这是程序输出”与“这是日志文件内容”，日志里的字节与程序打印的字节走同一条渲染路径，因此只要攻击者能影响日志内容，就能影响读取者的屏幕。
- 之所以有效：显示层没有数据/控制平面隔离，而日志审查依赖人眼读取终端渲染结果；被篡改的是“看到的证据”，不是磁盘上的原始字节。

## 触发条件

- 攻击者能在受害者会查看的日志/输出中写入原始字节，例如 HTTP 请求行、URL、User-Agent、SSH 用户名、文件名、容器 `/dev/termination-log`、应用日志字段；
- 日志中间件未剥离控制字符，写入时未转义；
- 管理员在支持 ANSI 的终端里用裸 `cat`、`tail`、`less`（未加安全选项）查看；
- 日志中的转义序列位于告警之前或中间，使后续伪造内容覆盖真实内容。

## 利用步骤

1. 选择一个可注入且会被落盘的字段（如请求路径）。
2. 在字段中嵌入 `\e[2J\e[H`，再追加一段伪造的正常日志；若想更隐蔽，用 `\e[8m` 把关键告警隐藏而不是清屏。
3. 等待管理员查看日志；终端先渲染真实内容，再执行清屏/隐藏，最终呈现“一切正常”。
4. 结合 `\e[?25l` 隐藏光标、光标定位等序列，可进一步限制管理员滚动回溯的范围。

## PoC

```bash
LOG=/tmp/demo_app.log
echo "[10:15:33] WARN: Failed login from 10.0.0.99" > "$LOG"
echo "[10:15:34] CRITICAL: Reverse shell to 10.0.0.99:4444" >> "$LOG"
printf '\e[2J\e[H' >> "$LOG"
echo "[10:15:33] INFO: Health check passed" >> "$LOG"
echo "[12:30:00] INFO: 0 errors in last 24 hours" >> "$LOG"
cat "$LOG"          # 只看到伪造的两行
cat -v "$LOG"       # ^[[2J^[[H 暴露注入
```

隐藏而非清屏的变体：

```bash
printf '\e[8m[CRITICAL] shadow exfiltrated\e[0m\n' >> "$LOG"
```

HTTP 入口示例：请求行中包含 `%1b[2J%1b[H`，Web 服务器把解码后的原始字节写入 access.log。

## 变体与关联

- 变体：OSC 2 改窗口标题、OSC 8 超链接伪造、光标定位覆盖局部行、`\e[?25l` 隐藏光标；不限于日志，`curl` 响应体、Git 提交信息、CI 输出同样可注入。
- 关联：[[defense-forensics-carriage-return-output-overwrite]]（用 `\r` 做同行覆盖，且能绕过 `less -R`）；[[defense-forensics-terminal-title-query-stdin-rce]]（同一注入面升级为 RCE）。
- 影响边界：只影响“通过终端查看”的显示，磁盘原始字节仍在；用 `cat -v`、`hexdump`、`less -U` 可还原。若日志经 SIEM/文件解析而非终端渲染，视觉欺骗不成立。
- 注意：`less` 默认会以安全模式显示控制字符，但并非所有版本/参数都如此；`less -R` 会放行部分转义序列。

## 检测与防御

- 检测：日志中出现 `0x1b`、`0x0d` 等控制字节；`cat -v` 输出含 `^[`；集中式日志平台对控制字符做告警；比对终端显示内容与原始字节哈希。
- 防御：日志写入前剥离 `ESC` 与除 `\n\t` 外的控制字符；查看不可信文件一律用 `cat -v`/`hexdump -C`/`less -U`；SIEM 与终端分离，先解析后展示；终端侧禁用危险窗口操作并限制转义序列透传。
