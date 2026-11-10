---
id: web-php-rce-short-command-od-wildcard-octal-root-read
title: 命令长度<6 且禁用 nl：用 `od /*` 八进制转储根目录文件还原 flag
type: scenario
domain: web
path: web/php/rce
technique: short-command-od-wildcard-octal-dump
aliases:
- 武功山杯 真君擒龙
- od 通配符
- 短命令绕过
- 八进制还原 flag
- strlen(cmd)<6
tags:
- php
- rce
- command-injection
- waf-bypass
- short-command
- wildcard
- od
- octal
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:21:38+08:00'
  notes: 已对照原文与全部25张图核对：源码strlen(cmd)<6且!strpos(strtolower(cmd),'nl')（图13）、?cmd=od%20/*、od默认八进制2字节输出、还原脚本与输出含flag{df9448d4-...}（图14）均一致。卡内nl/*利用strpos=0绕过为源码推导，原文未实测。未验证点：未实际请求目标。
---

## 一句话结论

`system($cmd)` 前只检查 `strlen($cmd)<6` 且 `strtolower($cmd)` 不含 `nl`，用 `od /*`（5 字符）即可借 shell 通配符把根目录下文件全部作为 od 输入，输出八进制字节流；把 od 输出按 2 字节小端还原即可得到 `/flag` 内容。

## 原理

- **长度限制不是安全边界**：`cat /flag` 9 字符、`cat /*` 6 字符均被 `<6` 挡住；`od /*` 只有 5 字符（`od`、空格、`/`、`*`），却能读取根目录所有匹配文件。
- **通配符展开**：`/*` 由 shell 展开为根目录下的文件列表（目录会产生报错但不影响其它文件的转储），od 按顺序输出这些文件的内容。
- **od 默认八进制格式**：`od` 无参数时以八进制词（每词 2 字节，另加偏移行）输出二进制；flag 的每个字符都能从八进制词按 2 字节小端还原，偏移行和错误行在脚本里可按 token 过滤/拼接。
- **`nl` 检查的 `strpos` 假值缺陷**：`!strpos(strtolower($cmd),'nl')` 在 `nl` 位于命令开头时 `strpos` 返回 `0`，`!0` 为真，因此 `nl /*` 这类以 `nl` 开头的短命令同样能通过检查（原文选择 `od` 是另一种直接绕过）。
- **为什么成立**：过滤只限制命令字符串长度和单个关键词，没有禁用通配符、没有白名单可执行文件；shell 的路径展开把“短命令”放大成对任意根目录文件的读取。

## 触发条件

- PHP 页面把 `$_GET['cmd']` 直接交给 `system()`（或同类命令执行函数）。
- 前置检查为 `strlen($cmd)<6` 且不含 `nl`（或类似的短命令/关键字过滤）。
- 目标为 Linux，根目录存在可直接读取的 flag 文件，shell 支持通配符展开。
- 命令输出会回显给攻击者（本题 `od` 输出直接显示在页面）。

## 利用步骤

1. 查看源码或测试确认长度与 `nl` 限制：`cat /flag` 被拒，`od /*` 通过。
2. 请求 `?cmd=od%20/*`，页面返回根目录文件的八进制转储（含偏移行与目录报错）。
3. 复制八进制文本，用脚本把每个八进制 token 转为 2 字节小端并拼接。
4. 在还原出的字节流中定位 `flag{...}`；本题需处理 `\x00` 等杂字节，按可打印串提取即可。
5. 若 `od` 不存在，可用 `nl /*`（利用 strpos=0 绕过）、`ls`、`rev`、`xxd` 等短命令变体（长度允许时）。

## PoC

请求：

```
GET /?cmd=od%20/* HTTP/1.1
```

八进制还原脚本：

```python
s = "0000000 066146 063541 062173 034546 032064 062070 026464 062462 0000020 032060 032055 062063 026461 062471 031143 061055 062142 0000040 031146 033066 062144 032461 076545 000012 0000053"
data = b''.join(int(ss, 8).to_bytes(2, 'little') for ss in s.split())
print(data)
# 输出中包含 flag{df9448d4-...}
```

要点：`od` 默认按 2 字节八进制词输出，偏移行（如 `0000000`、`0000020`）也会被脚本当作八进制数，需按实际输出调整过滤。

## 变体与关联

- **`nl` 开头绕过**：`nl /*` 长度 5，`strpos('nl /*','nl')` 返回 0 → 检查通过；若 `nl` 可执行，可直接带行号读取根目录文件。
- **通配符放大**：`*`、`?`、`[a-z]` 可匹配 flag 文件名/内容；`cat /*` 被长度挡住时用 `od /*`、`ls /*`、`head /*` 等。
- **编码/转储工具**：`od -c`、`xxd`、`hexdump` 可输出可读/十六进制，但命令更长；短命令场景优先 `od` 默认格式。
- **关联卡**：`web-php-rce-four-char-command-length-bypass` 讨论 ≤4 字符命令下用重定向+通配符拼命令，本卡是 <6 字符下用 `od` 通配符直接读文件，过滤器与利用手法不同。

## 检测与防御

- 禁止把用户输入交给 `system`/`exec`/`shell_exec`/反引号；必须执行外部命令时使用参数数组、固定白名单与 `escapeshellarg`。
- 长度/关键字黑名单不能阻止通配符与命令组合，应改为“只允许预定义命令与参数”的白名单。
- 以低权限运行 Web 进程，flag/敏感文件不放在 Web 进程可读路径；启用 `open_basedir` 与 `disable_functions`（system、exec、shell_exec、popen、proc_open、passthru 等）。
- 监控含 `*`、`/*`、`od`、`nl` 等特征的 `cmd` 参数请求，及页面返回的大段八进制/十六进制数据。
