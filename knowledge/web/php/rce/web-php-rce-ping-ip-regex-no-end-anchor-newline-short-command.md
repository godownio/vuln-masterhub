---
id: web-php-rce-ping-ip-regex-no-end-anchor-newline-short-command
title: ping 参数校验只锚定开头 + 12 字符长度上限：用换行符在 IP 后另起一条命令，5 个字符内完成注入
type: scenario
domain: web
path: web/php/rce
technique: ping-command-injection-regex-missing-end-anchor-newline-length-limit
aliases:
- ping 命令注入
- IP 正则未锚定结尾
- 换行符绕过命令注入黑名单
- 长度限制下的短命令注入
- popmart index.php
tags:
- php
- rce
- command-injection
- regex-bypass
- newline
- length-limit
- blacklist
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:15:28+08:00'
  notes: 已对照原文核对；本次核对未读取图片；源码 ping 正则缺少结尾锚定、黑名单字符集、strlen>12 上限、system(ping -c 2 \) 拼接点均与原文一致；未验证点：原文黑名单写法多出 '<'（可能为 WP 笔误），卡内按两种情形分别说明，实际拦截行为需目标环境确认
---

## 一句话结论

当 `system("ping -c 2 $ip")` 前面的校验是「`preg_match('/^...IP.../')` 只锚定开头」＋「长度 ≤12」＋「可疑字符黑名单」时，IP 后仍可跟任意字符：用换行符（黑名单通常不含 `\n`）在 IP 之后另起一条 shell 命令，`1.1.1.1\nid` 只有 11 字节，即可在长度限制内执行命令。

## 原理

- `preg_match('/^(((1?\d{1,2})|(2[0-4]\d)|(25[0-5]))\.){3}((1?\d{1,2})|(2[0-4]\d)|(25[0-5]))/', $lsj)` 只有 `^` 没有 `$`：只要**开头**像 IP 就通过，后面的内容完全不校验。IP 校验必须 `^...$` 全串匹配才有意义。
- 长度 ≤12 的约束看似堵死注入，但一个最短合法 IP `1.1.1.1` 只占 7 字节，仍留 5 字节给注入段；把注入段压到 `\nid`（3 字节）或 `\nls`（3 字节）即可。
- 黑名单 `/[`;\|\&$() \/\'>\"\t]/` 覆盖了空格、分号、管道、`$`、括号、引号、斜杠、Tab，但**没有覆盖换行符**（`\n`、URL 中 `%0a`）。Bash 把换行当命令分隔符，与 `;` 等价，于是“无空格、无分号”也能执行下一条命令。
- 若该正则按原文漏写了一个字符类结束符（原文写作 `...\t]<`，多出一个 `<`），黑名单就退化成“仅当可疑字符后面紧跟 `<` 才拦”，此时空格、分号都可直接用，注入面更大。
- 之所以可复用：`ping $user_input` 是最典型的命令拼接点，防御常见三步（格式校验、黑名单、长度限制）只要任一处不严格（缺 `$` 锚定、漏 `\n`、长度够放换行）就整体失效；且换行绕过对“只过滤空格/分号”的 WAF 普遍有效。

## 触发条件

- 用户输入被拼进 shell 命令（`system`/`exec`/`shell_exec`/`popen`），未用 `escapeshellarg`。
- 格式校验正则缺少结尾锚定 `$`，或只做前缀/部分匹配。
- 黑名单未包含换行符（以及 `\r`、`%0a`、`%0d` 等编码形式）。
- 长度限制不足以覆盖“合法前缀 + 分隔符 + 至少 2~3 字节命令”。

## 利用步骤

1. 读源码确认拼接点、正则是否带 `$`、黑名单字符集、长度上限。
2. 计算可用长度：`上限 - 最短合法前缀`。本例 12 - 7 = 5 字节。
3. 选择分隔符：黑名单未含 `\n` 时用 `%0a`；未含 `;`/`|`/`&` 时直接用它们；空格被禁时可用 `\n` 起命令、用 `<`/通配符代替参数。
4. 在 5 字节内放最短命令：`id`、`ls`、`sh`（借 ping 的超时进入交互）、`env`。
5. 需要读文件时先 `ls` 定位，再用 `nl<f*`（6 字节）之类的重定向+通配符形式；或先写一个短脚本再用它。

## PoC

```http
POST /index.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

lsj=1.1.1.1%0aid
```

服务端得到：`ping -c 2 1.1.1.1
id `，先 ping 再执行 `id`，回显中带 uid 信息。

黑名单漏拦 `<`（按原文写法）时更直接：

```http
lsj=1.1.1.1;id
```

长度吃紧时的读文件形式（IP 7 字节 + 5 字节）：

```text
1.1.1.1\nsh        # 起一个交互 shell（ping 会持续，可后续喂命令）
1.1.1.1\nls
```

## 变体与关联

- 变体：黑名单含 `\n` 时改用 `%0d`（`\r`）、`$(...)`（`$` 未禁时）、反引号、`<(...)` 进程替换、`{cmd,}` 花括号展开。
- 变体：长度限制更紧时用 `$_GET[x]` 二次注入（把命令放另一个参数，用 `\n$a` 之类引用），或把命令拆成多次请求写入临时脚本再执行。
- 变体：`ping -c 2` 后不接受多余参数时，用 `<` 重定向把文件内容喂给 ping，借助错误回显带出内容（`ping 1.1.1.1<flag`）。
- 关联：[[web-php-rce-icpas-ping-ip-exec-command-injection]]（同类 ping 拼接，但走 `;`/`&`）、[[web-php-rce-command-space-blacklist-tab-passthru]]（空格被禁时用 Tab）、[[web-php-rce-ifs-space-bypass-command-injection]]（`$IFS` 替空格）。
- 边界：正则改为 `^...$` 全串匹配、改用 `escapeshellarg` 或 `filter_var(FILTER_VALIDATE_IP)`、或用 `proc_open` 传参数数组时，本链不成立。

## 检测与防御

- 代码层：不要把用户输入拼进命令行；用 `escapeshellarg()` + 参数数组（`proc_open(['ping','-c','2',$ip], ...)`）。
- 校验层：IP 用 `filter_var($ip, FILTER_VALIDATE_IP)`（等价全串匹配），不要手写缺 `$` 的正则；长度限制只是辅助，不能替代白名单。
- 黑名单层：不要依赖字符黑名单；若必须用，至少覆盖 `\n`、`\r`、`;`、`|`、`&`、`$`、反引号、`<>`、`{`、`}`、`(`、`)`。
- 检测：请求参数中出现 `%0a`/`%0d`/换行、值以合法 IP 开头但尾部含字母或重定向符；进程树出现 `ping` 与 `sh`/`id`/`ls` 同源父子关系；`ping` 进程存活时间异常短且伴随子进程。
