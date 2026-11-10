---
id: web-php-rce-call-user-func-leading-backslash-blacklist-bypass
title: PHP 函数名前置反斜杠绕过 in_array 精确黑名单，call_user_func 任意命令执行
type: scenario
domain: web
path: web/php/rce
technique: call-user-func-leading-backslash-blacklist-bypass
aliases:
- 反斜杠绕过黑名单
- 全局命名空间函数
- in_array 精确匹配绕过
- call_user_func 变量函数 RCE
tags:
- web
- php
- rce
- blacklist-bypass
- callback
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-25
  verified_at: '2026-11-08T14:28:22+08:00'
  notes: 已对照原文与图08-10核对：源码为 in_array(strtolower) 精确黑名单+call_user_func($b,$star)，num前置条件 isset&&!=1234&&is_numeric&&>1234；图10显示 new=\passthru&star=cat /f* 执行成功回显flag，PoC实证成立；机制与既有自增/create_function/正则转义卡均不同，dedup理由成立
---

## 一句话结论

PHP 里 `\system` 与 `system` 指向同一个全局命名空间函数，而黑名单用 `in_array(strtolower($a), $disable_fun)` 做**字符串精确匹配**时不会命中带前置反斜杠的名字，把 `\system`、`\passthru`、`\show_source` 传给 `call_user_func($b, $star)` 即绕过禁用函数表执行任意命令。

## 原理

PHP 默认从全局命名空间解析函数；当调用方（如 `call_user_func`、`array_map`、变量函数 `$f()`）收到以 `\` 开头的函数名时，PHP 将其解释为"全局命名空间中的该函数"，运行效果与不带反斜杠完全一致。防御若用"把用户输入与禁用函数名数组做 in_array/=== 全等比较"这种精确字符串匹配，`\system` 作为字符串与 `"system"` 不相等，黑名单形同虚设——匹配发生在字符串层，而调用发生在符号表层，两层表示不一致即形成绕过。这类校验的正确替代（FFI/自实现白名单、disable_functions 配置、符号解析后比对）不受影响。

## 触发条件

- 代码把用户可控字符串作为回调函数名传入 `call_user_func`/`call_user_func_array`/`usort`/`array_map` 等 callback 参数。
- 校验采用 `in_array`/`===` 与函数名黑名单做精确字符串比较，未 strip 前导 `\`、未做符号表级校验。

## 利用步骤

1. 审计源码确认 `call_user_func($b, $star)` 且 `$b` 仅过 in_array 黑名单（exec/shell_exec/system/passthru/proc_open/show_source 等）。
2. 先过前置条件（如 `is_numeric($num) && $num > 1234` 且 `$num != 1234`，传 `num=1245`）。
3. POST `new=\system&star=cat /f*`：waf 检查 `\system` 不在黑名单中放行，`call_user_func('\system', 'cat /f*')` 实际执行 system。
4. 同型载荷：`new=\passthru&star=cat /f*`、`new=\show_source&star=/flag`。

## PoC

```text
POST /?num=1245 HTTP/1.1
Content-Type: application/x-www-form-urlencoded

new=\system&star=cat /f*
```

响应回显命令输出（根目录 flag 文件内容）。

## 变体与关联

- 变体：大小写混淆对 strtolower 无效但 `\` 有效；`\\system`（双反斜杠）同样指向全局函数；配合可变变量 `$$_GET`。
- 关联：disable_functions 绕过家族（LD_PRELOAD、回调 gadget `create_function`/`array_map+assert`）；字符串层校验与语义层调用不一致是共同根因。

## 检测与防御

- 禁止把用户输入直接作为可调用函数名；必须回调时用硬编码白名单映射（`$map = ['ls'=>'my_ls'];`）。
- 若必须字符串校验：`ltrim($a, '\\')` 归一化后再比对，或用 `function_exists + 白名单交集`，最好升级为禁用函数配置（disable_functions）而非应用层黑名单。
- 审计工具应把 `\func` 规范化后纳入危险 sink 匹配。
