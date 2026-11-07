---
id: web-generic-xss-double-url-decode-settimeout-sink
title: 双重 URL 解码差异配合 setTimeout 字符串参数导致 DOM XSS
type: scenario
domain: web
path: web/generic/xss
technique: double-decode-settimeout-eval
tags:
- xss
- dom-xss
- url-encoding
- settimeout
- waf-bypass
- client-side
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V13
  verified_at: '2026-11-05T01:49:22+08:00'
  notes: 已对照原文核对：服务端 preg_match+urlencode、前端两次 decodeURIComponent、setTimeout 字符串 sink 均一致；卡片把原始 PoC 修正为 URL 中提交 %2522（原文写 %22，考虑 PHP 查询串已解码一层，%2522 才符合其解码链），逻辑自洽；未实际执行
url: /docs/web/generic/xss/web-generic-xss-double-url-decode-settimeout-sink/
draft: false
kb_aliases:
- 双重 URL 解码 XSS
- setTimeout 字符串执行 XSS
- WAF 编码差异绕过
- decodeURIComponent 两次
---

## 一句话结论

服务端用 `preg_match` 拦截原始引号/尖括号后再 `urlencode`，看似安全；但前端为兼容旧数据执行了两次 `decodeURIComponent`，解码后的内容又被拼进 `setTimeout` 的字符串参数（等价于 `eval`），导致攻击者用双重编码的 `%2522` 绕过检查并闭合字符串执行 JS。

## 原理

- 服务端检查的是 `$_GET` 中的值：`preg_match("/['\"<>]/", $str)` 拦截 `'`、`"`、`<`、`>`，命中则替换为 `_`；通过后再 `urlencode($str)` 输出。直接提交 `"` 会被拦截。
- 前端对服务端输出做了**两次** `decodeURIComponent`：`step1 = decodeURIComponent(rawInput); step2 = decodeURIComponent(step1);`。这是典型的“WAF 只看一层可见字符、消费端解码两层”的规范化差异。
- 攻击者在 URL 中提交 `%2522`：PHP 查询串解析先解一次得到字面量 `%22`，`preg_match` 只看到 `%`、`2`、`2`，不命中；随后 `urlencode` 又把 `%` 编码成 `%25`，输出 `%2522`。浏览器第 1 次解码得到 `%22`，第 2 次解码才变成 `"`——此时已在前端，绕过服务端检查。
- Sink 为 `setTimeout('console.log("Log: ' + step2 + '")', 100)`。`setTimeout` 的第一个参数是字符串时会被当作代码求值（同 `eval`），因此 `step2` 中的 `");alert(1);//` 闭合日志行的双引号，后面的 `alert(1)` 成为独立语句，`//` 注释掉剩余部分。
- 根因是“校验/编码发生在不同层且解码次数不一致”，加上把不可信数据传入字符串形式的定时器。

## 触发条件

- 用户输入被服务端 `urlencode`/单次编码后回显到页面；
- 前端对同一值执行了额外一次（或多次）URL 解码；
- 解码结果被拼进 `setTimeout`/`setInterval` 的字符串参数、`eval`、`Function` 等动态执行 sink；
- 服务端 WAF 只检查原始/单次解码形态。

## 利用步骤

1. 观察响应中参数是否被 `urlencode`，以及前端是否出现多次 `decodeURIComponent`。
2. 确认 sink：`setTimeout('...' + value + '...')` 的引号类型（单/双）。
3. 计算编码层数：先在 URL 中多编一层，使 PHP `$_GET` 拿到字面量 `%22` 而不是 `"`，从而绕过 `preg_match`。
4. 构造闭合：URL 中提交 `%2522);alert(document.cookie);//`。
5. 触发页面加载，验证 alert 执行；若 `alert` 被拦截，换 `console.log`/`fetch` 验证。

## PoC

```javascript
// 前端错误代码
var rawInput = '<urlencode 后的输入>';
var step1 = decodeURIComponent(rawInput);
var step2 = decodeURIComponent(step1);
setTimeout('console.log("Log: ' + step2 + '")', 100);
```

```text
# 直接在 URL 的 keyword 参数中提交（两层编码）
%2522);alert(document.cookie);//

# 解码链：PHP $_GET 解一层 -> %22，WAF 不命中
#         PHP urlencode -> %2522...
#         浏览器 decode 1 -> %22...
#         浏览器 decode 2 -> ");alert(document.cookie);//
```

## 变体与关联

- 变体：前端解码一次 + 服务端解码一次、或框架路由自动解码，同样可造成“编码层数错位”。
- 变体：Sink 换成 `eval`、`new Function`、`document.write`、jQuery `html()`。
- 关联：[[web-generic-xss-javascript-context-injection]]（JS 字符串上下文闭合）；[[web-generic-xss-filter-bypass-encoding-obfuscation]]（编码类黑名单绕过）。

## 检测与防御

- 检测：审计 `decodeURIComponent` 连续调用、`setTimeout(`/`setInterval(` 首参为字符串的代码；请求中出现 `%25` 双重编码与 `");` 模式。
- 防御：统一在服务端做一次规范化（解码 → 校验 → 编码），保证校验与消费看到的字符串一致；不要重复解码。
- 防御：禁止 `setTimeout`/`setInterval` 传字符串，改为传函数；禁止 `eval`。
- 防御：输出到 JS 上下文时使用 JS 编码而非 URL 编码；部署 CSP nonce/hash 阻止内联脚本。
