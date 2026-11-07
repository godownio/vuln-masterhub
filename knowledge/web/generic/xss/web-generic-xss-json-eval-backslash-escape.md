---
id: web-generic-xss-json-eval-backslash-escape
title: JSON 只转义引号未转义反斜杠配合 eval 消费导致代码注入
type: scenario
domain: web
path: web/generic/xss
technique: json-eval-context-injection
aliases:
- JSON XSS
- eval 解析 JSON 注入
- 反斜杠转义缺陷
- searchTerm 注入
tags:
- xss
- json
- eval
- escaping
- dom-xss
- client-side
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V13
  verified_at: '2026-11-05T01:50:00+08:00'
  notes: 已对照原文核对：只转义双引号未转义反斜杠、eval 消费、\" 构造提前闭合字符串的推演与原文一致；未实际执行
---

## 一句话结论

服务端手工拼接 JSON 时只把 `"` 替换成 `\"`、却没有转义 `\`，客户端又用 `eval('(' + responseText + ')')` 解析；攻击者提交 `\"` 使服务端生成 `\\"`，在 JS 中 `\\` 成为字面反斜杠、后面的 `"` 提前闭合字符串，从而把数据注入为可执行代码。

## 原理

- 有缺陷的服务端转义：`str_replace('"', '\"', $q)`。它把每个 `"` 变成 `\"`，但输入中的反斜杠原样保留。
- 攻击者输入 `\"-alert(document.cookie)})//`：
  - 输入的 `\` 不被处理；
  - 输入的 `"` 被替换为 `\"`；
  - 拼接结果是 `\\"`：两个反斜杠 + 一个引号。
- 在 JavaScript 字符串字面量中：`\\` 转义为**一个字面反斜杠字符**，它不转义后面的 `"`；因此该 `"` 是字符串的结束引号。字符串提前闭合后，`-alert(document.cookie)` 成为减法表达式的一部分——JS 求值该表达式时必须先调用 `alert(document.cookie)`，随后 `})` 闭合对象与外层 `eval` 的括号，`//` 注释掉剩余内容。
- 客户端使用 `eval` 而非 `JSON.parse`：`eval` 按 JavaScript 语法求值，会把注入的运算符/语句当作代码执行；`JSON.parse` 只接受严格 JSON，遇到多余内容会抛错，不会执行。
- 根因组合：不完整的字符串转义（漏掉反斜杠）+ 危险的解析 sink（`eval`）。

## 触发条件

- 服务端手工拼接 JSON/JS 字符串返回给前端，转义只覆盖引号（或顺序错误地先转义引号再转义反斜杠）；
- 客户端用 `eval`、`new Function` 或 `setTimeout` 字符串解析响应；
- 输入被反射进 JSON 字符串值，且响应 `Content-Type` 不妨碍执行（`eval` 不依赖 MIME，但若浏览器按 JSON 解析则不会执行）；
- 页面允许执行内联脚本（或该响应被作为脚本加载）。

## 利用步骤

1. 找到返回 JSON 且被 `eval` 解析的接口，确认服务端对 `"` 的转义行为。
2. 提交单个 `\` 和 `"` 观察响应：若出现 `\\"` 而非 `\\\\\"`，说明反斜杠未转义。
3. 构造 payload：`\"-alert(document.cookie)})//`，目标是让 eval 后代码形态为 `({...,"searchTerm":"\\"-alert(document.cookie)})`。
4. 在浏览器触发该请求，确认 alert 执行；若 `alert` 被拦截，用 `fetch` 外带数据验证。

## PoC

```php
// 有漏洞的服务端
$safe_q = str_replace('"', '\"', $q);
echo '{"results":' . $results_json . ',"searchTerm":"' . $safe_q . '"}';
```

```javascript
// 有漏洞的客户端
var searchResultsObj = eval('(' + xhr.responseText + ')');
```

```text
# 输入
\"-alert(document.cookie)})//

# 服务端生成（关键片段）
"searchTerm":"\\"-alert(document.cookie)})//"

# eval 后等价代码
({"results":...,"searchTerm":"\\" -alert(document.cookie)})//"})
# 字符串值为单个反斜杠，随后减法表达式求值触发 alert，}) 闭合，// 注释尾部
```

## 变体与关联

- 变体：`</script>` 注入（JSON 被内联到 `<script>` 时）；U+2028/U+2029 破坏 JSONP；`__proto__` 属性污染（若客户端合并对象）。
- 变体：服务端先转义反斜杠后转义引号导致顺序错误，同样可构造 `\\"`。
- 关联：[[web-generic-xss-javascript-context-injection]]（JS 表达式位置的普适注入）；[[web-generic-xss-double-url-decode-settimeout-sink]]（另一种字符串转代码 sink）。

## 检测与防御

- 检测：审计 `str_replace('"','\"')`、`addslashes` 后手工拼 JSON 的代码；客户端 `eval(`、`new Function(`、字符串 `setTimeout`。
- 检测：请求参数含 `\"`、`//`、`})` 等 JSON 逃逸特征。
- 防御：服务端使用 `json_encode($data, JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)` 或等价安全序列化，禁止手工拼 JSON。
- 防御：客户端一律 `JSON.parse`，禁止 `eval` 解析响应；为响应设置 `Content-Type: application/json` 与 `X-Content-Type-Options: nosniff`。
