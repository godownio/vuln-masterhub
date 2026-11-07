---
id: web-generic-xss-javascript-context-injection
title: JavaScript 代码上下文注入：字符串闭合、表达式位置与模板字符串插槽
type: scenario
domain: web
path: web/generic/xss
technique: js-context-injection
tags:
- xss
- javascript-context
- inline-script
- template-literal
- output-encoding
- dom
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V13
  verified_at: '2026-11-05T01:49:20+08:00'
  notes: 已对照原文核对：HTML 实体在 script 上下文不生效、单引号闭合、'-alert(1)-' 表达式、模板字符串 ${} 插槽三种场景与原文示例一致；未实际在浏览器执行
url: /docs/web/generic/xss/web-generic-xss-javascript-context-injection/
draft: false
kb_aliases:
- JS 上下文 XSS
- 内联脚本字符串闭合
- 模板字符串注入
- JS 表达式注入 XSS
---

## 一句话结论

当用户输入被直接拼接进内联 `<script>` 的 JavaScript 源码（而不是 HTML 文本/属性）时，HTML 实体编码不起作用，攻击者可按插入位置闭合字符串、劫持表达式或利用模板字符串的 `${}` 插槽直接执行任意 JS。

## 原理

- 浏览器解析 `<script>` 内容时按 JavaScript 语法处理，不做 HTML 实体解码（`<`/`>`/`&` 在这里只是普通字符），因此服务端把 `<`、`>` 转成 `&lt;`/`&gt;` 并不能阻止脚本注入。
- 三种常见上下文：
  - **字符串字面量**：`var t = 'INPUT';`。输入 `';alert(1)//` 会变成 `var t = '';alert(1)//';`，分号结束语句，`//` 注释掉尾部。
  - **表达式位置**：`searchTerm: 'INPUT',`。输入 `'-alert(1)-'` 生成 `'INPUT'` 与相邻代码构成减法表达式 `''-alert(1)-''`；JS 求值时必须先计算 `alert(1)`，于是执行。即使输入被引号包裹，只要引号是输入的一部分且没有做 JS 转义，就能形成合法表达式。
  - **模板字符串**：反引号包裹的字符串中 `${...}` 是表达式插槽，解析阶段即求值。输入 `${alert(1)}` 插入 `` `...${alert(1)}...` `` 后立即执行；即使服务器把 `<`、`>`、引号转成 `\uXXXX`，`${}` 仍未被转义（只编码这些字符并不能阻止插槽）。
- 共同根因是“把不可信数据当代码拼接”。HTML 上下文编码、简单字符替换都不适用于 JS 语法层；正确的做法是 JavaScript/JSON 编码或干脆不生成内联脚本。

## 触发条件

- 用户输入被反射/存储后拼接到内联 `<script>` 或事件处理器代码中；
- 没有使用 `json_encode`、`JSON.stringify` 或专门的 JS 字符串转义，只做了 HTML 转义或部分字符替换；
- 输出位置处于字符串、对象属性值、模板字符串等可被语法闭合的位置；
- 页面未用 CSP 的 nonce/hash 限制内联脚本（否则注入代码可能被拦截）。

## 利用步骤

1. 判断输入落在 JS 字符串、表达式值还是模板字符串中（观察响应源码的引号/反引号包裹与拼接方式）。
2. 字符串上下文：用 `'` 或 `"` 闭合，`;` 结束语句，`//` 注释剩余部分。
3. 表达式上下文：用 `'-alert(1)-'` 构成减法表达式，或 `1;alert(1)//` 之类按语法切分。
4. 模板字符串上下文：直接提交 `${alert(1)}`；若 `$`、`{` 被过滤，尝试 `${...` 等 JS 转义（能否生效取决于是否处于源码层）。
5. 在浏览器验证执行，并检查 CSP 响应头。

## PoC

```javascript
// 1) 单引号字符串：var t_str = 'INPUT';
';alert(document.cookie);//

// 2) 表达式位置：searchTerm: 'INPUT',
'-alert(document.cookie)-'

// 3) 模板字符串：`...${INPUT}...`
${alert(document.cookie)}
```

对应的服务端错误写法：

```php
echo "var t_str = '$str';";                 // 只替换 < > 无效
echo "searchTerm: '$str',";                 // 引号是输入的一部分
echo "const msg = `Hello ${$str}`;";        // ${} 插槽
```

## 变体与关联

- 变体：双引号包裹、无引号数字位置、对象键位置、`eval`/`setTimeout` 字符串参数（见 [[web-generic-xss-double-url-decode-settimeout-sink]]）。
- 变体：`</script>` 可提前结束脚本块，把后续内容变成 HTML，再配合 HTML 上下文注入。
- 关联：[[web-generic-xss-filter-bypass-encoding-obfuscation]]（HTML 上下文的关键字黑名单绕过）；[[web-generic-xss-htmlspecialchars-single-quote-attribute]]（HTML 属性上下文）。
- 注意：PHP `json_encode($s, JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)` 可安全嵌入 JS 字符串/数据，但前提是只作为数据而非代码拼接。

## 检测与防御

- 检测：审计内联脚本中 `var x = '<?=`、`echo "var`、模板字符串拼接请求参数；CSP 报告出现 inline script 拦截但页面仍执行注入。
- 检测：请求参数含 `';`、`'-`、`${`、`</script>` 等 JS 上下文特征。
- 防御：不要用字符串拼接生成 JS；把数据放入 `data-*` 属性或 `<script type="application/json">`，前端读取后再使用。
- 防御：必须内联时使用语言提供的 JS/JSON 编码（PHP `json_encode`、Java `JSONObject.quote`），并对 `</script>` 做转义。
- 防御：部署带 nonce/hash 的 CSP，禁止 `unsafe-inline`，可显著降低此类注入的可执行性。
