---
id: web-generic-xss-filter-bypass-encoding-obfuscation
title: XSS 字符替换/黑名单绕过：双写、大小写、空白替代与实体编码
type: scenario
domain: web
path: web/generic/xss
technique: xss-blacklist-bypass
aliases:
- XSS 双写绕过
- XSS 大小写绕过
- XSS 空格绕过
- XSS 黑名单绕过
tags:
- xss
- bypass
- blacklist
- encoding
- html-entity
- filter
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V2
  verified_at: '2026-11-04T21:39:27+08:00'
  notes: 已对照原文核对：双写(scriscriptpt/hrhrefef)、大小写(hREf)、空白替代(%0A/%09/%0D/%0C)、注释(//http://)、HTML实体(javascr&#x69;pt) 均出自原文 level7/6/16/9/8 等；卡片按机制归纳合理。原文无图片，PoC 未独立执行。
---

## 一句话结论

当 XSS 防护只是把 `script`、`on`、`href` 等关键字替换为空字符串，或用大小写敏感的正则/黑名单匹配时，可以通过双写、大小写变换、空白替代、注释填充和 HTML 实体编码构造出仍会被浏览器解析、但不再匹配过滤规则的 payload。

## 原理

- **双写**：过滤器把关键字替换成空字符串（如 `str_replace("script","",$s)`），嵌套一次即可在删除后复原：`scriscriptpt` 删除中间的 `script` 后剩下 `script`。多轮替换可多层嵌套。
- **大小写**：正则未加 `i` 修饰符时，`<a hREf=...>` 不匹配 `href`，但 HTML 标签/属性名大小写不敏感，浏览器仍按 `href` 解析。
- **空白替代**：过滤器只匹配普通空格 `%20` 时，可用 `%09`（Tab）、`%0A`（换行）、`%0D`（回车）、`%0C`（换页）等 HTML 空白字符分隔属性；在标签内部，`/` 也可充当标签名与属性、属性与属性之间的分隔符。
- **注释填充**：后端要求输入必须包含 `http://` 时，用 JavaScript 的 `//` 把其后内容注释掉，既满足校验又不影响 payload。
- **HTML 实体编码**：HTML 解析器会在处理属性值/文本前解码实体（十进制、十六进制、命名实体），因此 `javascr&#x69;pt:` 在浏览器看来仍是 `javascript:`，但字符串黑名单看不到完整关键字。
- 这些技巧的共同点是：过滤发生在“字符串层”，浏览器解析发生在“语法/解码层”，两层对同一输入的理解不一致。

## 触发条件

- 应用使用字符串替换、正则黑名单或“必须包含某关键字”的正向校验，而不是上下文输出编码。
- 用户输入被反射或存储到 HTML 页面中，且没有被模板引擎自动转义。
- 过滤规则存在上述任一实现缺陷（替换为空、大小写敏感、只匹配普通空格、先校验后使用等）。
- 浏览器按 HTML 语法解析响应（而不是纯文本/JSON）。

## 利用步骤

1. 先用无害 payload（如 `alert(1)`、`print(1)`）确认输入点与输出上下文。
2. 判断过滤行为：提交 `script`、`on`、`href`、空格、`http://` 等，观察哪些被删除/替换/拒绝。
3. 按过滤类型选择绕过：
   - 关键字被替换为空 → 双写/多写；
   - 正则大小写敏感 → 混合大小写；
   - 只过滤普通空格 → `%09`/`%0A`/`%0D`/`%0C` 或 `/`；
   - 要求包含某字符串 → 用 `//` 注释或放在无害位置；
   - 关键字黑名单 → HTML 实体/URL 编码/Unicode 转义。
4. 组合使用：例如 `<img/src=x/onerror=alert(1)>` 同时绕过空格过滤与属性分隔。
5. 在目标浏览器验证执行，注意 CSP 可能阻止内联脚本/事件处理器。

## PoC

```text
# 双写：过滤器 str_replace("script","",$s)
<scriscriptpt>alert(1)</scriscriptpt>

# 双写：过滤器 str_replace("href","",$s)
"> <a hrhrefef=javascript:alert(1)>x</a>

# 大小写：正则未加 /i
"> <a hREf=javascript:alert(1)>x</a>

# 空白替代：只过滤 %20
<img%09src=x%09onerror=alert(1)>
<img/src=x/onerror=alert(1)>

# 注释：要求必须包含 http://
javascr&#x69;pt:alert(1)//http://

# HTML 实体：绕过 javascript 关键字黑名单
<a href="javascr&#x69;pt:alert(1)">x</a>
```

说明：payload 需按目标过滤规则调整；部分向量依赖用户交互（点击/悬停），`onerror`/`onload` 可自动触发。PoC 未在目标环境执行。

## 变体与关联

- 变体：多重替换时用多层嵌套（如 `scrscriptipt`）；过滤 `on` 时用 `oonn` 双写。
- 变体：URL 编码/双重 URL 编码用于 URL 参数或 JavaScript 上下文；Unicode 转义用于 JavaScript 字符串上下文。
- 变体：`/` 作为 HTML 标签内空白替代只适用于属性之间，引号内按文本处理。
- 关联：[[web-generic-xss-htmlspecialchars-single-quote-attribute]]（单引号属性上下文与 `htmlspecialchars` 默认 flags）；[[web-generic-xss-scriptless-execution-vectors]]（无 `<script>` 标签时的替代载体，含 HTML 实体与 `javascript:` 伪协议）。
- 关联：[[web-generic-file-upload-extension-zero-check]]（同为“字符串层校验 vs 解析层语义”的差异，但属于文件上传）。

## 检测与防御

- 检测：审计代码中的 `str_replace`、`preg_replace`、黑名单数组与正向 `contains` 校验；搜索 `htmlspecialchars`/`strip_tags` 之外的“手写过滤”。
- 检测：请求参数中出现 `scriscriptpt`、`hrhrefef`、`%0A`/`%09`/`%0C`、`&#x`、`//http://` 等组合。
- 防御：不要用字符串替换/黑名单做 XSS 防护；使用上下文相关的输出编码（HTML、属性、JS、URL、CSS）。
- 防御：富文本使用成熟的白名单 sanitizer（DOMPurify、HTMLPurifier），并在服务端做同样的解析级校验。
- 防御：部署 CSP（禁止 `unsafe-inline`，使用 nonce/hash）；对输入先解码/规范化再校验，避免“校验与使用不一致”。
