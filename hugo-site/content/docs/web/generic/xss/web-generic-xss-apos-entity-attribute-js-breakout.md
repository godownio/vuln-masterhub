---
id: web-generic-xss-apos-entity-attribute-js-breakout
title: 属性内联 JS 只转义字面单引号，&apos; 实体在 HTML 解析阶段还原导致闭合
type: scenario
domain: web
path: web/generic/xss
technique: entity-decode-order-breakout
tags:
- xss
- html-entity
- attribute-context
- javascript-handler
- encoding-order
- bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V13
  verified_at: '2026-11-05T01:50:04+08:00'
  notes: 已对照原文核对：&apos; 在 HTML 属性解析阶段还原为单引号、JS 字符串闭合后 -alert(1)- 表达式执行，与原文 payload 一致；原文未给完整 encode_for_onclick_js_single_quoted 与最终 HTML，卡片已标 confidence medium；未实际执行
url: /docs/web/generic/xss/web-generic-xss-apos-entity-attribute-js-breakout/
draft: false
kb_aliases:
- '&apos; 绕过'
- HTML 实体二次解码 XSS
- onclick JS 字符串闭合
- 编码顺序错误 XSS
---

## 一句话结论

当用户输入先被放进 `onclick` 等事件处理器的 JavaScript 单引号字符串、服务端只转义字面 `'` 却未处理 `&apos;` 实体时，HTML 解析器会在属性值阶段把 `&apos;` 解码成 `'`，该引号出现在 JS 源码中并闭合字符串，随后 `'-alert(1)-'` 作为表达式执行。

## 原理

- 事件处理器属性（如 `onclick="doSomething('USER')"`）经历两层解析：
  1. **HTML 属性解析**：浏览器先对属性值做 HTML 实体解码，`&apos;` → `'`、`&quot;` → `"`、`&#39;` → `'`；
  2. **JavaScript 解析**：解码后的属性值作为 JS 代码编译执行，其中的引号决定字符串边界。
- 服务端的 `encode_for_onclick_js_single_quoted()` 只处理输入中**字面**的单引号（把 `'` 转成 `\'`），但输入 `&apos;` 时它看到的是 `&`、`a`、`p`…，不含 `'`，原样保留。
- 输出到 HTML 属性后，HTML 解析器把 `&apos;` 还原成 `'`。此时在 JS 解析阶段，这个 `'` 就是真正的字符串结束符。
- 攻击者输入 `http://foo?&apos;-alert(document.cookie)-&apos;`，属性解码后成为 `http://foo?'-alert(document.cookie)-'`。若它被嵌入 `... 'URL' ...` 的 JS 字符串中，则形成 `''-alert(document.cookie)-''` 的减法表达式；JS 求值时先执行 `alert(...)`。点击触发该 handler 即执行。
- 根因是**编码/转义的顺序与层数不一致**：JS 层转义在 HTML 解码之前，HTML 解码又能生成 JS 元字符。安全顺序应是先做 JS 字符串编码，再对整个属性值做 HTML 编码（把 `&` 变成 `&amp;`），或直接避免内联事件处理器。

## 触发条件

- 用户输入被拼进 HTML 事件处理器属性中的 JS 字符串（单引号或双引号包裹）；
- 服务端只转义字面引号/反斜杠，未处理 HTML 实体（`&apos;`、`&#39;`、`&quot;` 等），且未在最终属性值上做 HTML 编码；
- 属性值被双引号包裹（这样 `&apos;` 解码出的 `'` 不会提前结束属性，只影响内层 JS 字符串）；
- 页面未用 CSP 禁止内联事件处理器。

## 利用步骤

1. 找到输入进入 `onclick=`/`onmouseover=` 等属性的位置，确认内层 JS 字符串使用的引号类型。
2. 提交 `&apos;`，观察响应属性值中是否原样保留；浏览器 DOM 中查看该属性是否已变为 `'`。
3. 构造闭合：`&apos;-alert(document.cookie)-&apos;`（利用减法表达式让 alert 被求值）。
4. 触发事件（点击/悬停），验证执行；若 `alert` 被拦截，用 `fetch` 外带数据。
5. 若 `&apos;` 被过滤，尝试 `&#39;`、`&#x27;`、`&quot;`（属性用单引号包裹时）。

## PoC

```html
<!-- 服务端（简化）：先做 JS 单引号转义，再直接放入 HTML 属性 -->
<button onclick="track('<?php echo encode_for_onclick_js_single_quoted($website); ?>')">Visit</button>

<!-- 输入 -->
http://foo?&apos;-alert(document.cookie)-&apos;

<!-- HTML 解析后的属性值（内层单引号被实体还原） -->
<button onclick="track('http://foo?'-alert(document.cookie)-'')">Visit</button>
```

```text
# 简化为属性内 JS 字符串闭合模型
onclick="track('INPUT')"
INPUT = &apos;-alert(1)-&apos;
HTML 解码后 -> '-alert(1)-'
JS 解析 -> ''-alert(1)-''  // 减法表达式求值时执行 alert
```

## 变体与关联

- 变体：`&quot;`/`&#34;` 闭合双引号包裹的 JS 字符串；`&#39;`/`&#x27;` 等价于 `&apos;`。
- 变体：HTML 实体出现在 `href="javascript:..."`、`srcdoc`、`style` 等其他需要多层解析的属性中。
- 关联：[[web-generic-xss-htmlspecialchars-single-quote-attribute]]（字面单引号属性闭合，根因是 flags 未含 `ENT_QUOTES`）；[[web-generic-xss-javascript-context-injection]]（JS 字符串/表达式上下文注入）。
- 局限：原文只给出漏洞片段与 payload，未展示完整 `encode_for_onclick_js_single_quoted` 实现与最终 HTML，故 confidence 记 medium。

## 检测与防御

- 检测：审计拼接到事件处理器属性中的用户输入，检查是否有“JS 转义后未再做 HTML 属性编码”的顺序问题；搜索 `onclick="...<?=` 模式。
- 检测：请求参数中出现 `&apos;`、`&#39;`、`&#x27;`、`&quot;` 与 `-alert(`、`-confirm(` 等表达式特征。
- 防御：避免内联事件处理器；使用 `addEventListener` + `dataset` 传递数据，数据只作为值而非代码。
- 防御：必须拼接时，先做 JS 字符串编码（如 `json_encode`），再对最终属性值做 HTML 实体编码（`ENT_QUOTES`），确保顺序正确、只解码一次。
- 防御：部署 CSP，禁止 `unsafe-inline`，可阻断内联事件处理器执行。
