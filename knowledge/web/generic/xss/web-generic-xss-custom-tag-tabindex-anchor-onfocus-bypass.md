---
id: web-generic-xss-custom-tag-tabindex-anchor-onfocus-bypass
title: 全标签黑名单下的自定义标签 XSS：onfocus + tabIndex + URL 锚点自动聚焦触发
type: scenario
domain: web
path: web/generic/xss
technique: custom-tag-tabindex-anchor-onfocus
aliases:
- 自定义标签 XSS
- tabIndex onfocus
- 锚点聚焦 XSS
- 标签绕过
- 未知元素事件处理器
tags:
- web
- xss
- filter-bypass
- html-parser
- dom
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V679
  verified_at: '2026-11-13T12:11:40+08:00'
  notes: '已对照原文核对：payload <qweasd id=''qweasd'' onfocus=alert(1) tabIndex=1> 与 #qweasd 锚点用法与原文一致；原文该向量无执行截图（javascript:/img onerror/SVG 有截图），卡内已如实标注 medium。原文未给受影响版本，affected_versions 保持为空；dedup 无同链卡片。'
---

## 一句话结论

当 XSS 防护把已知 HTML 标签（`script`、`img`、`svg` 等）与常见事件属性全部拉黑时，HTML 解析器仍会照常解析未登记的自定义标签；构造 `<qweasd id='qweasd' onfocus=alert(1) tabIndex=1>` 注入页面，再让受害者访问带 `#qweasd` 的 URL，浏览器会按 fragment 定位并聚焦该元素，从而自动触发 `onfocus` 执行脚本，实现不依赖任何标准标签的 XSS。

## 原理

- **未知元素照样被解析**：HTML 解析器对不在规范内的标签名不报错，会按普通元素创建节点并应用属性；自定义标签（如 `<qweasd>`）与它的 `onfocus`、`id`、`tabIndex` 属性都能进入 DOM 并生效。
- **事件处理器是通用属性**：`onfocus` 等事件内容属性可挂在任意元素上；框架/黑白名单过滤器通常只枚举已知标签与属性，自定义标签名不在名单中。
- **默认元素不可聚焦**：多数元素默认不能获得焦点，`tabIndex=1` 把元素加入 tab 焦点序，使其可被脚本或导航聚焦。
- **URL fragment 自动聚焦**：浏览器加载完文档后会查找 `id` 等于 fragment 的元素并聚焦/滚动到它，焦点到达即触发 `focus` 事件，进而执行 `onfocus` 中的 JS——整个过程不需要用户点击。
- **为什么成立**：过滤发生在"标签名字符串"层，而浏览器解析发生在"HTML 语法/DOM 层"；两层对同一输入的理解不一致，黑名单未覆盖的标签名就是绕过空间。

## 触发条件

- 用户输入能进入 HTML 上下文且未被上下文编码或白名单 sanitizer 清洗（仅做标签/属性黑名单）。
- 反射型场景可通过 GET 参数回显 payload 并能控制 URL fragment；存储型场景直接把 payload 存进页面，访问时加 `#id` 即可。
- 目标浏览器支持 `tabindex` 与 fragment 聚焦（主流浏览器均支持）。
- 没有 CSP 禁止内联事件处理器（`unsafe-inline` 未禁用或不存在强 CSP）。

## 利用步骤

1. 用无害 payload 确认注入点与输出上下文，测试 `<script>`、`<img src=x onerror=...>`、`<svg onload=...>` 是否被过滤/剥离，判断是否为纯黑名单。
2. 构造自定义标签 payload，指定唯一 `id` 与 `tabIndex`：`<qweasd id='qweasd' onfocus=alert(1) tabIndex=1>`。
3. 反射型：把 payload 放入可回显参数，并让受害者访问 `<url>?param=<payload>#qweasd`；存储型：直接访问含 payload 的页面并追加 `#qweasd`。
4. 验证脚本执行；若 `onfocus` 被单独过滤，可换 `onpointerover`、`onanimationstart`（配合 CSS 动画）等仍可自动触发的组合。
5. 若自定义标签名也被规则拦截，尝试随机标签名/带连字符的元素名（如 `<x-a>`），并同步改变 fragment 的 id。

## PoC

```html
<qweasd id='qweasd' onfocus=alert(1) tabIndex=1>
```

```text
https://target/?id=<qweasd id='qweasd' onfocus=alert(1) tabIndex=1>#qweasd
```

说明：原理依据 HTML 解析与焦点规范；原文仅给出 payload 与用法，未附该向量的执行截图（其余向量如 javascript: 链接、img onerror、SVG 有截图），confidence 标 medium。未在目标环境执行。

## 变体与关联

- 变体：`onfocus` + `autofocus`（无需锚点，但 `autofocus` 可能被过滤或在多元素时失效）；`<details open ontoggle=...>`；`<video><source onerror=...>`；SMIL `<animate onbegin=...>`。
- 变体：所有标签名被过滤时用随机自定义元素名、Web Components 风格 `<x-y>`，再配合其它通用事件属性。
- 关联：[[web-generic-xss-scriptless-execution-vectors]]（不依赖 `<script>` 的事件处理器/伪协议载体，含 onfocus+autofocus 变体）、[[web-generic-xss-filter-bypass-encoding-obfuscation]]（字符串黑名单与解析层差异的通用绕过）。
- 边界：白名单 sanitizer（如 DOMPurify 默认配置）会直接剥离未知标签，本手法失效；严格 CSP 也会阻止内联事件处理器。

## 检测与防御

- 检测：请求/响应中出现未知标签名 + `onfocus=` + `tabindex=` 组合，尤其是同时在 URL 中出现同名 `#id`；存储型内容的 HTML 中新增自定义元素与事件属性。
- 防御：使用白名单 sanitizer（按标签+属性+协议白名单，未知标签直接剥离），不要用标签名黑名单。
- 防御：输出上下文编码；禁止内联事件处理器与 `javascript:` URL；部署严格 CSP（nonce/hash + 禁止 `unsafe-inline`）。
- 说明：本手法只影响"黑名单式"过滤；白名单与 CSP 可从根本上阻断。
