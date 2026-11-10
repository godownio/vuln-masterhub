---
id: xss-cold-event-content-visibility-bypass
title: 冷门事件 oncontentvisibilityautostatechange 结合 content-visibility 绕过 XSS 过滤器自动触发
type: scenario
domain: web
path: web/generic/xss
technique: 使用 CSS 属性 content-visibility:auto 搭配冷门事件处理器 oncontentvisibilityautostatechange 构造 XSS，利用黑名单不收录的冷门事件、合法 CSS 白名单属性与 input 低风险标签三重规避过滤，且状态切换自动触发无需用户交互
tags:
- xss
- filter-bypass
- css
- content-visibility
- event-handler
- input-tag
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-33
  verified_at: '2026-11-08T17:18:45+08:00'
  notes: 已对照原文核对：payload 与原文逐字一致，img02 证实该 PC 客户端（localhost 页面）粘贴 payload 即弹窗执行（alert(1)），冷门事件+content-visibility+input 三重绕过逻辑为原文分析；dedup 与冷门事件逗号表达式卡、onmouseover 属性逃逸卡机制不同，非同一链
url: /docs/web/generic/xss/xss-cold-event-content-visibility-bypass/
draft: false
kb_aliases:
- content-visibility XSS
- 冷门事件 XSS 绕过
- oncontentvisibilityautostatechange XSS
---

# 一句话结论

`<input style=content-visibility:auto oncontentvisibilityautostatechange="alert(1)">` 可在未转义/黑名单式过滤的页面执行 JS：黑名单只盯 onload/onerror 等常见事件，而 `oncontentvisibilityautostatechange` 是与 CSS `content-visibility` 关联的极冷门事件，过滤器不收录；元素渲染状态（如从隐藏变可见）切换时事件自动触发，无需用户交互；`input` 与标准 CSS 性能属性均属低风险白名单，易通过 CSP/过滤器。

# 原理

为什么成立：

1. `content-visibility: auto` 是标准性能优化 CSS 属性，浏览器会跳过非视口内容的渲染；当元素进入/离开视口导致渲染状态切换时，派发 `contentvisibilityautostatechange` 事件，对应的内联事件处理器属性 `oncontentvisibilityautostatechange` 即执行 JS——攻击逻辑完全隐藏在"合法功能"里。
2. 多数 XSS 过滤/WAF 规则采用事件黑名单（onload、onerror、onfocus、onmouseover 等高频事件），该事件几乎不被收录，直接绕过。
3. `<input>` 被普遍视为低风险标签（对比 `<script>`/`<img>`/`<svg>`），评论框等输入点常只过滤高危标签，`input` 往往存活。
4. 无需用户交互：只要元素渲染状态发生变化（滚动进入视口、容器显示/隐藏、页面布局变化）即自动触发，可"静默"执行。

# 触发条件

- 目标页面将用户输入（含 `input` 标签与 style 属性）原样输出或仅做黑名单/标签过滤，未做属性级白名单与输出编码。
- 注入元素在渲染生命周期中发生 content-visibility 状态切换（进入视口、父容器显示等）——纯静态不滚动页面需要布局变化才能触发。
- 浏览器支持 content-visibility（Chromium 85+、Firefox 125+、Safari 18+）；PC 客户端内嵌 WebView（Chromium 内核）同样适用。

# 利用步骤

1. 在存在存储/反射 XSS 的注入点插入 `<input style=content-visibility:auto oncontentvisibilityautostatechange="PAYLOAD">`。
2. PAYLOAD 可为任意 JS：alert(1) 验证、外带 cookie、或进一步链式利用（见变体）。
3. 元素渲染状态切换时自动执行，无需点击/悬停。

# PoC

```html
<input style=content-visibility:auto oncontentvisibilityautostatechange="alert(1)">
```

原文在 PC 桌面客户端（Chromium 内嵌 WebView 的记事本类工具）中粘贴该 payload 到命令记录，客户端直接弹窗执行成功。

# 变体与关联

- 同类思路可枚举其他冷门派发事件/新 CSS 属性联动事件，黑名单天然滞后。
- 与窗口滚动、懒加载、`content-visibility: hidden` 与 auto 切换等组合，可控制触发时机。
- 该 payload 是「PC 客户端 XSS 到文件写入/RCE」链条的入口（见同源场景卡：showSaveFilePicker 写 bat）。
- 关联：mutation XSS、非常规标签/属性 XSS、CSP nonce 场景下内联事件受限时需另寻绕过。

# 检测与防御

- 检测：正则/语义扫描所有 `on[a-z]+` 内联事件属性而非仅黑名单事件；对 `content-visibility` 后跟事件属性的组合告警。
- 防御：输出编码（HTML entity）+ 属性白名单；CSP 禁止 inline script 与 `unsafe-inline`（内联事件处理器受 script-src-attr 控制）；客户端 WebView 配置禁用第三方内容加载。
