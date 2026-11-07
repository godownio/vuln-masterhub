---
id: web-generic-xss-dom-clobbering-library-config-gadget
title: DOM Clobbering 劫持第三方库配置对象：HTMLCollection 静默赋值失效 + 库内 gadget 删 escapeHtml 后注入 iframe onload
type: scenario
domain: web
path: web/generic/xss
technique: dom-clobbering-library-config-gadget-chain
tags:
- web
- xss
- dom-clobbering
- dompurify
- third-party-library
- iframe
- gadget-chain
- sloppy-mode
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V215
  verified_at: '2026-11-07T05:04:43+08:00'
  notes: 已对照原文与 img/09-11 核对多个 id=Beamer 形成 HTMLCollection、非严格模式命名属性赋值失效、removeIframe 删除 escapeHtml、pushDomain 跳过 escapeHtml 分支、customDomain 用 &#39; 实体引号走私进 iframe onload；payload 与原文一致。未验证点：原文只展示 escapeHtml clobber 的本地控制台结果，未展示最终 iframe onload 端到端执行，卡 confidence medium。
url: /docs/web/generic/xss/web-generic-xss-dom-clobbering-library-config-gadget/
draft: false
kb_aliases:
- Beamer DOM Clobbering
- classic configurable library
- HTMLCollection 命名属性赋值失效
- escapeHtml clobber
- customDomain iframe 注入
- beamerOverlay removeIframe
---

## 一句话结论

当第三方库采用 `window.Beamer = window.Beamer || {}` 这类经典配置模式，并在加载时把 `escapeHtml` 等函数挂到 `Beamer` 上时，攻击者用带 `id`/`name` 的元素把 `window.Beamer` 变成 HTMLCollection；非严格模式下对命名属性的赋值被静默忽略，库里的 `escapeHtml` 仍是攻击者元素。再借库自身的 `update → appendAlert → removeIframe` 调用链删掉该元素，使 `escapeHtml` 变为 undefined，随后库把可控的 `customDomain` 不加转义地拼进 `iframe src='...'`，用引号 smuggled 注入 `onload` 执行 XSS。

## 原理

- **经典可配置库模式**：库开头执行 `"undefined" === typeof window.Beamer && (window.Beamer = {})`，之后在 `Beamer` 上定义 `escapeHtml`、`customDomain` 等属性。若页面已有 `<a id="Beamer">`，`window.Beamer` 已定义，库不会再创建干净对象。
- **HTMLCollection 命名属性**：多个同名 `id="Beamer"` 元素让 `window.Beamer` 成为 HTMLCollection；其中带 `name="escapeHtml"`、`name="customDomain"`、`name="pushDomain"` 的子元素分别成为集合的命名属性，读取 `Beamer.escapeHtml` 等得到的是元素而不是库函数。
- **非严格模式静默失败**：默认（sloppy mode）下对 HTMLCollection 命名属性赋值会被忽略或抛错被吞掉，`Beamer.escapeHtml = function(a){...}` 不会覆盖元素；strict mode 下会抛 `TypeError: Named property setter is not supported`。因此库以为已安装 escape 函数，实际拿到的是攻击者元素。
- **库内删除 gadget**：`Beamer.removeIframe` 根据 `Beamer.isInApp()` 选择 `beamerNews` 或 `beamerOverlay`，再遍历并 `parentNode.removeChild`。把 `name="escapeHtml"` 的节点包在 `<a id="beamerOverlay">` 内，`removeIframe` 会把它删除，之后 `Beamer.escapeHtml` 变成 undefined。
- **触发入口**：页面初始化调用 `Beamer.update({language:"FR"})`；`update` 检测到语言变化后置 `b=true`，调用 `appendAlert`；`appendAlert` 内部先走 `removeIframe`（依 auto_refresh 等配置），再调用 `appendUtilitiesIframe`。原文链：`update → appendAlert → removeIframe/appendUtilitiesIframe`。
- **未转义的 customDomain**：`appendUtilitiesIframe` 中 `b = Beamer.customDomain + "utilities?app_id=" + product_id`；若 `typeof Beamer.escapeHtml !== "undefined"` 则先 `b = Beamer.escapeHtml(b)`。此时 escapeHtml 已被删除，b 不经转义；随后 `Beamer.appendHtml(document.body, "<iframe id='beamerUtilities' src='" + b + "' ...></iframe>")`。`Beamer.customDomain` 是 anchor 元素，转字符串时取 href；href 中的单引号在拼进单引号包裹的 `src` 时闭合属性，插入 `onload=` 事件。
- **pushDomain 的用途**：`appendPushScript` 在 `Beamer.pushDomain` 未定义时会走调用 `Beamer.escapeHtml(b)` 的分支并抛错；payload 放一个 `name="pushDomain"` 的元素让该分支被跳过，避免提前中断链。
- 根因是库把安全状态（escape 函数是否存在）放在可被 DOM 命名属性覆盖的全局对象上，并且自身存在可被页面 API 驱动的 DOM 删除操作。

## 触发条件

- 页面加载使用 `window.X || {}` 经典配置模式的第三方库，且在加载时给 X 赋 `escapeHtml` 等函数属性；
- 攻击者可控 HTML 能保留 `id`/`name`（DOMPurify 默认允许 `a`、`p` 等标签和 `id`/`name` 属性）；
- 库内存在可从公开 API 触发的删除节点 gadget，且被删节点包含被 clobber 的 escape 函数元素；
- 页面调用了 `update`/`init` 等入口（本例为 `Beamer.update({language:"FR"})`）；
- 库把某个可控 clobber 属性拼接进 iframe/HTML 属性且未转义，或转义函数本身可被 clobber；
- 没有 CSP 阻止内联事件处理器，或 CSP 可被绕过。

## 利用步骤

1. 阅读库头部，确认 `"undefined" === typeof window.Beamer && (window.Beamer = {})` 以及 `Beamer.escapeHtml = function...`。
2. 用多个 `id="Beamer"` 元素把 `window.Beamer` 变成 HTMLCollection；在控制台验证 `Beamer.escapeHtml` 赋值后仍返回元素。
3. 找库内的节点删除 gadget（如 `removeIframe`）及其触发入口（如 `update → appendAlert`）。
4. 构造 payload：`pushDomain` 用于跳过会调用 escapeHtml 的分支；`customDomain` anchor 的 href 放引号 sandwich；`beamerOverlay` 内放 `name="escapeHtml"` 的节点供删除。
5. 页面加载后约 1 秒调用 `update`，库自动执行删除与 iframe 拼接，`onload` 触发。
6. 在浏览器/bot 中验证 `alert` 或外带请求。

## PoC

```html
<p id="Beamer" name="pushDomain"></p>
<p id="Beamer"></p>
<a id="Beamer" name="customDomain"
   href="http:&#39;/onload=&#39;console.log(document.cookie)&#39;/x=&#39;"></a>
<a id="beamerOverlay"><p id="Beamer" name="escapeHtml"></p></a>
```

拼接后库生成的 iframe 片段等价于：

```html
<iframe id='beamerUtilities' src='http:'/onload='console.log(document.cookie)'/x='utilities?app_id=...' width='0' height='0' frameborder='0' scrolling='no'></iframe>
```

浏览器把 `src='http:'` 后的 `/onload='console.log(document.cookie)'` 解析为 `onload` 属性并执行。

## 变体与关联

- 可 clobber 的库配置名包括任意 `window.<NAME>`；除 HTMLCollection 外，单个 `<a id="X" href="...">`、`<form id="X" action="...">` 也能覆盖对象或布尔开关。
- 删除 gadget 可以是 `removeIframe`、`removeElement`、`forEachElement` 等；只要页面能触发遍历删除，就能清掉 clobber 节点。
- 若 escapeHtml 无法删除，可尝试用 `toString`/`valueOf` 可控的元素让转义函数返回攻击者字符串，或换一个不被调用的分支。
- 关联：[[web-generic-xss-dom-clobbering-window-name-collision]]（命名属性覆盖的基础机制）、[[web-generic-xss-dom-clobbering-window-globals-config-exfil]]（window 配置变量 clobbering + DOMPurify 放行 form）、[[web-generic-xss-apos-entity-attribute-js-breakout]]（实体引号在属性解析阶段还原的同类技巧）。
- 边界：库用 `const`/模块作用域保存配置、`Object.freeze`、DOMPurify 禁止 `id`/`name`、strict mode 下赋值直接抛错、没有可触发的删除 gadget、或 CSP 禁止内联 handler 时失效。

## 检测与防御

- 不要用 `window.X` 判断配置是否存在；使用模块内常量、显式配置对象或 `data-*`，并对读取值做类型校验。
- 对 `window` 关键配置名使用 `Object.defineProperty` 锁定，禁用隐式全局；DOMPurify 配置 `FORBID_ATTR: ['id','name']` 或开启 `SANITIZE_NAMED_PROPS`。
- 第三方库升级到修复版本，并做完整性校验；CSP 设置 `script-src-attr 'none'` 可阻断 onload 注入。
- 检测：DOM 中出现多个同名 `id`/`name` 元素；控制台出现 HTMLCollection 命名属性赋值/`TypeError`；库动态创建带 `onload`/`onerror` 的 iframe；`window.X instanceof HTMLCollection` 等异常类型。
