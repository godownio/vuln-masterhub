---
id: web-generic-xss-hash-route-param-jquery-html-sink
title: 前端 hash 路由参数直入 jQuery .html() 导致 DOM XSS
type: scenario
domain: web
path: web/generic/xss
technique: hash-route-param-html-sink-dom-xss
aliases:
- DOM XSS
- hash 路由 XSS
- Backbone 路由参数注入
- showTestParam
- jQuery html sink
- 测试路由残留
tags:
- xss
- dom-xss
- javascript
- jquery
- hash-route
- backbone
- sink
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T03:09:21+08:00'
  notes: 已对照原文2.2.1节与图46-57核对：GoatRouter.js test/:param→testRoute→testHandler→LessonContentView.showTestParam，param 直接拼入 .html('test:'+param)；#test/123456 回显，编码后的 script 弹窗成功，模块11 用同一 sink 触发 webgoat.customjs.phoneHome()。原文未给组件版本（WebGoat 8.2.2 靶场），未设置 affected_versions。未复现。
---

## 一句话结论

单页应用把 URL hash 中的路由参数直接拼进 jQuery `.html()`（或 `innerHTML`）时，参数会在浏览器端被当作 HTML 解析，`<script>`、`<img onerror>` 等载荷无需经过服务端即可执行；由于 hash 片段不会发送给服务器，服务端过滤、WAF 与访问日志都看不到它。

## 原理

- hash 路由（如 `start.mvc#test/<param>`）由前端 JavaScript 解析，`#` 之后的内容不会进入 HTTP 请求行；服务端无法对它做输入校验，只能靠前端。
- 路由处理器把参数层层传递到视图方法，最终执行 `this.$el.find('.lesson-content').html('test:' + param)`。jQuery `.html()` 接受字符串时会按 HTML 解析并插入 DOM，`<script>` 会执行，`<img src=x onerror=...>`、`<svg onload=...>` 等事件属性也会执行。
- 这不是“反射型 XSS”：服务端响应里没有恶意代码，恶意代码只存在于浏览器根据 URL 自行构建的 DOM 中，因此基于响应体的扫描器看不到。
- 常见成因是开发/测试代码残留：`testRoute`、`showTestParam` 这类方法只用于联调，却随生产包发布，且没有对参数做 `textContent`/转义处理。
- 攻击者只需诱导受害者打开构造好的链接触发；也可用短链、二维码、站内消息等方式投递。

## 触发条件

- 前端使用 hash 路由或 history 路由，路由参数可被用户控制。
- 参数最终进入 `.html()`、`.append()`、`innerHTML`、`document.write()`、`insertAdjacentHTML()` 等 HTML 解析型 sink。
- sink 前没有白名单净化或 HTML 转义（仅做 URL 解码不算）。
- 页面没有严格 CSP（`script-src 'self'` 且无 `unsafe-inline` 可显著降低危害）。

## 利用步骤

1. 阅读前端路由配置，找出接收参数的 route，如 `test/:param`、`lesson/:name/:pageNum`。
2. 跟踪参数流向：route handler → controller → view，定位最终 sink（`.html()`、`innerHTML`）。
3. 先提交普通字符串确认参数被回显，如 `#test/123456` 页面显示 `test:123456`。
4. 构造 HTML 载荷并做 URL 编码，访问带 payload 的 hash URL。
5. 观察是否弹窗/执行；若 `<script>` 被某些浏览器或框架过滤，改用事件属性标签。

## PoC

```text
http://target/start.mvc#test/%3c%73%63%72%69%70%74%3e%70%72%6f%6d%70%74%28%31%29%3c%2f%73%63%72%69%70%74%3e
```

解码后等价于：

```html
<script>prompt(1)</script>
```

```text
# 预期：页面 .lesson-content 区域渲染 "test:" + 载荷，浏览器执行 prompt(1)。
# 若 <script> 不执行，可换：
#   <img src=x onerror=alert(document.domain)>
#   <svg onload=alert(1)>
```

## 变体与关联

- 变体：history 路由（`/test/<param>`）同样可注入，但参数会进入服务端访问日志，可能被服务端过滤。
- 变体：参数先经过 `decodeURIComponent` 再进入 sink，可用双重编码绕过简单的关键字检查。
- 变体：jQuery 选择器/`$()` 拼接还可能触发 DOM clobbering 或选择器注入，进一步劫持页面逻辑。
- 关联：[[web-generic-xss-data-iframe-postmessage-innerhtml]]（postMessage 数据进入 innerHTML 的另一条 DOM XSS 路径）。
- 关联：[[web-generic-xss-dom-clobbering-window-name-collision]]（DOM clobbering 与前端逻辑劫持）。
- 边界：若 sink 使用 `.text()`/`textContent`、或参数经过 DOMPurify 等基于白名单的净化，XSS 不成立；CSP 可阻止内联脚本执行但不阻止数据外带。

## 检测与防御

- 修复：删除生产包中的测试路由与调试方法；路由参数一律按文本处理（`.text()`、`textContent`）。
- 修复：必须渲染 HTML 时使用白名单净化（DOMPurify、OWASP Java HTML Sanitizer 等），禁止把原始参数直接交给 `.html()`。
- 加固：部署严格 CSP（`script-src 'self'`、禁止 `unsafe-inline`/`unsafe-eval`），并对 `innerHTML` 等 sink 做 ESLint/SAST 规则拦截。
- 检测：前端代码中出现 `location.hash`/路由参数流向 `.html()`/`innerHTML`；访问 URL 的 hash 中含 `<script`、`onerror`、`onload`、`javascript:` 等编码片段；浏览器端 CSP 报告。
- 注意：hash 不进入服务端日志，服务端 WAF 无法检测，需依赖前端监控与 CSP 报告。
