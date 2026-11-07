---
id: web-generic-xss-data-iframe-postmessage-innerhtml
title: 'data: iframe 配合无源校验的 postMessage 接收端导致父页面 DOM XSS'
type: scenario
domain: web
path: web/generic/xss
technique: postmessage-sink-dom-xss
tags:
- xss
- dom-xss
- postmessage
- iframe
- data-uri
- sop-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V13
  verified_at: '2026-11-05T01:49:27+08:00'
  notes: '已对照原文核对：只过滤 javascript: 而允许 data:、htmlspecialchars 不阻止 data URL、无源校验 message handler 写 innerHTML 均与原文一致；未实际执行'
url: /docs/web/generic/xss/web-generic-xss-data-iframe-postmessage-innerhtml/
draft: false
kb_aliases:
- postMessage XSS
- data 协议 iframe XSS
- 消息接收端 innerHTML
- 跨源消息注入
---

## 一句话结论

当服务端只过滤 `javascript:` 却允许 iframe 加载 `data:`，且父页面的 `message` 事件处理器不做来源校验就把 `e.data` 写入 `innerHTML` 时，攻击者可让 `data:` iframe 内的脚本通过 `parent.postMessage()` 把 HTML payload 注入父页面，从而在同源父页面执行 XSS。

## 原理

- `data:text/html,...` iframe 的文档源是**不透明/null origin**，与父页面不同源，因此 iframe 内的 JS 不能直接读取或修改父页面 DOM——同源策略确实生效。
- 但 `window.postMessage()` 是跨源通信的合法通道：子框架可以调用 `parent.postMessage(data, targetOrigin)` 向父窗口发送任意数据，父窗口通过监听 `message` 事件接收。
- 父页面的处理器 `document.getElementById('message-output').innerHTML = "Received: " + e.data;` 把消息内容当 HTML 解析，且没有检查 `e.origin`/`e.source`。于是跨源发来的字符串成了 HTML/DOM sink 的输入，`<img src=x onerror=alert(1)>` 在父页面上下文中执行。
- 服务端的防护是 `str_ireplace("javascript", "", ...)`，只针对 `javascript:` 伪协议；`data:` 未被拦截，且 `htmlspecialchars` 只保证属性不被闭合，不阻止 data URL 本身。危险点从“iframe 的 URL 协议”转移到了“postMessage 消费端”。

## 触发条件

- 页面把用户输入放进 `<iframe src>`，只做了 HTML 转义或只过滤 `javascript:`，允许 `data:`/`blob:` 等协议；
- 父页面注册了 `message` 监听器，并把 `e.data` 写入 `innerHTML`/`outerHTML`/`document.write`/`eval` 等 sink；
- 监听器未校验 `e.origin` 或校验可绕过；
- iframe 允许脚本执行（CSP 未拦截 `frame-src data:` 或子文档脚本）。

## 利用步骤

1. 确认输入能进入 iframe 的 `src`，且 `data:` 未被过滤。
2. 确认父页面存在 `message` 监听器，并定位其 sink（本例为 `innerHTML`）。
3. 构造 `data:text/html` 文档，内含 `parent.postMessage('<img src=x onerror=alert(1)>','*')`。
4. 提交/访问该 URL，iframe 加载后脚本执行并向父页面发消息，父页面 innerHTML 解析 payload 触发事件。
5. 若 `onerror` 被 CSP 拦截，改用可自动触发的事件或其他不依赖内联脚本的 DOM 注入效果（如覆盖登录表单）。

## PoC

```html
<!-- 服务端输出：<iframe src="DATA_URL" width="100%" height="100"></iframe> -->
<!-- 父页面监听器 -->
<script>
window.addEventListener('message', function(e) {
  document.getElementById('message-output').innerHTML = "Received: " + e.data;
});
</script>

<!-- DATA_URL 内容 -->
data:text/html,<script>parent.postMessage('<img src=x onerror=alert(1)>', '*')</script>
```

```text
# 完整注入值
data:text/html,<script>parent.postMessage('<img src=x onerror=alert(1)>', '*')</script>
```

## 变体与关联

- 变体：`blob:` URL、`srcdoc` 属性、同源但受控的子页面同样可作为 message 发送方。
- 变体：接收端 sink 换成 `eval(e.data)`、`location=e.data`（开放重定向/`javascript:`）、`insertAdjacentHTML`。
- 变体：若监听器只校验 `e.origin === 'null'`，data: iframe 恰好满足，校验形同虚设。
- 关联：[[web-generic-xss-scriptless-execution-vectors]]（`data:`/伪协议等无 script 标签载体）；[[web-generic-xss-javascript-context-injection]]（消息内容进入 JS 上下文的变体）。

## 检测与防御

- 检测：审计所有 `addEventListener('message'` 处理器，检查是否校验 `e.origin` 与 `e.source`，以及 `e.data` 是否进入 HTML/JS sink。
- 检测：iframe `src` 中出现 `data:text/html`、`blob:`、`srcdoc` 与用户输入拼接。
- 防御：`message` 处理器必须校验 `e.origin` 为可信源白名单，并校验 `e.source`；数据只通过 `textContent`/属性赋值使用，禁止 `innerHTML`。
- 防御：iframe 的 `src` 使用协议/域名白名单（仅 `https:` 与固定域名），过滤 `data:`/`blob:`/`javascript:`；必要时加 `sandbox` 属性。
- 防御：CSP `frame-src` 限制可嵌入源，`script-src` 使用 nonce/hash。
