---
id: web-generic-xss-dompurify-textcontent-innerhtml-reparse
title: DOMPurify 净化后 textContent 再写 innerHTML：用 i 标签拆分重组出可执行标签
type: scenario
domain: web
path: web/generic/xss
technique: dompurify-textcontent-innerhtml-reparse
aliases:
- textContent innerHTML 二次解析
- DOMPurify textContent trick
- 标签拆分绕过 DOMPurify
- textContent 重解析 XSS
- 净化结果二次 innerHTML
tags:
- web
- xss
- dom-xss
- dompurify
- sanitizer-bypass
- mxss
- textcontent
- innerhtml
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V215
  verified_at: '2026-11-07T05:04:39+08:00'
  notes: 已对照原文与 img/03-07 核对 DOMPurify.sanitize 后写入 msg_url.innerHTML、somethingWentWrong 读取 textContent 再拼 error.innerHTML，payload http://<<i>img src onerror=alert(origin)</i>> 与 8 秒定时器/慢响应挂起条件。未验证点：未复跑；原文未给 DOMPurify 版本。
---

## 一句话结论

当页面先用 DOMPurify 把用户输入净化并通过 `innerHTML` 写入，后续又把该节点的 `textContent` 拼进另一个 `innerHTML` 时，净化后的文本会被第二次当作标记解析；用 DOMPurify 允许的 `<i>` 把 `<img ...>` 拆成文本片段，就能让它净化时不成标签、再解析时重组为真实标签并执行 `onerror`。

## 原理

- DOMPurify 第一次解析时按标签识别危险节点，`<i>` 是默认允许的普通标签。
- 输入 `http://<<i>img src onerror=alert(origin)</i>>` 被解析成：文本 `http://<`、元素 `<i>`（其文本为 `img src onerror=alert(origin)`）、文本 `>`。`<img` 被文本和 `<i>` 打断，第一次解析时不构成标签，`onerror` 不会被识别为事件属性。
- `innerHTML` 序列化会把文本节点里的 `<`、`>` 转回 `&lt;`、`&gt;`，所以把净化结果写回 `msg_url.innerHTML` 时仍不会执行。
- 后续代码读取 `msg_url.textContent`：`textContent` 返回所有后代文本的拼接，并把 `&lt;`、`&gt;` 解码回 `<`、`>`，于是得到 `http://<img src onerror=alert(origin)>`。
- 这段字符串再被拼进另一个 `innerHTML`（如错误提示 `error.innerHTML = ... ${url}`），浏览器第二次解析时 `<img>` 成为真实元素，`onerror` 执行。
- 根因是 sanitizer 的解析结果与最终 sink 的第二次解析结果不一致（mXSS），并且 `textContent` 会跨元素拼接、丢失标签边界；不需要浏览器解析器 bug，只需要“净化 → textContent → innerHTML”这种往返。
- `textContent` 与 `innerText` 不同：`textContent` 包含 `<script>`、`<style>` 等所有文本，且不做布局相关处理；把它当纯文本拼进 `innerHTML` 就等于把已净化的内容重新变成未净化 HTML。

## 触发条件

- 存在 HTML 注入点，输入经过 DOMPurify 净化后写入 `innerHTML`；
- 同一段内容之后还会被 `textContent` 读取并写入另一个 `innerHTML`（错误提示、预览、模板字符串等）；
- DOMPurify 配置允许用于拆分的标签（`i`、`b`、`span`、`u` 等）；
- 页面没有 CSP 阻止内联事件处理器，或 CSP 可被绕过；
- 若 XSS 位于延迟回调中而页面会因表单提交/跳转离开，需要让目标 URL 长时间不返回（慢响应、挂起连接或耗尽连接池），使旧文档保持活动到定时器触发。

## 利用步骤

1. 找到“净化后 `innerHTML` 写入”的落点，以及后续把该节点 `textContent` 拼进 `innerHTML` 的二次 sink。
2. 用允许的标签把目标标签拆开，例如 `http://<<i>img src onerror=alert(origin)</i>>`。
3. 在浏览器中确认第一次写入后 `<img>` 不是真实节点，第二次写入后成为节点并执行。
4. 在带 bot 的题目中，若二次 sink 在 `setTimeout` 后执行，而页面会先自动提交表单导航走，则提交一个 8 秒以上不返回的 URL（攻击者服务器 sleep，或建立大量挂起连接占满连接池）让导航保持 pending，旧文档中的定时器才有机会执行。
5. 在 bot 会话中把 `alert` 换成同源 `fetch` 或外带请求。

## PoC

```html
<!-- 放在 checker 页的 url 参数中（URL 编码后） -->
http://<<i>img src onerror=alert(origin)</i>>
```

```javascript
// 最小复现：净化后第一次 innerHTML 不执行，textContent 再拼入 innerHTML 才执行
const dirty = 'http://<<i>img src onerror=alert(origin)</i>>';
const clean = DOMPurify.sanitize(dirty);
document.getElementById('msg').innerHTML = clean;       // <img> 不是真实标签
setTimeout(() => {
  document.getElementById('err').innerHTML =
    'oops ' + document.getElementById('msg').textContent; // 重组后执行
}, 0);
```

## 变体与关联

- 拆分标签可换 `<b>`、`<span>`、`<u>`、`<s>` 等；也可结合属性和注释拆分，只要第一次解析时 `<img`/`<svg` 等未形成完整标签。
- 二次 sink 可以是 `innerHTML`、`insertAdjacentHTML`、模板字符串拼回、`document.write`；甚至服务端回显后再次走前端渲染。
- 关联：[[web-generic-xss-dompurify-mxss-caption-flattening]]（同为净化后二次解析，但依赖 512 层扁平化与命名空间突变）、[[web-generic-xss-dompurify-parentnode-clobbering-depth-bypass]]（用 DOM clobbering 干扰 sanitizer 深度计数）、[[web-generic-xss-html-entity-decode-innerhtml-support]]（实体解码后 innerHTML 的另一条路径）。
- 边界：二次 sink 使用 `textContent`、只做一次 `innerHTML`、DOMPurify 禁止 `i`/`b`/`span` 等拆分标签、或 CSP 禁止内联 handler 时失效。

## 检测与防御

- 禁止“净化结果 → `textContent` → `innerHTML`”的往返；已净化的 DOM 节点直接插入，纯文本渲染使用 `textContent`。
- 升级 DOMPurify 并收紧 `ALLOWED_TAGS`/`ALLOWED_ATTR`；需要富文本时用白名单重建，而不是把序列化文本重新解析。
- 使用 Trusted Types 与 CSP（禁止 `unsafe-inline`）降低执行面；对 `innerHTML` sink 做代码审计和告警。
- 检测：DOM 中出现 `textContent` 后接 `innerHTML` 的代码模式；请求参数包含 `<<`、`<i>img`、`onerror` 等拆分特征；bot 访问后出现异常同源 POST/外连。
