---
id: web-generic-cache-poisoning-smuggling-private-response-deception
title: 请求走私缓存欺骗：走私 GET /my-account 让后端以受害会话渲染私有页，前端却按受害者请求的静态 URL 缓存，攻击者再从缓存取 API Key
type: scenario
domain: web
path: web/generic/cache-poisoning
technique: request-smuggling-cache-deception
tags:
- http-smuggling
- cache-deception
- cache-poisoning
- session-data
- api-key
- cl-te
- http1
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V614
  verified_at: '2026-11-12T20:50:55+08:00'
  notes: '已对照原文『缓存欺骗』节正文核对（该节 7 张截图为 xzfile.aliyuncs.com 外链，下载 403 无法读图）：外层 CL 42 + 0 块后 GET /my-account HTTP/1.1 + X-Ignore: X；后端在受害者会话渲染私有页，前端按受害者请求的静态 URL 缓存，Burp 搜索 Your API Key 后提交。参数与原文一致。未验证点：缺该节截图，仅正文核对；未本机复跑；无 sources；无版本/CVE。dedup：url-normalization-mismatch 是不依赖走私的 CDN 归一化缓存欺骗，机制不同；与 cache-poisoning-smuggling-redirect 同原语不同目标，保留。'
url: /docs/web/generic/cache-poisoning/web-generic-cache-poisoning-smuggling-private-response-deception/
draft: false
kb_aliases:
- 走私缓存欺骗
- smuggling cache deception
- 私有响应缓存劫持
- API Key 缓存窃取
- my-account 缓存
---

## 一句话结论

利用请求走私让后端在受害者会话上下文中处理 `GET /my-account` 并返回其 API Key，前端却按受害者实际请求的静态资源 URL 缓存该响应；攻击者随后遍历静态 URL 从缓存中取走受害者的私有数据。

## 原理

- 缓存欺骗的核心是"私有响应被写进公共缓存条目"；普通缓存欺骗依赖 URL 归一化让 CDN 把私有接口当成静态资源，本变体则用请求走私直接控制后端处理哪个请求。
- 攻击者走私 `GET /my-account HTTP/1.1\r\nX-Ignore: X` 到后端连接；下一个受害者请求（如 `/resources/js/...`）被拼接到走私请求之后，后端把它当作同连接上的下一个请求。
- 后端处理走私的 `GET /my-account`，此时连接上带着受害者的 Cookie（受害者请求头的一部分），于是返回包含 API Key 的私有页面。
- 前端缓存按它看到的 URL（受害者请求的静态资源路径）存储这个响应；由于缓存键是静态 URL，攻击者无需登录即可请求同一 URL 命中缓存。
- 与缓存投毒的区别：投毒是把恶意内容推给其他用户；欺骗是把其他用户的敏感内容拉进缓存供自己读取。攻击者不知道敏感内容落在哪个 URL，需遍历或从日志/页面引用中枚举静态资源。

## 触发条件

- 存在请求走私原语（如 CL.TE），前后端复用连接。
- 前端缓存静态资源且缓存键取 URL，不区分响应是否含会话数据。
- 应用存在返回会话私有数据的 GET 端点（账户页、API Key、订单等），且不返回 `Cache-Control: private/no-store`。
- 受害者会持续访问站点，其请求会落在被走私请求之后的同一连接上。
- 攻击者可以枚举/猜测静态资源 URL 以查找被缓存的私有内容。

## 利用步骤

1. 登录自己的账户，观察 `/my-account` 等私有页面是否返回 API Key 等可识别字段，并确认响应没有禁止缓存头。
2. 记录站点静态资源 URL 列表（JS/CSS/图片），这些是潜在的缓存键。
3. 构造走私请求：外层 `POST /` 带 `Transfer-Encoding: chunked` 与覆盖 `0` 块前缀的 `Content-Length`，正文 `0` 块后写 `GET /my-account HTTP/1.1` + `X-Ignore: X`。
4. 重复发送几次，强制受害者请求与走私请求相遇；随后用匿名浏览器访问站点主页/静态资源，使受害者请求落点被缓存。
5. 用 Burp 搜索功能或脚本遍历静态 URL，查找 `Your API Key` 等私有字段；若未出现，重复步骤 3-4 并重新加载。
6. 找到缓存条目后读取受害者的 API Key/会话数据，完成数据窃取；在实验环境提交该 Key 作为解。

## PoC

```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Transfer-Encoding: chunked

0

GET /my-account HTTP/1.1
X-Ignore: X
```

说明：走私的 `GET /my-account` 在后端以受害者会话上下文执行；前端把它后续请求的静态 URL 作为缓存键存储响应。攻击者遍历静态 URL 查找 `Your API Key`。PoC 为靶场流程的结构化复现，未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：私有端点可换成订单、消息、预签 URL、CSRF Token；静态 URL 可换成任意可缓存路径。
- 变体：若缓存键包含查询串，可利用 `?cb=` 等参数控制缓存条目；若前端不缓存 200，可尝试让响应变为 301/304 等可缓存状态。
- 关联：[[web-generic-cache-poisoning-smuggling-redirect-static-asset]]（同一走私原语的投毒方向）、[[web-generic-cache-poisoning-web-cache-deception-url-normalization-mismatch]]（不依赖走私的 URL 归一化缓存欺骗）、[[web-generic-http-smuggling-capture-victim-requests-oversized-cl]]（另一种窃取受害者会话数据的方式）。
- 边界：私有响应带 `Cache-Control: private/no-store`、缓存键包含 Cookie/会话、前后端不复用连接时，本链不成立。

## 检测与防御

- 检测：缓存中静态 URL 的响应包含 HTML/JSON 私有字段；匿名请求命中缓存返回登录后内容；同一 URL 先出现带 Cookie 的请求、后出现匿名命中；响应体大小与静态资源不符。
- 防御：所有私有/会话响应返回 `Cache-Control: private, no-store`；缓存层只缓存白名单静态目录或带内容哈希的资源；缓存键纳入会话或拒绝缓存含 Set-Cookie 的响应。
- 加固：拒绝 CL+TE 并存；前端重新序列化请求；禁用后端连接复用；部署缓存欺骗检测（匿名命中私有字段告警）。
