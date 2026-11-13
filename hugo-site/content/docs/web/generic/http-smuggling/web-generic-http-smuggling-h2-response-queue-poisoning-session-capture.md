---
id: web-generic-http-smuggling-h2-response-queue-poisoning-session-capture
title: 响应队列中毒（H2.TE）：走私完整请求让后端多发一个响应，劫持后续用户的响应并捕获管理员会话
type: scenario
domain: web
path: web/generic/http-smuggling
technique: response-queue-poisoning-h2-te
tags:
- http2
- request-smuggling
- response-queue-poisoning
- h2-te
- session
- desync
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V609
  verified_at: '2026-11-12T19:38:46+08:00'
  notes: 已对照原文12691「队列中毒」节及截图16-25核对：响应-请求错配原理图、队列中毒后重发请求循环窃取他人响应图、H2.TE走私完整GET /x(两请求均为404便于区分)、捕获管理员302+Set-Cookie、会话访问/admin、删除carlos、Solved；利用要求(连接跨请求复用、走私完整独立请求、双方不因异常断连)与原文一致，原文每10个请求重置连接的细节也已写入步骤5。dedup：除自身外最高相关为pause-based desync、客户端去同步CSD、Host连接状态等，均不同链；本卡描述的是响应队列中毒利用阶段与Session捕获危害，走私向量明确写为H2.TE并列出其他向量变体，与H2.TE原语卡不重复，原子。原文未给产品版本，保持省略；未在本机复现。
url: /docs/web/generic/http-smuggling/web-generic-http-smuggling-h2-response-queue-poisoning-session-capture/
draft: false
kb_aliases:
- Response Queue Poisoning
- 响应队列中毒
- HTTP/2 响应队列投毒
- 捕获管理员会话
- H2.TE session capture
---

## 一句话结论

在 H2.TE 请求走私成立的前提下，向前端和后端之间的连接走私一个**完整**请求：前端以为只转发了一个请求，后端却返回两个响应；多出的响应留在前端/后端连接队列中，被前端错误地映射给下一个经同一连接进来的用户。攻击者随后连续发正常请求即可持续读到他人响应，典型战果是捕获管理员登录后的 302 + `Set-Cookie` 会话令牌，再以管理员身份进入后台。

## 原理

- 前端与后端之间的 TCP 连接通常被多个客户端请求复用（连接池）。前端按"一个请求对应一个响应"的顺序从连接上读取响应并回传给对应客户端。
- 走私一个完整请求后，后端实际处理了两个请求并产生两个响应：第一个响应被前端正确映射给攻击者的"包装器"请求；第二个响应没有等待它的前端请求，就滞留在连接队列里。
- 当另一个用户（如管理员）的请求经同一连接转发到后端时，后端返回的是该用户请求的响应，但前端从连接上读到的第一个响应是队列里滞留的旧响应，于是把它发给该用户；该用户的真实响应又滞留，循环持续。攻击者此时再发任意请求，就会拿到队列中的下一个响应——很可能是管理员登录后的 302 和会话 Cookie。
- 响应队列中毒不要求攻击者控制受害者的请求，只要求：前后端 TCP 连接跨请求/响应周期复用；攻击者能走私一个完整、独立的请求并得到自己的响应；攻击不会让任一端关闭连接。前端允许的"每 N 个请求重置连接"只会周期性打断，重新建连后可继续。
- 为什么成立：HTTP/1.1 连接是"按序请求-响应"的隐式队列，走私打破了请求与响应的 1:1 对应，前端没有额外的响应-请求绑定机制时就会错配。

## 触发条件

- 存在可用的请求走私向量（原文用 H2.TE：HTTP/2 里带 `transfer-encoding: chunked` 的请求经前端降级后在后端提前结束 body）。
- 前端与后端连接复用，且不同用户的请求可能共享同一后端连接。
- 走私的请求是完整请求（含请求行、Host、结束标志），后端会为它生成独立响应。
- 攻击过程中前端/后端不因异常立即断开连接；若每 N 个请求重置，可在重建连接后重试。
- 前端把后端响应按到达顺序映射给请求，没有响应-请求关联校验。

## 利用步骤

1. 先确认走私前缀生效：发送 `POST / HTTP/2` + `Transfer-Encoding: chunked`，body 为 `0` 空行 `SMUGGLED`；随后正常请求应返回 404，说明后续请求被拼到前缀上。
2. 走私完整请求并毒化队列：body 改为 `0` 空行加 `GET /x HTTP/1.1` + `Host: TARGET`。两个请求都指向不存在的路径，方便把 404 与"捕获到的他人响应"区分开。
3. 立即发送普通请求轮询队列；一旦看到非 404 响应（如 `HTTP/2 302 Found`、`Location: /my-account?id=administrator`、`Set-Cookie: session=...`），即捕获到他人响应。
4. 用捕获的会话 Cookie 访问 `/my-account` 或 `/admin` 验证权限；原文直接用该 Cookie 调用 `/admin/delete?username=carlos` 完成靶场。
5. 若一次没捕获到目标，用 Burp Intruder 反复"走私 + 发请求"；连接每 N 个请求重置时，先发几个正常请求建立新连接再继续。
6. 保持利用直到拿到所需响应；注意该技术会持续影响同一连接上的其他用户，属于高风险操作，仅在授权环境使用。

## PoC

```http
POST / HTTP/2
Host: TARGET
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: TARGET
```

```http
GET / HTTP/2
Host: TARGET
```

```http
# 捕获到的管理员响应示例
HTTP/2 302 Found
Location: /my-account?id=administrator
Set-Cookie: session=<admin-session>; Secure; HttpOnly; SameSite=None
```

说明：PoC 为原文响应队列中毒靶场流程的结构化复现，域名与会话值已泛化；实际连接重置阈值（原文每 10 个请求）因环境而异。未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：走私向量可换成 H2.CL、HTTP/1 的 CL.TE/TE.CL、CL.0、pause-based desync 等，只要能让后端多发一个响应。
- 变体：捕获的响应可能是 API 数据、个人信息、CSRF token、会话 Cookie；也可结合缓存投毒把他人响应写入缓存。
- 关联：[[web-generic-http-smuggling-h2-te-downgrade-chunked]]（原文使用的走私向量）、[[web-generic-http-smuggling-h2-cl-downgrade-injected-content-length]]（另一向量）、[[web-generic-http-smuggling-client-side-desync-cookie-leak]]（客户端侧去同步的对应场景）。
- 边界：前端不复用后端连接、前端严格校验请求-响应配对、任一端在走私后关闭连接、或后端不生成第二个响应时，本链不成立。

## 检测与防御

- 检测：前端日志中出现"一个请求对应多个响应"或响应与请求 URL/方法不匹配；用户收到他人页面/302/Set-Cookie；同一后端连接出现异常 404 与来源不明的响应；请求体中出现 `Transfer-Encoding`/异常 chunked 终止符。
- 防御：修复走私根因（严格校验长度、剥离 TE、拒绝 CRLF 注入）；前端/后端连接按客户端隔离或每次请求新建连接；在响应中绑定请求 ID 并校验；限制单连接请求数并及时轮换。
- 加固：端到端 HTTP/2；反代/CDN 升级到修复 H2 降级问题的版本；监控响应错配与会话异常。
