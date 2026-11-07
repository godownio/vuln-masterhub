---
id: web-generic-ssrf-host-header-routing-ssrf
title: Host 头路由型 SSRF：负载均衡按可控 Host 转发到内网并访问管理面板
type: scenario
domain: web
path: web/generic/ssrf
technique: host-header-routing-ssrf
aliases:
- Host 头 SSRF
- 基于路由的 SSRF
- routing-based SSRF
- 负载均衡 Host 转发
- 绝对 URL 解析差异 SSRF
tags:
- web
- ssrf
- host-header
- load-balancer
- reverse-proxy
- internal-network
- absolute-url
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V19
  verified_at: '2026-11-05T02:27:23+08:00'
  notes: 已对照原文核对；Collaborator确认任意Host出站、192.168.0.0/24扫描命中302 /admin、绝对URL+内网Host解析差异均一致；把flawed request parsing实验室并入本卡合理；未复跑
---

## 一句话结论

当负载均衡器/反向代理按未校验的 `Host` 头选择后端服务器时，攻击者把 `Host` 改成内网 IP 就能让前端把请求转发到任意内部系统，扫描内网后访问内部管理面板；若前端只校验请求行中的绝对 URL，则可用“合法绝对 URL + 内网 Host”组合绕过。

## 原理

- 反向代理/负载均衡通常根据 `Host` 决定把请求转发到哪个虚拟主机或后端节点。若它不校验 Host 是否属于允许的域名，而是直接用它做路由键，`Host: 192.168.0.82` 就会被解析为内网目标地址。
- 这与经典 SSRF 的区别：漏洞点在基础设施的**路由层**，不需要应用提供 URL 参数；攻击者控制的是 Host 头，前端组件把请求发往内部 IP。
- 前端还可能出现解析差异：某些实现只校验请求行中的绝对 URL（`GET https://target.example/ HTTP/1.1`），而真正转发时仍使用 `Host` 头。此时用合法绝对 URL 通过校验、用内网 IP 作 Host，即可绕过 Host 白名单。
- 请求到达内网服务后，响应（管理面板 HTML、CSRF token）会经前端原样返回，攻击者可直接操作内部管理功能。

## 触发条件

- 目标位于 CDN/负载均衡/反向代理之后，代理按 Host 转发且未做目标地址白名单。
- 攻击者能修改 Host（或请求行绝对 URL + Host 组合）。
- 内网存在可访问的管理面板/服务，且代理到内网的网络路径可达。
- `Host` 中允许 IP 字面量（或可通过 DNS 解析到内网）。

## 利用步骤

1. 用 Burp Collaborator 作为 Host 值发送请求；若 Collaborator 收到 DNS/HTTP 交互，说明前端会向任意 Host 发起请求。
2. 把 Host 改为 `192.168.0.§0§` 等内网地址，用 Intruder 遍历 0–255，观察状态码/响应长度差异。
3. 找到返回 `302 Location: /admin` 等特征的内网 IP，访问其管理面板。
4. 若 Host 被白名单拦截，尝试在请求行写合法绝对 URL、Host 写内网 IP（解析差异绕过）。
5. 从管理面板提取 CSRF token，构造删除/修改请求并验证影响。

## PoC

Host 路由扫描：

```http
GET / HTTP/1.1
Host: 192.168.0.§0§
```

Intruder Numbers 0–255；某 IP 返回：

```http
HTTP/1.1 302 Found
Location: /admin
```

访问该内网管理面板：

```http
GET /admin HTTP/1.1
Host: 192.168.0.82
```

绝对 URL 解析差异变体：

```http
GET https://target.example/ HTTP/1.1
Host: 192.168.0.82
```

前端校验的是请求行里的合法绝对 URL，后端仍按 `Host` 路由；把绝对 URL 的路径改为 `/admin` 即可访问内网管理面板。原文用 Collaborator 确认了任意 Host 会触发外部请求（DNS + HTTP 交互）。

## 变体与关联

- 变体：Host 用十进制/八进制 IP、IPv6、内部 DNS 名；通过 `X-Forwarded-Host` 等覆盖头影响路由。
- 变体：请求行绝对 URL 与 Host 不一致、重复 Host、缩进 Host 等解析差异（见 Host 校验绕过卡片）。
- 关联：[[web-generic-auth-host-header-localhost-auth-bypass]]（应用自身信任 Host，而非代理路由）、[[web-generic-cache-poisoning-host-header-ambiguous-request]]、[[web-generic-http-smuggling-host-connection-state-bypass]]。
- 关联：[[web-generic-ssrf-url-parser-differential-allowlist-bypass]]（URL 解析差异绕过白名单的同类思路）。

## 检测与防御

- 边缘代理对 Host 做严格 allowlist（域名 + 端口），拒绝 IP 字面量与未知域名；路由目标由固定配置映射，不用 Host 直接拼接。
- 禁止代理访问内网/回环/元数据地址，实施出站 ACL；管理面板不要与公网入口共用代理。
- 统一请求解析：前端与后端对绝对 URL、Host、重复头的优先级必须一致，避免解析差异。
- 监控 Host 为内网 IP、Collaborator 域名、非常规端口的请求，以及代理向 RFC1918 地址发起的连接。
