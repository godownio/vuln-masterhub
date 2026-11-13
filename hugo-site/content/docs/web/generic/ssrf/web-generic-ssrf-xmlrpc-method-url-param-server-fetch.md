---
id: web-generic-ssrf-xmlrpc-method-url-param-server-fetch
title: XML-RPC 业务方法 URL 参数 SSRF：dvws.CheckUptime(url) 由服务端请求任意地址并回传结果
type: scenario
domain: web
path: web/generic/ssrf
technique: xmlrpc-method-url-param-ssrf
tags:
- ssrf
- xml-rpc
- rpc
- url-fetch
- portscan
- api
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V567
  verified_at: '2026-11-12T09:11:51+08:00'
  notes: 已对照原文与23张截图核对：POST /xmlrpc 到 9090 端口发送 dvws.CheckUptime(http://127.0.0.1/uptime)，methodResponse 返回服务端抓取到的响应对象字段(Fig.12)，证明服务端发起请求；PoC 报文/Content-Type/Content-Length(174)与原文一致；原文未给出端口扫描完整脚本，卡内已如实注明；无 CVE/版本区间，affected_versions 保持为空。dedup：仅与 XXE 派生 SSRF 卡 related(0.893)，机制不同(本卡为业务方法主动 URL 抓取而非实体注入)，其余 SSRF 卡入口不同，无同链重复。同时核对 worker 的 merge/排除：SOAP in-band XXE、XML XHTML 命名空间 script XSS、注册用户名后台 XSS、用户名枚举四份草稿的 merge 目标卡(web-generic-xxe-inband-file-read-default-insecure、web-generic-xxe-soap-parameter-nested-xml-saxbuilder-oob、web-generic-file-upload-xml-xhtml-namespace-script-xss、web-generic-xss-admin-blind-stored-registration、web-generic-auth-error-message-username-enumeration)均存在且为同场景变体，merge 成立；XML DoS 按 brief 排除正确；WSDL/ReadyAPI 工具流程不建卡合理。未验证点：未实机复现
url: /docs/web/generic/ssrf/web-generic-ssrf-xmlrpc-method-url-param-server-fetch/
draft: false
kb_aliases:
- XML-RPC SSRF
- xmlrpc 方法参数 SSRF
- dvws.CheckUptime
- /xmlrpc 端口扫描
- methodCall url 参数
---

## 一句话结论

XML-RPC 服务的业务方法把调用参数里的 URL 字符串直接交给服务端发起 HTTP 请求并把结果序列化返回（DVWS 的 `dvws.CheckUptime(url)` 即请求 `url` 并返回响应对象），攻击者可在 `<methodCall>` 中传入内网/回环地址实现 SSRF、端口探测与内网服务访问。

## 原理

- XML-RPC 请求体是固定的 `<methodCall><methodName>...<params><param><value>...` 结构；服务端按 methodName 反射调用方法，并反序列化参数。
- 若某方法语义是"检查目标 URL 是否存活/抓取内容"，其参数值会被服务端 HTTP 客户端（Ruby `Net::HTTP`、Java HttpClient、Python requests 等）直接请求，且未限制协议、主机与内网地址。
- 响应把请求结果（状态码/响应对象字段）序列化回 `<methodResponse>`，可以据此判断目标端口是否开放、服务是否响应；无回显时也可用时间差/错误差异做盲探测。
- XML-RPC 端点常见路径为 `/xmlrpc`、`/RPC2`、`/xmlrpc.php`，可从错误页注释、robots、扫描或方法名爆破发现（DVWS 中 `:9090/xmlrpc`，提示出现在 error.html 注释）。

## 触发条件

- 目标暴露 XML-RPC 服务且存在接受 URL/主机参数的公开方法。
- 服务端方法未对 URL 做协议与内网地址校验（或可用重定向/解析差异绕过）。
- 攻击者可访问 XML-RPC 端口（原文 9090）且方法无需鉴权。

## 利用步骤

1. 发现 XML-RPC 端点：尝试 `/xmlrpc`、`/RPC2`，发送 `system.listMethods` 或观察错误/方法爆破。
2. 枚举方法，寻找 `CheckUptime`、`fetch`、`ping` 等接收 URL 的方法。
3. 构造 `methodCall`，参数填 `http://127.0.0.1:<port>/` 或内网地址，观察响应差异判断开放端口/服务。
4. 进一步访问内网 HTTP 应用、云元数据地址，或结合重定向/Gopher 扩大利用（取决于客户端实现）。

## PoC

```http
POST /xmlrpc HTTP/1.1
Host: target:9090
Content-Type: application/x-www-form-urlencoded
Content-Length: 174

<?xml version="1.0"?>
<methodCall>
  <methodName>dvws.CheckUptime</methodName>
  <params>
    <param><value><string>http://127.0.0.1/uptime</string></value></param>
  </params>
</methodCall>
```

原文在 DVWS 上发送后，响应为 XML-RPC `<methodResponse>`，包含服务端请求 `http://127.0.0.1/uptime` 得到的对象字段（状态、headers、body 大小等），证明请求由服务端发起。原文未展示端口扫描的完整脚本。

## 变体与关联

- 方法名不一定是 CheckUptime：任何接收 URL/域名/主机端口的业务方法都可能形成 SSRF（健康检查、Webhook 测试、代理抓取）。
- 探测方式：`system.listMethods`、错误信息回显方法名、WSDL/文档泄露、路径爆破。
- 无回显时用响应时间/错误码差异做盲 SSRF；支持重定向时可打 gopher/内网协议（另卡）。

## 检测与防御

- 对方法参数中的 URL 做协议白名单（仅 http/https）、解析并校验 IP 段（拒绝回环/私网/链路本地），禁止跟随跨域重定向。
- 出站代理与网络分段；XML-RPC 端点鉴权、方法白名单、限速。
- 日志排查：`<methodName>` 含 CheckUptime/ping/fetch 的请求、参数为内网地址、服务端异常出站连接。
