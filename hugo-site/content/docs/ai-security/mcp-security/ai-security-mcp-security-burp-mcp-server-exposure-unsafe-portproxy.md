---
id: ai-security-mcp-security-burp-mcp-server-exposure-unsafe-portproxy
title: Burp MCP Server 暴露面：Unsafe mode + 0.0.0.0 portproxy + Privacy OFF 的未授权请求代理与流量读取
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: burp-mcp-server-exposure
tags:
- burp
- mcp
- exposure
- unsafe-mode
- privacy
- portproxy
- traffic
- credential-theft
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V104
  verified_at: '2026-11-05T22:44:56+08:00'
  notes: 已对照原文与8张图核对：Burp AI Agent MCP Server 配置无认证字段、Host 127.0.0.1:9876（图02）、portproxy listenaddress=0.0.0.0→127.0.0.1（图04/06），正文展示了 Hermes 经该网络路径调用 http1_request 与 proxy_http_history_regex 并读取 Cookie/Authorization（Privacy OFF 后）。未验证点：原文是接入教程，未从第三方主机做未授权访问/凭据窃取 PoC，暴露链为配置语义推断；图03/07 显示 Privacy 仍为 BALANCED，与正文“改为 OFF”不直接对应；卡片已标 confidence=medium 并在 PoC 注明“仅为协议结构示意，未对真实实例执行”；frontmatter 无 sources/source_url。
url: /docs/ai-security/mcp-security/ai-security-mcp-security-burp-mcp-server-exposure-unsafe-portproxy/
draft: false
kb_aliases:
- Burp MCP 暴露
- Unsafe mode
- 未授权请求代理
- 代理历史读取
- portproxy 0.0.0.0
- Privacy OFF
---

## 一句话结论

Burp AI Agent 内置的 MCP Server 没有认证；为了让 WSL 里的 Agent 连上，教程常用 `netsh portproxy` 把 `0.0.0.0:9876` 转发到 `127.0.0.1:9876`，若再开启 Unsafe mode 并关闭 Privacy，任何能访问 9876 的主机都可以无认证调用 `http1_request` 发任意请求，并通过 `proxy_http_history_regex` 读取含 Cookie/JWT 的代理历史。

## 原理

- **MCP Server 无认证**：Burp AI Agent 的 MCP 走 SSE：`GET /sse` 获得 session，`POST` 消息调用工具；协议本身没有 API Key/Token 校验，信任边界完全依赖监听地址与防火墙。
- **0.0.0.0 转发打破环回边界**：Burp 默认只绑 `127.0.0.1`，WSL 的环回地址与 Windows 隔离；为连通性使用 `netsh portproxy listenaddress=0.0.0.0` 后，9876 在 Windows 所有网卡上可达，同 LAN、WSL 网段或其他能路由到该主机的系统都能连接。
- **Unsafe mode 放大能力**：勾选后 MCP 暴露写/变更类工具（`http1_request`、Repeater、Intruder、Collaborator 等），攻击者可以让 Burp 所在主机向任意目标发请求（包括内网服务、云元数据、localhost 管理接口），并把响应读回——相当于一个高权限 HTTP 代理/SSRF 跳板。
- **Privacy OFF 泄露凭据**：BALANCED 会把 `Cookie`/`Authorization` 脱敏为 `[REDACTED]`/`[STRIPPED]`；OFF 后 `proxy_http_history_regex` 直接返回完整 Cookie、JWT、API Key，攻击者可读取受害者浏览器/业务流量的登录态。
- **组合后果**：无认证 + 0.0.0.0 + Unsafe + Privacy OFF = 同网段攻击者可“以 Burp 主机身份”发请求并窃取流量凭据；若 Burp 主机在云上/内网，还可作为横向移动与云元数据读取的跳板。
- **为什么会发生**：这是便捷性与安全性的经典冲突——`127.0.0.1` 绑定无法跨 WSL，`0.0.0.0` 转发最省事；教程还建议测试时关闭防火墙、开启 Unsafe mode，进一步移除边界。

## 触发条件

- Burp AI Agent MCP Server 已启用，且通过 `netsh portproxy listenaddress=0.0.0.0`（或 `External access`/TLS 配置）暴露到非环回地址。
- Windows 防火墙允许 9876 入站，或测试时被关闭；攻击者能路由到该主机。
- Unsafe mode 开启，`http1_request` 等写/变更工具可用。
- Privacy mode 为 OFF，代理历史包含未脱敏 Cookie/Authorization/JWT。
- 攻击者能访问 `/sse` 并完成 MCP 握手（无需凭据）。

## 利用步骤

1. **发现**：扫描/探测 9876 端口，或从 `netstat`/portproxy 配置得知；`curl http://target:9876/sse` 观察是否建立 SSE 流。
2. **建立会话**：GET `/sse` 获取 sessionId；保持连接，记下服务端返回的 message endpoint。
3. **列工具**：POST `tools/list`，确认 `http1_request`、`proxy_http_history_regex`、Repeater/Intruder 等工具可用。
4. **发请求**：POST `tools/call` 调用 `http1_request`，`targetHostname` 填内网服务/云元数据/localhost 管理接口，读取 SSE 返回的响应。
5. **读流量**：调用 `proxy_http_history_regex`，用正则筛选登录接口、API、Cookie、Authorization；Privacy OFF 时可直接拿到完整凭据。
6. **利用**：用泄露的 Cookie/JWT 登录业务系统；用请求代理访问内网/元数据；必要时结合 Repeater/Intruder 扩大影响。
7. **验证**：从攻击者主机复现，确认无认证即可调用；检查 Burp 主机网络位置与可达范围。

## PoC

MCP 交互示意（SSE + POST，具体消息格式以 Burp AI Agent 版本为准）：

```http
GET /sse HTTP/1.1
Host: target:9876
Accept: text/event-stream
```

```http
POST /message?sessionId=<session_id> HTTP/1.1
Host: target:9876
Content-Type: application/json

{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"http1_request","arguments":{"content":"GET / HTTP/1.1\r\nHost: 169.254.169.254\r\nConnection: close\r\n\r\n","targetHostname":"169.254.169.254","targetPort":80,"usesHttps":false}}}
```

```http
POST /message?sessionId=<session_id> HTTP/1.1
Content-Type: application/json

{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"proxy_http_history_regex","arguments":{"regex":"(?i)(cookie|authorization|token)"}}}
```

以上仅为协议结构示意，未对任何真实 Burp 实例执行。

## 变体与关联

- **暴露方式变体**：`0.0.0.0` portproxy、Burp 的 `External access (requires TLS)`、Docker `-p 9876:9876`、云主机安全组放行。
- **能力变体**：Unsafe mode 下的 Repeater/Intruder/Collaborator、代理历史、扫描器结果；即使 Unsafe mode 关闭，只读工具也可能泄露历史中的凭据。
- **认证缺失变体**：其他本地/内网 MCP server（Inspector、浏览器 MCP、数据库 MCP）同样常见无认证 + 0.0.0.0 暴露。
- **关联卡片**：[[tools-burp-hermes-mcp-wsl-sse-integration]]（同一套接入配置）、[[ai-security-mcp-security-inspector-cors-stdio-rce]]（MCP Inspector 暴露/RCE）、[[ai-security-mcp-security-oauth-authz-server-missing-host-check-rebinding]]（MCP 授权服务器 Host 校验缺失）。
- **边界**：默认 `127.0.0.1` 绑定且防火墙正确时不可远程利用；若 portproxy 仅绑定 WSL 网段或加了来源限制，攻击面缩小；Burp AI Agent 未来版本可能增加认证/TLS 校验；Unsafe mode 未开启时写工具不可用。

## 检测与防御

- **绑定与转发**：不要用 `listenaddress=0.0.0.0` 长期暴露 Burp MCP；优先在 WSL/容器内使用 host 网络或 Unix socket，或只转发到 WSL 网段并加防火墙来源限制。
- **认证与 TLS**：在 MCP 前置一层带认证的反向代理（mTLS/Token）；启用 TLS 并校验客户端；不要依赖“端口不公开”作为安全边界。
- **权限最小化**：默认关闭 Unsafe mode，只在需要时临时开启；限制可访问目标（in-scope hosts）；用完立即关闭 MCP Server。
- **隐私保护**：Privacy mode 保持 BALANCED/严格；不要为方便长期 OFF；对 Agent 上下文与日志做脱敏与留存限制。
- **检测**：监控 9876 的非本机连接、异常 `tools/call`（尤其 `http1_request` 指向内网/元数据）、代理历史批量查询；审计 portproxy 与防火墙规则变更；检查 Burp 主机是否被用作内网跳板。
- **响应**：关闭暴露端口、撤销 portproxy/防火墙规则、轮换流量中泄露的 Cookie/JWT/API Key、排查内网目标是否被访问。
