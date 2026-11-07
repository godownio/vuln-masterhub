---
id: tools-burp-hermes-mcp-wsl-sse-integration
title: Hermes Agent 接入 Burp MCP：WSL 端口桥接、Origin 403 与异步 SSE 排障
type: scenario
domain: tools
path: tools/burp
technique: burp-mcp-hermes-wsl-integration
aliases:
- Burp MCP
- Hermes 接入 Burp
- WSL portproxy
- 异步 tools/call
- SSE 结果读取
- Burp AI Agent
tags:
- burp
- mcp
- hermes
- wsl
- sse
- portproxy
- ai-agent
- tooling
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V104
  verified_at: '2026-11-05T22:44:54+08:00'
  notes: 已对照原文与8张图核对：Burp Suite 2026.3.2 + Burp AI Agent v0.9.0（图01/02）、MCP Host 127.0.0.1:9876、portproxy 0.0.0.0→127.0.0.1（图04/06）、防火墙/Origin 403/202+SSE/Privacy 五个坑与正文一致；环境版本（Burp 2026.3.x、AI Agent 0.9.0、Hermes 0.13+、JDK 21+）仅为搭建环境，未设为 affected_versions。未验证点：原文为接入教程，未在本机执行 Burp/Hermes 命令；图02/03 的 Unsafe/Privacy 截图与正文操作后状态不完全对应；frontmatter 无 sources/source_url。
---

## 一句话结论

Hermes Agent 原生支持 MCP，可以不经 MCPorter 直接连接 Windows 上的 Burp AI Agent；在 WSL 环境下需要依次解决 `netsh portproxy` 顺序、Windows 防火墙、Origin 403、`tools/call` 异步 202+SSE 以及 Privacy 脱敏五个问题，才能真正用 Agent 发请求和读历史。

## 原理

- **架构**：Burp AI Agent 插件内置 MCP Server（SSE + 可选 stdio bridge），默认监听 `127.0.0.1:9876`；Hermes 的 native-mcp 客户端通过 `http://<Windows 网关 IP>:9876/sse` 连接，链路为 `Hermes → Burp AI Agent → Burp Suite`，比 `OpenClaw → MCPorter → Burp AI Agent` 少一层中间件。
- **WSL 与 Windows 的环回地址隔离**：WSL 的 `127.0.0.1` 与 Windows 的 `127.0.0.1` 不是同一个网络命名空间。Burp 只绑 `127.0.0.1` 时 WSL 连不上；Burp AI Agent v0.9.0 又不支持直接绑 `0.0.0.0`（改了会 Error），所以要用 `netsh interface portproxy` 把 Windows 的 `0.0.0.0:9876` 转发到 `127.0.0.1:9876`。
- **portproxy 顺序坑**：如果先加 portproxy 再启动 MCP，portproxy 已占用 9876，Burp MCP 会报 “Port in use”。正确顺序是：删旧转发 → 在 Burp 里启用 MCP 并等 Running → 再加转发。`netstat -ano | findstr 9876` 看到 `127.0.0.1:9876` 对应 PID 是 `javaw.exe`（不是 `svchost.exe`）才说明 Burp 在监听。
- **Windows 防火墙**：Defender 默认拦截从 vEthernet（WSL）网卡进入的连接；测试环境可临时关闭，生产环境应加放行规则只允许 WSL 网段访问 9876。
- **Origin 403**：Hermes 的 httpx 会自动带 `Origin` 头，Burp AI Agent v0.9.0 有 CORS 检查；curl 手动测是 200，Hermes 却 403。在 `config.yaml` 的 MCP server 配置里加 `headers: {Origin: ""}`，让客户端不发送 Origin 头即可。
- **异步 tools/call**：Burp MCP 的所有 `tools/call` 都是异步的——POST 返回 `202 Accepted`，实际结果通过已建立的 SSE 连接推回。只发 POST 就断开会丢结果；客户端必须保持 SSE 连接并读取异步消息。
- **Privacy 脱敏**：Privacy mode 为 BALANCED 时，历史里的 `Cookie`/`Authorization` 会被替换为 `[REDACTED]`/`[STRIPPED]`；要拿完整 Cookie/JWT 需改为 OFF（同时意味着敏感数据进入 Agent 上下文，需权衡）。
- **环境要求**：Burp Suite 2026.3.x 需要 JDK 21+（class file version 65.0），JDK 17 会报 `UnsupportedClassVersionError`；Hermes v0.13+、Python 3.11+；社区版 AI 功能不可用（`ai_analyze`/`ai_passive_scan` 报错），但 MCP 的 HTTP/历史/Repeater/Intruder/Collaborator 工具仍可用。

## 触发条件

- 宿主机 Windows，Agent 跑在 WSL/macOS/Linux；Burp AI Agent v0.9.0+ 已加载并启用 MCP Server。
- 需要让 Agent 调用 Burp 的 `http1_request`、`proxy_http_history_regex`、Repeater/Intruder/Collaborator 等工具。
- WSL 能访问 Windows 的 vEthernet 网关 IP（如 `172.18.x.1`），且 9876 未被其他进程占用。
- 允许配置 `netsh portproxy`（管理员权限）、防火墙规则与 Hermes `config.yaml`。
- 已明确授权目标与扫描范围；Agent 只用于授权测试。

## 利用步骤

1. **装 Burp 与插件**：用 JDK 21 启动 Burp；`Extensions → Add → Java` 选择 Burp AI Agent v0.9.0 jar；打开 `Custom AI Agent` 标签页。
2. **配 MCP Server**：Host `127.0.0.1`、Port `9876`；需要写操作时勾 `Unsafe mode`；`Settings → Privacy & Logging` 按需把 Privacy mode 从 BALANCED 改为 OFF。
3. **装 Hermes**：执行安装脚本；把 `~/.hermes/hermes-agent` 加入 `~/.profile` 的 PATH；补齐 `fire prompt_toolkit rich openai requests pyyaml`。
4. **建端口转发**：先删除旧 portproxy，启动 Burp MCP 等 Running，再执行 `netsh interface portproxy add v4tov4 listenport=9876 listenaddress=0.0.0.0 connectport=9876 connectaddress=127.0.0.1`；用 `netstat -ano | findstr 9876` 验证 PID 为 `javaw.exe`。
5. **放行防火墙**：测试环境可临时关闭；生产环境加 `dir=in action=allow protocol=TCP localport=9876` 规则，并限制来源网段。
6. **配 Hermes**：`mcp_servers.burpsuite.url = http://<网关IP>:9876/sse`，`timeout/connect_timeout` 适当放大，`headers: {Origin: ""}`。
7. **调工具**：用封装脚本保持 SSE 连接：先 GET `/sse` 拿 sessionId，再 POST `tools/call`，从 SSE 读取异步结果；例如 `status`、`http1_request`、`proxy_http_history_regex`。
8. **验证**：用 `status` 确认连接；用 `http1_request` 对授权目标发 GET；用 `proxy_http_history_regex` 查历史；确认 Cookie/JWT 是否被脱敏。

## PoC

Hermes `config.yaml`：

```yaml
mcp_servers:
  burpsuite:
    url: "http://172.18.64.1:9876/sse"
    timeout: 300
    connect_timeout: 60
    headers:
      Origin: ""
```

Windows 端口转发（顺序不能错）：

```bat
:: 1) 删旧转发
netsh interface portproxy delete v4tov4 listenport=9876 listenaddress=0.0.0.0
:: 2) 在 Burp AI Agent 里启用 MCP，等状态变 Running
:: 3) 再加转发
netsh interface portproxy add v4tov4 listenport=9876 listenaddress=0.0.0.0 connectport=9876 connectaddress=127.0.0.1
:: 4) 验证：PID 应为 javaw.exe
netstat -ano | findstr 9876
```

异步 SSE 调用封装（伪代码）：

```python
# 1) 开 SSE 连接拿 sessionId
sse = connect_sse("http://172.18.64.1:9876/sse")
session_id = get_session_id(sse)

# 2) 发 POST 请求调工具（服务端返回 202）
post_message(session_id, "tools/call", {"name": "status", "arguments": {}})

# 3) 从同一条 SSE 连接读取异步结果
result = read_sse_result(sse)
```

命令行示例：

```bash
python3 burp_mcp.py tools/call status '{}'
python3 burp_mcp.py tools/call http1_request '{"content":"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n","targetHostname":"example.com","targetPort":443,"usesHttps":true}'
python3 burp_mcp.py tools/call proxy_http_history_regex '{"regex":"target"}'
```

## 变体与关联

- **中间件变体**：OpenClaw + MCPorter（多一层 npm 翻译层）、其他原生 MCP 客户端（Claude Desktop、Cursor）直连 Burp AI Agent。
- **传输变体**：SSE、stdio bridge、HTTP streamable；不同客户端对 Origin/异步结果的处理不同。
- **环境变体**：WSL2 镜像网络模式下环回地址行为不同；Docker 容器内的 Agent 需要 host 网络或额外端口映射。
- **关联卡片**：[[ai-security-mcp-security-burp-mcp-server-exposure-unsafe-portproxy]]（同一套配置的暴露面风险）、[[ai-security-agent-security-ai-pentest-evidence-driven-pipeline]]（Agent 验证流水线）、[[ai-security-mcp-stdio-endpoint-command-injection]]（MCP stdio 风险）。
- **边界**：Burp AI Agent 版本升级可能改变端口/Origin/异步行为；社区版 AI 功能不可用；Cloudflare/WAF 可能拦截 Burp 直发请求，需要浏览器代理配合；未授权目标不适用。

## 检测与防御

- **最小暴露**：Burp MCP 只绑 `127.0.0.1`；不要长期保留 `0.0.0.0` portproxy；防火墙规则只允许 WSL/本机网段访问 9876。
- **权限最小化**：只在需要写操作时开启 Unsafe mode；用完关闭；把 MCP 工具限制在授权目标（in-scope hosts）。
- **隐私权衡**：Privacy mode 默认 BALANCED；只有确需完整 Cookie/JWT 时才临时改 OFF，并限制 Agent 日志/上下文留存。
- **审计**：记录 MCP 工具调用、目标域名、请求数量；监控 9876 的连接来源；定期检查 portproxy 与防火墙规则。
- **合规**：只对授权目标测试；限速；避免用 Agent 自动构造破坏性请求；报告脱敏。
