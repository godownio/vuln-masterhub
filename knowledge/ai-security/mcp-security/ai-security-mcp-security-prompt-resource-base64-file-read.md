---
id: ai-security-mcp-security-prompt-resource-base64-file-read
title: MCP 服务 prompt 泄露敏感路径 + get_file_base64 资源模板以 root 读取任意文件
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: mcp-prompt-resource-base64-file-read
aliases:
- MCP prompt 泄露路径
- get_file_base64 资源模板
- MCP Inspector 读取文件
- 本地 MCP 服务提权读取
- MCP resource template 任意文件读取
tags:
- ai
- mcp
- prompt
- resource-template
- file-read
- localhost
- inspector
- root
- post-exploitation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:18+08:00'
  notes: 已对照原文与全部 89 张图片核对；修正 flag 路径为 /root/1fff111aaaggg；未在目标复现
---

## 一句话结论

目标容器内以 root 身份运行的 MCP server（监听 `127.0.0.1:9000`）暴露了 `where_is_flag` prompt 和 `get_file_base64` 资源模板：前者直接返回 flag 路径 `/root/1fff111aaaggg`，后者接受文件路径并以 base64 返回文件内容；攻击者从应用 RCE 后用 frp 把 9000 端口代理出来，连接 MCP Inspector 调用 prompt/resource 即可读出 root 才能访问的文件。

## 原理

- MCP（Model Context Protocol）服务端可以定义 prompts、resources、resource templates 和 tools；客户端通过 `prompts/get`、`resources/templates/list`、`resources/read` 等 JSON-RPC 方法调用。
- 如果服务端把“文件读取”实现为资源模板（如 `get_file_base64`），并且没有路径白名单/沙箱，任何能访问 MCP 端点的客户端都可以让服务端读取任意文件；返回内容通常是 base64，客户端解码即可。
- 本例中 MCP server 以 root 运行（`python /app/mcp/server.py`，ps 显示 root），而 Web 应用以低权限用户运行；MCP 的 prompt 直接告诉客户端 flag 在 `/root/1fff111aaaggg`，资源模板负责读取。
- MCP 默认绑定 localhost 并不等于安全：应用 RCE/SSRF 后可本地访问，或通过 frp/端口转发把 9000 暴露给攻击者；MCP Inspector 等客户端可完成协议交互。
- 根因是“MCP 服务把高权限文件访问能力暴露给任意客户端，且 prompt 泄露敏感路径”，属于 MCP 服务的权限边界与资源模板设计缺陷。

## 触发条件

- MCP server 可访问（本地 localhost 经 SSRF/RCE 代理，或直接暴露）。
- 服务端定义了文件读取类 resource/tool，且未做路径允许列表。
- prompt 或资源元数据泄露敏感路径/凭据。
- MCP 进程权限高于攻击者当前权限（本例为 root）。

## 利用步骤

1. 在受控主机上 `ps aux`/`netstat` 发现 `python /app/mcp/server.py` 以 root 运行并监听 `127.0.0.1:9000`。
2. 用 frp/SSH 隧道/SSRF 把 9000 端口映射到攻击者可访问的位置。
3. 使用 MCP Inspector（如 `npx @modelcontextprotocol/inspector http://localhost:9000/mcp`）连接，Transport 选 Streamable HTTP。
4. 在 Prompts 页列出并调用 `where_is_flag`，从返回消息中得到 flag 路径。
5. 在 Resources/Templates 页找到 `get_file_base64`，传入目标路径，读取 base64 内容并解码。
6. 如需其他文件，替换路径重复调用；若模板限制 URI scheme，可尝试 `base64://`、`file://` 或路径穿越形式。

## PoC

MCP Inspector 连接地址：`http://localhost:9000/mcp`（经 frp 映射后为攻击者地址）。

`where_is_flag` prompt 返回（示意）：

```json
{
  "description": "Where is the flag located?",
  "messages": [
    {"role": "user", "content": {"type": "text", "text": "flag, flag is in /root/1fff111aaaggg"}}
  ]
}
```

`get_file_base64` 资源返回（示意）：

```json
{
  "contents": [
    {"uri": "base64://...", "mimeType": "text/plain",
     "text": "{\"filename\":\"/root/1fff111aaaggg\",\"content\":\"<base64>\"}"}
  ]
}
```

解码 `content` 即得到 flag。

## 变体与关联

- MCP 工具型文件读取：`read_file(path)`、`download(url)`、`execute(sql)` 等；与资源模板同样缺少路径/权限校验。
- MCP 未授权访问：SSE/HTTP 端点无鉴权、绑定 0.0.0.0；MySQL MCP SSE 未授权 SQL 查询。
- MCP stdio 命令注入：`CreateMCPService` 直接执行用户 command/args；与资源模板文件读取同属 MCP 信任边界问题。
- 关联：容器内本地服务发现、frp 隧道、SSRF 打 localhost、post-exploitation 提权读取。

## 检测与防御

- MCP server 以最小权限运行，不要用 root；文件读取资源限制在专用目录并做路径规范化/允许列表。
- 对 MCP 端点启用认证与来源校验，禁止绑定 0.0.0.0；localhost 服务也要防 SSRF。
- prompt/resource 元数据不得包含 flag 路径、凭据或内部目录结构。
- 审计 MCP 调用日志，监控异常文件读取与高权限进程访问。
