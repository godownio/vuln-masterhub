---
id: web-java-component-nifi-unauth-executeprocess-rce
title: Apache NiFi 未启用认证 + ExecuteProcess 处理器：在 UI/API 建流执行系统命令，再用 LogMessage+listQueue 取回回显
type: scenario
domain: web
path: web/java/component
technique: nifi-unauth-execute-process-processor-rce
aliases:
- NiFi ExecuteProcess RCE
- Apache NiFi 未授权命令执行
- NiFi listQueue 取回显
- NiFi 处理器后门
tags:
- apache-nifi
- java
- rce
- unauthorized
- misconfiguration
- processor
- listqueue
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:47:56+08:00'
  notes: 已对照原文核对；本次核对未读取图片；受影响面为「管理面未鉴权（HTTP 暴露且未启用认证）+ ExecuteProcess 处理器」的配置型 RCE，与正文所记 nifi-1.28.1 本地复现路径（拖入 ExecuteProcess、配 LogMessage、listQueue 读 FlowFile）一致；原文仅写「早期版本默认不安全」且 1.28.1 只是环境版本，未给出明确受影响区间，故不填 affected_versions；卡内 REST 接口名为通用形状，原文未给脚本化请求与响应，PoC 未对真实目标运行
---

## 一句话结论

Apache NiFi 的 `ExecuteProcess` 处理器本身就是“执行系统命令”的合法能力；当实例以 HTTP 暴露且未配置认证（或凭据弱/泄露）时，任何能访问 Web UI 或 REST API 的人都能拖入 `ExecuteProcess`、配置命令并启动流，命令即以 NiFi 进程权限执行；借 `LogMessage`/`UpdateAttribute` 连接下游并查看队列（listQueue）即可拿到命令输出，解决公开 exp“无回显”的痛点。

## 原理

- **能力即接口**：NiFi 的设计目标之一就是跑任意外部程序，`ExecuteProcess` 的 Command/Command Arguments/Working Directory 全部由用户配置，处理器启动后由 NiFi 直接 `fork/exec`。因此“能配置处理器”等价于“能在主机上执行命令”。
- **认证缺失 = 完整控制面**：NiFi 默认只监听 127.0.0.1 且遗留示例强调“不要裸奔”，但实践中常被改成 `nifi.web.http.host=0.0.0.0` 或放入内网暴露，并且没有启用 TLS/单点登录；此时创建处理器组、拖拽、启动、停止等 API 全部无鉴权。
- **无回显问题的解法**：命令的 stdout 不会回到 HTTP 响应，但 `ExecuteProcess` 的输出 FlowFile 会落到下游连接队列里；用一个 `LogMessage`（或任意把内容写入属性/日志的处理器）接在后面，再对上游队列执行 listQueue，即可在响应里读到 FlowFile 内容（日志也可通过 `nifi-app.log` 或日志查看器读取）。
- **为何仍算漏洞**：问题不在某个 CVE，而在于“暴露未鉴权的管理面 + 内置高危处理器”，属于典型配置型 RCE；原文实测在 1.28.1 上完成。

## 触发条件

- 目标 NiFi 的 Web 端口可从攻击者网络访问（HTTP 而非仅 127.0.0.1）。
- 未启用认证（无 TLS/无单点登录），或存在弱口令/默认凭据/可绕过的代理认证。
- 目标进程有执行命令的权限，且 `ExecuteProcess` 处理器未被移除或加白名单限制。

## 利用步骤

1. 访问 Web 根路径或 `/nifi-api/flow/process-groups/root`，确认未跳转登录页且能拿到流程信息（有 `processGroups`/`processors` 即未授权）。
2. 取得/创建流程组（root 或新建 group），在画布中拖入 `ExecuteProcess`（搜索 executeprocess，带盾牌标识的即为危险处理器）。
3. 配置 Command 为要执行的程序（如 `cmd.exe`/`/bin/sh`），Command Arguments 为参数（如 `/c whoami` 或 `-c id`），设置工作目录后启动处理器。
4. 拖入 `LogMessage` 并用连接线从 `ExecuteProcess` 的 success 关系连到 `LogMessage`，形成“执行→记录”的最小流。
5. 在 `ExecuteProcess` 与 `LogMessage` 之间的连接上右键 listQueue（或调 `GET /nifi-api/flowfile-queues/{id}/flowfiles`），在 FlowFile 内容中读取命令输出。
6. 需要长期控制时，可把命令改成下载/执行远端脚本、写 crontab 或加 SSH key；完成后停止流并删除队列以清理痕迹。

## PoC

```http
# 1) 探测是否未授权（未启用认证时应返回流程 JSON 而非 302 到登录页）
GET /nifi-api/flow/process-groups/root HTTP/1.1
Host: target:8080
```

```text
# 2) UI 操作序列（原文复现路径；也可用同一批 REST 接口脚本化）
拖入 ExecuteProcess -> Command = cmd.exe / Command Arguments = /c whoami -> 启动
拖入 LogMessage   -> 连线 ExecuteProcess(success) -> LogMessage
右键该连接 -> List Queue -> 查看 FlowFile 内容 => 命令输出
```

```text
# 3) 关键判据
- /nifi-api/flow/process-groups/root 无需 Cookie 即可返回 JSON
- 新建/启动处理器返回 200 且 status.runStatus 变为 Running
- listQueue 返回的 flowfile 内容等于命令输出
```

无真实目标 PoC：原文在本地 1.28.1 环境通过 UI 完成上述链路，未给出脚本化 API 请求；接口名随 NiFi 版本略有差异。

## 变体与关联

- **处理器替换**：`ExecuteStreamCommand`、`ExecuteSQL`（可打数据库）、`InvokeHTTP`（SSRF/内网探测）、`PutFile`/`FetchFile`（任意写/读）、`ScriptedReportingTask`（Groovy/ECMAScript 脚本执行）。
- **API 化利用**：公开 exp 走“取 group → 建 processor → PUT 更新配置 → 启动 → 传参”的 REST 流程，但没有回显；本卡的 LogMessage+listQueue 组合可为其补上回显通道。
- **凭据路径**：弱口令/默认凭据登录后用同一手法；也可读取 `/conf/login-identity-providers.xml`、`flow.xml.gz` 中保存的敏感参数。
- **关联**：`web-java-deserialization-nifi-getasanaobject-cache-state-deser`（同产品的反序列化面）、`web-java-rce-processimpl-constructor-reflect-exec`（Java 层命令执行原语）。
- **边界**：启用 TLS + 认证（或仅监听 127.0.0.1）时该链路不成立；部分加固版本会禁用危险处理器或要求额外权限。

## 检测与防御

- **暴露面**：NiFi 只监听 127.0.0.1 或置于认证网关之后；必须启用 HTTPS 与单点登录（LDAP/Kerberos），禁止匿名访问 `/nifi-api/*`。
- **权限**：对 `ExecuteProcess`/`ExecuteStreamCommand`/`ExecuteSQL` 等危险处理器做组件级策略限制或从 NAR 中移除；普通用户不给“修改流程”权限。
- **审计**：监控处理器创建/配置变更（`/nifi-api/processors` 的 POST/PUT）、启动事件、`nifi-user.log` 中的匿名或异常账号操作；对 NiFi 进程派生的子进程（`sh`/`cmd`/`curl`/`nc`）告警。
- **检测特征**：同一会话短时间内“创建处理器 → 设置 Command 含 shell → 启动 → 读队列”；`ExecuteProcess` 的 Command 指向 `cmd.exe`/`/bin/sh`/`powershell`；队列中出现命令输出样式的 FlowFile 内容。
