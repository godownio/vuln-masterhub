---
id: ai-security-agent-security-sandbox-shared-artifactory-property-channel
title: AI 代码执行沙箱跨账号共享制品属性信道：Artifactory Item Properties 写入与受害者连接器任务借用
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: cross-tenant-shared-object-property-channel
aliases:
- ChatGPT 沙箱跨账号数据泄露
- Shared Clipboard Inside the Sandbox
- Artifactory Item Properties 信道
- reader 凭据 Annotate 越权
- 共享缓存对象状态信道
- 沙箱跨租户任务投递
tags:
- ai-security
- agent
- sandbox
- multi-tenant
- artifactory
- jfrog
- item-properties
- covert-channel
- connector
- confused-deputy
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:49:58+08:00'
  notes: 已对照原文与全部 51 张图核对：Artifactory Item Properties 的 GET/PUT 接口、Read vs Annotate、204/403/401 本地对照（Artifactory-Lab/1.0 Python 3.11.1）、2400 字符/分片 blob_n、sandbox_agent --hidden 任务流与结果回写均与正文一致；公开 Gmail 连接器链为引用案例、卡片已标注条件性；未复跑
---

## 一句话结论

当两个网络互不可达的 AI 代码执行沙箱使用同一内部制品仓库、且运行时凭据对同一 `repoKey + itemPath` 同时具备读取与 `Annotate`（修改 Item Properties）权限时，攻击者可在共享缓存对象的属性中写入任务，另一租户的会话读取同一属性后若把它当作任务来源，就可能借用该会话已合法授权的连接器执行并回写结果，形成跨账号数据泄露与能力借用。

## 原理

- 代码执行沙箱需要安装依赖，平台通常放行到内部 Artifactory 的出口；制品正文（数据面）可以而且应该被多个租户共享。
- Artifactory 用 `repoKey + itemPath` 定位对象，对象旁边的 Item Properties（状态面）可通过 Storage API 读写，不需要替换包正文：
  - `GET /artifactory/api/storage/{repoKey}/{itemPath}?properties` 读取属性；
  - `PUT /artifactory/api/storage/{repoKey}/{itemPath}?properties=key=value&recursive=0` 修改属性。
- 网络白名单只决定请求能否到达 Artifactory；是否允许改属性由服务端权限决定。JFrog 把 `Read`（下载制品并读取元数据）与 `Annotate`（为制品/目录增加或修改属性）分开授权。若沙箱运行时用的 reader 凭据同时带有 `Annotate`，那么“只能装依赖”的容器就多出了改写共享对象状态的能力。
- 状态坐标若不含租户维度，A 写入的属性会被 B 在相同 `repoKey + itemPath` 上读回。可以把隔离模型写成 `StateKey = tenant_id + repoKey + itemPath + state_namespace`；公开案例的可观察行为相当于 `StateKey = repoKey + itemPath`。这是隔离模型，不是对 Artifactory 后台存储键的断言。
- 单属性值上限约 2400 字符（键上限 255 字符），因此短标记可直接放一个键；更长内容要按 Base64 分片（`blob_n`、`blob_0..blob_n`、摘要、`READY`/`CONSUMED` 状态），接收端轮询同一属性表。属性接口没有天然的认领、确认、CAS 或过期语义，覆盖、半写入和重复消费都要上层自己处理。
- 影响扩展：跨账号属性可见性本身只传递字符串。公开案例进一步出现 Gmail 数据读取，是因为受害会话的执行流程把共享属性当作任务来源，并使用了该会话已经连接的 Gmail 工具；攻击者没有取得 Gmail OAuth 凭据，借用的是受害会话已有的合法能力，接近“混淆代理”（Confused Deputy）。是否成立还取决于模型是否采纳任务、平台工具策略与用户确认机制。

## 触发条件

- 两个租户的沙箱都能访问同一个内部制品服务，但彼此没有直接网络路径；共享依赖缓存路径可预测（包名 + 版本）。
- 沙箱运行时凭据在同一对象上具备属性读取与 `Annotate` 权限（名称叫 reader 不代表默认只读，取决于实际配置）。
- 共享对象上存在可写属性面，且属性状态未按租户隔离。
- 受害会话中存在促使它检查共享状态的上下文（粘贴内容、共享对话、自定义配置等），且模型/平台允许调用目标连接器；受害会话对目标数据拥有合法权限；结果可回写共享状态。

## 利用步骤

1. 识别内部制品服务与可预测的缓存路径，例如 `pypi-cache/packages/requests/2.32.3/requests-2.32.3.tar.gz`。
2. 验证读取：向 `GET /artifactory/api/storage/<repo>/<path>?properties` 发送请求；错误 Token 返回 401，合法 Token 返回 200。
3. 验证写入：向同一路径发送 `PUT ...?properties=probe=should-deny&recursive=0`；返回 204 表示当前身份可写属性，403 表示 `Annotate` 被关闭（不要与 401 认证失败混为一谈）。
4. 建立单向信道：A 写入 `task.message_id`、`task.part_count`、`task.part_i`（Base64）、`task.digest`，全部就绪后写 `task.state=ready`；B 轮询同一路径的 `?properties`。
5. 受害侧采纳任务后调用其已有连接器（公开案例为 Gmail），把结果写入 `result.*`；A 再读取 `result.*`。投递任务和读取结果都不需要容器互访。
6. 如需双向或大消息，用 `task.*`/`result.*` 两组键和分片；接收方核验分片数与摘要后再标记 `CONSUMED` 并清理旧键。

## PoC

最小属性写入与读取（仅用于授权环境，Token 已省略）：

```http
PUT /artifactory/api/storage/pypi-cache/packages/requests/2.32.3/requests-2.32.3.tar.gz?properties=probe%3Dshould-deny&recursive=0 HTTP/1.1
Host: artifactory.internal
Authorization: Bearer <runtime-token>

GET /artifactory/api/storage/pypi-cache/packages/requests/2.32.3/requests-2.32.3.tar.gz?properties HTTP/1.1
Host: artifactory.internal
Authorization: Bearer <runtime-token>
```

原文本地对照服务（`Artifactory-Lab/1.0 Python 3.11.1`，非真实 ChatGPT 环境）的结果：

```text
PUT  ...?properties=probe=should-deny     -> 204 No Content
PUT  （撤销 Annotate 后同一请求）          -> 403 Forbidden
     {"errors":[{"status":403,"message":"Permission Denied -- annotate disabled"}]}
GET  （错误 Token 查询同一路径）           -> 401 Unauthorized
```

分片写入示例（本地对照，5000 字节拆成 4 片）：

```http
PUT /artifactory/api/storage/pypi-cache/packages/requests/2.32.3/requests-2.32.3.tar.gz?properties=blob_n%3D4&blob_0%3D...&blob_1%3D...&blob_2%3D...&blob_3%3D...&recursive=0 HTTP/1.1
```

读取端重组得到 5000 字节；该结果只证明本地服务在给定参数下能恢复分片，不代表真实 Artifactory 的吞吐量或可靠性。

受害侧任务处理流程（原文本地 `sandbox_agent.py --hidden` 模拟，使用假连接器和 `lab/mail.json`）：

```text
[attacker] published hidden task: {"id": "t-...", "op": "list_mail", "args": {"limit": 2}}
[victim]   inspect-task  -> [READ ONLY] task received ... [NO CONNECTOR CALL] [NO RESULT WRITE]
[victim]   victim-turn --hidden -> "Talked to Mail" + 合成邮件
[attacker] collect -> {"ok": true, "op": "list_mail", "items": [...]}
```

`--hidden` 是实验程序显式打开的分支，不是真实模型被攻击者诱导后自行决定的证据；真实 Gmail 读取行为来自公开披露，不能由本地假连接器结果直接外推。

## 变体与关联

- 同一原语的不同服务实现：Jupyter Contents 用 `root_dir + path` 定位共享文件；MinIO/S3 用 `bucket + objectKey` 加 `?tagging` 读写对象标签；三者都是“共同服务 + 稳定对象坐标 + 一侧可写 + 另一侧可读”。
- Tagging 被禁用后，未完成 Multipart 上传的 `ListParts` 元数据仍可承载状态（见对象存储元数据信道卡）。
- 消息组织变体：单键短消息；`blob_n` 分片；用 `state=ready/consumed` 做提交与消费标记；用时间戳或消息编号区分新旧。
- 关联：间接提示词注入（把任务推入受害会话上下文）、Agent 工具调用劫持、混淆代理、MCP 工具越权、制品缓存投毒。
- 公开案例中的 `reader` 只是凭据名称，不代表 JFrog 默认给读取者授予修改权限；风险来自实际环境把 `Read` 与 `Annotate` 一起授给了运行时。

## 检测与防御

- 权限拆分：沙箱运行时只授予 `Read`，显式拒绝 `PUT /api/storage/...?...properties`；不要因为下载与属性接口共用同一个 Artifactory 出口就顺带放行属性写。
- 网络与 API 双层控制：出口白名单之外，在代理/网关层按 HTTP 方法与 API 路径限制，下载只需 `GET /artifactory/<repo>/<path>`，不应允许 `PUT /api/storage`。
- 状态归属：`StateKey = tenant_id + repoKey + itemPath + state_namespace`；共享缓存正文，但不共享可写伴生状态；或为每个租户使用独立缓存命名空间。
- Agent 执行器：任务来源必须来自当前受信会话或服务端授权上下文，不能仅凭共享属性中的字符串调用连接器；高风险连接器调用前要求用户确认，确认必须发生在调用之前。
- 检测：沙箱身份对共享包路径的 `PUT /api/storage/...?properties` 成功（204）；对 `?properties` 的高频轮询；`task.*`/`result.*`/`blob_*` 等异常属性键；同一轮交互中出现隐藏的连接器调用与结果回写；跨租户对同一对象的属性读取。403/401 只是失败信号，成功写入才是关键。
- 响应：撤销运行时 `Annotate`、清理被写入的属性、轮换疑似泄露的运行时凭据、审计受害会话的连接器调用与数据访问记录。
- 局限：原文未给出具体产品受影响版本（这是平台配置/授权问题，不是单个 CVE）；本地 Artifactory 为对照 Mock；公开披露未说明其内部租户与属性存储实现；连接器自动执行依赖模型与平台策略，不能视为稳定可复现的默认行为。
